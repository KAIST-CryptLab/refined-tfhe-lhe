use rand::Rng;
use tfhe::core_crypto::prelude::*;
use hom_trace::{
    automorphism::gen_all_auto_keys, byte_array_to_mat, generate_scheme_switching_key, get_he_state_error, he_add_round_key, he_mix_columns, he_shift_rows, he_sub_bytes_by_patched_wwllp_cbs, keygen_pbs, Aes128Ref, FftType, BLOCKSIZE_IN_BIT, BLOCKSIZE_IN_BYTE, BYTESIZE, NUM_ROUNDS
};

type Scalar = u64;
const FFT_TYPE: FftType = FftType::Split16;
const NUM_REPEAT: usize = 1;

fn main() {
    // Set I
    let lwe_dimension = LweDimension(769);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.0000043131554647504185);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(15);
    let pbs_level = DecompositionLevelCount(2);
    let ks_base_log = DecompositionBaseLog(6);
    let ks_level = DecompositionLevelCount(2);
    let cbs_base_log = DecompositionBaseLog(5);
    let cbs_level = DecompositionLevelCount(3);

    let auto_base_log = DecompositionBaseLog(7);
    let auto_level = DecompositionLevelCount(7);
    let ss_base_log = DecompositionBaseLog(8);
    let ss_level = DecompositionLevelCount(6);
    let log_lut_count = LutCountLog(2);

    sample_aes_eval_err(lwe_dimension, glwe_dimension, polynomial_size, lwe_modular_std_dev, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, auto_base_log, auto_level, ss_base_log, ss_level, cbs_base_log, cbs_level, log_lut_count, NUM_REPEAT);
}

#[allow(unused)]
fn sample_aes_eval_err(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: StandardDev,
    glwe_modular_std_dev: StandardDev,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    cbs_base_log: DecompositionBaseLog,
    cbs_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    num_repeat: usize,
) {
    println!(
        "n: {}, N: {}, k: {}, B_pbs: 2^{}, l_pbs: {}, B_ks: 2^{}, l_ks: {}, B_cbs: 2^{}, l_cbs: {},
B_auto: 2^{}, l_auto: {}, B_ss: 2^{}, l_ss: {}, log_lut_count: {}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_base_log.0, pbs_level.0, ks_base_log.0, ks_level.0, cbs_base_log.0, cbs_level.0,
        auto_base_log.0, auto_level.0, ss_base_log.0, ss_level.0, log_lut_count.0,
    );
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    let glwe_size = glwe_dimension.to_glwe_size();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let (
        lwe_sk,
        glwe_sk,
        lwe_sk_after_ks,
        fourier_bsk,
        ksk,
    ) = keygen_pbs(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        ks_base_log,
        ks_level,
        &mut secret_generator,
        &mut encryption_generator,
    );
    let fourier_bsk = fourier_bsk.as_view();

    let ss_key = generate_scheme_switching_key(
        &glwe_sk,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let ss_key = ss_key.as_view();

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        FFT_TYPE,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let mut rng = rand::thread_rng();
    let mut lwe_ks_err_list = vec![];
    let mut sub_err_list = vec![];
    let mut lin_err_list = vec![];
    let mut total_max_err = Scalar::ZERO;

    // ======== Plain ========
    let mut key = [0u8; BLOCKSIZE_IN_BYTE];
    for i in 0..BLOCKSIZE_IN_BYTE {
        key[i] = rng.gen_range(0..=u8::MAX);
    }

    let aes = Aes128Ref::new(&key);
    let round_keys = aes.get_round_keys();

    let mut message = [0u8; BLOCKSIZE_IN_BYTE];
    for i in 0..16 {
        message[i] = rng.gen_range(0..=255);
    }
    let mut state = byte_array_to_mat(message);

    // ======== HE ========
    let mut he_round_keys = Vec::<LweCiphertextListOwned<u64>>::with_capacity(NUM_ROUNDS + 1);
    for r in 0..=NUM_ROUNDS {
        let mut lwe_list_rk = LweCiphertextList::new(
            0u64,
            fourier_bsk.output_lwe_dimension().to_lwe_size(),
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );

        let rk = PlaintextList::from_container((0..BLOCKSIZE_IN_BIT).map(|i| {
            let byte_idx = i / BYTESIZE;
            let bit_idx = i % BYTESIZE;
            let round_key_byte = round_keys[r][byte_idx];
            let round_key_bit = (round_key_byte & (1 << bit_idx)) >> bit_idx;
            (round_key_bit as u64) << 63
        }).collect::<Vec<u64>>());
        encrypt_lwe_ciphertext_list(
            &lwe_sk,
            &mut lwe_list_rk,
            &rk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        he_round_keys.push(lwe_list_rk);
    }

    let mut he_state = LweCiphertextList::new(
        0u64,
        fourier_bsk.output_lwe_dimension().to_lwe_size(),
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );
    let mut he_state_ks = LweCiphertextList::new(
        0u64,
        ksk.output_lwe_size(),
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    for (bit_idx, mut he_bit) in he_state.iter_mut().enumerate() {
        let byte_idx = bit_idx / 8;
        let pt = (message[byte_idx] & (1 << bit_idx)) >> bit_idx;
        *he_bit.get_mut_body().data += (pt as u64) << 63;
    }

    // AddRoundKey
    he_add_round_key(&mut he_state, &he_round_keys[0]);
    aes.add_round_key(&mut state, 0);

    for r in 1..NUM_ROUNDS {
        // LWE KS
        for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
            keyswitch_lwe_ciphertext(&ksk, &lwe, &mut lwe_ks);
        }

        let (_, max_err) = get_he_state_error(&he_state_ks, state, &lwe_sk_after_ks);
        lwe_ks_err_list.push(max_err);
        total_max_err = std::cmp::max(total_max_err, max_err);

        // SubBytes
        he_sub_bytes_by_patched_wwllp_cbs(
            &he_state_ks,
            &mut he_state,
            fourier_bsk,
            &auto_keys,
            ss_key,
            cbs_base_log,
            cbs_level,
            log_lut_count,
        );

        aes.sub_bytes(&mut state);
        let (_, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
        sub_err_list.push(max_err);
        total_max_err = std::cmp::max(total_max_err, max_err);

        // ShiftRows
        he_shift_rows(&mut he_state);

        // MixColumns
        he_mix_columns(&mut he_state);

        // AddRoundKey
        he_add_round_key(&mut he_state, &he_round_keys[r]);

        aes.shift_rows(&mut state);
        aes.mix_columns(&mut state);
        aes.add_round_key(&mut state, r);
        let (_, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
        lin_err_list.push(max_err);
        total_max_err = std::cmp::max(total_max_err, max_err);
    }

    // LWE KS
    for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
        keyswitch_lwe_ciphertext(&ksk, &lwe, &mut lwe_ks);
    }

    let (_, max_err) = get_he_state_error(&he_state_ks, state, &lwe_sk_after_ks);
    lwe_ks_err_list.push(max_err);
    total_max_err = std::cmp::max(total_max_err, max_err);


    // SubBytes
    he_sub_bytes_by_patched_wwllp_cbs(
        &he_state_ks,
        &mut he_state,
        fourier_bsk,
        &auto_keys,
        ss_key,
        cbs_base_log,
        cbs_level,
        log_lut_count,
    );

    aes.sub_bytes(&mut state);
    let (_, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
    sub_err_list.push(max_err);
    total_max_err = std::cmp::max(total_max_err, max_err);

    // ShiftRows
    he_shift_rows(&mut he_state);

    // AddRoundKey
    he_add_round_key(&mut he_state, &he_round_keys[NUM_ROUNDS]);

    aes.shift_rows(&mut state);
    aes.add_round_key(&mut state, NUM_ROUNDS);
    let (_, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
    lin_err_list.push(max_err);
    total_max_err = std::cmp::max(total_max_err, max_err);

    println!("max {:.2}", (total_max_err as f64).log2());
    println!("x e");
    let mut ctr = 1;
    for ((lwe_ks_err, sub_err), lin_err) in lwe_ks_err_list.iter()
        .zip(sub_err_list.iter())
        .zip(lin_err_list.iter())
    {
        println!("{} {:.2}", ctr, (*lwe_ks_err as f64).log2());
        println!("{} {:.2}", ctr+1, (*sub_err as f64).log2());
        println!("{} {:.2}", ctr+2, (*lin_err as f64).log2());
        ctr += 3;
    }
}
