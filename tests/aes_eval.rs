use std::time::{Duration, Instant};

use rand::Rng;
use tfhe::core_crypto::prelude::*;
use hom_trace::{keygen_pbs, aes_he::*, aes_ref::*, automorphism::*, ggsw_conv::*, FftType};

fn main() {
    // AES evaluation by patched WWLL+ circuit bootstrapping
    let lwe_dimension = LweDimension(769);
    let lwe_modular_std_dev = StandardDev(0.0000043131554647504185);
    let polynomial_size = PolynomialSize(1024);
    let glwe_dimension = GlweDimension(2);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);

    let pbs_base_log = DecompositionBaseLog(15);
    let pbs_level = DecompositionLevelCount(2);
    let ks_level = DecompositionLevelCount(2);
    let ks_base_log = DecompositionBaseLog(6);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(3);
    let auto_base_log = DecompositionBaseLog(7);
    let auto_level = DecompositionLevelCount(7);
    let fft_type = FftType::Split16;
    let ss_base_log = DecompositionBaseLog(8);
    let ss_level = DecompositionLevelCount(6);
    let log_lut_count = LutCountLog(2);

    test_aes_eval_by_patched_wwllp_cbs(
        lwe_dimension,
        polynomial_size,
        glwe_dimension,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log, pbs_level,
        ks_base_log,
        ks_level,
        ss_base_log,
        ss_level,
        auto_base_log,
        auto_level,
        fft_type,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
}

#[allow(unused)]
fn test_aes_eval_by_patched_wwllp_cbs(
    lwe_dimension: LweDimension,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    fft_type: FftType,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== AES evaluation by patched WWLL+ circuit bootstrapping ====
n: {}, N: {}, k: {}, l_ks: {}, B_ks: 2^{}
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, ks_level.0, ks_base_log.0,
        pbs_level.0, pbs_base_log.0, ggsw_level.0, ggsw_base_log.0, log_lut_count.0,
        auto_level.0, auto_base_log.0, ss_level.0, ss_base_log.0,
    );

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
        fft_type,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // ======== Plain ========
    let mut rng = rand::thread_rng();
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
    let num_bytes_to_print = 2;
    let mut he_round_keys = Vec::<LweCiphertextListOwned<u64>>::with_capacity(NUM_ROUNDS + 1);
    for r in 0..=NUM_ROUNDS {
        // let lwe_size = if r < NUM_ROUNDS {fourier_bsk.output_lwe_dimension().to_lwe_size()} else {fourier_bsk.output_lwe_dimension().to_lwe_size()};

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

    let mut time_lwe_ks = Duration::ZERO;
    let mut time_sub_bytes = Duration::ZERO;
    let mut time_linear = Duration::ZERO;

    println!("---- Error (bits) ----");
    // AddRoundKey
    let now = Instant::now();
    he_add_round_key(&mut he_state, &he_round_keys[0]);
    time_linear += now.elapsed();

    aes.add_round_key(&mut state, 0);

    for r in 1..NUM_ROUNDS {
        println!("Round {r}");
        // LWE KS
        let now = Instant::now();
        for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
            keyswitch_lwe_ciphertext(&ksk, &lwe, &mut lwe_ks);
        }
        time_lwe_ks += now.elapsed();

        let (vec_err, max_err) = get_he_state_error(&he_state_ks, state, &lwe_sk_after_ks);
        print!("  - LWE ks  :");
        for bit_err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
            print!(" {bit_err:>2}");
        }
        println!(" ... (max: {:.3})", (max_err as f64).log2());

        // SubBytes
        let now = Instant::now();
        he_sub_bytes_by_patched_wwllp_cbs(
            &he_state_ks,
            &mut he_state,
            fourier_bsk,
            &auto_keys,
            ss_key,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
        time_sub_bytes += now.elapsed();

        aes.sub_bytes(&mut state);
        let (vec_err, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
        print!("  - SubBytes:");
        for bit_err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
            print!(" {bit_err:>2}");
        }
        println!(" ... (max: {:.3})", (max_err as f64).log2());

        let now = Instant::now();
        // ShiftRows
        he_shift_rows(&mut he_state);

        // MixColumns
        he_mix_columns(&mut he_state);

        // AddRoundKey
        he_add_round_key(&mut he_state, &he_round_keys[r]);
        time_linear += now.elapsed();

        aes.shift_rows(&mut state);
        aes.mix_columns(&mut state);
        aes.add_round_key(&mut state, r);

        // Check error
        let (vec_err, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
        print!("  - Linear  :");
        for bit_err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
            print!(" {bit_err:>2}");
        }
        println!(" ... (max: {:.3})", (max_err as f64).log2());
    }

    println!("Final Round");
    // SubBytes
    let now = Instant::now();
    for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
        keyswitch_lwe_ciphertext(&ksk, &lwe, &mut lwe_ks);
    }
    time_lwe_ks += now.elapsed();

    let now = Instant::now();
    he_sub_bytes_by_patched_wwllp_cbs(
        &he_state_ks,
        &mut he_state,
        fourier_bsk,
        &auto_keys,
        ss_key,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
    );
    time_sub_bytes += now.elapsed();

    aes.sub_bytes(&mut state);
    let (vec_err, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
    print!("  - SubBytes:");
    for bit_err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
        print!(" {bit_err:>2}");
    }
    println!(" ... (max: {:.3})", (max_err as f64).log2());

    let now = Instant::now();
    // ShiftRows
    he_shift_rows(&mut he_state);

    // AddRoundKey
    he_add_round_key(&mut he_state, &he_round_keys[NUM_ROUNDS]);
    time_linear += now.elapsed();

    aes.shift_rows(&mut state);
    aes.add_round_key(&mut state, NUM_ROUNDS);

    print!("  - Linear  :");
    let (vec_err, max_err) = get_he_state_error(&he_state, state, &lwe_sk);
    for bit_err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
        print!(" {bit_err:>2}");
    }
    println!(" ... (max: {:.3})", (max_err as f64).log2());

    // Evaluation Time
    println!("\n---- Evaluation Time ----");
    println!("LWE KS  : {} s", time_lwe_ks.as_millis() as f64 / 1000f64);
    println!("SubBytes: {} s", time_sub_bytes.as_millis() as f64 / 1000f64);
    println!("Linear  : {} ms", time_linear.as_micros() as f64 / 1000f64);

    let time_total = time_lwe_ks + time_sub_bytes + time_linear;
    println!("Total   : {} s", time_total.as_millis() as f64 / 1000f64);
}
