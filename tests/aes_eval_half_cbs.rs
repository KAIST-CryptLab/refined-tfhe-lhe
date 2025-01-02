use std::time::{Duration, Instant};

use rand::Rng;
use tfhe::core_crypto::prelude::*;
use auto_base_conv::{aes_he::*, aes_ref::*, allocate_and_generate_new_glwe_keyswitch_key, automorphism::*, convert_standard_glwe_keyswitch_key_to_fourier, get_max_err_ggsw_int, ggsw_conv::*, keygen_pbs_with_glwe_ds, keyswitch_lwe_ciphertext_by_glwe_keyswitch, FftType, FourierGlweKeyswitchKey};

fn main() {
    // AES evaluation by patched WWL+ circuit bootstrapping
    let lwe_dimension = LweDimension(768);
    let lwe_modular_std_dev = StandardDev(8.763872947670246e-06);
    let polynomial_size = PolynomialSize(1024);
    let glwe_dimension = GlweDimension(2);
    let glwe_modular_std_dev = StandardDev(9.25119974676756e-16);

    let common_polynomial_size = PolynomialSize(256);
    let ds_fft_type = FftType::Vanilla;
    let glwe_ds_level = DecompositionLevelCount(3);
    let glwe_ds_base_log = DecompositionBaseLog(4);

    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let auto_base_log = DecompositionBaseLog(12);
    let auto_level = DecompositionLevelCount(3);
    let auto_fft_type = FftType::Vanilla;
    let ss_base_log = DecompositionBaseLog(17);
    let ss_level = DecompositionLevelCount(2);
    let cbs_base_log = DecompositionBaseLog(2);
    let cbs_level = DecompositionLevelCount(6);
    let log_lut_count = LutCountLog(3);

    // let half_cbs_glwe_dimension = GlweDimension(2);
    // let half_cbs_polynomial_size = PolynomialSize(1024);
    // let half_cbs_glwe_modular_std_dev = StandardDev(9.25119974676756e-16);
    let half_cbs_glwe_dimension = GlweDimension(3);
    let half_cbs_polynomial_size = PolynomialSize(1024);
    let half_cbs_glwe_modular_std_dev = StandardDev(2.168404344971009e-19);
    let half_cbs_glwe_ds_base_log = DecompositionBaseLog(4);
    let half_cbs_glwe_ds_level = DecompositionLevelCount(3);
    let half_cbs_ds_fft_type = FftType::Vanilla;

    // let half_cbs_auto_base_log = DecompositionBaseLog(4);
    // let half_cbs_auto_level = DecompositionLevelCount(11);
    // let half_cbs_auto_fft_type = FftType::Vanilla;
    // let half_cbs_ss_base_log = DecompositionBaseLog(17);
    // let half_cbs_ss_level = DecompositionLevelCount(2);
    // let half_cbs_base_log = DecompositionBaseLog(4);
    // let half_cbs_level = DecompositionLevelCount(5);
    let half_cbs_auto_base_log = DecompositionBaseLog(15);
    let half_cbs_auto_level = DecompositionLevelCount(3);
    let half_cbs_auto_fft_type = FftType::Split(42);
    let half_cbs_ss_base_log = DecompositionBaseLog(13);
    let half_cbs_ss_level = DecompositionLevelCount(3);
    let half_cbs_base_log = DecompositionBaseLog(7);
    let half_cbs_level = DecompositionLevelCount(3);

    test_aes_eval_by_half_cbs(
        lwe_dimension,
        polynomial_size,
        glwe_dimension,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log, pbs_level,
        glwe_ds_base_log,
        glwe_ds_level,
        common_polynomial_size,
        ds_fft_type,
        ss_base_log,
        ss_level,
        auto_base_log,
        auto_level,
        auto_fft_type,
        cbs_base_log,
        cbs_level,
        log_lut_count,
        half_cbs_glwe_dimension,
        half_cbs_polynomial_size,
        half_cbs_glwe_modular_std_dev,
        half_cbs_glwe_ds_base_log,
        half_cbs_glwe_ds_level,
        half_cbs_ds_fft_type,
        half_cbs_ss_base_log,
        half_cbs_ss_level,
        half_cbs_auto_base_log,
        half_cbs_auto_level,
        half_cbs_auto_fft_type,
        half_cbs_base_log,
        half_cbs_level,
        ciphertext_modulus,
    );
}

#[allow(unused)]
fn test_aes_eval_by_half_cbs(
    lwe_dimension: LweDimension,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    glwe_ds_base_log: DecompositionBaseLog,
    glwe_ds_level: DecompositionLevelCount,
    common_polynomial_size: PolynomialSize,
    ds_fft_type: FftType,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    auto_fft_type: FftType,
    cbs_base_log: DecompositionBaseLog,
    cbs_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    half_cbs_glwe_dimension: GlweDimension,
    half_cbs_polynomial_size: PolynomialSize,
    half_cbs_glwe_modular_std_dev: impl DispersionParameter,
    half_cbs_glwe_ds_base_log: DecompositionBaseLog,
    half_cbs_glwe_ds_level: DecompositionLevelCount,
    half_cbs_ds_fft_type: FftType,
    half_cbs_ss_base_log: DecompositionBaseLog,
    half_cbs_ss_level: DecompositionLevelCount,
    half_cbs_auto_base_log: DecompositionBaseLog,
    half_cbs_auto_level: DecompositionLevelCount,
    half_cbs_auto_fft_type: FftType,
    half_cbs_base_log: DecompositionBaseLog,
    half_cbs_level: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== AES evaluation by Half-CBS ====
---- CBS Param ----
n: {}, N: {}, k: {}, l_glwe_ds: {}, B_glwe_ds: 2^{}
l_pbs: {}, B_pbs: 2^{}, l_cbs: {}, B_cbs: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, fft_auto: {:?}, l_ss: {}, B_ss: 2^{},
---- HalfCBS Param ----
l_auto: {}, B_auto: 2^{}, fft_auto: {:?}, l_ss: {}, B_ss: 2^{}, l_cbs: {}, B_cbs: 2^{}
\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, glwe_ds_level.0, glwe_ds_base_log.0,
        pbs_level.0, pbs_base_log.0, cbs_level.0, cbs_base_log.0, log_lut_count.0,
        auto_level.0, auto_base_log.0, auto_fft_type, ss_level.0, ss_base_log.0,
        half_cbs_auto_level.0, half_cbs_auto_base_log.0, half_cbs_auto_fft_type, half_cbs_ss_level.0, half_cbs_ss_base_log.0, half_cbs_level.0, half_cbs_base_log.0,
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
        glwe_ksk,
    ) = keygen_pbs_with_glwe_ds(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        glwe_ds_base_log,
        glwe_ds_level,
        common_polynomial_size,
        ds_fft_type,
        ciphertext_modulus,
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
        auto_fft_type,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let glwe_size = glwe_sk.glwe_dimension().to_glwe_size();
    let large_lwe_size = lwe_sk.lwe_dimension().to_lwe_size();

    let half_cbs_glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(half_cbs_glwe_dimension, half_cbs_polynomial_size, &mut secret_generator);
    let half_cbs_lwe_sk_view = GlweSecretKey::from_container(half_cbs_glwe_sk.as_ref(), common_polynomial_size);
    let lwe_sk_after_ks_view = GlweSecretKey::from_container(lwe_sk_after_ks.as_ref(), common_polynomial_size);
    let half_cbs_lwe_sk = half_cbs_glwe_sk.clone().into_lwe_secret_key();

    let half_cbs_glwe_size = half_cbs_glwe_dimension.to_glwe_size();
    let half_cbs_lwe_size = half_cbs_lwe_sk.lwe_dimension().to_lwe_size();

    let half_cbs_standard_glwe_ksk = allocate_and_generate_new_glwe_keyswitch_key(
        &half_cbs_lwe_sk_view,
        &lwe_sk_after_ks_view,
        half_cbs_glwe_ds_base_log,
        half_cbs_glwe_ds_level,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut half_cbs_glwe_ksk = FourierGlweKeyswitchKey::new(
        half_cbs_lwe_sk_view.glwe_dimension().to_glwe_size(),
        lwe_sk_after_ks_view.glwe_dimension().to_glwe_size(),
        common_polynomial_size,
        glwe_ds_base_log,
        glwe_ds_level,
        half_cbs_ds_fft_type,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&half_cbs_standard_glwe_ksk, &mut half_cbs_glwe_ksk);

    let half_cbs_auto_keys = gen_all_auto_keys(
        half_cbs_auto_base_log,
        half_cbs_auto_level,
        half_cbs_auto_fft_type,
        &half_cbs_glwe_sk,
        half_cbs_glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let half_cbs_ss_key = generate_scheme_switching_key(
        &half_cbs_glwe_sk,
        half_cbs_ss_base_log,
        half_cbs_ss_level,
        half_cbs_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let half_cbs_ss_key = half_cbs_ss_key.as_view();

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

    let correct_output = byte_array_to_mat(aes.encrypt_block(message));

    // ======== HE ========
    let num_bytes_to_print = 2;
    let mut he_round_keys = Vec::<LweCiphertextListOwned<u64>>::with_capacity(NUM_ROUNDS + 1);
    for r in 0..=NUM_ROUNDS {
        let mut lwe_list_rk = if r <= 2 {
            LweCiphertextList::new(
                0u64,
                half_cbs_lwe_size,
                LweCiphertextCount(BLOCKSIZE_IN_BIT),
                ciphertext_modulus,
            )
        } else {
            LweCiphertextList::new(
                0u64,
                large_lwe_size,
                LweCiphertextCount(BLOCKSIZE_IN_BIT),
                ciphertext_modulus,
            )
        };
        // let mut lwe_list_rk = LweCiphertextList::new(
        //     0u64,
        //     large_lwe_size,
        //     LweCiphertextCount(BLOCKSIZE_IN_BIT),
        //     ciphertext_modulus,
        // );

        let rk = PlaintextList::from_container((0..BLOCKSIZE_IN_BIT).map(|i| {
            let byte_idx = i / BYTESIZE;
            let bit_idx = i % BYTESIZE;
            let round_key_byte = round_keys[r][byte_idx];
            let round_key_bit = (round_key_byte & (1 << bit_idx)) >> bit_idx;
            (round_key_bit as u64) << 63
        }).collect::<Vec<u64>>());
        if r <= 2 {
            encrypt_lwe_ciphertext_list(
                &half_cbs_lwe_sk,
                &mut lwe_list_rk,
                &rk,
                half_cbs_glwe_modular_std_dev,
                &mut encryption_generator,
            );
        } else {
            encrypt_lwe_ciphertext_list(
                &lwe_sk,
                &mut lwe_list_rk,
                &rk,
                glwe_modular_std_dev,
                &mut encryption_generator,
            );
        }

        he_round_keys.push(lwe_list_rk);
    }

    let mut he_state = LweCiphertextList::new(
        0u64,
        large_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );
    let mut he_state_mult_by_2 = LweCiphertextList::new(
        0u64,
        large_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );
    let mut he_state_mult_by_3 = LweCiphertextList::new(
        0u64,
        large_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );
    let mut he_state_ks = LweCiphertextList::new(
        0u64,
        lwe_sk_after_ks.lwe_dimension().to_lwe_size(),
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    let mut half_cbs_he_state = LweCiphertextList::new(
        0u64,
        half_cbs_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );
    let mut half_cbs_he_state_mult_by_2 = LweCiphertextList::new(
        0u64,
        half_cbs_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );
    let mut half_cbs_he_state_mult_by_3 = LweCiphertextList::new(
        0u64,
        half_cbs_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    let mut lev_state = Vec::<LweCiphertextListOwned<u64>>::with_capacity(BLOCKSIZE_IN_BIT);
    let mut lev_state_mult_by_2 = Vec::<LweCiphertextListOwned<u64>>::with_capacity(BLOCKSIZE_IN_BIT);
    let mut lev_state_mult_by_3 = Vec::<LweCiphertextListOwned<u64>>::with_capacity(BLOCKSIZE_IN_BIT);

    for i in 0..BLOCKSIZE_IN_BIT {
        lev_state.push(LweCiphertextList::new(0u64, half_cbs_lwe_size, LweCiphertextCount(half_cbs_level.0), ciphertext_modulus));
        lev_state_mult_by_2.push(LweCiphertextList::new(0u64, half_cbs_lwe_size, LweCiphertextCount(half_cbs_level.0), ciphertext_modulus));
        lev_state_mult_by_3.push(LweCiphertextList::new(0u64, half_cbs_lwe_size, LweCiphertextCount(half_cbs_level.0), ciphertext_modulus));
    }

    for (bit_idx, mut he_bit) in he_state.iter_mut().enumerate() {
        let byte_idx = bit_idx / 8;
        let pt = (message[byte_idx] & (1 << bit_idx)) >> bit_idx;
        *he_bit.get_mut_body().data += (pt as u64) << 63;
    }

    let vec_keyed_sbox_glev_round_1 = generate_vec_keyed_lut_glev(
        aes.get_keyed_sbox(0),
        half_cbs_base_log,
        half_cbs_level,
        &half_cbs_glwe_sk,
        half_cbs_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let vec_keyed_sbox_mult_by_2_glev_round_1 = generate_vec_keyed_lut_glev(
        aes.get_keyed_sbox_mult_by_2(0),
        half_cbs_base_log,
        half_cbs_level,
        &half_cbs_glwe_sk,
        half_cbs_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let vec_keyed_sbox_mult_by_3_glev_round_1 = generate_vec_keyed_lut_glev(
        aes.get_keyed_sbox_mult_by_3(0),
        half_cbs_base_log,
        half_cbs_level,
        &half_cbs_glwe_sk,
        half_cbs_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let vec_keyed_sbox_acc_round_2 = generate_vec_keyed_lut_accumulator(
        aes.get_keyed_sbox(1),
        u64::BITS as usize - 1,
        &half_cbs_glwe_sk,
        half_cbs_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let vec_keyed_sbox_mult_by_2_acc_round_2 = generate_vec_keyed_lut_accumulator(
        aes.get_keyed_sbox_mult_by_2(1),
        u64::BITS as usize - 1,
        &half_cbs_glwe_sk,
        half_cbs_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let vec_keyed_sbox_mult_by_3_acc_round_2 = generate_vec_keyed_lut_accumulator(
        aes.get_keyed_sbox_mult_by_3(1),
        u64::BITS as usize - 1,
        &half_cbs_glwe_sk,
        half_cbs_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut time_lwe_ks = Duration::ZERO;
    let mut time_sub_bytes = Duration::ZERO;
    let mut time_linear = Duration::ZERO;

    println!("---- Error (bits) ----");
    aes.add_round_key(&mut state, 0);

    let mut int_state = [0u8; BLOCKSIZE_IN_BIT];
    for r in 1..NUM_ROUNDS {
        if r == 1 {
            println!("Round {r}: cleartext input -> HalfCBS output");
            // Keyed LUT with cleartext input
            let now = Instant::now();
            known_rotate_keyed_lut_for_half_cbs(
                message,
                &vec_keyed_sbox_glev_round_1,
                &mut lev_state,
            );
            known_rotate_keyed_lut_for_half_cbs(
                message,
                &vec_keyed_sbox_mult_by_2_glev_round_1,
                &mut lev_state_mult_by_2,
            );
            known_rotate_keyed_lut_for_half_cbs(
                message,
                &vec_keyed_sbox_mult_by_3_glev_round_1,
                &mut lev_state_mult_by_3,
            );
            time_sub_bytes += now.elapsed();

            aes.sub_bytes(&mut state);

            int_state = byte_mat_to_bit_array(state);
            let (vec_err, max_err) = get_lev_int_state_error(&lev_state, int_state, half_cbs_base_log, &half_cbs_lwe_sk);
            print!("  - KeyedLUT:");
            for err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
                print!(" {:>2}", err.ilog2());
            }
            println!(" ... (max: {:.3})", (max_err as f64).log2());

            // ShiftRows and MixColumns
            let now = Instant::now();
            lev_shift_rows(&mut lev_state);
            lev_shift_rows(&mut lev_state_mult_by_2);
            lev_shift_rows(&mut lev_state_mult_by_3);

            lev_mix_columns_precomp(
                &mut lev_state,
                &lev_state_mult_by_2,
                &lev_state_mult_by_3,
            );
            time_linear += now.elapsed();

            aes.shift_rows(&mut state);
            int_state = mix_columns_integer(state);
            aes.mix_columns(&mut state);

            let (vec_err, max_err) = get_lev_int_state_error(&lev_state, int_state, half_cbs_base_log, &half_cbs_lwe_sk);
            print!("  - SR & MR :");
            for err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
                print!(" {:>2}", err.ilog2());
            }
            println!(" ... (max: {:.3})", (max_err as f64).log2());

            let cur_time = time_sub_bytes + time_linear + time_lwe_ks;
            println!("  - Latency: {:.3} ms", cur_time.as_micros() as f64 / 1000f64);
        } else if r == 2 {
            println!("Round {r}: HalfCBS input -> LWE output");
            // Keyed LUT
            let now = Instant::now();
            let mut ggsw_state = GgswCiphertextList::new(0u64, half_cbs_glwe_size, half_cbs_polynomial_size, half_cbs_base_log, half_cbs_level, GgswCiphertextCount(BLOCKSIZE_IN_BIT), ciphertext_modulus);

            convert_lev_state_to_ggsw(
                &lev_state,
                &mut ggsw_state,
                &half_cbs_auto_keys,
                half_cbs_ss_key,
            );
            time_sub_bytes += now.elapsed();

            let mut vec_err = Vec::<u64>::with_capacity(BLOCKSIZE_IN_BIT);
            let mut max_err = 0u64;
            for (correct_val, ggsw) in int_state.iter().zip(ggsw_state.iter()) {
                let correct_val = *correct_val as u64;
                let err = get_max_err_ggsw_int(&half_cbs_glwe_sk, &ggsw, correct_val);

                vec_err.push(err);
                max_err = std::cmp::max(max_err, err);
            }
            print!("  - Conv    :");
            for err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
                print!(" {:>2}", err.ilog2());
            }
            println!(" ... (max: {:.3})", (max_err as f64).log2());

            let now = Instant::now();
            blind_rotate_keyed_sboxes(
                &ggsw_state,
                &vec_keyed_sbox_acc_round_2,
                &vec_keyed_sbox_mult_by_2_acc_round_2,
                &vec_keyed_sbox_mult_by_3_acc_round_2,
                &mut half_cbs_he_state,
                &mut half_cbs_he_state_mult_by_2,
                &mut half_cbs_he_state_mult_by_3,
            );
            time_sub_bytes += now.elapsed();

            aes.add_round_key(&mut state, 1);
            aes.sub_bytes(&mut state);

            let (vec_err, max_err) = get_he_state_error(&half_cbs_he_state, state, &half_cbs_lwe_sk);

            print!("  - KeyedLUT:");
            for bit_err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
                print!(" {bit_err:>2}");
            }
            println!(" ... (max: {:.3})", (max_err as f64).log2());

            // ShiftRows and MixColumns
            let now = Instant::now();
            he_shift_rows(&mut half_cbs_he_state);
            he_shift_rows(&mut half_cbs_he_state_mult_by_2);
            he_shift_rows(&mut half_cbs_he_state_mult_by_3);

            he_mix_columns_precomp(
                &mut half_cbs_he_state,
                &half_cbs_he_state_mult_by_2,
                &half_cbs_he_state_mult_by_3,
            );
            time_linear += now.elapsed();

            aes.shift_rows(&mut state);
            aes.mix_columns(&mut state);

            let (vec_err, max_err) = get_he_state_error(&half_cbs_he_state, state, &half_cbs_lwe_sk);

            print!("  - SR & MC :");
            for bit_err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
                print!(" {bit_err:>2}");
            }
            println!(" ... (max: {:.3})", (max_err as f64).log2());

            // AddRoundKey
            let now = Instant::now();
            he_add_round_key(&mut half_cbs_he_state, &he_round_keys[r]);
            time_linear += now.elapsed();

            aes.add_round_key(&mut state, r);
            let (vec_err, max_err) = get_he_state_error(&half_cbs_he_state, state, &half_cbs_lwe_sk);
            print!("  - ARK     :");
            for bit_err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
                print!(" {bit_err:>2}");
            }
            println!(" ... (max: {:.3})", (max_err as f64).log2());

            let cur_time = time_sub_bytes + time_linear + time_lwe_ks;
            println!("  - Latency: {:.3} ms", cur_time.as_micros() as f64 / 1000f64);
        } else {
            println!("Round {r}: CBS-based");
            // LWE KS
            let now = Instant::now();
            if r == 3 {
                for (lwe, mut lwe_ks) in half_cbs_he_state.iter().zip(he_state_ks.iter_mut()) {
                    keyswitch_lwe_ciphertext_by_glwe_keyswitch(
                        &lwe,
                        &mut lwe_ks,
                        &half_cbs_glwe_ksk,
                    );
                }
            } else {
                for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
                    keyswitch_lwe_ciphertext_by_glwe_keyswitch(
                        &lwe,
                        &mut lwe_ks,
                        &glwe_ksk,
                    );
                }
            }
            time_lwe_ks += now.elapsed();

            let (vec_err, max_err) = get_he_state_error(&he_state_ks, state, &lwe_sk_after_ks);
            print!("  - LWE ks  :");
            for bit_err in vec_err.iter().take(BYTESIZE * num_bytes_to_print) {
                print!(" {bit_err:>2}");
            }
            println!(" ... (max: {:.3})", (max_err as f64).log2());

            let bit_state = byte_mat_to_bit_array(state);
            print!("  - CBS     :");
            let mut max_err = 0u64;
            for (i, lwe) in he_state_ks.iter().enumerate() {
                let mut glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(cbs_level.0), ciphertext_modulus);
                let glev_mut_view = GlweCiphertextListMutView::from_container(
                    glev.as_mut(),
                    glwe_size,
                    polynomial_size,
                    ciphertext_modulus,
                );
                lwe_msb_bit_to_glev_by_trace_with_preprocessing(
                    lwe.as_view(),
                    glev_mut_view,
                    fourier_bsk,
                    &auto_keys,
                    cbs_base_log,
                    cbs_level,
                    log_lut_count,
                );

                let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);
                switch_scheme(&glev, &mut ggsw, ss_key);

                let correct_val = bit_state[i] as u64;
                let err = get_max_err_ggsw_int(&glwe_sk, &ggsw, correct_val);
                max_err = std::cmp::max(max_err, err);
                if i < 16 {
                    print!(" {}", err.ilog2());
                }
            }
            print!(" ... (max: {:.3})", (max_err as f64).log2());
            println!();

            // SubBytes
            let now = Instant::now();
            he_sub_bytes_8_to_24_by_patched_wwlp_cbs(
                &he_state_ks,
                &mut he_state,
                &mut he_state_mult_by_2,
                &mut he_state_mult_by_3,
                fourier_bsk,
                &auto_keys,
                ss_key,
                cbs_base_log,
                cbs_level,
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
            he_shift_rows(&mut he_state_mult_by_2);
            he_shift_rows(&mut he_state_mult_by_3);

            // MixColumns
            he_mix_columns_precomp(
                &mut he_state,
                &he_state_mult_by_2,
                &he_state_mult_by_3,
            );

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

            let cur_time = time_sub_bytes + time_linear + time_lwe_ks;
            println!("  - Latency: {:.3} ms", cur_time.as_micros() as f64 / 1000f64);
        }
    }

    println!("Final Round");
    // LWE KS
    let now = Instant::now();
    for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
        keyswitch_lwe_ciphertext_by_glwe_keyswitch(
            &lwe,
            &mut lwe_ks,
            &glwe_ksk,
        );
    }
    time_lwe_ks += now.elapsed();

    // SubBytes
    let now = Instant::now();
    he_sub_bytes_by_patched_wwlp_cbs(
        &he_state_ks,
        &mut he_state,
        fourier_bsk,
        &auto_keys,
        ss_key,
        cbs_base_log,
        cbs_level,
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

    let (vec_out, _, max_err2) = get_he_state_and_error(&he_state, correct_output, &lwe_sk);
    println!("max: {:.2}", (max_err2 as f64).log2());

    let plain_state = byte_mat_to_bit_array(correct_output);
    for (out, correct) in vec_out.iter().zip(plain_state.iter()) {
        let out = *out as u8;
        if out != *correct {
            println!("wrong!");
        }
        break;
    }

    // Evaluation Time
    println!("\n---- Evaluation Time ----");
    println!("LWE KS  : {} s", time_lwe_ks.as_millis() as f64 / 1000f64);
    println!("SubBytes: {} s", time_sub_bytes.as_millis() as f64 / 1000f64);
    println!("Linear  : {} ms", time_linear.as_micros() as f64 / 1000f64);

    let time_total = time_lwe_ks + time_sub_bytes + time_linear;
    println!("Total   : {} s", time_total.as_millis() as f64 / 1000f64);
}


fn mix_columns_integer(state: StateByteMat) -> [u8; BLOCKSIZE_IN_BIT] {
    let mut int_state = [0u8; BLOCKSIZE_IN_BIT];
    for col in 0..4 {
        for row in 0..4 {
            for bit_idx in 0..BYTESIZE {
                let byte_idx = 4 * col + row;
                let idx = BYTESIZE * byte_idx + bit_idx;

                let byte_mult_by_2 = mult_by_two(state[col][row]);
                int_state[idx] += (byte_mult_by_2 & (1 << bit_idx)) >> bit_idx;

                let byte_mult_by_3 = mult_by_two(state[col][(row + 1) % 4]) ^ state[col][(row + 1) % 4];
                int_state[idx] += (byte_mult_by_3 & (1 << bit_idx)) >> bit_idx;

                int_state[idx] += (state[col][(row + 2) % 4] & (1 << bit_idx)) >> bit_idx;
                int_state[idx] += (state[col][(row + 3) % 4] & (1 << bit_idx)) >> bit_idx;
            }
        }
    }

    int_state
}
