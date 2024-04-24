use hom_trace::{allocate_and_generate_new_glwe_keyswitch_key, convert_lwe_to_glwe_by_trace_with_preprocessing, convert_lwe_to_glwe_by_trace_with_preprocessing_high_prec, convert_standard_glwe_keyswitch_key_to_fourier, gen_all_auto_keys, generate_scheme_switching_key, get_glwe_l2_err, get_glwe_max_err, switch_scheme, FftType, FourierGlweKeyswitchKey};
use rand::Rng;
use tfhe::core_crypto::prelude::*;

type Scalar = u64;
const NUM_REPEAT: usize = 1000;
const FFT_TYPE: FftType = FftType::Split16;

fn main() {
    /* Lev to GGSW by trace and scheme switching */
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let auto_base_log = DecompositionBaseLog(7);
    let auto_level = DecompositionLevelCount(7);
    let ss_base_log = DecompositionBaseLog(8);
    let ss_level = DecompositionLevelCount(6);
    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(3);

    sample_ggsw_conv_err_by_trace_and_ss(glwe_dimension, polynomial_size, glwe_modular_std_dev, auto_base_log, auto_level, ss_base_log, ss_level, ggsw_base_log, ggsw_level, NUM_REPEAT);

    // wopbs_message_3_carry_3_ks_pbs
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let ggsw_base_log = DecompositionBaseLog(6);
    let ggsw_level = DecompositionLevelCount(3);

    let large_glwe_dimension = GlweDimension(2);
    let large_glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let ks_to_large_base_log = DecompositionBaseLog(15);
    let ks_to_large_level = DecompositionLevelCount(3);
    let ks_from_large_base_log = DecompositionBaseLog(5);
    let ks_from_large_level = DecompositionLevelCount(10);
    let auto_base_log = DecompositionBaseLog(6);
    let auto_level = DecompositionLevelCount(10);
    let ss_base_log = DecompositionBaseLog(6);
    let ss_level = DecompositionLevelCount(9);

    sample_ggsw_conv_err_by_high_prec_trace_and_ss(glwe_dimension, large_glwe_dimension, polynomial_size, glwe_modular_std_dev, large_glwe_modular_std_dev, ks_to_large_base_log, ks_to_large_level, ks_from_large_base_log, ks_from_large_level, auto_base_log, auto_level, ss_base_log, ss_level, ggsw_base_log, ggsw_level, NUM_REPEAT);

    /* Lev to GGSW by pfks */
    // wopbs_message_2_carry_2_ks_pbs
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pfks_base_log = DecompositionBaseLog(15);
    let pfks_level = DecompositionLevelCount(2);

    sample_ggsw_conv_err_by_pfks(glwe_dimension, polynomial_size, glwe_modular_std_dev, pfks_base_log, pfks_level, NUM_REPEAT);

    // wopbs_message_3_carry_3_ks_pbs and wopbs_message_4_carry_4_ks_pbs
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pfks_base_log = DecompositionBaseLog(9);
    let pfks_level = DecompositionLevelCount(4);

    sample_ggsw_conv_err_by_pfks(glwe_dimension, polynomial_size, glwe_modular_std_dev, pfks_base_log, pfks_level, NUM_REPEAT);
}

#[allow(unused)]
fn sample_ggsw_conv_err_by_trace_and_ss(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: StandardDev,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    num_repeat: usize,
) {
    println!("GGSW conversion by trace and ss");
    println!(
        "N: {}, k: {}, B_auto: 2^{}, l_auto: {}, B_ss: 2^{}, l_ss: {}",
        polynomial_size.0, glwe_dimension.0, auto_base_log.0, auto_level.0, ss_base_log.0, ss_level.0
    );

    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();
    let lwe_size = lwe_sk.lwe_dimension().to_lwe_size();

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        FFT_TYPE,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let ss_key = generate_scheme_switching_key(
        &glwe_sk,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let ss_key = ss_key.as_view();

    let mut rng = rand::thread_rng();

    let mut glev_l_infty_err_list = vec![];
    let mut glev_l2_err_list = vec![];
    let mut ggsw_l_infty_err_list = vec![];
    let mut ggsw_l2_err_list = vec![];

    let glwe_sk_poly_list = glwe_sk.as_polynomial_list();
    let glwe_sk_poly = glwe_sk_poly_list.get(0);

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..2) as Scalar;

        let mut lev = LweCiphertextList::new(Scalar::ZERO, lwe_size, LweCiphertextCount(ggsw_level.0), ciphertext_modulus);

        for (k, mut lwe) in lev.iter_mut().enumerate() {
            let level = k + 1;
            let log_scale = Scalar::BITS as usize - level * ggsw_base_log.0;

            encrypt_lwe_ciphertext(&lwe_sk, &mut lwe, Plaintext(msg << log_scale), StandardDev(0.0), &mut encryption_generator);
        }

        let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);

        for (lwe, mut glwe) in lev.iter().zip(glev.iter_mut()) {
            convert_lwe_to_glwe_by_trace_with_preprocessing(&lwe, &mut glwe, &auto_keys);
        }

        let glwe = glev.get(0);
        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if i == 0 {(msg << (Scalar::BITS as usize - ggsw_base_log.0))} else {Scalar::ZERO}
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &glwe, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &glwe, &correct_val_list);

        glev_l_infty_err_list.push(max_err);
        glev_l2_err_list.push(l2_err);

        let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);
        switch_scheme(&glev, &mut ggsw, ss_key);

        let glwe_list = ggsw.as_glwe_list();
        let output = glwe_list.get(0);

        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if msg == 0 {
                Scalar::ZERO
            } else {
                let glwe_sk_val = *glwe_sk_poly.as_ref().get(i).unwrap();
                glwe_sk_val.wrapping_neg() << (Scalar::BITS as usize - ggsw_base_log.0)
            }
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &output, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &output, &correct_val_list);

        ggsw_l_infty_err_list.push(max_err);
        ggsw_l2_err_list.push(l2_err);
    }

    println!("Lev -> GLev by Trace");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in glev_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in glev_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());

    println!("GLev -> GGSW by Scheme Switching");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in ggsw_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in ggsw_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}


#[allow(unused)]
fn sample_ggsw_conv_err_by_high_prec_trace_and_ss(
    glwe_dimension: GlweDimension,
    large_glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: StandardDev,
    large_glwe_modular_std_dev: StandardDev,
    ks_to_large_base_log: DecompositionBaseLog,
    ks_to_large_level: DecompositionLevelCount,
    ks_from_large_base_log: DecompositionBaseLog,
    ks_from_large_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    num_repeat: usize,
) {
    println!("GGSW conversion by high prec trace and ss");
    println!(
        "N: {}, k: {}, k': {}, B_to_k': 2^{}, l_to_k': {}, B_to_k: 2^{}, l_to_k: {}, B_auto: 2^{}, l_auto: {}, B_ss: 2^{}, l_ss: {}",
        polynomial_size.0, glwe_dimension.0, large_glwe_dimension.0, ks_to_large_base_log.0, ks_to_large_level.0, ks_from_large_base_log.0, ks_from_large_level.0, auto_base_log.0, auto_level.0, ss_base_log.0, ss_level.0
    );

    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();
    let lwe_size = lwe_sk.lwe_dimension().to_lwe_size();

    let large_glwe_sk = GlweSecretKey::generate_new_binary(large_glwe_dimension, polynomial_size, &mut secret_generator);
    let large_glwe_size = large_glwe_dimension.to_glwe_size();

    let glwe_ksk_to_large = allocate_and_generate_new_glwe_keyswitch_key(
        &glwe_sk,
        &large_glwe_sk,
        ks_to_large_base_log,
        ks_to_large_level,
        large_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_ksk_to_large = FourierGlweKeyswitchKey::new(
        glwe_size,
        large_glwe_size,
        polynomial_size,
        ks_to_large_base_log,
        ks_to_large_level,
        FFT_TYPE,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&glwe_ksk_to_large, &mut fourier_glwe_ksk_to_large);

    let glwe_ksk_from_large = allocate_and_generate_new_glwe_keyswitch_key(
        &large_glwe_sk,
        &glwe_sk,
        ks_from_large_base_log,
        ks_from_large_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_ksk_from_large = FourierGlweKeyswitchKey::new(
        large_glwe_size,
        glwe_size,
        polynomial_size,
        ks_from_large_base_log,
        ks_from_large_level,
        FFT_TYPE,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&glwe_ksk_from_large, &mut fourier_glwe_ksk_from_large);

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        FFT_TYPE,
        &large_glwe_sk,
        large_glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let ss_key = generate_scheme_switching_key(
        &glwe_sk,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let ss_key = ss_key.as_view();

    let mut rng = rand::thread_rng();

    let mut glev_l_infty_err_list = vec![];
    let mut glev_l2_err_list = vec![];
    let mut ggsw_l_infty_err_list = vec![];
    let mut ggsw_l2_err_list = vec![];

    let glwe_sk_poly_list = glwe_sk.as_polynomial_list();
    let glwe_sk_poly = glwe_sk_poly_list.get(0);

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..2) as Scalar;

        let mut lev = LweCiphertextList::new(Scalar::ZERO, lwe_size, LweCiphertextCount(ggsw_level.0), ciphertext_modulus);

        for (k, mut lwe) in lev.iter_mut().enumerate() {
            let level = k + 1;
            let log_scale = Scalar::BITS as usize - level * ggsw_base_log.0;

            encrypt_lwe_ciphertext(&lwe_sk, &mut lwe, Plaintext(msg << log_scale), StandardDev(0.0), &mut encryption_generator);
        }

        let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);

        for (lwe, mut glwe) in lev.iter().zip(glev.iter_mut()) {
            convert_lwe_to_glwe_by_trace_with_preprocessing_high_prec(&lwe, &mut glwe, &fourier_glwe_ksk_to_large, &fourier_glwe_ksk_from_large, &auto_keys);
        }

        let glwe = glev.get(0);
        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if i == 0 {(msg << (Scalar::BITS as usize - ggsw_base_log.0))} else {Scalar::ZERO}
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &glwe, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &glwe, &correct_val_list);

        glev_l_infty_err_list.push(max_err);
        glev_l2_err_list.push(l2_err);


        let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);
        switch_scheme(&glev, &mut ggsw, ss_key);

        let glwe_list = ggsw.as_glwe_list();
        let output = glwe_list.get(0);

        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if msg == 0 {
                Scalar::ZERO
            } else {
                let glwe_sk_val = *glwe_sk_poly.as_ref().get(i).unwrap();
                glwe_sk_val.wrapping_neg() << (Scalar::BITS as usize - ggsw_base_log.0)
            }
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &output, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &output, &correct_val_list);

        ggsw_l_infty_err_list.push(max_err);
        ggsw_l2_err_list.push(l2_err);
    }

    println!("Lev -> GLev by Trace");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in glev_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in glev_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());

    println!("GLev -> GGSW by Scheme Switching");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in ggsw_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in ggsw_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}


#[allow(unused)]
fn sample_ggsw_conv_err_by_pfks(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: StandardDev,
    pfks_base_log: DecompositionBaseLog,
    pfks_level: DecompositionLevelCount,
    num_repeat: usize,
) {
    println!("GGSW conversion by pfks");
    println!(
        "N: {}, k: {}, B_pfks: 2^{}, l_pfks: {}",
        polynomial_size.0, glwe_dimension.0, pfks_base_log.0, pfks_level.0,
    );

    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let pfpksk_list = allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &lwe_sk,
        &glwe_sk,
        pfks_base_log,
        pfks_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let pfpksk = pfpksk_list.get(0);

    let mut rng = rand::thread_rng();

    let mut l_infty_err_list = vec![];
    let mut l2_err_list = vec![];

    let glwe_sk_poly_list = glwe_sk.as_polynomial_list();
    let glwe_sk_poly = glwe_sk_poly_list.get(0);

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..2) as Scalar;
        let pt = Plaintext(msg << (Scalar::BITS - 1));

        let input = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            pt,
            StandardDev(0.0),
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            &pfpksk,
            &mut output,
            &input,
        );

        let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
            if msg == 0 {
                Scalar::ZERO
            } else {
                glwe_sk_poly.as_ref().get(i).unwrap() << (Scalar::BITS - 1)
            }
        }).collect::<Vec<Scalar>>());

        let max_err = get_glwe_max_err(&glwe_sk, &output, &correct_val_list);
        let l2_err = get_glwe_l2_err(&glwe_sk, &output, &correct_val_list);

        l_infty_err_list.push(max_err);
        l2_err_list.push(l2_err);
    }

    println!("GGSW Conv by PrivKS");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}
