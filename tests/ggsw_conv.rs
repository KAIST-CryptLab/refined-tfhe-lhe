use std::time::Instant;

use tfhe::core_crypto::prelude::*;
use hom_trace::{keygen_pbs_without_ksk, automorphism::*, automorphism128::*, ggsw_conv::*, utils::*};

fn main() {
    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(2);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);
    let ss_base_log = DecompositionBaseLog(15);
    let ss_level = DecompositionLevelCount(2);
    let log_lut_count = LutCountLog(1);

    test_ggsw_conv_by_trace_with_mod_switch(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        ss_base_log,
        ss_level,
        auto_base_log,
        auto_level,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
    println!();


    test_ggsw_conv_by_trace128_and_rescale(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        ss_base_log,
        ss_level,
        auto_base_log,
        auto_level,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
    println!();

    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(2);
    let pksk_base_log = DecompositionBaseLog(23);
    let pksk_level = DecompositionLevelCount(1);
    let ss_base_log = DecompositionBaseLog(15);
    let ss_level = DecompositionLevelCount(2);
    let log_lut_count = LutCountLog(1);

    test_ggsw_conv_by_pksk(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        ss_base_log,
        ss_level,
        pksk_base_log,
        pksk_level,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
    println!();

    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(4);
    let polynomial_size = PolynomialSize(512);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(15);
    let pbs_level = DecompositionLevelCount(2);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(4);
    let auto_base_log = DecompositionBaseLog(10);
    let auto_level = DecompositionLevelCount(4);
    let ss_base_log = DecompositionBaseLog(9);
    let ss_level = DecompositionLevelCount(4);
    let log_lut_count = LutCountLog(2);

    test_ggsw_conv_by_trace(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        ss_base_log,
        ss_level,
        auto_base_log,
        auto_level,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
    println!();
}

fn test_ggsw_conv_by_trace_with_mod_switch(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== GGSW conversion by trace with mod switch ====
n: {}, N: {}, k: {},
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0,
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
        big_lwe_sk,
        glwe_sk,
        small_lwe_sk,
        fourier_bsk,
    ) = keygen_pbs_without_ksk(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
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
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );


    // Set input LWE ciphertext
    let msg = 1u64;
    let log_delta = u64::BITS - 1;
    let pt = Plaintext(msg << log_delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&small_lwe_sk, pt, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    // LWE to GLEV
    let glwe_size = glwe_dimension.to_glwe_size();
    let mut glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    let glev_mut_view = GlweCiphertextListMutView::from_container(glev.as_mut(), glwe_size, polynomial_size, ciphertext_modulus);

    let now = Instant::now();
    lwe_msb_bit_to_glev_by_trace_with_mod_switch(lwe_in.as_view(), glev_mut_view, fourier_bsk, &auto_keys, ggsw_base_log, ggsw_level, log_lut_count);
    let time = now.elapsed();
    println!("LWE to GLEV: {} ms", time.as_micros() as f64 / 1000f64);

    for (k, glwe) in glev.iter().enumerate() {
        let level = k + 1;
        let log_scale = u64::BITS as usize -  ggsw_base_log.0 * level;
        print!("  Level {level}: ");
        let mut max_err = 0;
        for i in 0..polynomial_size.0 {
            let mut lwe: LweCiphertext<Vec<u64>> = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut lwe, MonomialDegree(i));

            let correct_val = if i == 0 {msg} else {0};
            let (_decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe, correct_val, 1 << log_scale);
            max_err = std::cmp::max(max_err, abs_err);
        }
        println!("{:.2} bits", (max_err as f64).log2());
    }

    // Scheme Switching
    let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);

    let now = Instant::now();
    switch_scheme(&glev, &mut ggsw, ss_key);
    let time = now.elapsed();

    let max_err = get_max_err_ggsw_bit(&glwe_sk, ggsw.as_view(), msg);
    println!("Scheme switching: {} ms, {:.2} bits", time.as_micros() as f64 / 1000f64, (max_err as f64).log2());

    let now = Instant::now();
    let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, ggsw_base_log, ggsw_level);
    convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    let time = now.elapsed();
    println!("Fourier Transform: {} ms", time.as_micros() as f64 / 1000f64);

    // Circuit Bootstrapping
    let now = Instant::now();
    let fourier_ggsw = circuit_bootstrap_lwe_ciphertext_by_trace_with_mod_switch(
        lwe_in.as_view(),
        fourier_bsk,
        &auto_keys,
        ss_key,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
    );
    let time = now.elapsed();
    println!("\nCircuit bootstrapping: {} ms", time.as_micros() as f64 / 1000f64);
    let mut glwe_lhs = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    let pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        if i == 0 {1u64 << 63} else {0u64}
    }).collect::<Vec<u64>>());

    let mut glwe_out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_sk, &mut glwe_lhs, &pt, glwe_modular_std_dev, &mut encryption_generator);
    add_external_product_assign(&mut glwe_out, &fourier_ggsw, &glwe_lhs);

    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let mut lwe = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe, MonomialDegree(i));

        let correct_val = *pt.get(i).0 >> 63;
        let (_, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe, correct_val, 1u64 << 63);
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("External product to fresh GLWE: {:.2} bits", (max_err as f64).log2());
}


fn test_ggsw_conv_by_trace128_and_rescale(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== GGSW conversion by trace128 and rescale ====
n: {}, N: {}, k: {},
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0,
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
        big_lwe_sk,
        glwe_sk,
        small_lwe_sk,
        fourier_bsk,
    ) = keygen_pbs_without_ksk(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
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

    let mut glwe_sk_128 = GlweSecretKey::new_empty_key(0u128, glwe_dimension, polynomial_size);
    for (src, dst) in glwe_sk.as_ref().iter().zip(glwe_sk_128.as_mut().iter_mut()) {
        *dst = *src as u128;
    }
    let auto128_keys = gen_all_auto128_keys(
        auto_base_log,
        auto_level,
        &glwe_sk_128,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );


    // Set input LWE ciphertext
    let msg = 1u64;
    let log_delta = u64::BITS - 1;
    let pt = Plaintext(msg << log_delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&small_lwe_sk, pt, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    // LWE to GLEV
    let glwe_size = glwe_dimension.to_glwe_size();
    let mut glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    let glev_mut_view = GlweCiphertextListMutView::from_container(glev.as_mut(), glwe_size, polynomial_size, ciphertext_modulus);

    let now = Instant::now();
    lwe_msb_bit_to_glev_by_trace128_with_mod_switch(lwe_in.as_view(), glev_mut_view, fourier_bsk, &auto128_keys, ggsw_base_log, ggsw_level, log_lut_count);
    let time = now.elapsed();
    println!("LWE to GLEV: {} ms", time.as_micros() as f64 / 1000f64);

    for (k, glwe) in glev.iter().enumerate() {
        let level = k + 1;
        let log_scale = u64::BITS as usize -  ggsw_base_log.0 * level;
        print!("  Level {level}: ");
        let mut max_err = 0;
        for i in 0..polynomial_size.0 {
            let mut lwe: LweCiphertext<Vec<u64>> = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut lwe, MonomialDegree(i));

            let correct_val = if i == 0 {msg} else {0};
            let (_decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe, correct_val, 1 << log_scale);
            max_err = std::cmp::max(max_err, abs_err);
        }
        println!("{:.2} bits", (max_err as f64).log2());
    }

    // Scheme Switching
    let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);

    let now = Instant::now();
    switch_scheme(&glev, &mut ggsw, ss_key);
    let time = now.elapsed();

    let max_err = get_max_err_ggsw_bit(&glwe_sk, ggsw.as_view(), msg);
    println!("Scheme switching: {} ms, {:.2} bits", time.as_micros() as f64 / 1000f64, (max_err as f64).log2());

    let now = Instant::now();
    let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, ggsw_base_log, ggsw_level);
    convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    let time = now.elapsed();
    println!("Fourier Transform: {} ms", time.as_micros() as f64 / 1000f64);

    // Circuit Bootstrapping
    let now = Instant::now();
    let fourier_ggsw = circuit_bootstrap_lwe_ciphertext_by_trace128_and_rescale(
        lwe_in.as_view(),
        fourier_bsk,
        &auto128_keys,
        ss_key,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
    );
    let time = now.elapsed();
    println!("\nCircuit bootstrapping: {} ms", time.as_micros() as f64 / 1000f64);
    let mut glwe_lhs = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    let pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        if i == 0 {1u64 << 63} else {0u64}
    }).collect::<Vec<u64>>());

    let mut glwe_out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_sk, &mut glwe_lhs, &pt, glwe_modular_std_dev, &mut encryption_generator);
    add_external_product_assign(&mut glwe_out, &fourier_ggsw, &glwe_lhs);

    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let mut lwe = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe, MonomialDegree(i));

        let correct_val = *pt.get(i).0 >> 63;
        let (_, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe, correct_val, 1u64 << 63);
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("External product to fresh GLWE: {:.2} bits", (max_err as f64).log2());
}

fn test_ggsw_conv_by_pksk(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    pksk_base_log: DecompositionBaseLog,
    pksk_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== GGSW conversion by pksk ====
n: {}, N: {}, k: {},
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_pksk: {}, B_pksk: 2^{}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0,
        pbs_level.0, pbs_base_log.0, ggsw_level.0, ggsw_base_log.0, log_lut_count.0,
        pksk_level.0, pksk_base_log.0, ss_level.0, ss_base_log.0,
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let (
        big_lwe_sk,
        glwe_sk,
        small_lwe_sk,
        fourier_bsk,
    ) = keygen_pbs_without_ksk(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
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

    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &big_lwe_sk,
        &glwe_sk,
        pksk_base_log,
        pksk_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let pksk = pksk.as_view();

    // Set input LWE ciphertext
    let msg = 1u64;
    let log_delta = u64::BITS - 1;
    let pt = Plaintext(msg << log_delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&small_lwe_sk, pt, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    // LWE to GLEV
    let glwe_size = glwe_dimension.to_glwe_size();
    let mut glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    let glev_mut_view = GlweCiphertextListMutView::from_container(glev.as_mut(), glwe_size, polynomial_size, ciphertext_modulus);

    let now = Instant::now();
    lwe_msb_bit_to_glev_by_pksk(lwe_in.as_view(), glev_mut_view, fourier_bsk, &pksk, ggsw_base_log, ggsw_level, log_lut_count);
    let time = now.elapsed();
    println!("LWE to GLEV: {} ms", time.as_micros() as f64 / 1000f64);

    for (k, glwe) in glev.iter().enumerate() {
        let level = k + 1;
        let log_scale = u64::BITS as usize -  ggsw_base_log.0 * level;
        print!("  Level {level}: ");
        let mut max_err = 0;
        for i in 0..polynomial_size.0 {
            let mut lwe: LweCiphertext<Vec<u64>> = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut lwe, MonomialDegree(i));

            let correct_val = if i == 0 {msg} else {0};
            let (_decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe, correct_val, 1 << log_scale);
            max_err = std::cmp::max(max_err, abs_err);
        }
        println!("{:.2} bits", (max_err as f64).log2());
    }

    // Scheme Switching
    let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);

    let now = Instant::now();
    switch_scheme(&glev, &mut ggsw, ss_key);
    let time = now.elapsed();

    let max_err = get_max_err_ggsw_bit(&glwe_sk, ggsw.as_view(), msg);
    println!("Scheme switching: {} ms, {:.2} bits", time.as_micros() as f64 / 1000f64, (max_err as f64).log2());

    let now = Instant::now();
    let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, ggsw_base_log, ggsw_level);
    convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    let time = now.elapsed();
    println!("Fourier Transform: {} ms", time.as_micros() as f64 / 1000f64);

    // Circuit Bootstrapping
    let now = Instant::now();
    let fourier_ggsw = circuit_bootstrap_lwe_ciphertext_by_pksk(
        lwe_in.as_view(),
        fourier_bsk,
        &pksk,
        ss_key,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
    );
    let time = now.elapsed();
    println!("\nCircuit bootstrapping: {} ms", time.as_micros() as f64 / 1000f64);
    let mut glwe_lhs = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    let pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        if i == 0 {1u64 << 63} else {0u64}
    }).collect::<Vec<u64>>());

    let mut glwe_out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_sk, &mut glwe_lhs, &pt, glwe_modular_std_dev, &mut encryption_generator);
    add_external_product_assign(&mut glwe_out, &fourier_ggsw, &glwe_lhs);

    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let mut lwe = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe, MonomialDegree(i));

        let correct_val = *pt.get(i).0 >> 63;
        let (_, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe, correct_val, 1u64 << 63);
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("External product to fresh GLWE: {:.2} bits", (max_err as f64).log2());
}

fn test_ggsw_conv_by_trace(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== GGSW conversion by trace ====
n: {}, N: {}, k: {},
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0,
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
        big_lwe_sk,
        glwe_sk,
        small_lwe_sk,
        fourier_bsk,
    ) = keygen_pbs_without_ksk(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
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
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );


    // Set input LWE ciphertext
    let msg = 1u64;
    let log_delta = u64::BITS - 1;
    let pt = Plaintext(msg << log_delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&small_lwe_sk, pt, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    // LWE to GLEV
    let glwe_size = glwe_dimension.to_glwe_size();
    let mut glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    let glev_mut_view = GlweCiphertextListMutView::from_container(glev.as_mut(), glwe_size, polynomial_size, ciphertext_modulus);

    let now = Instant::now();
    lwe_msb_bit_to_glev_by_trace(lwe_in.as_view(), glev_mut_view, fourier_bsk, &auto_keys, ggsw_base_log, ggsw_level, log_lut_count);
    let time = now.elapsed();
    println!("LWE to GLEV: {} ms", time.as_micros() as f64 / 1000f64);

    for (k, glwe) in glev.iter().enumerate() {
        let level = k + 1;
        let log_scale = u64::BITS as usize -  ggsw_base_log.0 * level;
        print!("  Level {level}: ");
        let mut max_err = 0;
        for i in 0..polynomial_size.0 {
            let mut lwe: LweCiphertext<Vec<u64>> = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut lwe, MonomialDegree(i));

            let correct_val = if i == 0 {msg} else {0};
            let (_decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe, correct_val, 1 << log_scale);
            max_err = std::cmp::max(max_err, abs_err);
        }
        println!("{:.2} bits", (max_err as f64).log2());
    }

    // Scheme Switching
    let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);

    let now = Instant::now();
    switch_scheme(&glev, &mut ggsw, ss_key);
    let time = now.elapsed();

    let max_err = get_max_err_ggsw_bit(&glwe_sk, ggsw.as_view(), msg);
    println!("Scheme switching: {} ms, {:.2} bits", time.as_micros() as f64 / 1000f64, (max_err as f64).log2());

    let now = Instant::now();
    let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, ggsw_base_log, ggsw_level);
    convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    let time = now.elapsed();
    println!("Fourier Transform: {} ms", time.as_micros() as f64 / 1000f64);

    // Circuit Bootstrapping
    let now = Instant::now();
    let fourier_ggsw = circuit_bootstrap_lwe_ciphertext_by_trace(
        lwe_in.as_view(),
        fourier_bsk,
        &auto_keys,
        ss_key,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
    );
    let time = now.elapsed();
    println!("\nCircuit bootstrapping: {} ms", time.as_micros() as f64 / 1000f64);
    let mut glwe_lhs = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    let pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        if i == 0 {1u64 << 63} else {0u64}
    }).collect::<Vec<u64>>());

    let mut glwe_out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_sk, &mut glwe_lhs, &pt, glwe_modular_std_dev, &mut encryption_generator);
    add_external_product_assign(&mut glwe_out, &fourier_ggsw, &glwe_lhs);

    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let mut lwe = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe, MonomialDegree(i));

        let correct_val = *pt.get(i).0 >> 63;
        let (_, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe, correct_val, 1u64 << 63);
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("External product to fresh GLWE: {:.2} bits", (max_err as f64).log2());
}
