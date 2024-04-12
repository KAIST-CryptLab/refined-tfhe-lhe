use std::time::Instant;
use rand::Rng;
use tfhe::core_crypto::prelude::*;
use hom_trace::{keygen_pbs_without_ksk, utils::*, pbs::*, automorphism::*, fast_automorphism::*};

fn main() {
    // PBS to GLWE by trace with mod switch
    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    test_pbs_to_glwe_by_trace_with_mod_switch(
        lwe_dimension,
        polynomial_size,
        glwe_dimension,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        auto_base_log,
        auto_level,
        ciphertext_modulus,
    );
    println!();

    // PBS to GLWE by fast trace with mod switch
    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    test_pbs_to_glwe_by_fast_trace_with_mod_switch(
        lwe_dimension,
        polynomial_size,
        glwe_dimension,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        auto_base_log,
        auto_level,
        ciphertext_modulus,
    );
    println!();

    // PBS to GLWE by pksk
    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let pksk_base_log = DecompositionBaseLog(23);
    let pksk_level = DecompositionLevelCount(1);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    test_pbs_to_glwe_by_pksk(
        lwe_dimension,
        polynomial_size,
        glwe_dimension,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        pksk_base_log,
        pksk_level,
        ciphertext_modulus,
    );
    println!();
}

fn test_pbs_to_glwe_by_trace_with_mod_switch(
    lwe_dimension: LweDimension,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== PBS to GLWE by trace with mod switch ====
n: {}, N: {}, k: {}, l_pbs: {}, B_pbs: 2^{}, l_auto: {}, B_auto: 2^{}",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, auto_level.0, auto_base_log.0
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

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Set input LWE ciphertext
    let modulus_bit = 4;
    let modulus_sup = 1usize << modulus_bit;
    let log_delta = u64::BITS - (modulus_bit + 1);
    let delta = 1 << log_delta;

    let mut rng = rand::thread_rng();
    let msg = rng.gen_range(0..modulus_sup) as u64;
    let pt = Plaintext(msg << log_delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&small_lwe_sk, pt, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    // PBS to GLWE ciphertext
    let glwe_size = glwe_dimension.to_glwe_size();
    let accumulator = generate_accumulator(polynomial_size, glwe_size, modulus_sup, ciphertext_modulus, delta, |i| {i});
    let mut glwe_out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

    let now = Instant::now();
    pbs_to_glwe_by_trace_with_mod_switch(&lwe_in, &mut glwe_out, &accumulator, fourier_bsk, &auto_keys);
    let time = now.elapsed();
    println!("Time: {} ms", time.as_micros() as f64 / 1000f64);

    print!("Err: ");
    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let mut lwe_out = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe_out, MonomialDegree(i));

        let correct_val = if i == 0 {msg} else {0};
        let (_decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe_out, correct_val, delta);
        if i < 10 {
            print!("{:.2} ", (abs_err as f64).log2());
        }
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("... ({:.2})", (max_err as f64).log2());
}


fn test_pbs_to_glwe_by_fast_trace_with_mod_switch(
    lwe_dimension: LweDimension,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== PBS to GLWE by fast trace with mod switch ====
n: {}, N: {}, k: {}, l_pbs: {}, B_pbs: 2^{}, l_auto: {}, B_auto: 2^{}",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, auto_level.0, auto_base_log.0
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

    let fast_auto_keys = gen_all_fast_auto_keys(
        auto_base_log,
        auto_level,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Set input LWE ciphertext
    let modulus_bit = 4;
    let modulus_sup = 1usize << modulus_bit;
    let log_delta = u64::BITS - (modulus_bit + 1);
    let delta = 1 << log_delta;

    let mut rng = rand::thread_rng();
    let msg = rng.gen_range(0..modulus_sup) as u64;
    let pt = Plaintext(msg << log_delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&small_lwe_sk, pt, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    // PBS to GLWE ciphertext
    let glwe_size = glwe_dimension.to_glwe_size();
    let accumulator = generate_accumulator(polynomial_size, glwe_size, modulus_sup, ciphertext_modulus, delta, |i| {i});
    let mut glwe_out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

    let now = Instant::now();
    pbs_to_glwe_by_fast_trace_with_mod_switch(&lwe_in, &mut glwe_out, &accumulator, fourier_bsk, &fast_auto_keys);
    let time = now.elapsed();
    println!("Time: {} ms", time.as_micros() as f64 / 1000f64);

    print!("Err: ");
    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let mut lwe_out = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe_out, MonomialDegree(i));

        let correct_val = if i == 0 {msg} else {0};
        let (_decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe_out, correct_val, delta);
        if i < 10 {
            print!("{:.2} ", (abs_err as f64).log2());
        }
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("... ({:.2})", (max_err as f64).log2());
}


fn test_pbs_to_glwe_by_pksk(
    lwe_dimension: LweDimension,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pksk_base_log: DecompositionBaseLog,
    pksk_level: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== PBS to GLWE by pksk ====
n: {}, N: {}, k: {}, l_pbs: {}, B_pbs: 2^{}, l_pksk: {}, B_pksk: 2^{}",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, pksk_level.0, pksk_base_log.0
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

    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &big_lwe_sk,
        &glwe_sk,
        pksk_base_log,
        pksk_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // Set input LWE ciphertext
    let modulus_bit = 4;
    let modulus_sup = 1usize << modulus_bit;
    let log_delta = u64::BITS - (modulus_bit + 1);
    let delta = 1 << log_delta;

    let mut rng = rand::thread_rng();
    let msg = rng.gen_range(0..modulus_sup) as u64;
    let pt = Plaintext(msg << log_delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&small_lwe_sk, pt, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    // PBS to GLWE ciphertext
    let glwe_size = glwe_dimension.to_glwe_size();
    let accumulator = generate_accumulator(polynomial_size, glwe_size, modulus_sup, ciphertext_modulus, delta, |i| {i});
    let mut glwe_out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    let mut lwe_out = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);

    let now = Instant::now();
    programmable_bootstrap_lwe_ciphertext(&lwe_in, &mut lwe_out, &accumulator, &fourier_bsk);
    keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pksk, &lwe_out, &mut glwe_out);
    let time = now.elapsed();
    println!("Time: {} ms", time.as_micros() as f64 / 1000f64);

    print!("Err: ");
    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let mut lwe_out = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe_out, MonomialDegree(i));

        let correct_val = if i == 0 {msg} else {0};
        let (_decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe_out, correct_val, delta);
        if i < 10 {
            print!("{:.2} ", (abs_err as f64).log2());
        }
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("... ({:.2})", (max_err as f64).log2());
}
