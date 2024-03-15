use std::time::Instant;
use tfhe::core_crypto::prelude::*;

fn main() {
    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let ks_level = DecompositionLevelCount(5);
    let ks_base_log = DecompositionBaseLog(3);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let big_pksk_decomp_base_log = DecompositionBaseLog(23);
    let big_pksk_decomp_level = DecompositionLevelCount(1);
    let small_pksk_decomp_base_log = DecompositionBaseLog(23);
    let small_pksk_decomp_level = DecompositionLevelCount(1);

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let small_lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &small_lwe_sk,
        ks_base_log,
        ks_level,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let big_pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &big_lwe_sk,
        &glwe_sk,
        big_pksk_decomp_base_log,
        big_pksk_decomp_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let small_pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &small_lwe_sk,
        &glwe_sk,
        small_pksk_decomp_base_log,
        small_pksk_decomp_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let lwe_big = allocate_and_encrypt_new_lwe_ciphertext(
        &big_lwe_sk,
        Plaintext(0),
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut out = GlweCiphertext::new(0u64, glwe_dimension.to_glwe_size(), polynomial_size, ciphertext_modulus);
    let now = Instant::now();
    keyswitch_lwe_ciphertext_into_glwe_ciphertext(&big_pksk, &lwe_big, &mut out);
    let time = now.elapsed();
    println!("big pksk: {} ms", time.as_micros() as f64 / 1000f64);

    let mut dec = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &out, &mut dec);
    for i in 0..4 {
        let val = *dec.get(i).0;
        let err = std::cmp::min(val, val.wrapping_neg());
        let bit_err = if err == 0 {0} else {64 - err.leading_zeros()};
        print!("{bit_err} ");
    }
    println!();

    let mut lwe_ks = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
    let now = Instant::now();
    keyswitch_lwe_ciphertext(&ksk, &lwe_big, &mut lwe_ks);
    let time_lwe_ks = now.elapsed();
    let now = Instant::now();
    keyswitch_lwe_ciphertext_into_glwe_ciphertext(&small_pksk, &lwe_ks, &mut out);
    let time_pksk = now.elapsed();
    let time_total = time_lwe_ks + time_pksk;
    println!("\nsmall pksk: {} ms + {} ms = {} ms",
        time_lwe_ks.as_micros() as f64 / 1000f64,
        time_pksk.as_micros() as f64 / 1000f64,
        time_total.as_micros() as f64 / 1000f64,
    );

    let mut dec = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &out, &mut dec);
    for i in 0..4 {
        let val = *dec.get(i).0;
        let err = std::cmp::min(val, val.wrapping_neg());
        let bit_err = if err == 0 {0} else {64 - err.leading_zeros()};
        print!("{bit_err} ");
    }
    println!();
}