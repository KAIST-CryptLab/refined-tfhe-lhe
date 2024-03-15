use std::time::Instant;

use tfhe::core_crypto::prelude::*;
use hom_trace::{rescale::*, automorphism128::*};

fn main() {
    type SmallQ = u64;
    type LargeQ = u128;

    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);
    println!("PolynomialSize: {}, GlweDim: {}, AutoBaseLog: {}, AutoLevel: {}",
        polynomial_size.0, glwe_dimension.0, auto_base_log.0, auto_level.0,
    );

    let log_polynomial_size = polynomial_size.0.ilog2() as usize;
    let log_large_q = SmallQ::BITS as usize + log_polynomial_size;

    let small_ciphertext_modulus = CiphertextModulus::<SmallQ>::new_native();
    let large_ciphertext_modulus = CiphertextModulus::<LargeQ>::try_new_power_of_2(log_large_q).unwrap();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<SmallQ>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    let mut glwe_sk_large_q: GlweSecretKey<Vec<LargeQ>> = GlweSecretKey::new_empty_key(LargeQ::ZERO, glwe_dimension, polynomial_size);
    for (src, dst) in glwe_sk.as_ref().iter().zip(glwe_sk_large_q.as_mut().iter_mut()) {
        *dst = (*src) as LargeQ;
    }

    let auto_keys = gen_all_auto128_keys(
        auto_base_log,
        auto_level,
        &glwe_sk_large_q,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Set input ciphertext
    let modulus_bit = 4usize;
    let log_delta = SmallQ::BITS as usize - modulus_bit;

    let pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        (i as SmallQ) << log_delta
    }).collect::<Vec<SmallQ>>());

    let mut ct = GlweCiphertext::new(SmallQ::ZERO, glwe_size, polynomial_size, small_ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_sk, &mut ct, &pt, glwe_modular_std_dev, &mut encryption_generator);

    let now = Instant::now();
    // Mod Raise
    let mut ct_large_q = GlweCiphertext::new(LargeQ::ZERO, glwe_size, polynomial_size, large_ciphertext_modulus);
    glwe_ciphertext_mod_raise_from_native_to_non_native_power_of_two(&ct, &mut ct_large_q);

    // Trace
    let out = trace128_and_rescale_to_native(ct_large_q.as_view(), &auto_keys);
    let time = now.elapsed();

    // Decryption
    let mut dec = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &out, &mut dec);

    let decrypted_u64 = *dec.get(0).0;
    let err = {
        let correct_val = *pt.get(0).0;
        let d0 = decrypted_u64.wrapping_sub(correct_val);
        let d1 = correct_val.wrapping_sub(decrypted_u64);
        std::cmp::min(d0, d1)
    };
    let bit_err = if err == 0 {0} else {SmallQ::BITS - err.leading_zeros()};
    println!("Time: {} ms, Err: {} bits", time.as_micros() as f64 / 1000f64, bit_err);
}