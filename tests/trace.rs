use std::time::Instant;

use tfhe::{
    core_crypto::prelude::*,
    shortint::prelude::*
};

use hom_trace::automorphism::*;

fn main() {
    // Generator and buffer setting
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let param = PARAM_MESSAGE_2_CARRY_2;
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);
    println!("PolynomialSize: {}, GlweDim: {}, AutoBaseLog: {}, AutoLevel: {}",
        param.polynomial_size.0, param.glwe_dimension.0, auto_base_log.0, auto_level.0,
    );

    // Keygen
    let glwe_secret_key = GlweSecretKey::generate_new_binary(param.glwe_dimension, param.polynomial_size, &mut secret_generator);
    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        &glwe_secret_key,
        param.glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let modulus_bit = 4usize;
    let modulus_sup = 1 << modulus_bit;
    let log_delta = 64 - modulus_bit;
    let log_polynomial_size = 11;
    assert!(param.polynomial_size.0 == 1 << log_polynomial_size);

    let pt = PlaintextList::from_container((0..param.polynomial_size.0).map(|i| {
        let scale = log_delta - log_polynomial_size;
        (((i + 1) % modulus_sup) << scale) as u64
    }).collect::<Vec<u64>>());

    let mut ciphertext = GlweCiphertext::new(0u64, param.glwe_dimension.to_glwe_size(), param.polynomial_size, param.ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_secret_key, &mut ciphertext, &pt, param.glwe_modular_std_dev, &mut encryption_generator);

    let now = Instant::now();
    let out = trace(ciphertext.as_view(), &auto_keys);
    let time_trace = now.elapsed();
    println!("Trace time: {} ms", time_trace.as_micros() as f64 / 1000f64);

    let mut dec = PlaintextList::new(0u64, PlaintextCount(param.polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_secret_key, &out, &mut dec);

    let correct_val = *pt.get(0).0 << log_polynomial_size;
    let decrypted_u64 = *dec.get(0).0;
    let err = {
        let d0 = correct_val.wrapping_sub(decrypted_u64);
        let d1 = decrypted_u64.wrapping_sub(correct_val);
        std::cmp::min(d0, d1)
    };
    let err_bits = if err == 0 {0} else {u64::BITS - err.leading_zeros()};
    let rounding = decrypted_u64 & (1 << (log_delta - 1));
    let decoded = decrypted_u64.wrapping_add(rounding) >> log_delta;

    println!("Decoded: {decoded}, Err bits: {err_bits} bits");
}
