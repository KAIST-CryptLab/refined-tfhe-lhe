use std::time::Instant;

use tfhe::{
    core_crypto::prelude::*,
    shortint::prelude::*
};

use hom_trace::{keygen::*, automorphism128::*};

fn main() {
    // Generator and buffer setting
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let mut computation_buffers = ComputationBuffers::new();

    let param = PARAM_MESSAGE_2_CARRY_2;
    let log_polynomial_size = param.polynomial_size.0.ilog2() as usize;
    let log_large_q = u64::BITS as usize + log_polynomial_size;
    let ciphertext_modulus = tfhe::core_crypto::prelude::CiphertextModulus::<u128>::try_new_power_of_2(u64::BITS as usize + log_polynomial_size).unwrap();
    let subs_decomp_base_log = DecompositionBaseLog(15);
    let subs_decomp_level = DecompositionLevelCount(2);

    // Keygen
    let (
        _lwe_secret_key,
        glwe_secret_key,
        _lwe_secret_key_after_ks,
        _fourier_bsk,
        _ksk,
    ) = keygen_basic(
        &param,
        &mut secret_generator,
        &mut encryption_generator,
        &mut computation_buffers,
    );

    let all_ksk = gen_all_auto128_keys(
        subs_decomp_base_log,
        subs_decomp_level,
        &glwe_secret_key,
        param.glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let modulus_bit = 4usize;
    let modulus_sup = 1 << modulus_bit;
    let log_delta = log_large_q - modulus_bit;
    assert!(param.polynomial_size.0 == 1 << log_polynomial_size);

    let pt = PlaintextList::from_container((0..param.polynomial_size.0).map(|i| {
        let scale = log_delta - log_polynomial_size;
        (((i + 1) % modulus_sup) << scale) as u128
    }).collect::<Vec<u128>>());

    let mut ciphertext = GlweCiphertext::new(0u128, param.glwe_dimension.to_glwe_size(), param.polynomial_size, ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_secret_key, &mut ciphertext, &pt, param.glwe_modular_std_dev, &mut encryption_generator);

    let now = Instant::now();
    let out = trace128(ciphertext.as_view(), &all_ksk);
    let time_trace = now.elapsed();
    println!("Trace time: {} ms", time_trace.as_micros() as f64 / 1000f64);

    let mut dec = PlaintextList::new(0u128, PlaintextCount(param.polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_secret_key, &out, &mut dec);

    let correct_val = *pt.get(0).0 << log_polynomial_size;
    let decrypted_u128 = *dec.get(0).0;
    let err = {
        let d0 = correct_val.wrapping_sub(decrypted_u128);
        let d1 = decrypted_u128.wrapping_sub(correct_val);
        std::cmp::min(d0, d1)
    };
    let err_bits = if err == 0 {0} else {u128::BITS - err.leading_zeros()};
    let rounding = decrypted_u128 & (1 << (log_delta - 1));
    let decoded = decrypted_u128.wrapping_add(rounding) >> log_delta;

    println!("Decoded: {decoded}, Err bits: {err_bits} bits");


    // Rescale after trace
    let mut glwe_secret_key_rs = GlweSecretKey::new_empty_key(0u64, param.glwe_dimension, param.polynomial_size);
    for (src, dst) in glwe_secret_key.as_ref().iter().zip(glwe_secret_key_rs.as_mut().iter_mut()) {
        *dst = (*src) as u64;
    }

    let now = Instant::now();
    let out = trace128_and_rescale_to_native(ciphertext.as_view(), &all_ksk);
    let time_trace_and_rs = now.elapsed();
    println!("\nTrace and RS time: {} ms", time_trace_and_rs.as_micros() as f64 / 1000f64);

    let mut dec = PlaintextList::new(0u64, PlaintextCount(param.polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_secret_key_rs, &out, &mut dec);

    let correct_val = *pt.get(0).0 as u64;
    let decrypted_u64 = *dec.get(0).0;
    let err = {
        let d0 = correct_val.wrapping_sub(decrypted_u64);
        let d1 = decrypted_u64.wrapping_sub(correct_val);
        std::cmp::min(d0, d1)
    };
    let err_bits = if err == 0 {0} else {u64::BITS - err.leading_zeros()};
    let log_delta = u64::BITS as usize - modulus_bit;
    let rounding = decrypted_u64 & (1 << (log_delta - 1));
    let decoded = decrypted_u64.wrapping_add(rounding) >> log_delta;

    println!("Decoded: {decoded}, Err bits: {err_bits} bits");
}
