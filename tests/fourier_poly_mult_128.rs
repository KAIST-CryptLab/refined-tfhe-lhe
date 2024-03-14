use std::time::Instant;

use rand::Rng;
use tfhe::core_crypto::{
    prelude::*,
    algorithms::polynomial_algorithms::*,
};
use hom_trace::fourier_poly_mult::*;

fn main() {
    let polynomial_size = PolynomialSize(2048);
    let num_repeat = 1000;
    let modulus_bit = 4;
    let modulus_sup = 1 << modulus_bit;
    let log_delta = 128 - modulus_bit;

    let mut rng = rand::thread_rng();
    let poly_torus = Polynomial::from_container((0..polynomial_size.0).map(|_| {
        (rng.gen_range(0..modulus_sup) as u128) << log_delta
    }).collect::<Vec<u128>>());
    let poly_integer = Polynomial::from_container((0..polynomial_size.0).map(|_| {
        rng.gen_range(0..modulus_sup) as u128
    }).collect::<Vec<u128>>());

    // Warm-up
    let mut out = Polynomial::new(0u128, polynomial_size);
    for _ in 0..1000 {
        polynomial_wrapping_mul(&mut out, &poly_torus, &poly_integer);
        fourier_polynomial_torus_integer_mult_128(
            &mut out,
            &poly_torus,
            &poly_integer,
            128 - log_delta,
        );
    }

    println!("-------- polynomial * polynomial --------");
    // Naive polynomial multiplication
    let mut out = Polynomial::new(0u128, polynomial_size);
    let now = Instant::now();
    for _ in 0..num_repeat {
        polynomial_wrapping_mul(&mut out, &poly_torus, &poly_integer);
    }
    let time_naive = now.elapsed();

    print!("[ Naive ] ");
    for i in 0..16 {
        print!("{} ", out.as_ref().get(i).unwrap() >> log_delta);
    }
    println!("... {} μs", time_naive.as_micros() as f64 / num_repeat as f64);

    // Fourier polylnomial multiplication
    let mut out = Polynomial::new(0u128, polynomial_size);
    let now = Instant::now();
    for _ in 0..num_repeat {
        fourier_polynomial_torus_integer_mult_128(
            &mut out,
            &poly_torus,
            &poly_integer,
            128 - log_delta,
        );
    }
    let time_fourier = now.elapsed();

    print!("[Fourier] ");
    for i in 0..16 {
        let decrypted = *out.as_ref().get(i).unwrap();
        let rounding = decrypted & (1 << (log_delta - 1));
        let decoded = decrypted.wrapping_add(rounding) >> log_delta;
        print!("{decoded} ");
    }
    println!("... {} µs", time_fourier.as_micros() as f64 / num_repeat as f64);


    println!("-------- GLWE * polynomial --------");
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_secret_key = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    let ciphertext_modulus = CiphertextModulus::new_native();
    let modulus_bit = 4;
    let modulus_sup = 1 << modulus_bit;
    let log_delta = 128 - modulus_bit;

    let pt = PlaintextList::from_container((0..polynomial_size.0).map(|_| {
        rng.gen_range(0..modulus_sup) as u128
    }).collect::<Vec<u128>>());
    let scaled_pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        *pt.get(i).0 << log_delta
    }).collect::<Vec<u128>>());
    let poly_int = Polynomial::from_container((0..polynomial_size.0).map(|_| {
        rng.gen_range(0..modulus_sup) as u128
    }).collect::<Vec<u128>>());

    let mut ct = GlweCiphertext::new(0u128, glwe_size, polynomial_size, ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_secret_key, &mut ct, &scaled_pt, StandardDev(0f64), &mut encryption_generator);

    // Naive polynomial multiplication
    let mut out = GlweCiphertext::new(0u128, glwe_size, polynomial_size, ciphertext_modulus);
    let now = Instant::now();
    for _ in 0..num_repeat {
        for (mut out_poly, ct_poly) in out.as_mut_polynomial_list().iter_mut().zip(ct.as_polynomial_list().iter()) {
            polynomial_wrapping_mul(&mut out_poly, &ct_poly, &poly_int);
        }
    }
    let time_naive = now.elapsed();

    let mut dec = PlaintextList::new(0u128, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_secret_key, &out, &mut dec);

    print!("[ Naive ]");
    for i in 0..16 {
        let decrypted = *dec.get(i).0;
        let rounding = decrypted & (1 << (log_delta - 1));
        let decoded = decrypted.wrapping_add(rounding) >> log_delta;
        print!(" {}", decoded);
    }
    println!("... {} μs", time_naive.as_micros() as f64 / num_repeat as f64);

    // Fourier polynomial multiplication
    let mut out = GlweCiphertext::new(0u128, glwe_size, polynomial_size, ciphertext_modulus);
    let now = Instant::now();
    for _ in 0..num_repeat {
        fourier_glwe_polynomial_mult_128(&mut out, &ct, &poly_int, modulus_sup);
    }
    let time_fourier = now.elapsed();

    let mut dec = PlaintextList::new(0u128, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_secret_key, &out, &mut dec);

    print!("[Fourier]");
    for i in 0..16 {
        let decrypted = *dec.get(i).0;
        let rounding = decrypted & (1 << (log_delta - 1));
        let decoded = decrypted.wrapping_add(rounding) >> log_delta;
        print!(" {}", decoded);
    }
    println!("... {} μs", time_fourier.as_micros() as f64 / num_repeat as f64);
}
