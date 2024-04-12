use std::time::Instant;

use rand::Rng;
use tfhe::core_crypto::{
    algorithms::polynomial_algorithms::*, prelude::*
};
use hom_trace::fourier_poly_mult::*;

fn main() {
    let polynomial_size = PolynomialSize(2048);
    let num_repeat = 1000;
    let modulus_bit = 10;
    let modulus_sup = 1u64 << modulus_bit;
    let log_delta = 64 - modulus_bit;

    let mut rng = rand::thread_rng();
    let poly_torus = Polynomial::from_container((0..polynomial_size.0).map(|_| {
        rng.gen_range(0..=u64::MAX)
    }).collect::<Vec<u64>>());
    let poly_integer = Polynomial::from_container((0..polynomial_size.0).map(|_| {
        (rng.gen_range(0..modulus_sup) - modulus_sup/2) as u64
    }).collect::<Vec<u64>>());

    // Warm-up
    let mut out = Polynomial::new(0u64, polynomial_size);
    for _ in 0..1000 {
        polynomial_wrapping_mul(&mut out, &poly_torus, &poly_integer);
        fourier_polynomial_torus_integer_mult(
            &mut out,
            &poly_torus,
            &poly_integer,
            modulus_bit,
        );
    }

    println!("-------- polynomial * polynomial --------");
    // Naive polynomial multiplication
    let mut out = Polynomial::new(0u64, polynomial_size);
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
    let mut out_fourier = Polynomial::new(0u64, polynomial_size);
    let now = Instant::now();
    for _ in 0..num_repeat {
        fourier_polynomial_torus_integer_mult(
            &mut out_fourier,
            &poly_torus,
            &poly_integer,
            modulus_bit,
        );
    }
    let time_fourier = now.elapsed();

    print!("[Fourier] ");
    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let decrypted = *out_fourier.as_ref().get(i).unwrap();
        let rounding = decrypted & (1 << (log_delta - 1));
        let decoded = decrypted.wrapping_add(rounding) >> log_delta;

        if i < 16 {
            print!("{decoded} ");
        }

        let correct_val = *out.as_ref().get(i).unwrap();
        let abs_err = {
            let d0 = decrypted.wrapping_sub(correct_val);
            let d1 = correct_val.wrapping_sub(decrypted);
            std::cmp::min(d0, d1)
        };
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("... {} µs", time_fourier.as_micros() as f64 / num_repeat as f64);
    println!("modulus_bit: {modulus_bit}");
    println!("fourier max err: {:.2} bits", (max_err as f64).log2());

    let mut out_fourier_decomp = Polynomial::new(0u64, polynomial_size);
    let now = Instant::now();
    for _ in 0..num_repeat {
        fourier_polynomial_torus_integer_mult_split(
            &mut out_fourier_decomp,
            &poly_torus,
            &poly_integer,
            modulus_bit
        );
    }
    let time_fourier_decomp = now.elapsed();

    print!("[Decomposed Fourier] ");
    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let decrypted = *out_fourier_decomp.as_ref().get(i).unwrap();
        let rounding = decrypted & (1 << (log_delta - 1));
        let decoded = decrypted.wrapping_add(rounding) >> log_delta;

        if i < 16 {
            print!("{decoded} ");
        }

        let correct_val = *out.as_ref().get(i).unwrap();
        let abs_err = {
            let d0 = decrypted.wrapping_sub(correct_val);
            let d1 = correct_val.wrapping_sub(decrypted);
            std::cmp::min(d0, d1)
        };
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("... {} µs", time_fourier_decomp.as_micros() as f64 / num_repeat as f64);
    println!("modulus_bit: {modulus_bit}");
    println!("fourier max err: {:.2} bits", (max_err as f64).log2());
    println!();

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
    let log_delta = 64 - modulus_bit;

    let pt = PlaintextList::from_container((0..polynomial_size.0).map(|_i| {
        (rng.gen_range(0..modulus_sup) - modulus_sup/2) as u64
    }).collect::<Vec<u64>>());
    let scaled_pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        *pt.get(i).0 << log_delta
    }).collect::<Vec<u64>>());
    let poly_int = Polynomial::from_container((0..polynomial_size.0).map(|_| {
        (rng.gen_range(0..modulus_sup) - modulus_sup/2) as u64
    }).collect::<Vec<u64>>());

    let mut ct = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_secret_key, &mut ct, &scaled_pt, StandardDev(0f64), &mut encryption_generator);

    let mut res_poly = Polynomial::new(0u64, polynomial_size);
    polynomial_wrapping_add_mul_assign(
        &mut res_poly,
        &Polynomial::from_container(scaled_pt.as_ref()),
        &poly_int,
    );
    let res = PlaintextList::from_container(res_poly.as_ref());

    // Naive polynomial multiplication
    let mut out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    let now = Instant::now();
    for _ in 0..num_repeat {
        for (mut out_poly, ct_poly) in out.as_mut_polynomial_list().iter_mut().zip(ct.as_polynomial_list().iter()) {
            polynomial_wrapping_mul(&mut out_poly, &ct_poly, &poly_int);
        }
    }
    let time_naive = now.elapsed();

    let mut dec = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_secret_key, &out, &mut dec);

    print!("[ Naive ]");
    let mut max_err = 0;
    for i in 0..polynomial_size.0 {
        let decrypted = *dec.get(i).0;
        let rounding = decrypted & (1 << (log_delta - 1));
        let decoded = decrypted.wrapping_add(rounding) >> log_delta;

        let correct_val = *res.get(i).0;
        let abs_err = {
            let d0 = decrypted.wrapping_sub(correct_val);
            let d1 = correct_val.wrapping_sub(decrypted);
            std::cmp::min(d0, d1)
        };
        max_err = std::cmp::max(max_err, abs_err);

        if i < 16 {
            print!(" {}", decoded);
        }
    }
    println!("... {} μs", time_naive.as_micros() as f64 / num_repeat as f64);
    println!("Naive max err: {:.2} bits", (max_err as f64).log2());


    // Fourier polynomial multiplication
    let mut out_fourier = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    let now = Instant::now();
    for _ in 0..num_repeat {
        fourier_glwe_polynomial_mult(&mut out_fourier, &ct, &poly_int, 65 - log_delta);
    }
    let time_fourier = now.elapsed();

    let mut dec_fourier = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_secret_key, &out_fourier, &mut dec_fourier);

    print!("[Fourier]");
    let mut max_err = 0;
    for i in 0..16 {
        let decrypted = *dec_fourier.get(i).0;
        let rounding = decrypted & (1 << (log_delta - 1));
        let decoded = decrypted.wrapping_add(rounding) >> log_delta;

        let correct_val = *res.get(i).0;
        let abs_err = {
            let d0 = decrypted.wrapping_sub(correct_val);
            let d1 = correct_val.wrapping_sub(decrypted);
            std::cmp::min(d0, d1)
        };
        max_err = std::cmp::max(max_err, abs_err);

        if i < 16 {
            print!(" {}", decoded);
        }
    }
    println!("... {} μs", time_fourier.as_micros() as f64 / num_repeat as f64);
    println!("fourier max err: {:.2} bits", (max_err as f64).log2());

    for (k, (out_poly, out_fourier_poly)) in out.as_polynomial_list().iter()
        .zip(out_fourier.as_polynomial_list().iter())
        .enumerate()
    {
        let mut max_err = 0;
        let out_poly = out_poly.as_ref();
        let out_fourier_poly = out_fourier_poly.as_ref();
        for (naive_val, fourier_val) in out_poly.iter().zip(out_fourier_poly.iter()) {
            let abs_err = {
                let d0 = fourier_val.wrapping_sub(*naive_val);
                let d1 = naive_val.wrapping_sub(*fourier_val);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        println!("Poly[{k}]: {:.2} bits", (max_err as f64).log2());
    }
}
