use std::time::Instant;

use dyn_stack::ReborrowMut;
use rand::Rng;
use tfhe::core_crypto::{
    algorithms::polynomial_algorithms::*, prelude::*
};
use auto_base_conv::fourier_poly_mult::*;

fn main() {
    let polynomial_size = PolynomialSize(8192);
    let num_repeat = 10;
    let modulus_bit = 12;
    let modulus_sup = 1u64 << modulus_bit;
    let log_delta = 64 - modulus_bit;

    let mut rng = rand::thread_rng();
    let poly_torus = Polynomial::from_container((0..polynomial_size.0).map(|_| {
        // rng.gen_range(0..=(u64::MAX))
        rng.gen_range(0..=(u32::MAX as u64))
    }).collect::<Vec<u64>>());
    let poly_integer = Polynomial::from_container((0..polynomial_size.0).map(|_| {
        (rng.gen_range(0..modulus_sup) - modulus_sup/2) as u64
    }).collect::<Vec<u64>>());

    // Warm-up
    let mut out = Polynomial::new(0u64, polynomial_size);
    for _ in 0..10 {
        polynomial_wrapping_mul(&mut out, &poly_torus, &poly_integer);
        polynomial_mul_by_fft(
            &mut out,
            &poly_integer,
            &poly_torus,
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
        let decrypted = *out.as_ref().get(i).unwrap();
        let rounding = decrypted & (1 << (log_delta - 1));
        let decoded = decrypted.wrapping_add(rounding) >> log_delta;

        print!("{} ", decoded);
    }
    println!("... {} μs", time_naive.as_micros() as f64 / num_repeat as f64);

    // Fourier polylnomial multiplication
    let mut out_fourier = Polynomial::new(0u64, polynomial_size);
    let now = Instant::now();
    for _ in 0..num_repeat {
        polynomial_mul_by_fft(
            &mut out_fourier,
            &poly_integer,
            &poly_torus,
        )
    }
    let time_fourier = now.elapsed();

    let mut fourier_poly_int = FourierPolynomial::new(polynomial_size);
    let mut fourier_poly_torus = FourierPolynomial::new(polynomial_size);

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        fft.backward_scratch()
        .unwrap()
        .unaligned_bytes_required(),
    );
    let mut stack = buffers.stack();

    let now = Instant::now();
    for _ in 0..num_repeat {
        fft.forward_as_integer(
            fourier_poly_int.as_mut_view(),
            poly_integer.as_view(),
            stack.rb_mut(),
        );
        fft.forward_as_torus(
            fourier_poly_torus.as_mut_view(),
            poly_torus.as_view(),
            stack.rb_mut(),
        );
    }
    let time_fourier_transform = now.elapsed();

    let mut out_fourier_buffer = FourierPolynomial::new(polynomial_size);

    let now = Instant::now();
    for _ in 0..num_repeat {
        fourier_poly_mult(
            &mut out_fourier_buffer,
            &fourier_poly_int,
            &fourier_poly_torus,
        );
    }
    let time_mult_on_fourier = now.elapsed();

    let now = Instant::now();
    for _ in 0..num_repeat {
        fft.backward_as_torus(
            out_fourier.as_mut_view(),
            out_fourier_buffer.as_view(),
            stack.rb_mut(),
        );
    }
    let time_fourier_backward = now.elapsed();

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
    println!("fourier forward {} µs", time_fourier_transform.as_micros() as f64 / num_repeat as f64);
    println!("mult in fourier domain {} µs", time_mult_on_fourier.as_micros() as f64 / num_repeat as f64);
    println!("fourier backward {} µs", time_fourier_backward.as_micros() as f64 / num_repeat as f64);
    println!("fourier max err: {:.2} bits", (max_err as f64).log2());
}
