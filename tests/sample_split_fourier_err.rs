use std::ops::Neg;

use dyn_stack::ReborrowMut;
use auto_base_conv::fourier_poly_mult::*;
use rand::Rng;
use tfhe::core_crypto::{
    prelude::*,
    algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign,
};

type Scalar = u64;
const FFT_BASE_LOG: usize = 16;
const NUM_REPEAT: usize = 10000;

fn main() {
    // -------- param_message_2_carry_2 -------- //
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let decomp_base_log = DecompositionBaseLog(13);
    let decomp_level = DecompositionLevelCount(3);

    sample_fourier_err(polynomial_size, glwe_dimension, decomp_base_log, decomp_level,FFT_BASE_LOG, NUM_REPEAT);

    // -------- param_message_3_carry_3 -------- //
    let polynomial_size = PolynomialSize(8192);
    let glwe_dimension = GlweDimension(1);
    let decomp_base_log = DecompositionBaseLog(15);
    let decomp_level = DecompositionLevelCount(3);

    sample_fourier_err(polynomial_size, glwe_dimension, decomp_base_log, decomp_level,FFT_BASE_LOG, NUM_REPEAT);

    let polynomial_size = PolynomialSize(8192);
    let glwe_dimension = GlweDimension(1);
    let decomp_base_log = DecompositionBaseLog(12);
    let decomp_level = DecompositionLevelCount(4);

    sample_fourier_err(polynomial_size, glwe_dimension, decomp_base_log, decomp_level,FFT_BASE_LOG, NUM_REPEAT);

    // -------- param_message_4_carry_4 -------- //
    let polynomial_size = PolynomialSize(32768);
    let glwe_dimension = GlweDimension(1);
    let decomp_base_log = DecompositionBaseLog(15);
    let decomp_level = DecompositionLevelCount(3);

    sample_fourier_err(polynomial_size, glwe_dimension, decomp_base_log, decomp_level,FFT_BASE_LOG, NUM_REPEAT);

    let polynomial_size = PolynomialSize(32768);
    let glwe_dimension = GlweDimension(1);
    let decomp_base_log = DecompositionBaseLog(13);
    let decomp_level = DecompositionLevelCount(4);

    sample_fourier_err(polynomial_size, glwe_dimension, decomp_base_log, decomp_level,FFT_BASE_LOG, NUM_REPEAT);

    // -------- wopbs -------- //
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let decomp_base_log = DecompositionBaseLog(7);
    let decomp_level = DecompositionLevelCount(7);

    sample_fourier_err(polynomial_size, glwe_dimension, decomp_base_log, decomp_level,FFT_BASE_LOG, NUM_REPEAT);

    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let decomp_base_log = DecompositionBaseLog(6);
    let decomp_level = DecompositionLevelCount(10);

    sample_fourier_err(polynomial_size, glwe_dimension, decomp_base_log, decomp_level,FFT_BASE_LOG, NUM_REPEAT);

    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let decomp_base_log = DecompositionBaseLog(15);
    let decomp_level = DecompositionLevelCount(3);

    sample_fourier_err(polynomial_size, glwe_dimension, decomp_base_log, decomp_level,FFT_BASE_LOG, NUM_REPEAT);

    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let decomp_base_log = DecompositionBaseLog(5);
    let decomp_level = DecompositionLevelCount(10);

    sample_fourier_err(polynomial_size, glwe_dimension, decomp_base_log, decomp_level,FFT_BASE_LOG, NUM_REPEAT);

}

fn sample_fourier_err(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    decomp_base_log: DecompositionBaseLog,
    decomp_level: DecompositionLevelCount,
    fft_base_log: usize,
    num_repeat: usize,
) {
    println!(
        "N: {}, k: {}, B: 2^{}, l: {}, fft base: {}",
        polynomial_size.0, glwe_dimension.0, decomp_base_log.0, decomp_level.0, fft_base_log,
    );

    let base = 1 << decomp_base_log.0;
    let fft_base = 1 << fft_base_log;

    let mut rng = rand::thread_rng();

    let mut poly_decomp_list = PolynomialList::new(Scalar::ZERO, polynomial_size, PolynomialCount(decomp_level.0 * glwe_dimension.0));
    let mut poly_split_list: PolynomialList<Vec<u64>> = PolynomialList::new(Scalar::ZERO, polynomial_size, PolynomialCount(decomp_level.0 * glwe_dimension.0));

    let mut err_list: Vec::<f64> = vec![];

    for _ in 0..num_repeat {
        for val in poly_decomp_list.as_mut().iter_mut() {
            *val = rng.gen_range(0..base) - base / 2;
        }
        for val in poly_split_list.as_mut().iter_mut() {
            *val = rng.gen_range(0..fft_base);
        }

        let mut poly_out_standard = Polynomial::new(Scalar::ZERO, polynomial_size);
        for (poly_decomp, poly_split) in poly_decomp_list.iter().zip(poly_split_list.iter()) {
            polynomial_wrapping_add_mul_assign(
                &mut poly_out_standard,
                &poly_decomp,
                &poly_split,
            );
        }

        let mut poly_out_fourier = FourierPolynomial::new(polynomial_size);

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        let mut buffers = ComputationBuffers::new();
        buffers.resize(
            fft.backward_scratch()
            .unwrap()
            .unaligned_bytes_required(),
        );

        let mut stack = buffers.stack();

        let mut poly_decomp_fourier = FourierPolynomial::new(polynomial_size);
        let mut poly_split_fourier = FourierPolynomial::new(polynomial_size);

        for (poly_decomp, poly_split) in poly_decomp_list.iter().zip(poly_split_list.iter()) {
            fft.forward_as_integer(
                poly_decomp_fourier.as_mut_view(),
                poly_decomp.as_view(),
                stack.rb_mut(),
            );

            fft.forward_as_torus(
                poly_split_fourier.as_mut_view(),
                poly_split.as_view(),
                stack.rb_mut(),
            );

            fourier_poly_mult_and_add(
                &mut poly_out_fourier,
                &poly_decomp_fourier,
                &poly_split_fourier,
            );
        }

        let mut poly_out_real = vec![f64::default(); polynomial_size.0];
        fft.backward_as_real_torus(
            poly_out_real.as_mut(),
            poly_out_fourier.as_view(),
            stack.rb_mut(),
        );

        let mut max_err = 0f64;
        for (scalar_val, torus_val) in poly_out_standard.as_ref().iter()
            .zip(poly_out_real.iter())
        {
            let mut scalar_val = *scalar_val;
            let mut torus_val = *torus_val;

            if scalar_val >> 63 == 1 {
                assert!(torus_val.is_sign_negative());
                scalar_val = scalar_val.wrapping_neg();
                torus_val = torus_val.neg();
            }

            let abs_err = ((scalar_val as f64) - (torus_val * 2f64.powi(64))).abs();
            if abs_err > max_err {
                max_err = abs_err;
            }
        }

        err_list.push(max_err);
    }

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in err_list.iter() {
        avg_err += *err;
        if max_err < *err {
            max_err = *err;
        }
    }
    avg_err /= num_repeat as f64;

    println!("FFT err: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}

