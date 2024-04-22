use hom_trace::fourier_poly_mult::*;
use rand::Rng;
use tfhe::core_crypto::{
    prelude::*,
    algorithms::polynomial_algorithms::polynomial_wrapping_mul,
};

type Scalar = u64;
const NUM_REPEAT: usize = 10000;

fn main() {
    let polynomial_size = PolynomialSize(2048);

    for log_b in 4..=12 {
        let decomp_base_log = DecompositionBaseLog(log_b);
        sample_fourier_poly_mult_err(polynomial_size, decomp_base_log, NUM_REPEAT);
    }
}

fn sample_fourier_poly_mult_err(
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    num_repeat: usize,
) {
    let base = 1 << decomp_base_log.0;

    let mut rng = rand::thread_rng();
    let mut poly_lhs = Polynomial::new(Scalar::ZERO, polynomial_size);
    let mut poly_rhs = Polynomial::new(Scalar::ZERO, polynomial_size);

    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;

    for _ in 0..num_repeat {
        for val in poly_lhs.as_mut().iter_mut() {
            *val = rng.gen_range(0..base) - base / 2;
        }
        for val in poly_rhs.as_mut().iter_mut() {
            *val = rng.gen_range(0..=Scalar::MAX);
        }

        let mut poly_out_standard = Polynomial::new(Scalar::ZERO, polynomial_size);
        polynomial_wrapping_mul(
            &mut poly_out_standard,
            &poly_lhs,
            &poly_rhs,
        );

        let mut poly_out_fourier = Polynomial::new(Scalar::ZERO, polynomial_size);
        polynomial_mul_by_fft(
            &mut poly_out_fourier,
            &poly_lhs,
            &poly_rhs,
        );

        let mut fft_err = Scalar::ZERO;
        for (standard_val, fourier_val) in poly_out_standard.as_ref().iter()
            .zip(poly_out_fourier.iter())
        {
            let abs_err = {
                let d0 = standard_val.wrapping_sub(*fourier_val);
                let d1 = fourier_val.wrapping_sub(*standard_val);
                std::cmp::min(d0, d1)
            };

            fft_err = std::cmp::max(fft_err, abs_err);
        }

        avg_err += fft_err;
        max_err = std::cmp::max(max_err, fft_err);
    }

    let avg_err = (avg_err as f64) / (num_repeat as f64);
    let max_err = max_err as f64;

    println!(
        "N: {}, B: 2^{}, FFT err: (Avg) {:.2} bits (Max) {:.2} bits\n",
        polynomial_size.0, decomp_base_log.0, avg_err.log2(), max_err.log2(),
    );
}

