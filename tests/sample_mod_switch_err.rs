use auto_base_conv::{
    utils::get_val_and_abs_err,
    mod_switch::lwe_ciphertext_mod_switch_from_native_to_non_native_power_of_two,
};
use tfhe::core_crypto::prelude::*;
type Scalar = u64;

const NUM_REPEAT: usize = 10000;

fn main() {
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);

    sample_lwe_mod_switch_err(polynomial_size, glwe_dimension);
    println!();

    let polynomial_size = PolynomialSize(8192);
    let glwe_dimension = GlweDimension(1);

    sample_lwe_mod_switch_err(polynomial_size, glwe_dimension);
    println!();

    let polynomial_size = PolynomialSize(32768);
    let glwe_dimension = GlweDimension(1);

    sample_lwe_mod_switch_err(polynomial_size, glwe_dimension);
    println!();

}

fn sample_lwe_mod_switch_err(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
) {
    let log_polynomial_size = polynomial_size.0.ilog2() as usize;
    let log_small_q = Scalar::BITS as usize - log_polynomial_size;

    let small_ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_small_q).unwrap();
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;

    for _ in 0..NUM_REPEAT {
        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
        let lwe_sk = glwe_sk.into_lwe_secret_key();
        let lwe_size = lwe_sk.lwe_dimension().to_lwe_size();

        // Set input ciphertext
        let mut input = LweCiphertext::new(Scalar::ZERO, lwe_size, ciphertext_modulus);
        encrypt_lwe_ciphertext(&lwe_sk, &mut input, Plaintext(0), StandardDev(0.0), &mut encryption_generator);

        let mut output = LweCiphertext::new(Scalar::ZERO, lwe_size, small_ciphertext_modulus);
        lwe_ciphertext_mod_switch_from_native_to_non_native_power_of_two(&input, &mut output);

        let (_, abs_err) = get_val_and_abs_err(&lwe_sk, &output, Scalar::ZERO, 1);

        avg_err += abs_err;
        max_err = std::cmp::max(max_err, abs_err);
    }

    let avg_err = (avg_err as f64) / (NUM_REPEAT as f64);
    let max_err = max_err as f64;

    println!(
        "N: {}, k: {} => Err: (Avg) {:.5} bits (Max) {:.5} bits",
        polynomial_size.0, glwe_dimension.0, avg_err.log2(), max_err.log2()
    );
}