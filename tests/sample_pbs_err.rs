use auto_base_conv::{generate_accumulator, get_val_and_abs_err};
use tfhe::core_crypto::prelude::*;

type Scalar = u64;
const NUM_REPEAT: usize = 1000;

fn main() {
    // wopbs_message_2_carry_2_ks_pbs
    let lwe_dimension = LweDimension(769);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(15);
    let pbs_level = DecompositionLevelCount(2);

    sample_pbs_err(lwe_dimension, glwe_dimension, polynomial_size, glwe_modular_std_dev, pbs_base_log, pbs_level, NUM_REPEAT);

    // wopbs_message_3_carry_3_ks_pbs
    let lwe_dimension = LweDimension(873);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(9);
    let pbs_level = DecompositionLevelCount(4);

    sample_pbs_err(lwe_dimension, glwe_dimension, polynomial_size, glwe_modular_std_dev, pbs_base_log, pbs_level, NUM_REPEAT);

    // wopbs_message_4_carry_4_ks_pbs
    let lwe_dimension = LweDimension(953);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(9);
    let pbs_level = DecompositionLevelCount(4);

    sample_pbs_err(lwe_dimension, glwe_dimension, polynomial_size, glwe_modular_std_dev, pbs_base_log, pbs_level, NUM_REPEAT);
}

fn sample_pbs_err(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    num_repeat: usize,
) {
    println!(
        "n: {}, N: {}, k: {}, B: 2^{}, l: {}",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_base_log.0, pbs_level.0
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // Set keys
    let small_lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let lwe_secret_key = big_lwe_sk;
    let lwe_secret_key_after_ks = small_lwe_sk;

    let std_bootstrap_key = allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_secret_key_after_ks,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        std_bootstrap_key.input_lwe_dimension(),
        std_bootstrap_key.glwe_size(),
        std_bootstrap_key.polynomial_size(),
        std_bootstrap_key.decomposition_base_log(),
        std_bootstrap_key.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrap_key, &mut fourier_bsk);
    let fourier_bsk = fourier_bsk.as_view();

    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;

    for _ in 0..num_repeat {
        // Set LWE input and accumulator
        let input = allocate_and_encrypt_new_lwe_ciphertext(&lwe_secret_key_after_ks, Plaintext(0), StandardDev(0.0), ciphertext_modulus, &mut encryption_generator);

        let accumulator = generate_accumulator(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            4,
            ciphertext_modulus,
            Scalar::ONE << 60,
            |i| i as Scalar,
        );

        let mut output = LweCiphertext::new(Scalar::ZERO, lwe_secret_key.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        programmable_bootstrap_lwe_ciphertext(&input, &mut output, &accumulator, &fourier_bsk);

        let (_, abs_err) = get_val_and_abs_err(&lwe_secret_key, &output, Scalar::ZERO, Scalar::ONE);

        avg_err += abs_err;
        max_err = std::cmp::max(max_err, abs_err);
    }

    let avg_err = (avg_err as f64) / (num_repeat as f64);
    let max_err = max_err as f64;

    println!("PBS err: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}
