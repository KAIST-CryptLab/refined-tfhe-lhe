use tfhe::core_crypto::prelude::*;

pub fn keygen_pbs<Scalar: UnsignedTorus, G: ByteRandomGenerator>(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    secret_generator: &mut SecretRandomGenerator<G>,
    encryption_generator: &mut EncryptionRandomGenerator<G>,
) -> (
    LweSecretKey<Vec<Scalar>>,
    GlweSecretKey<Vec<Scalar>>,
    LweSecretKey<Vec<Scalar>>,
    FourierLweBootstrapKeyOwned,
    LweKeyswitchKey<Vec<Scalar>>,
) {
    let small_lwe_secret_key: LweSecretKey<Vec<Scalar>> = LweSecretKey::generate_new_binary(lwe_dimension, secret_generator);
    let glwe_secret_key: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, secret_generator);
    let large_lwe_secret_key: LweSecretKey<Vec<Scalar>> = glwe_secret_key.clone().into_lwe_secret_key();

    let lwe_secret_key = large_lwe_secret_key;
    let lwe_secret_key_after_ks = small_lwe_secret_key;

    let bootstrap_key = allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_secret_key_after_ks,
        &glwe_secret_key,
        pbs_base_log,
        pbs_level,
        glwe_modular_std_dev,
        CiphertextModulus::<Scalar>::new_native(),
        encryption_generator,
    );

    let mut fourier_bsk = FourierLweBootstrapKey::new(
        bootstrap_key.input_lwe_dimension(),
        bootstrap_key.glwe_size(),
        bootstrap_key.polynomial_size(),
        bootstrap_key.decomposition_base_log(),
        bootstrap_key.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&bootstrap_key, &mut fourier_bsk);
    drop(bootstrap_key);

    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &lwe_secret_key,
        &lwe_secret_key_after_ks,
        ks_base_log,
        ks_level,
        lwe_modular_std_dev,
        CiphertextModulus::<Scalar>::new_native(),
        encryption_generator,
    );

    (lwe_secret_key, glwe_secret_key, lwe_secret_key_after_ks, fourier_bsk, ksk)
}

pub fn keygen_pbs_without_ksk<Scalar: UnsignedTorus, G: ByteRandomGenerator>(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    secret_generator: &mut SecretRandomGenerator<G>,
    encryption_generator: &mut EncryptionRandomGenerator<G>,
) -> (
    LweSecretKey<Vec<Scalar>>,
    GlweSecretKey<Vec<Scalar>>,
    LweSecretKey<Vec<Scalar>>,
    FourierLweBootstrapKeyOwned,
) {
    let small_lwe_secret_key: LweSecretKey<Vec<Scalar>> = LweSecretKey::generate_new_binary(lwe_dimension, secret_generator);
    let glwe_secret_key: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, secret_generator);
    let large_lwe_secret_key: LweSecretKey<Vec<Scalar>> = glwe_secret_key.clone().into_lwe_secret_key();

    let lwe_secret_key = large_lwe_secret_key;
    let lwe_secret_key_after_ks = small_lwe_secret_key;

    let bootstrap_key = allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_secret_key_after_ks,
        &glwe_secret_key,
        pbs_base_log,
        pbs_level,
        glwe_modular_std_dev,
        CiphertextModulus::<Scalar>::new_native(),
        encryption_generator,
    );

    let mut fourier_bsk = FourierLweBootstrapKey::new(
        bootstrap_key.input_lwe_dimension(),
        bootstrap_key.glwe_size(),
        bootstrap_key.polynomial_size(),
        bootstrap_key.decomposition_base_log(),
        bootstrap_key.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&bootstrap_key, &mut fourier_bsk);
    drop(bootstrap_key);

    (lwe_secret_key, glwe_secret_key, lwe_secret_key_after_ks, fourier_bsk)
}
