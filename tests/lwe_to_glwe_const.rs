use hom_trace::convert_lwe_to_glwe_const;
use tfhe::core_crypto::prelude::*;

fn main() {
    type Scalar = u64;
    let polynomial_size = PolynomialSize(512);
    let glwe_dimension = GlweDimension(3);
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    // LWEtoGLWEConst
    let lwe = allocate_and_encrypt_new_lwe_ciphertext(
        &lwe_sk,
        Plaintext(0),
        StandardDev(0.0),
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    convert_lwe_to_glwe_const(&lwe, &mut glwe);

    let mut pt = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);
    assert_eq!(*pt.get(0).0, 0);
}
