use std::time::Instant;

use tfhe::core_crypto::prelude::*;
use hom_trace::{mod_switch::*, automorphism::*};

fn main() {
    type Scalar = u32;
    let polynomial_size = PolynomialSize(512);
    let glwe_dimension = GlweDimension(2);
    let glwe_modular_std_dev = StandardDev(0.00000004990272175010415);
    let auto_base_log = DecompositionBaseLog(5);
    let auto_level = DecompositionLevelCount(4);

    println!("PolynomialSize: {}, GlweDim: {}, AutoBaseLog: {}, AutoLevel: {}",
        polynomial_size.0, glwe_dimension.0, auto_base_log.0, auto_level.0,
    );

    type LargeScalar = u64;
    let log_polynomial_size = polynomial_size.0.ilog2() as usize;
    let log_large_q = Scalar::BITS as usize + log_polynomial_size;

    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    let large_ciphertext_modulus = CiphertextModulus::<LargeScalar>::try_new_power_of_2(log_large_q).unwrap();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Set input ciphertext
    let modulus_bit = 4usize;
    let log_delta = Scalar::BITS as usize - modulus_bit;

    let pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        (i as Scalar) << log_delta
    }).collect::<Vec<Scalar>>());

    let mut ct = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_sk, &mut ct, &pt, glwe_modular_std_dev, &mut encryption_generator);

    // Error of Fresh Ciphertext
    let mut dec = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &ct, &mut dec);
    let mut max_err = Scalar::ZERO;
    for i in 0..polynomial_size.0 {
        let decrypted = *dec.get(i).0;
        let correct_val = *pt.get(i).0;
        let abs_err = {
            let d0 = decrypted.wrapping_sub(correct_val);
            let d1 = correct_val.wrapping_sub(decrypted);
            std::cmp::min(d0, d1)
        };
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("Fresh GLWE ctxt err: {:.2} bits", (max_err as f64).log2());

    let now = Instant::now();
    // Mod Up
    let mut ct_mod_up = GlweCiphertext::new(LargeScalar::ZERO, glwe_size, polynomial_size, large_ciphertext_modulus);
    glwe_ciphertext_mod_raise_from_native_to_non_native_power_of_two(&ct, &mut ct_mod_up);

    // Trace
    let mut out = trace(ct_mod_up.as_view(), &auto_keys);

    glwe_ciphertext_cleartext_mul(&mut out, &ct_mod_up, Cleartext(polynomial_size.0 as LargeScalar));

    // ModDown
    let mut ct_mod_down = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    glwe_ciphertext_rescale_from_non_native_power_of_two_to_native(&out, &mut ct_mod_down);
    let time = now.elapsed();


    // Decryption
    let mut dec = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &ct_mod_down, &mut dec);

    let mut max_err = Scalar::ZERO;
    for i in 0..polynomial_size.0 {
        let decrypted = *dec.get(i).0;
        let correct_val = if i == 0 {*pt.get(0).0} else {Scalar::ZERO};
        let abs_err = {
            let d0 = decrypted.wrapping_sub(correct_val);
            let d1 = correct_val.wrapping_sub(decrypted);
            std::cmp::min(d0, d1)
        };
        max_err = std::cmp::max(max_err, abs_err);
    }
    println!("\nModUp -> Trace -> ModDown");
    println!("- Time: {} ms", time.as_micros() as f64 / 1000f64);
    println!("- Err : {:.2} bits", (max_err as f64).log2());
}
