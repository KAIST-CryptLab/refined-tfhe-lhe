use std::time::Instant;

use rand::Rng;
use tfhe::core_crypto::prelude::*;
use hom_trace::{automorphism::*, convert_lwes_to_glwe_by_trace_with_mod_switch};

fn main() {
    type Scalar = u64;
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

    println!("PolynomialSize: {}, GlweDim: {}, AutoBaseLog: {}, AutoLevel: {}",
        polynomial_size.0, glwe_dimension.0, auto_base_log.0, auto_level.0,
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let glwe_size = glwe_dimension.to_glwe_size();
    let glwe_sk: GlweSecretKey<Vec<Scalar>> = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let lwe_dimension = lwe_sk.lwe_dimension();
    let lwe_size = lwe_dimension.to_lwe_size();

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Set input LWEs
    let lwe_count = 1 << 1;
    let modulus_bit = 4usize;
    let modulus_sup = 1 << modulus_bit;
    let log_scale = Scalar::BITS as usize - (modulus_bit + 1);

    let mut rng = rand::thread_rng();
    let pt = PlaintextList::from_container((0..lwe_count).map(|_| {
        (rng.gen_range(0..modulus_sup) as Scalar) << log_scale
    }).collect::<Vec<Scalar>>());

    let mut input_lwes = LweCiphertextList::new(Scalar::ZERO, lwe_size, LweCiphertextCount(lwe_count), ciphertext_modulus);
    encrypt_lwe_ciphertext_list(&lwe_sk, &mut input_lwes, &pt, glwe_modular_std_dev, &mut encryption_generator);

    // LWEs to GLWE
    let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    // warm-up
    for _ in 0..100 {
        convert_lwes_to_glwe_by_trace_with_mod_switch(&input_lwes, &mut output, &auto_keys);
    }

    let now = Instant::now();
    convert_lwes_to_glwe_by_trace_with_mod_switch(&input_lwes, &mut output, &auto_keys);
    let time = now.elapsed();

    let mut dec = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &output, &mut dec);

    let mut max_err = Scalar::ZERO;
    let box_size = polynomial_size.0 / lwe_count;
    for (i, val) in dec.iter().enumerate() {
        let val = *val.0;
        let correct_val = if i % box_size == 0 {*pt.get(i / box_size).0} else {Scalar::ZERO};
        let abs_err = {
            let d0 = val.wrapping_sub(correct_val);
            let d1 = correct_val.wrapping_sub(val);
            std::cmp::min(d0, d1)
        };
        max_err = std::cmp::max(max_err, abs_err);
    }

    println!("{} ms, err: {:.2}", time.as_micros() as f64 / 1000f64, (max_err as f64).log2());
}
