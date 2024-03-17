use std::time::Instant;
use rand::Rng;
use tfhe::core_crypto::prelude::*;
use hom_trace::{utils::*, pbs::*, automorphism128::*};

fn main() {
    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let glwe_size = glwe_dimension.to_glwe_size();
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let small_lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let mut glwe_sk_128 = GlweSecretKey::new_empty_key(0u128, glwe_dimension, polynomial_size);
    for (src, dst) in glwe_sk.as_ref().iter().zip(glwe_sk_128.as_mut().iter_mut()) {
        *dst = *src as u128;
    }

    let auto128_keys = gen_all_auto128_keys(
        auto_base_log,
        auto_level,
        &glwe_sk_128,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let std_bootstrap_key = allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
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

    // Set input LWE ciphertext
    let modulus_bit = 4;
    let modulus_sup = 1usize << modulus_bit;
    let log_delta = u64::BITS - (modulus_bit + 1);
    let delta = 1 << log_delta;

    let mut rng = rand::thread_rng();
    let msg = rng.gen_range(0..modulus_sup) as u64;
    let pt = Plaintext(msg << log_delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&small_lwe_sk, pt, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    // PBS to GLWE ciphertext
    let accumulator = generate_accumulator(polynomial_size, glwe_size, modulus_sup, ciphertext_modulus, delta, |i| {i});
    let mut glwe_out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

    let now = Instant::now();
    pbs_to_glwe_by_auto128_and_rescale(&lwe_in, &mut glwe_out, &accumulator, fourier_bsk, &auto128_keys);
    let time = now.elapsed();
    println!("Time: {} ms", time.as_micros() as f64 / 1000f64);

    print!("Err: ");
    for i in 0..10 {
        let mut lwe_out = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe_out, MonomialDegree(i));

        let correct_val = if i == 0 {msg} else {0};
        let (_decoded, bit_err) = get_val_and_bit_err(&big_lwe_sk, &lwe_out, correct_val, delta);
        print!("{bit_err} ");
    }
    println!("...");
}