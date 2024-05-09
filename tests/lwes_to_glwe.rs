use std::time::Instant;
use rand::Rng;
use tfhe::core_crypto::prelude::*;
use auto_base_conv::{automorphism::*, convert_lwes_to_glwe_by_trace_with_preprocessing, get_glwe_l2_err, get_glwe_max_err, FftType};

type Scalar = u64;

fn main() {
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let lwe_count = 16;
    let auto_base_log = DecompositionBaseLog(10);
    let auto_level = DecompositionLevelCount(4);
    let fft_type = FftType::Vanilla;

    test_lwes_to_glwe(polynomial_size, glwe_dimension, glwe_modular_std_dev, lwe_count, auto_base_log, auto_level, fft_type);
}

fn test_lwes_to_glwe(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    lwe_count: usize,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    fft_type: FftType,
) {
    println!("PolynomialSize: {}, GlweDim: {}, AutoBaseLog: {}, AutoLevel: {}, fft type: {:?}, # LWE: {}",
        polynomial_size.0, glwe_dimension.0, auto_base_log.0, auto_level.0, fft_type, lwe_count
    );

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

    let lwe_dimension = lwe_sk.lwe_dimension();
    let lwe_size = lwe_dimension.to_lwe_size();

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Set input LWEs
    let modulus_bit = 4usize;
    let modulus_sup = 1 << modulus_bit;
    let log_scale = Scalar::BITS as usize - (modulus_bit + 1);

    let mut rng = rand::thread_rng();
    let pt = PlaintextList::from_container((0..lwe_count).map(|_| {
        (rng.gen_range(0..modulus_sup) as Scalar) << log_scale
    }).collect::<Vec<Scalar>>());

    let mut input_lwes = LweCiphertextList::new(Scalar::ZERO, lwe_size, LweCiphertextCount(lwe_count), ciphertext_modulus);
    encrypt_lwe_ciphertext_list(&lwe_sk, &mut input_lwes, &pt, glwe_modular_std_dev, &mut encryption_generator);

    let box_size = polynomial_size.0 / lwe_count;
    let correct_val_list = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        if i % box_size == 0 {*pt.get(i / box_size).0} else {Scalar::ZERO}
    }).collect::<Vec<Scalar>>());

    // LWEs to GLWE
    let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    // warm-up
    for _ in 0..100 {
        convert_lwes_to_glwe_by_trace_with_preprocessing(&input_lwes, &mut output, &auto_keys);
    }

    let now = Instant::now();
    convert_lwes_to_glwe_by_trace_with_preprocessing(&input_lwes, &mut output, &auto_keys);
    let time = now.elapsed();

    let max_err = get_glwe_max_err(&glwe_sk, &output, &correct_val_list);
    let l2_err = get_glwe_l2_err(&glwe_sk, &output, &correct_val_list);

    println!("{} ms, err: (Max) {:.2} bit (l2) {:.2} bits", time.as_micros() as f64 / 1000f64, (max_err as f64).log2(), l2_err.log2());
}
