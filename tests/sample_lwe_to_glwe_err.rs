use hom_trace::{convert_lwe_to_glwe_const, gen_all_auto_keys, get_glwe_max_err, lwe_preprocessing_assign, trace_assign, FftType};
use rand::Rng;
use tfhe::core_crypto::prelude::*;

type Scalar = u64;
const NUM_REPEAT: usize = 1000;

fn main() {
    /* LWE to GLWE by trace with preprocessing */
    // -------- wopbs_message_2_carry_2 -------- //
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let auto_base_log = DecompositionBaseLog(7);
    let auto_level = DecompositionLevelCount(6);
    let modulus_sup = 16;
    let log_scale = 59;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    // -------- wopbs_message_3_carry_3 -------- //
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let auto_base_log = DecompositionBaseLog(5);
    let auto_level = DecompositionLevelCount(11);
    let modulus_sup = 16;
    let log_scale = 59;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let auto_base_log = DecompositionBaseLog(3);
    let auto_level = DecompositionLevelCount(18);
    let modulus_sup = 16;
    let log_scale = 59;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    // -------- param_message_2_carry_2 -------- //
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let auto_base_log = DecompositionBaseLog(12);
    let auto_level = DecompositionLevelCount(3);
    let modulus_sup = 16;
    let log_scale = 59;
    let fft_type = FftType::Vanilla;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let auto_base_log = DecompositionBaseLog(13);
    let auto_level = DecompositionLevelCount(3);
    let modulus_sup = 16;
    let log_scale = 59;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let auto_base_log = DecompositionBaseLog(10);
    let auto_level = DecompositionLevelCount(4);
    let modulus_sup = 16;
    let log_scale = 59;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    // -------- param_message_3_carry_3 -------- //
    let polynomial_size = PolynomialSize(8192);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let auto_base_log = DecompositionBaseLog(20);
    let auto_level = DecompositionLevelCount(2);
    let modulus_sup = 64;
    let log_scale = 57;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    let polynomial_size = PolynomialSize(8192);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(3);
    let modulus_sup = 64;
    let log_scale = 57;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    let polynomial_size = PolynomialSize(8192);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let auto_base_log = DecompositionBaseLog(12);
    let auto_level = DecompositionLevelCount(4);
    let modulus_sup = 64;
    let log_scale = 57;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    // -------- message_4_carry_4 -------- //
    let polynomial_size = PolynomialSize(32768);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(3);
    let modulus_sup = 256;
    let log_scale = 55;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    let polynomial_size = PolynomialSize(32768);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let auto_base_log = DecompositionBaseLog(13);
    let auto_level = DecompositionLevelCount(4);
    let modulus_sup = 256;
    let log_scale = 55;
    let fft_type = FftType::Split16;

    sample_lwe_to_glwe_by_trace_with_preprocessing(polynomial_size, glwe_dimension, glwe_modular_std_dev, auto_base_log, auto_level, modulus_sup, log_scale, fft_type, NUM_REPEAT);

    /* LWE to GLWE by packing keyswitching */
    // -------- param_message_2_carry_2 -------- //
    let lwe_dimension = LweDimension(742);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pksk_base_log = DecompositionBaseLog(24);
    let pksk_level = DecompositionLevelCount(1);
    let ks_base_log = DecompositionBaseLog(3);
    let ks_level = DecompositionLevelCount(5);
    let modulus_sup = 16;
    let log_scale = 59;

    sample_lwe_to_glwe_by_large_pksk(polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, modulus_sup, log_scale, NUM_REPEAT);
    sample_lwe_to_glwe_by_small_pksk(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, ks_base_log, ks_level, modulus_sup, log_scale, NUM_REPEAT);

    // -------- param_message_3_carry_3 -------- //
    let lwe_dimension = LweDimension(864);
    let lwe_modular_std_dev = StandardDev(0.000000757998020150446);
    let polynomial_size = PolynomialSize(8192);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let pksk_base_log = DecompositionBaseLog(29);
    let pksk_level = DecompositionLevelCount(1);
    let ks_base_log = DecompositionBaseLog(3);
    let ks_level = DecompositionLevelCount(6);
    let modulus_sup = 64;
    let log_scale = 57;

    sample_lwe_to_glwe_by_large_pksk(polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, modulus_sup, log_scale, NUM_REPEAT);
    sample_lwe_to_glwe_by_small_pksk(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, ks_base_log, ks_level, modulus_sup, log_scale, NUM_REPEAT);

    // -------- param_message_4_carry_4 -------- //
    let lwe_dimension = LweDimension(996);
    let lwe_modular_std_dev = StandardDev(0.00000006767666038309478);
    let polynomial_size = PolynomialSize(32768);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let pksk_base_log = DecompositionBaseLog(29);
    let pksk_level = DecompositionLevelCount(1);
    let ks_base_log = DecompositionBaseLog(3);
    let ks_level = DecompositionLevelCount(7);
    let modulus_sup = 256;
    let log_scale = 55;

    sample_lwe_to_glwe_by_large_pksk(polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, modulus_sup, log_scale, NUM_REPEAT);
    sample_lwe_to_glwe_by_small_pksk(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pksk_base_log, pksk_level, ks_base_log, ks_level, modulus_sup, log_scale, NUM_REPEAT);
}

#[allow(unused)]
fn sample_lwe_to_glwe_by_trace_with_preprocessing(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    modulus_sup: usize,
    log_scale: usize,
    fft_type: FftType,
    num_repeat: usize,
) {
    println!("lwe to glwe by trace with preprocessing");
    println!("N: {}, k: {}, B_auto: 2^{}, l_auto: {}, fft type: {:?}",
        polynomial_size.0, glwe_dimension.0, auto_base_log.0, auto_level.0, fft_type
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

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let mut rng = rand::thread_rng();

    let mut err_list: Vec<Scalar> = vec![];

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..modulus_sup) as Scalar;
        let pt = Plaintext(msg << log_scale);

        let mut input = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            pt,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        lwe_preprocessing_assign(&mut input, polynomial_size);
        convert_lwe_to_glwe_const(&input, &mut output);
        trace_assign(&mut output, &auto_keys);

        let max_err = get_glwe_max_err(
            &glwe_sk,
            &output,
            &PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                if i == 0 {msg << log_scale} else {Scalar::ZERO}
            }).collect::<Vec<Scalar>>())
        );

        err_list.push(max_err);
    }

    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("LWEtoGLWE err: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}

#[allow(unused)]
fn sample_lwe_to_glwe_by_large_pksk(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    pksk_base_log: DecompositionBaseLog,
    pksk_level: DecompositionLevelCount,
    modulus_sup: usize,
    log_scale: usize,
    num_repeat: usize,
) {
    println!("lwe to glwe by large pksk");
    println!("N: {}, k: {}, B_pksk: 2^{}, l_pksk: {}",
        polynomial_size.0, glwe_dimension.0, pksk_base_log.0, pksk_level.0
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

    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &lwe_sk,
        &glwe_sk,
        pksk_base_log,
        pksk_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut rng = rand::thread_rng();

    let mut err_list: Vec<Scalar> = vec![];

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..modulus_sup) as Scalar;
        let pt = Plaintext(msg << log_scale);

        let input = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            pt,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            &pksk,
            &input,
            &mut output,
        );

        let max_err = get_glwe_max_err(
            &glwe_sk,
            &output,
            &PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                if i == 0 {msg << log_scale} else {Scalar::ZERO}
            }).collect::<Vec<Scalar>>())
        );

        err_list.push(max_err);
    }

    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("LWEtoGLWE err: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}

#[allow(unused)]
fn sample_lwe_to_glwe_by_small_pksk(
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: impl DispersionParameter,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    pksk_base_log: DecompositionBaseLog,
    pksk_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    modulus_sup: usize,
    log_scale: usize,
    num_repeat: usize,
) {
    println!("lwe to glwe by small pksk");
    println!("n: {}, N: {}, k: {}, B_pksk: 2^{}, l_pksk: {}, B_ks: 2^{}, l_ks: {}",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pksk_base_log.0, pksk_level.0, ks_base_log.0, ks_level.0
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

    let lwe_sk_after_ks = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);

    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &lwe_sk,
        &lwe_sk_after_ks,
        ks_base_log,
        ks_level,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &lwe_sk_after_ks,
        &glwe_sk,
        pksk_base_log,
        pksk_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut rng = rand::thread_rng();

    let mut err_list: Vec<Scalar> = vec![];

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..modulus_sup) as Scalar;
        let pt = Plaintext(msg << log_scale);

        let input = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            pt,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut input_ks = LweCiphertext::new(Scalar::ZERO, lwe_dimension.to_lwe_size(), ciphertext_modulus);
        let mut output = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        keyswitch_lwe_ciphertext(
            &ksk,
            &input,
            &mut input_ks,
        );

        keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            &pksk,
            &input_ks,
            &mut output,
        );

        let max_err = get_glwe_max_err(
            &glwe_sk,
            &output,
            &PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                if i == 0 {msg << log_scale} else {Scalar::ZERO}
            }).collect::<Vec<Scalar>>())
        );

        err_list.push(max_err);
    }

    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;

    println!("LWEtoGLWE err: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}
