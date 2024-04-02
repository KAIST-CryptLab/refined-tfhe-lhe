use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::collections::HashMap;
use aligned_vec::ABox;
use tfhe::core_crypto::{
    fft_impl::fft64::c64, prelude::*
};
use hom_trace::{
    utils::convert_lwe_to_glwe_const,
    mod_switch::*,
    automorphism::{
        AutomorphKey,
        trace,
        gen_all_auto_keys,
    },
};

struct Param<Scalar: UnsignedTorus> {
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: StandardDev,
    decomp_base_log: DecompositionBaseLog,
    decomp_level: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
    log_scale: usize,
}

criterion_group!(
    benches,
    criterion_benchmark_a,
    criterion_benchmark_b,
    criterion_benchmark_pksk,
);
criterion_main!(benches);

fn criterion_benchmark_a(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwe_to_glwe_conversion");

    let shortint_message_2_carry_2 = Param {
        polynomial_size: PolynomialSize(2048),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        decomp_base_log: DecompositionBaseLog(15),
        decomp_level: DecompositionLevelCount(2),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 59,
    };

    let param_list = [
        (shortint_message_2_carry_2, "shortint_message_2_carry_2")
    ];

    for (param, id) in param_list.iter() {
        let polynomial_size = param.polynomial_size;
        let glwe_dimension = param.glwe_dimension;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let auto_base_log = param.decomp_base_log;
        let auto_level = param.decomp_level;
        let ciphertext_modulus = param.ciphertext_modulus;

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let glwe_size = glwe_dimension.to_glwe_size();
        let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
        let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        // Set input LWE ciphertext
        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            Plaintext(0),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut glwe = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "trace_with_mod_switch_a",
                id,
            ),
            |b| b.iter(
                || lwe_to_glwe_by_trace_with_mod_switch_a(
                    black_box(&lwe),
                    black_box(&mut glwe),
                    black_box(&auto_keys),
                )
            ),
        );

        // Error
        let mut pt = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);

        let log_scale = param.log_scale;
        let mut max_err = 0;
        for val in pt.as_ref().iter() {
            let rounding = val & (1 << (log_scale - 1));
            let decoded = val.wrapping_add(rounding) >> log_scale;
            assert_eq!(decoded, 0);

            let val = *val;
            let abs_err = {
                let d0 = 0.wrapping_sub(val);
                let d1 = val.wrapping_sub(0);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        let max_err = (max_err as f64).log2();

        println!(
            "N: {}, k: {}, l_auto: {}, B_auto: 2^{}, err: {:.2} bits",
            polynomial_size.0, glwe_dimension.0, auto_level.0, auto_base_log.0, max_err
        );
    }
}

fn criterion_benchmark_b(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwe_to_glwe_conversion");

    let boolean_default = Param {
        polynomial_size: PolynomialSize(512),
        glwe_dimension: GlweDimension(2),
        glwe_modular_std_dev: StandardDev(0.00000004990272175010415),
        decomp_base_log: DecompositionBaseLog(5),
        decomp_level: DecompositionLevelCount(4),
        ciphertext_modulus: CiphertextModulus::<u32>::new_native(),
        log_scale: 30,
    };
    let tfhe_lib_param = Param {
        polynomial_size: PolynomialSize(1024),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000002980232238769531),
        decomp_base_log: DecompositionBaseLog(5),
        decomp_level: DecompositionLevelCount(4),
        ciphertext_modulus: CiphertextModulus::<u32>::new_native(),
        log_scale: 30,
    };

    let param_list = [
        (boolean_default, "boolean default"),
        (tfhe_lib_param, "tfhe_lib_param"),
    ];

    for (param, id) in param_list.iter() {
        let polynomial_size = param.polynomial_size;
        let glwe_dimension = param.glwe_dimension;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let auto_base_log = param.decomp_base_log;
        let auto_level = param.decomp_level;
        let ciphertext_modulus = param.ciphertext_modulus;

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let glwe_size = glwe_dimension.to_glwe_size();
        let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
        let lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        // Set input LWE ciphertext
        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            Plaintext(0),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut glwe = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "trace_with_mod_switch_b",
                id,
            ),
            |b| b.iter(
                || lwe_to_glwe_by_trace_with_mod_switch_b(
                    black_box(&lwe),
                    black_box(&mut glwe),
                    black_box(&auto_keys),
                )
            ),
        );

        // Error
        let mut pt = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);

        let log_scale = param.log_scale;
        let mut max_err = 0;
        for val in pt.as_ref().iter() {
            let rounding = val & (1 << (log_scale - 1));
            let decoded = val.wrapping_add(rounding) >> log_scale;
            assert_eq!(decoded, 0);

            let val = *val;
            let abs_err = {
                let d0 = 0.wrapping_sub(val);
                let d1 = val.wrapping_sub(0);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        let max_err = (max_err as f64).log2();

        println!(
            "N: {}, k: {}, l_auto: {}, B_auto: 2^{}, err: {:.2} bits",
            polynomial_size.0, glwe_dimension.0, auto_level.0, auto_base_log.0, max_err
        );
    }
}

fn criterion_benchmark_pksk(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwe_to_glwe_conversion");

    let shortint_message_2_carry_2 = Param {
        polynomial_size: PolynomialSize(2048),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        decomp_base_log: DecompositionBaseLog(23),
        decomp_level: DecompositionLevelCount(1),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 59,
    };

    let param_list = [
        (shortint_message_2_carry_2, "shortint_message_2_carry_2")
    ];

    for (param, id) in param_list.iter() {
        let polynomial_size = param.polynomial_size;
        let glwe_dimension = param.glwe_dimension;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let pksk_base_log = param.decomp_base_log;
        let pksk_level = param.decomp_level;
        let ciphertext_modulus = param.ciphertext_modulus;

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let glwe_size = glwe_dimension.to_glwe_size();
        let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
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

        // Set input LWE ciphertext
        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            Plaintext(0),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut glwe = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "pksk",
                id,
            ),
            |b| b.iter(
                || keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                    black_box(&pksk),
                    black_box(&lwe),
                    black_box(&mut glwe),
                )
            ),
        );

        // Error
        let mut pt = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);

        let log_scale = param.log_scale;
        let mut max_err = 0;
        for val in pt.as_ref().iter() {
            let rounding = val & (1 << (log_scale - 1));
            let decoded = val.wrapping_add(rounding) >> log_scale;
            assert_eq!(decoded, 0);

            let val = *val;
            let abs_err = {
                let d0 = 0.wrapping_sub(val);
                let d1 = val.wrapping_sub(0);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        let max_err = (max_err as f64).log2();

        println!(
            "N: {}, k: {}, l_pksk: {}, B_pksk: 2^{}, err: {:.2} bits",
            polynomial_size.0, glwe_dimension.0, pksk_level.0, pksk_base_log.0, max_err
        );
    }
}

fn lwe_to_glwe_by_trace_with_mod_switch_a<Scalar, InputCont, OutputCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    let glwe_size = output.glwe_size();
    let polynomial_size = output.polynomial_size();
    let ciphertext_modulus = input.ciphertext_modulus();

    let log_polynomial_size = polynomial_size.0.ilog2() as usize;
    let log_small_q = Scalar::BITS as usize - log_polynomial_size;
    let small_ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_small_q).unwrap();

    // LWEtoGLWEConst
    convert_lwe_to_glwe_const(input, output);

    // ModDown
    let mut buf_mod_down = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, small_ciphertext_modulus);
    glwe_ciphertext_mod_down_from_native_to_non_native_power_of_two(&output, &mut buf_mod_down);

    // ModUp
    let mut buf_mod_up = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    glwe_ciphertext_mod_up_from_non_native_power_of_two_to_native(&buf_mod_down, &mut buf_mod_up);

    // Trace
    let buf = trace(buf_mod_up.as_view(), auto_keys);
    output.as_mut().clone_from_slice(buf.as_ref());
}

fn lwe_to_glwe_by_trace_with_mod_switch_b<Scalar, InputCont, OutputCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
) where
    Scalar: UnsignedTorus + CastInto<u64> + CastFrom<u64>,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    let glwe_size = output.glwe_size();
    let polynomial_size = output.polynomial_size();

    let log_polynomial_size = polynomial_size.0.ilog2() as usize;
    let log_large_q = Scalar::BITS as usize + log_polynomial_size;
    assert!(log_large_q <= 64);
    let large_ciphertext_modulus = CiphertextModulus::<u64>::try_new_power_of_2(log_large_q).unwrap();

    // LWEtoGLWEConst
    convert_lwe_to_glwe_const(input, output);

    // ModUp
    let mut buf_mod_up = GlweCiphertext::new(0u64, glwe_size, polynomial_size, large_ciphertext_modulus);
    glwe_ciphertext_mod_up_from_native_to_non_native_power_of_two(output, &mut buf_mod_up);

    // Trace
    let buf = trace(buf_mod_up.as_view(), auto_keys);

    // ModDown
    glwe_ciphertext_mod_down_from_non_native_power_of_two_to_native(&buf, output);
}
