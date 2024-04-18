use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hom_trace::{gen_all_auto_keys, gen_all_fast_auto_keys, glwe_conv::*};
use tfhe::core_crypto::prelude::*;

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets =
        criterion_benchmark_fast_trace_with_mod_switch,
        criterion_benchmark_trace_with_mod_switch,
        criterion_benchmark_small_pksk,
        criterion_benchmark_large_pksk,
);
criterion_main!(benches);

#[allow(unused)]
struct Param<Scalar: UnsignedInteger> {
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: StandardDev,
    decomp_base_log: DecompositionBaseLog,
    decomp_level: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
    log_scale: usize,
}

#[allow(unused)]
struct ParamWithLWEKS<Scalar: UnsignedInteger> {
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: StandardDev,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: StandardDev,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    pksk_base_log: DecompositionBaseLog,
    pksk_level: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
    log_scale: usize,
}

#[allow(unused)]
fn criterion_benchmark_trace_with_mod_switch(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwes_to_glwe_conversion");

    let shortint_message_2_carry_2_level_4 = Param {
        polynomial_size: PolynomialSize(2048),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        decomp_base_log: DecompositionBaseLog(10),
        decomp_level: DecompositionLevelCount(4),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 59,
    };

    let shortint_message_3_carry_3_level_4 = Param {
        polynomial_size: PolynomialSize(8192),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        decomp_base_log: DecompositionBaseLog(10),
        decomp_level: DecompositionLevelCount(4),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 57,
    };

    let shortint_message_3_carry_3_level_5 = Param {
        polynomial_size: PolynomialSize(8192),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        decomp_base_log: DecompositionBaseLog(10),
        decomp_level: DecompositionLevelCount(5),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 57,
    };

    let shortint_message_4_carry_4_level_6 = Param {
        polynomial_size: PolynomialSize(32768),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        decomp_base_log: DecompositionBaseLog(8),
        decomp_level: DecompositionLevelCount(6),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 55,
    };

    let param_list = [
        (shortint_message_2_carry_2_level_4, "shortint_message_2_carry_2, auto level 4"),
        (shortint_message_3_carry_3_level_4, "shortint_message_3_carry_3, auto level 4"),
        (shortint_message_3_carry_3_level_5, "shortint_message_3_carry_3, auto level 5"),
        (shortint_message_4_carry_4_level_6, "shortint_message_4_carry_4, auto level 6"),
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

        let lwe_dimension = lwe_sk.lwe_dimension();
        let lwe_size = lwe_dimension.to_lwe_size();

        // Benchmark
        for n in [16] {
            let parameter_string = format!("{id}, n = {n}");

            let pt = PlaintextList::new(0u64, PlaintextCount(n));
            let mut input_lwes = LweCiphertextList::new(0u64, lwe_size, LweCiphertextCount(n), ciphertext_modulus);
            encrypt_lwe_ciphertext_list(&lwe_sk, &mut input_lwes, &pt, glwe_modular_std_dev, &mut encryption_generator);
            let mut output_glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

            group.bench_with_input(
                BenchmarkId::new("trace_with_mod_switch", parameter_string),
                &n,
                |b, _| b.iter(
                    || convert_lwes_to_glwe_by_trace_with_mod_switch(
                        black_box(&input_lwes),
                        black_box(&mut output_glwe),
                        black_box(&auto_keys),
                    )
                ),
            );

            // Error
            let mut pt = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
            decrypt_glwe_ciphertext(&glwe_sk, &output_glwe, &mut pt);

            let log_scale = param.log_scale;
            let mut max_err = 0;
            for val in pt.iter() {
                let val = *val.0;
                let rounding = val & (1 << (log_scale - 1));
                let decoded = val.wrapping_add(rounding) >> log_scale;
                assert_eq!(decoded, 0);

                let abs_err = std::cmp::min(val, val.wrapping_neg());
                max_err = std::cmp::max(max_err, abs_err);
            }
            let max_err = (max_err as f64).log2();

            println!(
                "N: {}, k: {}, l_auto: {}, B_auto: 2^{}, err: {:.2} bits",
                polynomial_size.0, glwe_dimension.0, auto_level.0, auto_base_log.0, max_err
            );
        }
    }
}

#[allow(unused)]
fn criterion_benchmark_fast_trace_with_mod_switch(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwes_to_glwe_conversion");

    let shortint_message_2_carry_2_level_4 = Param {
        polynomial_size: PolynomialSize(2048),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        decomp_base_log: DecompositionBaseLog(12),
        decomp_level: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 59,
    };

    let param_list = [
        (shortint_message_2_carry_2_level_4, "shortint_message_2_carry_2, auto level 4"),
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

        let fast_auto_keys = gen_all_fast_auto_keys(
            auto_base_log,
            auto_level,
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let lwe_dimension = lwe_sk.lwe_dimension();
        let lwe_size = lwe_dimension.to_lwe_size();

        // Benchmark
        for n in [16] {
            let parameter_string = format!("{id}, n = {n}");

            let pt = PlaintextList::new(0u64, PlaintextCount(n));
            let mut input_lwes = LweCiphertextList::new(0u64, lwe_size, LweCiphertextCount(n), ciphertext_modulus);
            encrypt_lwe_ciphertext_list(&lwe_sk, &mut input_lwes, &pt, glwe_modular_std_dev, &mut encryption_generator);
            let mut output_glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

            group.bench_with_input(
                BenchmarkId::new("fast_trace_with_mod_switch", parameter_string),
                &n,
                |b, _| b.iter(
                    || convert_lwes_to_glwe_by_fast_trace_with_mod_switch(
                        black_box(&input_lwes),
                        black_box(&mut output_glwe),
                        black_box(&fast_auto_keys),
                    )
                ),
            );

            // Error
            let mut pt = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
            decrypt_glwe_ciphertext(&glwe_sk, &output_glwe, &mut pt);

            let log_scale = param.log_scale;
            let mut max_err = 0;
            for val in pt.iter() {
                let val = *val.0;
                let rounding = val & (1 << (log_scale - 1));
                let decoded = val.wrapping_add(rounding) >> log_scale;
                assert_eq!(decoded, 0);

                let abs_err = std::cmp::min(val, val.wrapping_neg());
                max_err = std::cmp::max(max_err, abs_err);
            }
            let max_err = (max_err as f64).log2();

            println!(
                "N: {}, k: {}, l_auto: {}, B_auto: 2^{}, err: {:.2} bits",
                polynomial_size.0, glwe_dimension.0, auto_level.0, auto_base_log.0, max_err
            );
        }
    }
}

#[allow(unused)]
fn criterion_benchmark_large_pksk(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwe_to_glwe_conversion");

    let shortint_message_2_carry_2_level_1 = Param {
        polynomial_size: PolynomialSize(2048),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        decomp_base_log: DecompositionBaseLog(24),
        decomp_level: DecompositionLevelCount(1),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 59,
    };

    let shortint_message_3_carry_3_level_1 = Param {
        polynomial_size: PolynomialSize(8192),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        decomp_base_log: DecompositionBaseLog(29),
        decomp_level: DecompositionLevelCount(1),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 57,
    };

    let shortint_message_4_carry_4_level_1 = Param {
        polynomial_size: PolynomialSize(32768),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        decomp_base_log: DecompositionBaseLog(29),
        decomp_level: DecompositionLevelCount(1),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 55,
    };


    let param_list = [
        (shortint_message_2_carry_2_level_1, "shortint_message_2_carry_2, pksk level 1"),
        (shortint_message_3_carry_3_level_1, "shortint_message_3_carry_3, pksk level 1"),
        (shortint_message_4_carry_4_level_1, "shortint_message_4_carry_4, pksk level 1"),
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

        for n in [16] {
            let parameter_string = format!("{id}, n = {n}");

            // Set input LWE ciphertext
            let mut lwe_list = LweCiphertextList::new(
                0,
                lwe_sk.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(n),
                ciphertext_modulus,
            );
            encrypt_lwe_ciphertext_list(
                &lwe_sk,
                &mut lwe_list,
                &PlaintextList::new(0, PlaintextCount(n)),
                glwe_modular_std_dev,
                &mut encryption_generator,
            );
            let mut glwe = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

            // Bench
            group.bench_function(
                BenchmarkId::new(
                    "large_pksk",
                    parameter_string,
                ),
                |b| b.iter(
                    || keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                        black_box(&pksk),
                        black_box(&lwe_list),
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
}

#[allow(unused)]
fn criterion_benchmark_small_pksk(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwe_to_glwe_conversion");

    let shortint_message_2_carry_2_level_1 = ParamWithLWEKS {
        lwe_dimension: LweDimension(742),
        lwe_modular_std_dev: StandardDev(0.000007069849454709433),
        polynomial_size: PolynomialSize(2048),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        pksk_base_log: DecompositionBaseLog(24),
        pksk_level: DecompositionLevelCount(1),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 59,
    };

    let shortint_message_3_carry_3_level_1 = ParamWithLWEKS {
        lwe_dimension: LweDimension(864),
        lwe_modular_std_dev: StandardDev(0.000000757998020150446),
        polynomial_size: PolynomialSize(8192),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        pksk_base_log: DecompositionBaseLog(29),
        pksk_level: DecompositionLevelCount(1),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 57,
    };

    let shortint_message_4_carry_4_level_1 = ParamWithLWEKS {
        lwe_dimension: LweDimension(996),
        lwe_modular_std_dev: StandardDev(0.00000006767666038309478),
        polynomial_size: PolynomialSize(32768),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        pksk_base_log: DecompositionBaseLog(29),
        pksk_level: DecompositionLevelCount(1),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 55,
    };


    let param_list = [
        (shortint_message_2_carry_2_level_1, "shortint_message_2_carry_2, pksk level 1"),
        (shortint_message_3_carry_3_level_1, "shortint_message_3_carry_3, pksk level 1"),
        (shortint_message_4_carry_4_level_1, "shortint_message_4_carry_4, pksk level 1"),
    ];

    for (param, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension;
        let lwe_modular_std_dev = param.lwe_modular_std_dev;
        let polynomial_size = param.polynomial_size;
        let glwe_dimension = param.glwe_dimension;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let ks_base_log = param.ks_base_log;
        let ks_level = param.ks_level;
        let pksk_base_log = param.pksk_base_log;
        let pksk_level = param.pksk_level;
        let ciphertext_modulus = param.ciphertext_modulus;

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
        let glwe_size = glwe_dimension.to_glwe_size();
        let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
        let large_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &large_lwe_sk,
            &lwe_sk,
            ks_base_log,
            ks_level,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
            &lwe_sk,
            &glwe_sk,
            pksk_base_log,
            pksk_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        for n in [16] {
            let parameter_string = format!("{id}, n = {n}");

            let mut lwe_list = LweCiphertextList::new(
                0,
                large_lwe_sk.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(n),
                ciphertext_modulus,
            );
            encrypt_lwe_ciphertext_list(
                &large_lwe_sk,
                &mut lwe_list,
                &PlaintextList::new(0, PlaintextCount(n)),
                glwe_modular_std_dev,
                &mut encryption_generator,
            );
            let mut lwe_list_ks = LweCiphertextList::new(
                0,
                lwe_dimension.to_lwe_size(),
                LweCiphertextCount(n),
                ciphertext_modulus,
            );
            let mut glwe = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

            // Bench
            group.bench_function(
                BenchmarkId::new(
                    "small_pksk",
                    id,
                ),
                |b| b.iter(
                    || {
                        for (lwe, mut lwe_ks) in lwe_list.iter().zip(lwe_list_ks.iter_mut()) {
                            keyswitch_lwe_ciphertext(
                                black_box(&ksk),
                                black_box(&lwe),
                                black_box(&mut lwe_ks),
                            );
                        }
                        keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                        black_box(&pksk),
                        black_box(&lwe_list_ks),
                        black_box(&mut glwe),
                        );
                    }
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
                "n: {}, N: {}, k: {}, l_pksk: {}, B_pksk: 2^{}, err: {:.2} bits",
                lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pksk_level.0, pksk_base_log.0, max_err
            );
        }
    }
}
