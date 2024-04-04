use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hom_trace::{convert_lwes_to_glwe_by_trace_with_mod_switch, gen_all_auto_keys};
use tfhe::core_crypto::prelude::*;

struct Param<Scalar: UnsignedInteger> {
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
    criterion_benchmark_trace_with_mod_switch,
);
criterion_main!(benches);

fn criterion_benchmark_trace_with_mod_switch(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwes_to_glwe_conversion");

    let shortint_message_2_carry_2_level_2 = Param {
        polynomial_size: PolynomialSize(2048),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        decomp_base_log: DecompositionBaseLog(15),
        decomp_level: DecompositionLevelCount(2),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 59,
    };
    let shortint_message_2_carry_2_level_4 = Param {
        polynomial_size: PolynomialSize(2048),
        glwe_dimension: GlweDimension(1),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        decomp_base_log: DecompositionBaseLog(10),
        decomp_level: DecompositionLevelCount(4),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        log_scale: 59,
    };

    let param_list = [
        (shortint_message_2_carry_2_level_2, "shortint_message_2_carry_2, auto level 2"),
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
        for n in [2, 8, 32] {
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
