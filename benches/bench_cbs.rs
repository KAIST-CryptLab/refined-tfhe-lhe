use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;
use hom_trace::{convert_lwe_to_glwe_const, gen_all_auto_keys, generate_scheme_switching_key, get_max_err_ggsw_bit, keygen_pbs, lwe_msb_bit_to_lev, lwe_preprocessing, switch_scheme, trace_assign, FftType};

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets =
        criterion_benchmark_cbs,
        criterion_benchmark_faster_and_smaller_cbs,
);
criterion_main!(benches);

#[allow(unused)]
struct CBSParam<Scalar: UnsignedInteger> {
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: StandardDev,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: StandardDev,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    pfks_base_log: DecompositionBaseLog,
    pfks_level: DecompositionLevelCount,
    cbs_base_log: DecompositionBaseLog,
    cbs_level: DecompositionLevelCount,
    log_pbs_many: usize,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
}

#[allow(unused)]
struct FasterAndSmallerCBSParam<Scalar: UnsignedInteger> {
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: StandardDev,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: StandardDev,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    fft_type: FftType,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    cbs_base_log: DecompositionBaseLog,
    cbs_level: DecompositionLevelCount,
    log_pbs_many: usize,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
}

#[allow(unused)]
fn criterion_benchmark_cbs(c: &mut Criterion) {
    let mut group = c.benchmark_group("cbs");

    let wopbs_message_2_carry_2_ks_pbs = CBSParam {
        lwe_dimension: LweDimension(769),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(6),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(15),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(5),
        log_pbs_many: 0,
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let wopbs_message_3_carry_3_ks_pbs = CBSParam {
        lwe_dimension: LweDimension(873),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000006428797112843789),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(10),
        pfks_level: DecompositionLevelCount(4),
        pfks_base_log: DecompositionBaseLog(9),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(6),
        log_pbs_many: 0,
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let wopbs_message_4_carry_4_ks_pbs = CBSParam {
        lwe_dimension: LweDimension(953),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000001486733969411098),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(11),
        pfks_level: DecompositionLevelCount(4),
        pfks_base_log: DecompositionBaseLog(9),
        cbs_level: DecompositionLevelCount(6),
        cbs_base_log: DecompositionBaseLog(4),
        log_pbs_many: 0,
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let param_list = [
        (wopbs_message_2_carry_2_ks_pbs, "wopbs_message_2_carry_2"),
        (wopbs_message_3_carry_3_ks_pbs, "wopbs_message_3_carry_3"),
        (wopbs_message_4_carry_4_ks_pbs, "wopbs_message_4_carry_4"),
    ];

    for (param, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension;
        let lwe_modular_std_dev = param.lwe_modular_std_dev;
        let glwe_dimension = param.glwe_dimension;
        let polynomial_size = param.polynomial_size;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let pbs_base_log = param.pbs_base_log;
        let pbs_level = param.pbs_level;
        let ks_base_log = param.ks_base_log;
        let ks_level = param.ks_level;
        let pfks_base_log = param.pfks_base_log;
        let pfks_level = param.pfks_level;
        let cbs_base_log = param.cbs_base_log;
        let cbs_level = param.cbs_level;
        let log_pbs_many = param.log_pbs_many;
        let ciphertext_modulus = param.ciphertext_modulus;

        let glwe_size = glwe_dimension.to_glwe_size();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_sk,
            glwe_sk,
            lwe_sk_after_ks,
            bsk,
            ksk,
        ) = keygen_pbs(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            &mut secret_generator,
            &mut encryption_generator,
        );
        let bsk = bsk.as_view();

        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &lwe_sk,
            &lwe_sk_after_ks,
            ks_base_log,
            ks_level,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let pfpksk_list = allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &lwe_sk,
            &glwe_sk,
            pfks_base_log,
            pfks_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        // Set input LWE ciphertext
        let msg = 1;
        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            Plaintext(msg << 63),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut lwe_ks = LweCiphertext::new(0u64, lwe_sk_after_ks.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        let mut lev = LweCiphertextList::new(0u64, lwe_sk.lwe_dimension().to_lwe_size(), LweCiphertextCount(cbs_level.0), ciphertext_modulus);
        let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);
        let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "circuit bootstrapping with PBSmanyLUT",
                format!("{id}, LWE to Lev"),
            ),
            |b| b.iter(|| {
                keyswitch_lwe_ciphertext(
                    black_box(&ksk),
                    black_box(&lwe),
                    black_box(&mut lwe_ks),
                );
                lwe_msb_bit_to_lev(
                    black_box(&lwe_ks),
                    black_box(&mut lev),
                    black_box(bsk),
                    black_box(cbs_base_log),
                    black_box(cbs_level),
                    black_box(LutCountLog(log_pbs_many)),
                );
            })
        );

        group.bench_function(
            BenchmarkId::new(
                "circuit bootstrapping with PBSmanyLUT",
                format!("{id}, Lev to GGSW"),
            ),
            |b| b.iter(|| {
                for (lwe, mut ggsw_level_matrix) in lev.iter().zip(ggsw.iter_mut()) {
                    for (pfpksk, mut glwe) in pfpksk_list.iter()
                        .zip(ggsw_level_matrix.as_mut_glwe_list().iter_mut())
                    {
                        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                            &pfpksk,
                            &mut glwe,
                            &lwe,
                        );
                    }
                }
                convert_standard_ggsw_ciphertext_to_fourier(
                    &ggsw,
                    &mut fourier_ggsw,
                );
            })
        );

        let max_err = get_max_err_ggsw_bit(
            &glwe_sk,
            ggsw.as_view(),
            msg,
        );

        println!(
            "n: {}, N: {}, k: {}, l_pbs: {}, B_pbs: 2^{}, l_cbs: {}, B_cbs: 2^{}
l_pfpks: {}, B_pfpks: 2^{}, log_pbs_many: {},
err: {:.2} bits",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, cbs_level.0, cbs_base_log.0,
            pfks_level.0, pfks_base_log.0, log_pbs_many,
            (max_err as f64).log2(),
        );
    }
}

#[allow(unused)]
fn criterion_benchmark_faster_and_smaller_cbs(c: &mut Criterion) {
    let mut group = c.benchmark_group("faster and smaller cbs");

    let wopbs_message_2_carry_2_ks_pbs = FasterAndSmallerCBSParam {
        lwe_dimension: LweDimension(769),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(6),
        auto_base_log: DecompositionBaseLog(7),
        auto_level: DecompositionLevelCount(6),
        fft_type: FftType::Split32,
        ss_base_log: DecompositionBaseLog(10),
        ss_level: DecompositionLevelCount(4),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(5),
        log_pbs_many: 2,
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let wopbs_message_3_carry_3_ks_pbs = FasterAndSmallerCBSParam {
        lwe_dimension: LweDimension(873),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000006428797112843789),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(10),
        auto_base_log: DecompositionBaseLog(5),
        auto_level: DecompositionLevelCount(11),
        fft_type: FftType::Split32,
        ss_base_log: DecompositionBaseLog(10),
        ss_level: DecompositionLevelCount(4),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(6),
        log_pbs_many: 2,
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let wopbs_message_4_carry_4_ks_pbs = FasterAndSmallerCBSParam {
        lwe_dimension: LweDimension(953),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000001486733969411098),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(11),
        auto_base_log: DecompositionBaseLog(5),
        auto_level: DecompositionLevelCount(11),
        fft_type: FftType::Split32,
        ss_base_log: DecompositionBaseLog(10),
        ss_level: DecompositionLevelCount(4),
        cbs_level: DecompositionLevelCount(6),
        cbs_base_log: DecompositionBaseLog(4),
        log_pbs_many: 3,
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let param_list = [
        (wopbs_message_2_carry_2_ks_pbs, "wopbs_message_2_carry_2"),
        (wopbs_message_3_carry_3_ks_pbs, "wopbs_message_3_carry_3"),
        (wopbs_message_4_carry_4_ks_pbs, "wopbs_message_4_carry_4"),
    ];

    for (param, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension;
        let lwe_modular_std_dev = param.lwe_modular_std_dev;
        let glwe_dimension = param.glwe_dimension;
        let polynomial_size = param.polynomial_size;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let pbs_base_log = param.pbs_base_log;
        let pbs_level = param.pbs_level;
        let ks_base_log = param.ks_base_log;
        let ks_level = param.ks_level;
        let auto_base_log = param.auto_base_log;
        let auto_level = param.auto_level;
        let fft_type = param.fft_type;
        let ss_base_log = param.ss_base_log;
        let ss_level = param.ss_level;
        let cbs_base_log = param.cbs_base_log;
        let cbs_level = param.cbs_level;
        let log_pbs_many = param.log_pbs_many;
        let ciphertext_modulus = param.ciphertext_modulus;

        let glwe_size = glwe_dimension.to_glwe_size();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_sk,
            glwe_sk,
            lwe_sk_after_ks,
            bsk,
            ksk,
        ) = keygen_pbs(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            &mut secret_generator,
            &mut encryption_generator,
        );
        let bsk = bsk.as_view();

        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &lwe_sk,
            &lwe_sk_after_ks,
            ks_base_log,
            ks_level,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            fft_type,
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let ss_key = generate_scheme_switching_key(
            &glwe_sk,
            ss_base_log,
            ss_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let ss_key = ss_key.as_view();

        // Set input LWE ciphertext
        let msg = 1;
        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            Plaintext(msg << 63),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut lwe_ks = LweCiphertext::new(0u64, lwe_sk_after_ks.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        let mut lev = LweCiphertextList::new(0u64, lwe_sk.lwe_dimension().to_lwe_size(), LweCiphertextCount(cbs_level.0), ciphertext_modulus);
        let mut glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(cbs_level.0), ciphertext_modulus);
        let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);
        let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);

        let mut buf = LweCiphertext::new(0u64, lwe.lwe_size(), ciphertext_modulus);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "faster and smaller circuit bootstrapping with PBSmanyLUT",
                format!("{id}, LWE to Lev"),
            ),
            |b| b.iter(|| {
                keyswitch_lwe_ciphertext(
                    black_box(&ksk),
                    black_box(&lwe),
                    black_box(&mut lwe_ks),
                );
                lwe_msb_bit_to_lev(
                    black_box(&lwe_ks),
                    black_box(&mut lev),
                    black_box(bsk),
                    black_box(cbs_base_log),
                    black_box(cbs_level),
                    black_box(LutCountLog(log_pbs_many)),
                );
            })
        );

        group.bench_function(
            BenchmarkId::new(
                "faster and smaller circuit bootstrapping with PBSmanyLUT",
                format!("{id}, Lev to GGSW"),
            ),
            |b| b.iter(|| {
                for (lwe, mut glwe) in lev.iter().zip(glev.iter_mut()) {
                    lwe_preprocessing(&lwe, &mut buf, polynomial_size);
                    convert_lwe_to_glwe_const(&buf, &mut glwe);
                    trace_assign(&mut glwe, &auto_keys);
                }
                switch_scheme(&glev, &mut ggsw, ss_key);
                convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
            })
        );

        let max_err = get_max_err_ggsw_bit(
            &glwe_sk,
            ggsw.as_view(),
            msg,
        );

        println!(
            "n: {}, N: {}, k: {}, l_pbs: {}, B_pbs: 2^{}, l_cbs: {}, B_cbs: 2^{}
l_auto: {}, B_auto: 2^{}, fft_type: {:?}, l_ss: {}, B_ss: 2^{}, log_pbs_many: {},
err: {:.2} bits",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, cbs_level.0, cbs_base_log.0,
            auto_level.0, auto_base_log.0, fft_type, ss_level.0, ss_base_log.0, log_pbs_many,
            (max_err as f64).log2(),
        );
    }
}
