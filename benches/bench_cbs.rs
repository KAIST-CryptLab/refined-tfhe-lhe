use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use dyn_stack::ReborrowMut;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::{circuit_bootstrap_boolean_scratch, circuit_bootstrap_boolean};
use auto_base_conv::{allocate_and_generate_new_glwe_keyswitch_key, convert_lwe_to_glwe_by_trace_with_preprocessing, convert_lwe_to_glwe_by_trace_with_preprocessing_high_prec, convert_standard_glwe_keyswitch_key_to_fourier, gen_all_auto_keys, generate_scheme_switching_key, get_max_err_ggsw_bit, keygen_pbs, lwe_msb_bit_refresh, lwe_msb_bit_to_lev, switch_scheme, FftType, FourierGlweKeyswitchKey};

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets =
        // criterion_benchmark_baseline,
        criterion_benchmark_cbs,
        criterion_benchmark_patched_wwllp_cbs,
        criterion_benchmark_patched_high_prec_wwllp_cbs,
);
criterion_main!(benches);

const FFT_TYPE: FftType = FftType::Split16;

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
    ciphertext_modulus: CiphertextModulus::<Scalar>,
}

#[allow(unused)]
struct WWLLpCBSParam<Scalar: UnsignedInteger> {
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: StandardDev,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: StandardDev,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    refresh_base_log: DecompositionBaseLog,
    refresh_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    cbs_base_log: DecompositionBaseLog,
    cbs_level: DecompositionLevelCount,
    log_pbs_many: usize,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
}

#[allow(unused)]
struct HighPrecWWLLpCBSParam<Scalar: UnsignedInteger> {
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: StandardDev,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    large_glwe_dimension: GlweDimension,
    glwe_modular_std_dev: StandardDev,
    large_glwe_modular_std_dev: StandardDev,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    refresh_base_log: DecompositionBaseLog,
    refresh_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    glwe_ks_to_large_base_log: DecompositionBaseLog,
    glwe_ks_to_large_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    glwe_ks_from_large_base_log: DecompositionBaseLog,
    glwe_ks_from_large_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    cbs_base_log: DecompositionBaseLog,
    cbs_level: DecompositionLevelCount,
    log_pbs_many: usize,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
}

#[allow(unused)]
fn criterion_benchmark_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("baseline");

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
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        let mut buffers = ComputationBuffers::new();
        buffers.resize(
            circuit_bootstrap_boolean_scratch::<u64>(
                lwe_sk_after_ks.lwe_dimension().to_lwe_size(),
                bsk.output_lwe_dimension().to_lwe_size(),
                glwe_size,
                polynomial_size,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let mut stack = buffers.stack();

        let mut ggsw = GgswCiphertext::new(u64::ZERO, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);

        group.bench_function(
            BenchmarkId::new(
                "CBS",
                format!("{id}, CBS"),
            ),
            |b| b.iter(|| {
                keyswitch_lwe_ciphertext(
                    black_box(&ksk),
                    black_box(&lwe),
                    black_box(&mut lwe_ks),
                );

                circuit_bootstrap_boolean(
                    bsk,
                    lwe_ks.as_view(),
                    ggsw.as_mut_view(),
                    DeltaLog(63),
                    pfpksk_list.as_view(),
                    fft,
                    stack.rb_mut(),
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
l_pfpks: {}, B_pfpks: 2^{},
err: {:.2} bits",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, cbs_level.0, cbs_base_log.0,
            pfks_level.0, pfks_base_log.0,
            (max_err as f64).log2(),
        );
    }
}

#[allow(unused)]
fn criterion_benchmark_cbs(c: &mut Criterion) {
    let mut group = c.benchmark_group("original circuit bootstrapping");

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
                "step 1",
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
                    black_box(LutCountLog(0)),
                );
            })
        );

        group.bench_function(
            BenchmarkId::new(
                "step 2",
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
l_pfpks: {}, B_pfpks: 2^{},
err: {:.2} bits",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, cbs_level.0, cbs_base_log.0,
            pfks_level.0, pfks_base_log.0,
            (max_err as f64).log2(),
        );
    }
}

#[allow(unused)]
fn criterion_benchmark_patched_wwllp_cbs(c: &mut Criterion) {
    let mut group = c.benchmark_group("patched WWLL+ circuit bootstrapping");

    let wopbs_message_2_carry_2_ks_pbs = WWLLpCBSParam {
        lwe_dimension: LweDimension(769),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        refresh_base_log: DecompositionBaseLog(23),
        refresh_level: DecompositionLevelCount(1),
        ks_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(6),
        auto_base_log: DecompositionBaseLog(7),
        auto_level: DecompositionLevelCount(7),
        ss_base_log: DecompositionBaseLog(8),
        ss_level: DecompositionLevelCount(6),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(5),
        log_pbs_many: 2,
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let param_list = [
        (wopbs_message_2_carry_2_ks_pbs, "wopbs_message_2_carry_2"),
    ];

    for (param, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension;
        let lwe_modular_std_dev = param.lwe_modular_std_dev;
        let glwe_dimension = param.glwe_dimension;
        let polynomial_size = param.polynomial_size;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let pbs_base_log = param.pbs_base_log;
        let pbs_level = param.pbs_level;
        let refresh_base_log = param.refresh_base_log;
        let refresh_level = param.refresh_level;
        let ks_base_log = param.ks_base_log;
        let ks_level = param.ks_level;
        let auto_base_log = param.auto_base_log;
        let auto_level = param.auto_level;
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

        let refresh_glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(glwe_dimension, polynomial_size, &mut secret_generator);
        let refresh_lwe_sk = refresh_glwe_sk.clone().into_lwe_secret_key();

        let standard_refresh_bsk = allocate_and_generate_new_lwe_bootstrap_key(
            &lwe_sk_after_ks,
            &refresh_glwe_sk,
            refresh_base_log,
            refresh_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut refresh_bsk = FourierLweBootstrapKey::new(
            lwe_sk_after_ks.lwe_dimension(),
            glwe_size,
            polynomial_size,
            refresh_base_log,
            refresh_level,
        );
        convert_standard_lwe_bootstrap_key_to_fourier(&standard_refresh_bsk, &mut refresh_bsk);
        let refresh_bsk = refresh_bsk.as_view();
        drop(standard_refresh_bsk);

        let ksk_from_refresh = allocate_and_generate_new_lwe_keyswitch_key(
            &refresh_lwe_sk,
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
            FFT_TYPE,
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
        let mut lwe_refresh = LweCiphertext::new(0u64, lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        let mut lev = LweCiphertextList::new(0u64, lwe_sk.lwe_dimension().to_lwe_size(), LweCiphertextCount(cbs_level.0), ciphertext_modulus);
        let mut glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(cbs_level.0), ciphertext_modulus);
        let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);
        let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);

        let mut buf = LweCiphertext::new(0u64, lwe.lwe_size(), ciphertext_modulus);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "step 1-1",
                format!("{id}, Refresh"),
            ),
            |b| b.iter(|| {
                keyswitch_lwe_ciphertext(
                    black_box(&ksk),
                    black_box(&lwe),
                    black_box(&mut lwe_ks),
                );
                lwe_msb_bit_refresh(&lwe_ks, &mut lwe_refresh, refresh_bsk);
            })
        );

        group.bench_function(
            BenchmarkId::new(
                "step 1-2",
                format!("{id}, LWE to Lev"),
            ),
            |b| b.iter(|| {
                keyswitch_lwe_ciphertext(
                    black_box(&ksk_from_refresh),
                    black_box(&lwe_refresh),
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
                "step 2",
                format!("{id}, Lev to GGSW"),
            ),
            |b| b.iter(|| {
                for (lwe, mut glwe) in lev.iter().zip(glev.iter_mut()) {
                    convert_lwe_to_glwe_by_trace_with_preprocessing(
                        &lwe,
                        &mut glwe,
                        &auto_keys,
                    );
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
            "n: {}, N: {}, k: {}, l_pbs: {}, B_pbs: 2^{}, l_refresh: {}, B_refresh: 2^{}, l_cbs: {}, B_cbs: 2^{}
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}, log_pbs_many: {},
err: {:.2} bits",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, refresh_level.0, refresh_base_log.0, cbs_level.0, cbs_base_log.0,
            auto_level.0, auto_base_log.0, ss_level.0, ss_base_log.0, log_pbs_many,
            (max_err as f64).log2(),
        );
    }
}

#[allow(unused)]
fn criterion_benchmark_patched_high_prec_wwllp_cbs(c: &mut Criterion) {
    let mut group = c.benchmark_group("patched high prec WWLL+ circuit bootstrapping");

    let wopbs_message_3_carry_3_ks_pbs = HighPrecWWLLpCBSParam {
        lwe_dimension: LweDimension(873),
        glwe_dimension: GlweDimension(1),
        large_glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000006428797112843789),
        large_glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        refresh_base_log: DecompositionBaseLog(23),
        refresh_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(10),
        ks_level: DecompositionLevelCount(1),
        glwe_ks_to_large_base_log: DecompositionBaseLog(15),
        glwe_ks_to_large_level: DecompositionLevelCount(3),
        glwe_ks_from_large_base_log: DecompositionBaseLog(5),
        glwe_ks_from_large_level: DecompositionLevelCount(10),
        auto_base_log: DecompositionBaseLog(6),
        auto_level: DecompositionLevelCount(10),
        ss_base_log: DecompositionBaseLog(6),
        ss_level: DecompositionLevelCount(9),
        cbs_base_log: DecompositionBaseLog(6),
        cbs_level: DecompositionLevelCount(3),
        log_pbs_many: 2,
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let wopbs_message_4_carry_4_ks_pbs = HighPrecWWLLpCBSParam {
        lwe_dimension: LweDimension(953),
        glwe_dimension: GlweDimension(1),
        large_glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000001486733969411098),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        large_glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        refresh_base_log: DecompositionBaseLog(23),
        refresh_level: DecompositionLevelCount(1),
        ks_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(11),
        glwe_ks_to_large_base_log: DecompositionBaseLog(15),
        glwe_ks_to_large_level: DecompositionLevelCount(3),
        glwe_ks_from_large_base_log: DecompositionBaseLog(5),
        glwe_ks_from_large_level: DecompositionLevelCount(10),
        auto_base_log: DecompositionBaseLog(6),
        auto_level: DecompositionLevelCount(10),
        ss_base_log: DecompositionBaseLog(6),
        ss_level: DecompositionLevelCount(9),
        cbs_level: DecompositionLevelCount(6),
        cbs_base_log: DecompositionBaseLog(4),
        log_pbs_many: 3,
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let param_list = [
        (wopbs_message_3_carry_3_ks_pbs, "wopbs_message_3_carry_3"),
        (wopbs_message_4_carry_4_ks_pbs, "wopbs_message_4_carry_4"),
    ];

    for (param, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension;
        let lwe_modular_std_dev = param.lwe_modular_std_dev;
        let glwe_dimension = param.glwe_dimension;
        let large_glwe_dimension = param.large_glwe_dimension;
        let polynomial_size = param.polynomial_size;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let large_glwe_modular_std_dev = param.large_glwe_modular_std_dev;
        let pbs_base_log = param.pbs_base_log;
        let pbs_level = param.pbs_level;
        let refresh_base_log = param.refresh_base_log;
        let refresh_level = param.refresh_level;
        let ks_base_log = param.ks_base_log;
        let ks_level = param.ks_level;
        let glwe_ks_to_large_base_log = param.glwe_ks_to_large_base_log;
        let glwe_ks_to_large_level = param.glwe_ks_to_large_level;
        let glwe_ks_from_large_base_log = param.glwe_ks_from_large_base_log;
        let glwe_ks_from_large_level = param.glwe_ks_from_large_level;
        let auto_base_log = param.auto_base_log;
        let auto_level = param.auto_level;
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

        let large_glwe_sk = GlweSecretKey::generate_new_binary(large_glwe_dimension, polynomial_size, &mut secret_generator);
        let large_glwe_size = large_glwe_dimension.to_glwe_size();

        let refresh_glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(glwe_dimension, polynomial_size, &mut secret_generator);
        let refresh_lwe_sk = refresh_glwe_sk.clone().into_lwe_secret_key();

        let standard_refresh_bsk = allocate_and_generate_new_lwe_bootstrap_key(
            &lwe_sk_after_ks,
            &refresh_glwe_sk,
            refresh_base_log,
            refresh_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut refresh_bsk = FourierLweBootstrapKey::new(
            lwe_sk_after_ks.lwe_dimension(),
            glwe_size,
            polynomial_size,
            refresh_base_log,
            refresh_level,
        );
        convert_standard_lwe_bootstrap_key_to_fourier(&standard_refresh_bsk, &mut refresh_bsk);
        let refresh_bsk = refresh_bsk.as_view();
        drop(standard_refresh_bsk);

        let ksk_from_refresh = allocate_and_generate_new_lwe_keyswitch_key(
            &refresh_lwe_sk,
            &lwe_sk_after_ks,
            ks_base_log,
            ks_level,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let glwe_ksk_to_large = allocate_and_generate_new_glwe_keyswitch_key(
            &glwe_sk,
            &large_glwe_sk,
            glwe_ks_to_large_base_log,
            glwe_ks_to_large_level,
            large_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut fourier_glwe_ksk_to_large = FourierGlweKeyswitchKey::new(
            glwe_size,
            large_glwe_size,
            polynomial_size,
            glwe_ks_to_large_base_log,
            glwe_ks_to_large_level,
            FFT_TYPE,
        );
        convert_standard_glwe_keyswitch_key_to_fourier(&glwe_ksk_to_large, &mut fourier_glwe_ksk_to_large);

        let glwe_ksk_from_large = allocate_and_generate_new_glwe_keyswitch_key(
            &large_glwe_sk,
            &glwe_sk,
            glwe_ks_from_large_base_log,
            glwe_ks_from_large_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut fourier_glwe_ksk_from_large = FourierGlweKeyswitchKey::new(
            large_glwe_size,
            glwe_size,
            polynomial_size,
            glwe_ks_from_large_base_log,
            glwe_ks_from_large_level,
            FFT_TYPE,
        );
        convert_standard_glwe_keyswitch_key_to_fourier(&glwe_ksk_from_large, &mut fourier_glwe_ksk_from_large);

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            FFT_TYPE,
            &large_glwe_sk,
            large_glwe_modular_std_dev,
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
        let mut lwe_refresh = LweCiphertext::new(0u64, lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        let mut lev = LweCiphertextList::new(0u64, lwe_sk.lwe_dimension().to_lwe_size(), LweCiphertextCount(cbs_level.0), ciphertext_modulus);
        let mut glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(cbs_level.0), ciphertext_modulus);
        let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);
        let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);

        let mut buf = LweCiphertext::new(0u64, lwe.lwe_size(), ciphertext_modulus);

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "step 1-1",
                format!("{id}, Refresh"),
            ),
            |b| b.iter(|| {
                keyswitch_lwe_ciphertext(
                    black_box(&ksk),
                    black_box(&lwe),
                    black_box(&mut lwe_ks),
                );
                lwe_msb_bit_refresh(&lwe_ks, &mut lwe_refresh, refresh_bsk);
            })
        );

        group.bench_function(
            BenchmarkId::new(
                "step 1-2",
                format!("{id}, LWE to Lev"),
            ),
            |b| b.iter(|| {
                keyswitch_lwe_ciphertext(
                    black_box(&ksk_from_refresh),
                    black_box(&lwe_refresh),
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
                "step 2",
                format!("{id}, Lev to GGSW"),
            ),
            |b| b.iter(|| {
                for (lwe, mut glwe) in lev.iter().zip(glev.iter_mut()) {
                    convert_lwe_to_glwe_by_trace_with_preprocessing_high_prec(
                        &lwe,
                        &mut glwe,
                        &fourier_glwe_ksk_to_large,
                        &fourier_glwe_ksk_from_large,
                        &auto_keys,
                    );
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
            "n: {}, N: {}, k: {}, l_pbs: {}, B_pbs: 2^{}, l_refresh: {}, B_refresh: 2^{}, l_cbs: {}, B_cbs: 2^{}
l_to_large: {}, B_to_large: 2^{}, l_from_large: {}, B_from_large: 2^{},
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}, log_pbs_many: {},
err: {:.2} bits",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, refresh_level.0, refresh_base_log.0, cbs_level.0, cbs_base_log.0,
            glwe_ks_to_large_level.0, glwe_ks_to_large_base_log.0, glwe_ks_from_large_level.0, glwe_ks_from_large_base_log.0,
            auto_level.0, auto_base_log.0, ss_level.0, ss_base_log.0, log_pbs_many,
            (max_err as f64).log2(),
        );
    }
}