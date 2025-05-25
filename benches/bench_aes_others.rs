use refined_tfhe_lhe::{generate_accumulator, keygen_pbs};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use polynomial_algorithms::polynomial_wrapping_mul;
use tfhe::core_crypto::prelude::*;

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets =
        // criterion_benchmark_tcbs,
        criterion_benchmark_bpr,
);
criterion_main!(benches);

#[allow(unused)]
fn criterion_benchmark_tcbs(c: &mut Criterion) {
    let lwe_dimension = LweDimension(1024);
    let lwe_modular_std_dev = StandardDev(6.5e-8);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(9.6e-11);
    let pbs_base_log = DecompositionBaseLog(8);
    let pbs_level = DecompositionLevelCount(3);
    let ks_base_log = DecompositionBaseLog(10);
    let ks_level = DecompositionLevelCount(2);
    let pksk_base_log = DecompositionBaseLog(23);
    let pksk_level = DecompositionLevelCount(1);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let (
        lwe_secret_key,
        glwe_secret_key,
        lwe_secret_key_after_ks,
        bsk,
        ksk
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
    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &lwe_secret_key,
        &glwe_secret_key,
        pksk_base_log,
        pksk_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let modulus_bit = 4;
    let delta = u64::ONE << (u64::BITS - 1 - modulus_bit);

    let msg = u64::ZERO;
    let pt = Plaintext(msg * delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(
        &lwe_secret_key,
        pt,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut lwe_ks = LweCiphertext::new(
        0u64,
        lwe_secret_key_after_ks.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );
    c.bench_function("TCBS LWE_KS", |b| b.iter(|| {
        keyswitch_lwe_ciphertext(
            black_box(&ksk),
            black_box(&lwe_in),
            black_box(&mut lwe_ks),
        );
    }));

    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        modulus_bit as usize,
        ciphertext_modulus,
        delta,
        |i| i,
    );
    let mut lwe_out = LweCiphertext::new(
        0u64,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );
    c.bench_function("TCBS PBS", |b| b.iter(|| {
        programmable_bootstrap_lwe_ciphertext(
            black_box(&lwe_ks),
            black_box(&mut lwe_out),
            black_box(&accumulator),
            black_box(&bsk),
        );
    }));

    let mut glwe_out = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );
    c.bench_function("TCBS PKSK", |b| b.iter(|| {
        keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            black_box(&pksk),
            black_box(&lwe_out),
            black_box(&mut glwe_out),
        );
    }));

    let poly_mult = Polynomial::new(0u64, polynomial_size);
    let mut buf = Polynomial::new(0u64, polynomial_size);
    c.bench_function("TCBS Poly x GLWE", |b| b.iter(|| {
        for mut glwe_poly in glwe_out.as_mut_polynomial_list().iter_mut() {
            buf.as_mut().clone_from_slice(glwe_poly.as_ref());
            polynomial_wrapping_mul(
                black_box(&mut glwe_poly),
                black_box(&poly_mult),
                black_box(&buf),
            );
        }
    }));
}

struct PBSParam {
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: StandardDev,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: StandardDev,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
}

#[allow(unused)]
fn criterion_benchmark_bpr(c: &mut Criterion) {
    let pbs_11_4 = PBSParam {
        lwe_dimension: LweDimension(708),
        lwe_modular_std_dev: StandardDev(0.00000762939),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        glwe_modular_std_dev: StandardDev(9.3132257e-10),
        pbs_base_log: DecompositionBaseLog(6),
        pbs_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(7),
    };
    let pbs_2_1 = PBSParam {
        lwe_dimension: LweDimension(676),
        lwe_modular_std_dev: StandardDev(0.0009765625),
        glwe_dimension: GlweDimension(5),
        polynomial_size: PolynomialSize(256),
        glwe_modular_std_dev: StandardDev(2.98023224e-8),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
    };

    type Scalar = u32;

    let param_list = [
        (pbs_11_4, "PBS_(11, 4)"),
        (pbs_2_1, "PBS_(2, 1)"),
    ];

    for (param, name) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension;
        let lwe_modular_std_dev = param.lwe_modular_std_dev;
        let glwe_dimension = param.glwe_dimension;
        let polynomial_size = param.polynomial_size;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let pbs_base_log = param.pbs_base_log;
        let pbs_level = param.pbs_level;
        let ks_base_log = param.ks_base_log;
        let ks_level = param.ks_level;
        let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_secret_key,
            glwe_secret_key,
            lwe_secret_key_after_ks,
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

        let pt = Plaintext(Scalar::ZERO);
        let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_secret_key,
            pt,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut lwe_ks = LweCiphertext::new(
            Scalar::ZERO,
            lwe_secret_key_after_ks.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );
        let accumulator = generate_accumulator(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            2,
            ciphertext_modulus,
            1 << (Scalar::BITS - 1),
            |i| i,
        );
        let mut lwe_out = LweCiphertext::new(
            Scalar::ZERO,
            lwe_secret_key.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        c.bench_function(&format!("BPR GenPBSAfterKS {name}"), |b| b.iter(|| {
            keyswitch_lwe_ciphertext(
                black_box(&ksk),
                black_box(&lwe_in),
                black_box(&mut lwe_ks),
            );

            programmable_bootstrap_lwe_ciphertext(
                black_box(&lwe_ks),
                black_box(&mut lwe_out),
                black_box(&accumulator),
                black_box(&bsk),
            );
        }));
    }
}
