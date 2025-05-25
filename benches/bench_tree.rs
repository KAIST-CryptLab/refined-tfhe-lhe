use refined_tfhe_lhe::{generate_accumulator, get_val_and_abs_err, keygen_pbs};
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
        criterion_benchmark_tree,
);
criterion_main!(benches);

type Scalar = u32;

fn criterion_benchmark_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("Tree-PBS");

    let base_16 = (
        LweDimension(1024), // lwe dimension
        StandardDev(6.5e-8), // lwe modular std dev
        GlweDimension(1), // glwe dimension
        PolynomialSize(2048), // polynomial size
        StandardDev(9.6e-11), // glwe modular std dev
        CiphertextModulus::<Scalar>::new_native(), // ciphertext modulus
        DecompositionLevelCount(3), // PBS level
        DecompositionBaseLog(8), // PBS base
        DecompositionLevelCount(2), // PKSK level
        DecompositionBaseLog(10), // PKSK base
        DecompositionLevelCount(5), // KS level
        DecompositionBaseLog(3), // KS base
        16,
    );

    let base_256_1_2 = (
        LweDimension(1024), // lwe dimension
        StandardDev(6.5e-8), // lwe modular std dev
        GlweDimension(1), // glwe dimension
        PolynomialSize(32768), // polynomial size
        if Scalar::BITS == 32 {
            StandardDev(9.6e-11)
        } else {
            StandardDev(2.17e-19)
        }, // glwe_modular_std_dev
        CiphertextModulus::<Scalar>::new_native(), // ciphertext modulus
        DecompositionLevelCount(1), // PBS level
        DecompositionBaseLog(28), // PBS base
        DecompositionLevelCount(2), // PKSK level
        DecompositionBaseLog(10), // PKSK base
        DecompositionLevelCount(5), // KS level
        DecompositionBaseLog(3), // KS base
        256,
    );

    let param_list = [
        base_16,
        base_256_1_2,
    ];

    for param in param_list {
        let lwe_dimension = param.0;
        let lwe_modular_std_dev = param.1;
        let glwe_dimension = param.2;
        let polynomial_size = param.3;
        let glwe_modular_std_dev = param.4;
        let ciphertext_modulus = param.5;
        let pbs_level = param.6;
        let pbs_base_log = param.7;
        let pksk_level = param.8;
        let pksk_base_log = param.9;
        let ks_level = param.10;
        let ks_base_log = param.11;
        let tree_base = param.12;

        let glwe_size = glwe_dimension.to_glwe_size();

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
            _ksk,
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

        let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(&lwe_secret_key, &glwe_secret_key, pksk_base_log, pksk_level, glwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

        let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&lwe_secret_key_after_ks, Plaintext(0), lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);
        let mut lwe_out = LweCiphertext::new(Scalar::ZERO, lwe_secret_key.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        let delta = ((1 << (Scalar::BITS - 1)) / tree_base) as Scalar;

        let accumulator = generate_accumulator(
            polynomial_size,
            glwe_size,
            2 * tree_base,
            ciphertext_modulus,
            delta,
            |i| i as Scalar,
        );

        group.bench_function(
            BenchmarkId::new(
                "PBS",
                format!("base {}, q = 2^{}", tree_base, Scalar::BITS),
            ),
            |b| b.iter(|| {
                programmable_bootstrap_lwe_ciphertext(
                    black_box(&lwe_in),
                    black_box(&mut lwe_out),
                    black_box(&accumulator),
                    black_box(&bsk),
                );
            }),
        );

        let (_, err) = get_val_and_abs_err(&lwe_secret_key, &lwe_out, 0, delta);
        println!("PBS err: {:.2} bits", (err as f64).log2());

        let mut lwe_in_list = LweCiphertextList::new(Scalar::ZERO, lwe_secret_key.lwe_dimension().to_lwe_size(), LweCiphertextCount(tree_base), ciphertext_modulus);
        for mut lwe in lwe_in_list.iter_mut() {
            encrypt_lwe_ciphertext(&lwe_secret_key, &mut lwe, Plaintext(0), glwe_modular_std_dev, &mut encryption_generator);
        }
        let mut glwe_out = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        let (_, err) = get_val_and_abs_err(&lwe_secret_key, &lwe_in_list.get(0), 0, 1 << (Scalar::BITS - 5));
        println!("err: {:.2} bits", (err as f64).log2());

        group.bench_function(
            BenchmarkId::new(
                "PKSK",
                format!("base {}, q = 2^{}", tree_base, Scalar::BITS),
            ),
            |b| b.iter(|| {
                keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                    black_box(&pksk),
                    black_box(&lwe_in_list),
                    black_box(&mut glwe_out),
                );
            }),
        );

        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe_out, MonomialDegree(0));
        let (_, err) = get_val_and_abs_err(&lwe_secret_key, &lwe_out, 0, delta);
        println!("PKSK err: {:.2} bits", (err as f64).log2());
    }
}
