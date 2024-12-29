use auto_base_conv::{generate_accumulator, get_val_and_abs_err, keygen_pbs};
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets =
        criterion_benchmark_tree,
);
criterion_main!(benches);

type Scalar = u32;

fn criterion_benchmark_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("Tree-PBS");

    let lwe_dimension = LweDimension(1024);
    let lwe_modular_std_dev = StandardDev(6.5e-8);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(9.6e-11);
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    let pbs_level = DecompositionLevelCount(3);
    let pbs_base_log = DecompositionBaseLog(8);
    let pksk_level = DecompositionLevelCount(2);
    let pksk_base_log = DecompositionBaseLog(10);
    let ks_level = DecompositionLevelCount(5);
    let ks_base_log = DecompositionBaseLog(3);
    let tree_base = 16;

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

    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_size,
        2 * tree_base,
        ciphertext_modulus,
        ((1 << 31) / tree_base) as Scalar,
        |i| i as Scalar,
    );

    group.bench_function(
        BenchmarkId::new(
            "PBS",
            format!("base 16, q = 2^{}", Scalar::BITS),
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
            format!("base 16, q = 2^{}", Scalar::BITS),
        ),
        |b| b.iter(|| {
            keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                black_box(&pksk),
                black_box(&lwe_in_list),
                black_box(&mut glwe_out),
            );
        }),
    );

}