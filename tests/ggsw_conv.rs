use std::time::Instant;

use tfhe::core_crypto::prelude::*;
use hom_trace::{automorphism128::*, circuit_bootstrap_by_trace128_and_rescale, generate_scheme_switching_key, lwe_msb_bit_to_glev_by_trace128_and_rescale, utils::*};

fn main() {
    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let glwe_size = glwe_dimension.to_glwe_size();
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(2);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);
    let ss_base_log = DecompositionBaseLog(15);
    let ss_level = DecompositionLevelCount(2);

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let small_lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let std_bootstrap_key = allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        std_bootstrap_key.input_lwe_dimension(),
        std_bootstrap_key.glwe_size(),
        std_bootstrap_key.polynomial_size(),
        std_bootstrap_key.decomposition_base_log(),
        std_bootstrap_key.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrap_key, &mut fourier_bsk);
    let fourier_bsk = fourier_bsk.as_view();

    let ss_key = generate_scheme_switching_key(
        &glwe_sk,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let ss_key = ss_key.as_view();

    let mut glwe_sk_128 = GlweSecretKey::new_empty_key(0u128, glwe_dimension, polynomial_size);
    for (src, dst) in glwe_sk.as_ref().iter().zip(glwe_sk_128.as_mut().iter_mut()) {
        *dst = *src as u128;
    }
    let auto128_keys = gen_all_auto128_keys(
        auto_base_log,
        auto_level,
        &glwe_sk_128,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );


    // Set input LWE ciphertext
    let msg = 1u64;
    let log_delta = u64::BITS - 1;
    let pt = Plaintext(msg << log_delta);
    let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&small_lwe_sk, pt, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    // LWE to GLEV
    let mut glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(ggsw_level.0), ciphertext_modulus);
    let glev_mut_view = GlweCiphertextListMutView::from_container(glev.as_mut(), glwe_size, polynomial_size, ciphertext_modulus);

    let now = Instant::now();
    lwe_msb_bit_to_glev_by_trace128_and_rescale(lwe_in.as_view(), glev_mut_view, fourier_bsk, &auto128_keys, ggsw_base_log, ggsw_level, LutCountLog(1));
    let time = now.elapsed();
    println!("LWE to GLEV: {} ms", time.as_micros() as f64 / 1000f64);

    for (k, glwe) in glev.iter().enumerate() {
        let level = k + 1;
        let log_scale = u64::BITS as usize -  ggsw_base_log.0 * level;
        print!("Level {level}: ");
        for i in 0..10 {
            let mut lwe = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut lwe, MonomialDegree(i));

            let correct_val = if i == 0 {msg} else {0};
            let (_decoded, bit_err) = get_val_and_bit_err(&big_lwe_sk, &lwe, correct_val, 1 << log_scale);
            print!("{bit_err} ");
        }
        println!();
    }

    // Scheme Switching
    let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, ggsw_base_log, ggsw_level, ciphertext_modulus);

    let now = Instant::now();
    for (col, mut glwe_list) in ggsw.as_mut_glwe_list().chunks_exact_mut(glwe_size.0).enumerate() {
        let glwe_bit = glev.get(col);
        let (mut glwe_mask_list, mut glwe_body_list) = glwe_list.split_at_mut(glwe_dimension.0);

        for (mut glwe_mask, fourier_ggsw) in glwe_mask_list.iter_mut().zip(ss_key.into_ggsw_iter()) {
            add_external_product_assign(&mut glwe_mask, &fourier_ggsw, &glwe_bit)
        }
        glwe_ciphertext_clone_from(glwe_body_list.get_mut(0).as_mut_view(), glwe_bit.as_view());
    }
    let time = now.elapsed();
    println!("\nScheme switching: {} ms", time.as_micros() as f64 / 1000f64);

    for level in 1..=ggsw_level.0 {
        ggsw_const_print_err(&glwe_sk, ggsw.as_view(), msg, level, 10);
    }

    // Circuit Bootstrapping
    let now = Instant::now();
    let fourier_ggsw = circuit_bootstrap_by_trace128_and_rescale(
        lwe_in.as_view(),
        fourier_bsk,
        &auto128_keys,
        ss_key,
        ggsw_base_log,
        ggsw_level,
        LutCountLog(1),
    );
    let time = now.elapsed();
    println!("\nCircuit bootstrapping: {} ms", time.as_micros() as f64 / 1000f64);

    let mut glwe_lhs = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    let pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
        if i == 0 {1u64 << 63} else {0u64}
    }).collect::<Vec<u64>>());

    let mut glwe_out = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    encrypt_glwe_ciphertext(&glwe_sk, &mut glwe_lhs, &pt, glwe_modular_std_dev, &mut encryption_generator);
    add_external_product_assign(&mut glwe_out, &fourier_ggsw, &glwe_lhs);

    for i in 0..10 {
        let mut lwe = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
        extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe, MonomialDegree(i));

        let correct_val = *pt.get(i).0 >> 63;
        let (_, bit_err) = get_val_and_bit_err(&big_lwe_sk, &lwe, correct_val, 1u64 << 63);
        print!("{bit_err} ");
    }
    println!("...");
}