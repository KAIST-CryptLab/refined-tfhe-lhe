use tfhe::core_crypto::{prelude::*, fft_impl::fft64::c64};
use hom_trace::{automorphism::*, automorphism128::*, ggsw_conv::*, utils::*};
use rand::Rng;
use std::time::{Instant, Duration};

fn main() {
    // GGSW LUT by trace with mod switch
    let lwe_dimension = LweDimension(742);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let ks_level = DecompositionLevelCount(5);
    let ks_base_log = DecompositionBaseLog(3);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ss_base_log = DecompositionBaseLog(15);
    let ss_level = DecompositionLevelCount(2);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);
    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(2);
    let log_lut_count = LutCountLog(1);

    test_ggsw_lut_by_trace_with_mod_switch(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        ks_base_log,
        ks_level,
        ss_base_log,
        ss_level,
        auto_base_log,
        auto_level,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
    println!("");
    println!("");

    // GGSW LUT by trace128 and rescale
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ss_base_log = DecompositionBaseLog(15);
    let ss_level = DecompositionLevelCount(2);
    let auto_base_log = DecompositionBaseLog(15);
    let auto_level = DecompositionLevelCount(2);
    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(2);
    let log_lut_count = LutCountLog(1);

    test_ggsw_lut_by_trace128_and_rescale(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        ks_base_log,
        ks_level,
        ss_base_log,
        ss_level,
        auto_base_log,
        auto_level,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
    println!("");
    println!("");

    // GGSW LUT by pksk
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ss_base_log = DecompositionBaseLog(15);
    let ss_level = DecompositionLevelCount(2);
    let pksk_base_log = DecompositionBaseLog(23);
    let pksk_level = DecompositionLevelCount(1);
    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(2);
    let log_lut_count = LutCountLog(1);

    test_ggsw_lut_by_pksk(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        ks_base_log,
        ks_level,
        ss_base_log,
        ss_level,
        pksk_base_log,
        pksk_level,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
    println!();
    println!();

    // GGSW LUT by trace
    let glwe_dimension = GlweDimension(8);
    let polynomial_size = PolynomialSize(256);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);

    let pbs_base_log = DecompositionBaseLog(15);
    let pbs_level = DecompositionLevelCount(2);
    let ss_base_log = DecompositionBaseLog(9);
    let ss_level = DecompositionLevelCount(4);
    let auto_base_log = DecompositionBaseLog(10);
    let auto_level = DecompositionLevelCount(4);
    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(4);
    let log_lut_count = LutCountLog(2);

    test_ggsw_lut_by_trace(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        ks_base_log,
        ks_level,
        ss_base_log,
        ss_level,
        auto_base_log,
        auto_level,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
    println!();
}

fn test_ggsw_lut_by_trace_with_mod_switch(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== GGSW LUT by trace with mod switch ====
n: {}, N: {}, k: {}, l_ks: {}, B_ks: 2^{}
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, ks_level.0, ks_base_log.0,
        pbs_level.0, pbs_base_log.0, ggsw_level.0, ggsw_base_log.0, log_lut_count.0,
        auto_level.0, auto_base_log.0, ss_level.0, ss_base_log.0,
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let small_lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let _ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &small_lwe_sk,
        ks_base_log,
        ks_level,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

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

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Set input and lookup tables
    let glwe_size = glwe_dimension.to_glwe_size();
    let polynomial_size = polynomial_size;

    let mut rng = rand::thread_rng();
    let bit_length = 8;
    assert!(polynomial_size.0 >= (1 << bit_length));

    let input_bits = (0..bit_length).map(|_| {
        rng.gen_range(0..2) as u64
    }).collect::<Vec<u64>>();

    let num_lut = polynomial_size.0 / (1 << bit_length);
    let vec_table = (0..num_lut).map(|_| {
        (0..(1 << bit_length)).map(|_| {
            rng.gen_range(0..2) as u64
        }).collect::<Vec<u64>>()
    }).collect::<Vec<Vec<u64>>>();

    // Make GLEV from LWE
    let mut lwe_list_in = LweCiphertextList::new(
        0u64,
        lwe_dimension.to_lwe_size(),
        LweCiphertextCount(bit_length),
        ciphertext_modulus,
    );
    for (mut lwe_in, bit_in) in lwe_list_in.iter_mut().zip(input_bits.iter()) {
        encrypt_lwe_ciphertext(&small_lwe_sk, &mut lwe_in, Plaintext(bit_in << 63), lwe_modular_std_dev, &mut encryption_generator);
    }

    let now = Instant::now();
    let mut vec_glev = vec![
        GlweCiphertextList::new(
            0u64,
            glwe_size,
            polynomial_size,
            GlweCiphertextCount(ggsw_level.0),
            ciphertext_modulus
        ); bit_length];
    for (lwe_in, glev) in lwe_list_in.iter().zip(vec_glev.iter_mut()) {
        let glev_mut_view = GlweCiphertextListMutView::from_container(
            glev.as_mut(),
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );
        lwe_msb_bit_to_glev_by_trace_with_mod_switch(
            lwe_in.as_view(),
            glev_mut_view,
            fourier_bsk,
            &auto_keys,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }
    let time_glev = now.elapsed();

    println!("---- GLEV Ctxts Error ----");
    for (idx, glev) in vec_glev.iter().enumerate() {
        print!("GLEV[{idx}] ");
        let input_bit = input_bits.get(idx).unwrap();
        for (k, glwe) in glev.iter().enumerate() {
            let mut max_err = 0u64;
            let level = k + 1;
            let mut pt = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);
            for i in 0..polynomial_size.0 {
                let decrypted_u64 = *pt.get(i).0;
                let correct_val = if i == 0 {(*input_bit) << (64 - level * ggsw_base_log.0)} else {0};
                let abs_err = {
                    let d0 = decrypted_u64.wrapping_sub(correct_val);
                    let d1 = correct_val.wrapping_sub(decrypted_u64);
                    std::cmp::min(d0, d1)
                };
                max_err = std::cmp::max(max_err, abs_err);
            }
            let log_max_err = (max_err as f64).log2();
            print!("{log_max_err:.2} ");
        }
        println!();
    }
    println!();

    // Make GGSW from GLEV
    let now = Instant::now();
    let mut ggsw_bit_list = GgswCiphertextList::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
        GgswCiphertextCount(vec_glev.len()),
        ciphertext_modulus,
    );
    for (mut ggsw, glev) in ggsw_bit_list.iter_mut().zip(vec_glev.iter()) {
        for (col, mut glwe_list) in ggsw.as_mut_glwe_list().chunks_exact_mut(glwe_size.0).enumerate() {
            let glwe_bit = glev.get(col);
            let (mut glwe_mask_list, mut glwe_body_list) = glwe_list.split_at_mut(glwe_dimension.0);

            for (mut glwe_mask, fourier_ss_key) in glwe_mask_list.iter_mut().zip(ss_key.into_ggsw_iter()) {
                add_external_product_assign(&mut glwe_mask, &fourier_ss_key, &glwe_bit);
            }
            glwe_ciphertext_clone_from(glwe_body_list.get_mut(0).as_mut_view(), glwe_bit.as_view());
        }
    }
    let mut time_ggsw = now.elapsed();

    println!("---- GGSW Ctxts Error ----");
    for (i, ggsw) in ggsw_bit_list.iter().enumerate() {
        let max_err = get_max_err_ggsw_bit(&glwe_sk, ggsw, *input_bits.get(i).unwrap());
        let log_max_err = (max_err as f64).log2();
        println!("ggsw[{i}] {log_max_err:.2}");
    }
    println!();

    let now = Instant::now();
    let mut fourier_ggsw_bit_list = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            bit_length * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * ggsw_level.0
        ],
        bit_length,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
    );

    for (mut fourier_ggsw, ggsw) in fourier_ggsw_bit_list.as_mut_view().into_ggsw_iter().zip(ggsw_bit_list.iter()) {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }
    time_ggsw += now.elapsed();

    // Homomorphic LUT
    println!("---- Homomorphic LUT Results ----");
    let mut time_lut = Duration::ZERO;
    let now = Instant::now();
    let accumulator = (0..polynomial_size.0).map(|i| {
        let table_idx = i / (1 << bit_length);
        let table = vec_table.get(table_idx).unwrap();
        table[i % (1 << bit_length)] << 63
    }).collect::<Vec<u64>>();
    let accumulator_plaintext = PlaintextList::from_container(accumulator);
    let mut accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext, ciphertext_modulus);
    time_lut += now.elapsed();

    let mut vec_acc_err = vec![0u64; bit_length];
    let mut vec_lut_err = vec![vec![0u64; bit_length]; num_lut];
    let mut tmp_plain_accumulator = accumulator.clone();
    let mut tmp_table_input = 0;
    for (bit_idx, fourier_ggsw_bit) in fourier_ggsw_bit_list.as_view().into_ggsw_iter().into_iter().enumerate() {
        let now = Instant::now();
        let mut buf = accumulator.clone();
        glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(1 << bit_idx));
        glwe_ciphertext_sub_assign(&mut buf, &accumulator);
        add_external_product_assign(&mut accumulator, &fourier_ggsw_bit, &buf);
        time_lut += now.elapsed();

        let cur_input_bit = *input_bits.get(bit_idx).unwrap();
        tmp_table_input += cur_input_bit << bit_idx;
        glwe_ciphertext_monic_monomial_div_assign(&mut tmp_plain_accumulator, MonomialDegree((cur_input_bit << bit_idx) as usize));

        let mut dec = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &accumulator, &mut dec);

        let mut correct_acc = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &tmp_plain_accumulator, &mut correct_acc);

        let mut max_err = 0u64;
        for i in 0..polynomial_size.0 {
            let abs_err = {
                let decrypted = *dec.get(i).0;
                let correct_val = *correct_acc.get(i).0;
                let d0 = decrypted.wrapping_sub(correct_val);
                let d1 = correct_val.wrapping_sub(decrypted);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        vec_acc_err[bit_idx] = max_err;

        for j in 0..num_lut {
            let mut lwe_out = LweCiphertext::new(0u64, fourier_bsk.output_lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut lwe_out, MonomialDegree(j * (1 << bit_length)));

            let tmp_table_output = vec_table.get(j).unwrap()[tmp_table_input as usize];
            let (decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe_out, tmp_table_output, 1 << 63);
            if decoded != tmp_table_output {
                println!("LUT fails");
                return;
            }
            vec_lut_err[j][bit_idx] = abs_err;
        }
    }

    print!("Acc");
    for i in 0..bit_length {
        print!(" {:.2}", (vec_acc_err[i] as f64).log2());
    }
    println!();

    for j in 0..num_lut {
        print!("Table[{j}]");
        for i in 0..bit_length {
            print!(" {:.2}", (vec_lut_err[j][i] as f64).log2());
        }
        println!();
    }

    println!("\n---- Time ----");
    println!("Time LWEtoGLEV:  {} ms", time_glev.as_micros() as f64 / 1000f64);
    println!("Time GLEVtoGGSW: {} ms", time_ggsw.as_micros() as f64 / 1000f64);
    println!("Time LUT:        {} ms", time_lut.as_micros() as f64 / 1000f64);
}

fn test_ggsw_lut_by_trace128_and_rescale(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== GGSW LUT by trace128 and rescale ====
n: {}, N: {}, k: {}, l_ks: {}, B_ks: 2^{}
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, ks_level.0, ks_base_log.0,
        pbs_level.0, pbs_base_log.0, ggsw_level.0, ggsw_base_log.0, log_lut_count.0,
        auto_level.0, auto_base_log.0, ss_level.0, ss_base_log.0,
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let small_lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let _ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &small_lwe_sk,
        ks_base_log,
        ks_level,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

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

    // Set input and lookup tables
    let glwe_size = glwe_dimension.to_glwe_size();
    let polynomial_size = polynomial_size;

    let mut rng = rand::thread_rng();
    let bit_length = 8;
    assert!(polynomial_size.0 >= (1 << bit_length));

    let input_bits = (0..bit_length).map(|_| {
        rng.gen_range(0..2) as u64
    }).collect::<Vec<u64>>();

    let num_lut = polynomial_size.0 / (1 << bit_length);
    let vec_table = (0..num_lut).map(|_| {
        (0..(1 << bit_length)).map(|_| {
            rng.gen_range(0..2) as u64
        }).collect::<Vec<u64>>()
    }).collect::<Vec<Vec<u64>>>();

    // Make GLEV from LWE
    let mut lwe_list_in = LweCiphertextList::new(
        0u64,
        lwe_dimension.to_lwe_size(),
        LweCiphertextCount(bit_length),
        ciphertext_modulus,
    );
    for (mut lwe_in, bit_in) in lwe_list_in.iter_mut().zip(input_bits.iter()) {
        encrypt_lwe_ciphertext(&small_lwe_sk, &mut lwe_in, Plaintext(bit_in << 63), lwe_modular_std_dev, &mut encryption_generator);
    }

    let now = Instant::now();
    let mut vec_glev = vec![
        GlweCiphertextList::new(
            0u64,
            glwe_size,
            polynomial_size,
            GlweCiphertextCount(ggsw_level.0),
            ciphertext_modulus
        ); bit_length];
    for (lwe_in, glev) in lwe_list_in.iter().zip(vec_glev.iter_mut()) {
        let glev_mut_view = GlweCiphertextListMutView::from_container(
            glev.as_mut(),
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );
        lwe_msb_bit_to_glev_by_trace128_and_rescale(
            lwe_in.as_view(),
            glev_mut_view,
            fourier_bsk,
            &auto128_keys,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }
    let time_glev = now.elapsed();

    println!("---- GLEV Ctxts Error ----");
    for (idx, glev) in vec_glev.iter().enumerate() {
        print!("GLEV[{idx}] ");
        let input_bit = input_bits.get(idx).unwrap();
        for (k, glwe) in glev.iter().enumerate() {
            let mut max_err = 0u64;
            let level = k + 1;
            let mut pt = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);
            for i in 0..polynomial_size.0 {
                let decrypted_u64 = *pt.get(i).0;
                let correct_val = if i == 0 {(*input_bit) << (64 - level * ggsw_base_log.0)} else {0};
                let abs_err = {
                    let d0 = decrypted_u64.wrapping_sub(correct_val);
                    let d1 = correct_val.wrapping_sub(decrypted_u64);
                    std::cmp::min(d0, d1)
                };
                max_err = std::cmp::max(max_err, abs_err);
            }
            let log_max_err = (max_err as f64).log2();
            print!("{log_max_err:.2} ");
        }
        println!();
    }
    println!();

    // Make GGSW from GLEV
    let now = Instant::now();
    let mut ggsw_bit_list = GgswCiphertextList::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
        GgswCiphertextCount(vec_glev.len()),
        ciphertext_modulus,
    );
    for (mut ggsw, glev) in ggsw_bit_list.iter_mut().zip(vec_glev.iter()) {
        for (col, mut glwe_list) in ggsw.as_mut_glwe_list().chunks_exact_mut(glwe_size.0).enumerate() {
            let glwe_bit = glev.get(col);
            let (mut glwe_mask_list, mut glwe_body_list) = glwe_list.split_at_mut(glwe_dimension.0);

            for (mut glwe_mask, fourier_ss_key) in glwe_mask_list.iter_mut().zip(ss_key.into_ggsw_iter()) {
                add_external_product_assign(&mut glwe_mask, &fourier_ss_key, &glwe_bit);
            }
            glwe_ciphertext_clone_from(glwe_body_list.get_mut(0).as_mut_view(), glwe_bit.as_view());
        }
    }
    let mut time_ggsw = now.elapsed();

    println!("---- GGSW Ctxts Error ----");
    for (i, ggsw) in ggsw_bit_list.iter().enumerate() {
        let max_err = get_max_err_ggsw_bit(&glwe_sk, ggsw, *input_bits.get(i).unwrap());
        let log_max_err = (max_err as f64).log2();
        println!("ggsw[{i}] {log_max_err:.2}");
    }
    println!();

    let now = Instant::now();
    let mut fourier_ggsw_bit_list = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            bit_length * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * ggsw_level.0
        ],
        bit_length,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
    );

    for (mut fourier_ggsw, ggsw) in fourier_ggsw_bit_list.as_mut_view().into_ggsw_iter().zip(ggsw_bit_list.iter()) {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }
    time_ggsw += now.elapsed();

    // Homomorphic LUT
    println!("---- Homomorphic LUT Results ----");
    let mut time_lut = Duration::ZERO;
    let now = Instant::now();
    let accumulator = (0..polynomial_size.0).map(|i| {
        let table_idx = i / (1 << bit_length);
        let table = vec_table.get(table_idx).unwrap();
        table[i % (1 << bit_length)] << 63
    }).collect::<Vec<u64>>();
    let accumulator_plaintext = PlaintextList::from_container(accumulator);
    let mut accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext, ciphertext_modulus);
    time_lut += now.elapsed();

    let mut vec_acc_err = vec![0u64; bit_length];
    let mut vec_lut_err = vec![vec![0u64; bit_length]; num_lut];
    let mut tmp_plain_accumulator = accumulator.clone();
    let mut tmp_table_input = 0;
    for (bit_idx, fourier_ggsw_bit) in fourier_ggsw_bit_list.as_view().into_ggsw_iter().into_iter().enumerate() {
        let now = Instant::now();
        let mut buf = accumulator.clone();
        glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(1 << bit_idx));
        glwe_ciphertext_sub_assign(&mut buf, &accumulator);
        add_external_product_assign(&mut accumulator, &fourier_ggsw_bit, &buf);
        time_lut += now.elapsed();

        let cur_input_bit = *input_bits.get(bit_idx).unwrap();
        tmp_table_input += cur_input_bit << bit_idx;
        glwe_ciphertext_monic_monomial_div_assign(&mut tmp_plain_accumulator, MonomialDegree((cur_input_bit << bit_idx) as usize));

        let mut dec = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &accumulator, &mut dec);

        let mut correct_acc = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &tmp_plain_accumulator, &mut correct_acc);

        let mut max_err = 0u64;
        for i in 0..polynomial_size.0 {
            let abs_err = {
                let decrypted = *dec.get(i).0;
                let correct_val = *correct_acc.get(i).0;
                let d0 = decrypted.wrapping_sub(correct_val);
                let d1 = correct_val.wrapping_sub(decrypted);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        vec_acc_err[bit_idx] = max_err;

        for j in 0..num_lut {
            let mut lwe_out = LweCiphertext::new(0u64, fourier_bsk.output_lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut lwe_out, MonomialDegree(j * (1 << bit_length)));

            let tmp_table_output = vec_table.get(j).unwrap()[tmp_table_input as usize];
            let (decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe_out, tmp_table_output, 1 << 63);
            if decoded != tmp_table_output {
                println!("LUT fails");
                return;
            }
            vec_lut_err[j][bit_idx] = abs_err;
        }
    }

    print!("Acc");
    for i in 0..bit_length {
        print!(" {:.2}", (vec_acc_err[i] as f64).log2());
    }
    println!();

    for j in 0..num_lut {
        print!("Table[{j}]");
        for i in 0..bit_length {
            print!(" {:.2}", (vec_lut_err[j][i] as f64).log2());
        }
        println!();
    }

    println!("\n---- Time ----");
    println!("Time LWEtoGLEV:  {} ms", time_glev.as_micros() as f64 / 1000f64);
    println!("Time GLEVtoGGSW: {} ms", time_ggsw.as_micros() as f64 / 1000f64);
    println!("Time LUT:        {} ms", time_lut.as_micros() as f64 / 1000f64);
}

fn test_ggsw_lut_by_pksk(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    pksk_base_log: DecompositionBaseLog,
    pksk_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== GGSW LUT by pksk ====
n: {}, N: {}, k: {}, l_ks: {}, B_ks: 2^{}
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, ks_level.0, ks_base_log.0,
        pbs_level.0, pbs_base_log.0, ggsw_level.0, ggsw_base_log.0, log_lut_count.0,
        pksk_level.0, pksk_base_log.0, ss_level.0, ss_base_log.0,
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let small_lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let _ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &small_lwe_sk,
        ks_base_log,
        ks_level,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

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

    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &big_lwe_sk,
        &glwe_sk,
        pksk_base_log,
        pksk_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let pksk = pksk.as_view();

    // Set input and lookup tables
    let glwe_size = glwe_dimension.to_glwe_size();
    let polynomial_size = polynomial_size;

    let mut rng = rand::thread_rng();
    let bit_length = 8;
    assert!(polynomial_size.0 >= (1 << bit_length));

    let input_bits = (0..bit_length).map(|_| {
        rng.gen_range(0..2) as u64
    }).collect::<Vec<u64>>();

    let num_lut = polynomial_size.0 / (1 << bit_length);
    let vec_table = (0..num_lut).map(|_| {
        (0..(1 << bit_length)).map(|_| {
            rng.gen_range(0..2) as u64
        }).collect::<Vec<u64>>()
    }).collect::<Vec<Vec<u64>>>();

    // Make GLEV from LWE
    let mut lwe_list_in = LweCiphertextList::new(
        0u64,
        lwe_dimension.to_lwe_size(),
        LweCiphertextCount(bit_length),
        ciphertext_modulus,
    );
    for (mut lwe_in, bit_in) in lwe_list_in.iter_mut().zip(input_bits.iter()) {
        encrypt_lwe_ciphertext(&small_lwe_sk, &mut lwe_in, Plaintext(bit_in << 63), lwe_modular_std_dev, &mut encryption_generator);
    }

    let now = Instant::now();
    let mut vec_glev = vec![
        GlweCiphertextList::new(
            0u64,
            glwe_size,
            polynomial_size,
            GlweCiphertextCount(ggsw_level.0),
            ciphertext_modulus
        ); bit_length];
    for (lwe_in, glev) in lwe_list_in.iter().zip(vec_glev.iter_mut()) {
        let glev_mut_view = GlweCiphertextListMutView::from_container(
            glev.as_mut(),
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );
        lwe_msb_bit_to_glev_by_pksk(
            lwe_in.as_view(),
            glev_mut_view,
            fourier_bsk,
            &pksk,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }
    let time_glev = now.elapsed();

    println!("---- GLEV Ctxts Error ----");
    for (idx, glev) in vec_glev.iter().enumerate() {
        print!("GLEV[{idx}] ");
        let input_bit = input_bits.get(idx).unwrap();
        for (k, glwe) in glev.iter().enumerate() {
            let mut max_err = 0u64;
            let level = k + 1;
            let mut pt = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);
            for i in 0..polynomial_size.0 {
                let decrypted_u64 = *pt.get(i).0;
                let correct_val = if i == 0 {(*input_bit) << (64 - level * ggsw_base_log.0)} else {0};
                let abs_err = {
                    let d0 = decrypted_u64.wrapping_sub(correct_val);
                    let d1 = correct_val.wrapping_sub(decrypted_u64);
                    std::cmp::min(d0, d1)
                };
                max_err = std::cmp::max(max_err, abs_err);
            }
            let log_max_err = (max_err as f64).log2();
            print!("{log_max_err:.2} ");
        }
        println!();
    }
    println!();

    // Make GGSW from GLEV
    let now = Instant::now();
    let mut ggsw_bit_list = GgswCiphertextList::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
        GgswCiphertextCount(vec_glev.len()),
        ciphertext_modulus,
    );
    for (mut ggsw, glev) in ggsw_bit_list.iter_mut().zip(vec_glev.iter()) {
        for (col, mut glwe_list) in ggsw.as_mut_glwe_list().chunks_exact_mut(glwe_size.0).enumerate() {
            let glwe_bit = glev.get(col);
            let (mut glwe_mask_list, mut glwe_body_list) = glwe_list.split_at_mut(glwe_dimension.0);

            for (mut glwe_mask, fourier_ss_key) in glwe_mask_list.iter_mut().zip(ss_key.into_ggsw_iter()) {
                add_external_product_assign(&mut glwe_mask, &fourier_ss_key, &glwe_bit);
            }
            glwe_ciphertext_clone_from(glwe_body_list.get_mut(0).as_mut_view(), glwe_bit.as_view());
        }
    }
    let mut time_ggsw = now.elapsed();

    println!("---- GGSW Ctxts Error ----");
    for (i, ggsw) in ggsw_bit_list.iter().enumerate() {
        let max_err = get_max_err_ggsw_bit(&glwe_sk, ggsw, *input_bits.get(i).unwrap());
        let log_max_err = (max_err as f64).log2();
        println!("ggsw[{i}] {log_max_err:.2}");
    }
    println!();

    let now = Instant::now();
    let mut fourier_ggsw_bit_list = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            bit_length * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * ggsw_level.0
        ],
        bit_length,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
    );

    for (mut fourier_ggsw, ggsw) in fourier_ggsw_bit_list.as_mut_view().into_ggsw_iter().zip(ggsw_bit_list.iter()) {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }
    time_ggsw += now.elapsed();

    // Homomorphic LUT
    println!("---- Homomorphic LUT Results ----");
    let mut time_lut = Duration::ZERO;
    let now = Instant::now();
    let accumulator = (0..polynomial_size.0).map(|i| {
        let table_idx = i / (1 << bit_length);
        let table = vec_table.get(table_idx).unwrap();
        table[i % (1 << bit_length)] << 63
    }).collect::<Vec<u64>>();
    let accumulator_plaintext = PlaintextList::from_container(accumulator);
    let mut accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext, ciphertext_modulus);
    time_lut += now.elapsed();

    let mut vec_acc_err = vec![0u64; bit_length];
    let mut vec_lut_err = vec![vec![0u64; bit_length]; num_lut];
    let mut tmp_plain_accumulator = accumulator.clone();
    let mut tmp_table_input = 0;
    for (bit_idx, fourier_ggsw_bit) in fourier_ggsw_bit_list.as_view().into_ggsw_iter().into_iter().enumerate() {
        let now = Instant::now();
        let mut buf = accumulator.clone();
        glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(1 << bit_idx));
        glwe_ciphertext_sub_assign(&mut buf, &accumulator);
        add_external_product_assign(&mut accumulator, &fourier_ggsw_bit, &buf);
        time_lut += now.elapsed();

        let cur_input_bit = *input_bits.get(bit_idx).unwrap();
        tmp_table_input += cur_input_bit << bit_idx;
        glwe_ciphertext_monic_monomial_div_assign(&mut tmp_plain_accumulator, MonomialDegree((cur_input_bit << bit_idx) as usize));

        let mut dec = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &accumulator, &mut dec);

        let mut correct_acc = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &tmp_plain_accumulator, &mut correct_acc);

        let mut max_err = 0u64;
        for i in 0..polynomial_size.0 {
            let abs_err = {
                let decrypted = *dec.get(i).0;
                let correct_val = *correct_acc.get(i).0;
                let d0 = decrypted.wrapping_sub(correct_val);
                let d1 = correct_val.wrapping_sub(decrypted);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        vec_acc_err[bit_idx] = max_err;

        for j in 0..num_lut {
            let mut lwe_out = LweCiphertext::new(0u64, fourier_bsk.output_lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut lwe_out, MonomialDegree(j * (1 << bit_length)));

            let tmp_table_output = vec_table.get(j).unwrap()[tmp_table_input as usize];
            let (decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe_out, tmp_table_output, 1 << 63);
            if decoded != tmp_table_output {
                println!("LUT fails");
                return;
            }
            vec_lut_err[j][bit_idx] = abs_err;
        }
    }

    print!("Acc");
    for i in 0..bit_length {
        print!(" {:.2}", (vec_acc_err[i] as f64).log2());
    }
    println!();

    for j in 0..num_lut {
        print!("Table[{j}]");
        for i in 0..bit_length {
            print!(" {:.2}", (vec_lut_err[j][i] as f64).log2());
        }
        println!();
    }

    println!("\n---- Time ----");
    println!("Time LWEtoGLEV:  {} ms", time_glev.as_micros() as f64 / 1000f64);
    println!("Time GLEVtoGGSW: {} ms", time_ggsw.as_micros() as f64 / 1000f64);
    println!("Time LUT:        {} ms", time_lut.as_micros() as f64 / 1000f64);
}

fn test_ggsw_lut_by_trace(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_modular_std_dev: impl DispersionParameter,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== GGSW LUT by trace ====
n: {}, N: {}, k: {}, l_ks: {}, B_ks: 2^{}
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, ks_level.0, ks_base_log.0,
        pbs_level.0, pbs_base_log.0, ggsw_level.0, ggsw_base_log.0, log_lut_count.0,
        auto_level.0, auto_base_log.0, ss_level.0, ss_base_log.0,
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let small_lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let _ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &small_lwe_sk,
        ks_base_log,
        ks_level,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

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

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Set input and lookup tables
    let glwe_size = glwe_dimension.to_glwe_size();
    let polynomial_size = polynomial_size;

    let mut rng = rand::thread_rng();
    let bit_length = 8;
    assert!(polynomial_size.0 >= (1 << bit_length));

    let input_bits = (0..bit_length).map(|_| {
        rng.gen_range(0..2) as u64
    }).collect::<Vec<u64>>();

    let num_lut = polynomial_size.0 / (1 << bit_length);
    let vec_table = (0..num_lut).map(|_| {
        (0..(1 << bit_length)).map(|_| {
            rng.gen_range(0..2) as u64
        }).collect::<Vec<u64>>()
    }).collect::<Vec<Vec<u64>>>();

    // Make GLEV from LWE
    let mut lwe_list_in = LweCiphertextList::new(
        0u64,
        lwe_dimension.to_lwe_size(),
        LweCiphertextCount(bit_length),
        ciphertext_modulus,
    );
    for (mut lwe_in, bit_in) in lwe_list_in.iter_mut().zip(input_bits.iter()) {
        encrypt_lwe_ciphertext(&small_lwe_sk, &mut lwe_in, Plaintext(bit_in << 63), lwe_modular_std_dev, &mut encryption_generator);
    }

    let now = Instant::now();
    let mut vec_glev = vec![
        GlweCiphertextList::new(
            0u64,
            glwe_size,
            polynomial_size,
            GlweCiphertextCount(ggsw_level.0),
            ciphertext_modulus
        ); bit_length];
    for (lwe_in, glev) in lwe_list_in.iter().zip(vec_glev.iter_mut()) {
        let glev_mut_view = GlweCiphertextListMutView::from_container(
            glev.as_mut(),
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );
        lwe_msb_bit_to_glev_by_trace(
            lwe_in.as_view(),
            glev_mut_view,
            fourier_bsk,
            &auto_keys,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }
    let time_glev = now.elapsed();

    println!("---- GLEV Ctxts Error ----");
    for (idx, glev) in vec_glev.iter().enumerate() {
        print!("GLEV[{idx}] ");
        let input_bit = input_bits.get(idx).unwrap();
        for (k, glwe) in glev.iter().enumerate() {
            let mut max_err = 0u64;
            let level = k + 1;
            let mut pt = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut pt);
            for i in 0..polynomial_size.0 {
                let decrypted_u64 = *pt.get(i).0;
                let correct_val = if i == 0 {(*input_bit) << (64 - level * ggsw_base_log.0)} else {0};
                let abs_err = {
                    let d0 = decrypted_u64.wrapping_sub(correct_val);
                    let d1 = correct_val.wrapping_sub(decrypted_u64);
                    std::cmp::min(d0, d1)
                };
                max_err = std::cmp::max(max_err, abs_err);
            }
            let log_max_err = (max_err as f64).log2();
            print!("{log_max_err:.2} ");
        }
        println!();
    }
    println!();

    // Make GGSW from GLEV
    let now = Instant::now();
    let mut ggsw_bit_list = GgswCiphertextList::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
        GgswCiphertextCount(vec_glev.len()),
        ciphertext_modulus,
    );
    for (mut ggsw, glev) in ggsw_bit_list.iter_mut().zip(vec_glev.iter()) {
        for (col, mut glwe_list) in ggsw.as_mut_glwe_list().chunks_exact_mut(glwe_size.0).enumerate() {
            let glwe_bit = glev.get(col);
            let (mut glwe_mask_list, mut glwe_body_list) = glwe_list.split_at_mut(glwe_dimension.0);

            for (mut glwe_mask, fourier_ss_key) in glwe_mask_list.iter_mut().zip(ss_key.into_ggsw_iter()) {
                add_external_product_assign(&mut glwe_mask, &fourier_ss_key, &glwe_bit);
            }
            glwe_ciphertext_clone_from(glwe_body_list.get_mut(0).as_mut_view(), glwe_bit.as_view());
        }
    }
    let mut time_ggsw = now.elapsed();

    println!("---- GGSW Ctxts Error ----");
    for (i, ggsw) in ggsw_bit_list.iter().enumerate() {
        let max_err = get_max_err_ggsw_bit(&glwe_sk, ggsw, *input_bits.get(i).unwrap());
        let log_max_err = (max_err as f64).log2();
        println!("ggsw[{i}] {log_max_err:.2}");
    }
    println!();

    let now = Instant::now();
    let mut fourier_ggsw_bit_list = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            bit_length * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * ggsw_level.0
        ],
        bit_length,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
    );

    for (mut fourier_ggsw, ggsw) in fourier_ggsw_bit_list.as_mut_view().into_ggsw_iter().zip(ggsw_bit_list.iter()) {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }
    time_ggsw += now.elapsed();

    // Homomorphic LUT
    println!("---- Homomorphic LUT Results ----");
    let mut time_lut = Duration::ZERO;
    let now = Instant::now();
    let accumulator = (0..polynomial_size.0).map(|i| {
        let table_idx = i / (1 << bit_length);
        let table = vec_table.get(table_idx).unwrap();
        table[i % (1 << bit_length)] << 63
    }).collect::<Vec<u64>>();
    let accumulator_plaintext = PlaintextList::from_container(accumulator);
    let mut accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext, ciphertext_modulus);
    time_lut += now.elapsed();

    let mut vec_acc_err = vec![0u64; bit_length];
    let mut vec_lut_err = vec![vec![0u64; bit_length]; num_lut];
    let mut tmp_plain_accumulator = accumulator.clone();
    let mut tmp_table_input = 0;
    for (bit_idx, fourier_ggsw_bit) in fourier_ggsw_bit_list.as_view().into_ggsw_iter().into_iter().enumerate() {
        let now = Instant::now();
        let mut buf = accumulator.clone();
        glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(1 << bit_idx));
        glwe_ciphertext_sub_assign(&mut buf, &accumulator);
        add_external_product_assign(&mut accumulator, &fourier_ggsw_bit, &buf);
        time_lut += now.elapsed();

        let cur_input_bit = *input_bits.get(bit_idx).unwrap();
        tmp_table_input += cur_input_bit << bit_idx;
        glwe_ciphertext_monic_monomial_div_assign(&mut tmp_plain_accumulator, MonomialDegree((cur_input_bit << bit_idx) as usize));

        let mut dec = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &accumulator, &mut dec);

        let mut correct_acc = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &tmp_plain_accumulator, &mut correct_acc);

        let mut max_err = 0u64;
        for i in 0..polynomial_size.0 {
            let abs_err = {
                let decrypted = *dec.get(i).0;
                let correct_val = *correct_acc.get(i).0;
                let d0 = decrypted.wrapping_sub(correct_val);
                let d1 = correct_val.wrapping_sub(decrypted);
                std::cmp::min(d0, d1)
            };
            max_err = std::cmp::max(max_err, abs_err);
        }
        vec_acc_err[bit_idx] = max_err;

        for j in 0..num_lut {
            let mut lwe_out = LweCiphertext::new(0u64, fourier_bsk.output_lwe_dimension().to_lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut lwe_out, MonomialDegree(j * (1 << bit_length)));

            let tmp_table_output = vec_table.get(j).unwrap()[tmp_table_input as usize];
            let (decoded, abs_err) = get_val_and_abs_err(&big_lwe_sk, &lwe_out, tmp_table_output, 1 << 63);
            if decoded != tmp_table_output {
                println!("LUT fails");
                return;
            }
            vec_lut_err[j][bit_idx] = abs_err;
        }
    }

    print!("Acc");
    for i in 0..bit_length {
        print!(" {:.2}", (vec_acc_err[i] as f64).log2());
    }
    println!();

    for j in 0..num_lut {
        print!("Table[{j}]");
        for i in 0..bit_length {
            print!(" {:.2}", (vec_lut_err[j][i] as f64).log2());
        }
        println!();
    }

    println!("\n---- Time ----");
    println!("Time LWEtoGLEV:  {} ms", time_glev.as_micros() as f64 / 1000f64);
    println!("Time GLEVtoGGSW: {} ms", time_ggsw.as_micros() as f64 / 1000f64);
    println!("Time LUT:        {} ms", time_lut.as_micros() as f64 / 1000f64);
}
