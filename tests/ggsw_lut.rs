use tfhe::core_crypto::{prelude::*, fft_impl::fft64::c64};
use hom_trace::{automorphism::*, ggsw_conv::*, keygen_pbs, utils::*, FftType};
use rand::Rng;
use std::time::{Instant, Duration};

fn main() {
    // GGSW LUT by trace with preprocessing
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
    let fft_type = FftType::Vanilla;
    let ggsw_base_log = DecompositionBaseLog(5);
    let ggsw_level = DecompositionLevelCount(2);
    let log_lut_count = LutCountLog(1);

    test_ggsw_lut_by_trace_with_preprocessing(
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
        fft_type,
        ggsw_base_log,
        ggsw_level,
        log_lut_count,
        ciphertext_modulus,
    );
    println!();
    println!();

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
}


fn test_ggsw_lut_by_trace_with_preprocessing(
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
    fft_type: FftType,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<u64>,
) {
    println!(
"==== GGSW LUT by trace with preprocessing ====
n: {}, N: {}, k: {}, l_ks: {}, B_ks: 2^{}
l_pbs: {}, B_pbs: 2^{}, l_ggsw: {}, B_ggsw: 2^{}, LutCount: 2^{},
l_auto: {}, B_auto: 2^{}, fft type: {:?}, l_ss: {}, B_ss: 2^{}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, ks_level.0, ks_base_log.0,
        pbs_level.0, pbs_base_log.0, ggsw_level.0, ggsw_base_log.0, log_lut_count.0,
        auto_level.0, auto_base_log.0, fft_type, ss_level.0, ss_base_log.0,
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let (
        _big_lwe_sk,
        glwe_sk,
        small_lwe_sk,
        fourier_bsk,
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
        fft_type,
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
        lwe_msb_bit_to_glev_by_trace_with_preprocessing(
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
        switch_scheme(&glev, &mut ggsw, ss_key);
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
    let (time_lut, vec_acc_err, vec_lut_err) = homomorphic_lut(
        &vec_table,
        &input_bits,
        fourier_ggsw_bit_list.as_view(),
        &glwe_sk,
        ciphertext_modulus,
    );

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
    let (
        big_lwe_sk,
        glwe_sk,
        small_lwe_sk,
        fourier_bsk,
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
        switch_scheme(&glev, &mut ggsw, ss_key);
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
    let (time_lut, vec_acc_err, vec_lut_err) = homomorphic_lut(
        &vec_table,
        &input_bits,
        fourier_ggsw_bit_list,
        &glwe_sk,
        ciphertext_modulus,
    );

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


fn homomorphic_lut<Scalar, C>(
    vec_table: &Vec<Vec<Scalar>>,
    input_bits: &Vec<Scalar>,
    fourier_ggsw_list: FourierGgswCiphertextList<C>,
    glwe_secret_key: &GlweSecretKeyOwned<Scalar>,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
) -> (Duration, Vec<Scalar>, Vec<Vec<Scalar>>)
where
    Scalar: UnsignedTorus + CastInto<usize>,
    C: Container<Element=c64>,
{
    let lwe_secret_key = glwe_secret_key.clone().into_lwe_secret_key();
    let lwe_size = lwe_secret_key.lwe_dimension().to_lwe_size();

    let bit_length = input_bits.len();
    assert_eq!(bit_length, fourier_ggsw_list.as_view().into_ggsw_iter().count());

    let glwe_size = fourier_ggsw_list.glwe_size();
    let polynomial_size = fourier_ggsw_list.polynomial_size().0;
    assert!(polynomial_size >= (1 << bit_length), "not enough polynomial size for homomorphic_lut");

    let num_lut = polynomial_size / (1 << bit_length);

    let mut time = Duration::ZERO;
    let now = Instant::now();
    let accumulator = (0..polynomial_size).map(|i| {
        let table_idx = i / (1 << bit_length);
        let table = vec_table.get(table_idx).unwrap();
        table[i % (1 << bit_length)] << (Scalar::BITS - 1)
    }).collect::<Vec<Scalar>>();
    let accumulator_plaintext = PlaintextList::from_container(accumulator);
    let mut accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext, ciphertext_modulus);

    let mut tmp_plain_accumulator = accumulator.clone();
    let mut tmp_table_input = 0usize;
    time += now.elapsed();

    let mut vec_acc_err = vec![Scalar::ZERO; bit_length];
    let mut vec_lut_err = vec![vec![Scalar:: ZERO; bit_length]; num_lut];

    for (bit_idx, fourier_ggsw_bit) in fourier_ggsw_list.as_view().into_ggsw_iter().into_iter().enumerate() {
        let now = Instant::now();
        let mut buf = accumulator.clone();
        glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(1 << bit_idx));
        glwe_ciphertext_sub_assign(&mut buf, &accumulator);
        add_external_product_assign(&mut accumulator, &fourier_ggsw_bit, &buf);
        time += now.elapsed();

        let cur_input_bit: usize = (*input_bits.get(bit_idx).unwrap()).cast_into();
        tmp_table_input += cur_input_bit << bit_idx;
        glwe_ciphertext_monic_monomial_div_assign(&mut tmp_plain_accumulator, MonomialDegree(cur_input_bit << bit_idx));

        let mut dec = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size));
        decrypt_glwe_ciphertext(&glwe_secret_key, &accumulator, &mut dec);

        let mut correct_acc = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size));
        decrypt_glwe_ciphertext(&glwe_secret_key, &tmp_plain_accumulator, &mut correct_acc);

        let mut max_err = Scalar::ZERO;
        for i in 0..polynomial_size {
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
            let mut lwe_out = LweCiphertext::new(Scalar::ZERO, lwe_size, ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut lwe_out, MonomialDegree(j << bit_length));

            let tmp_table_output = vec_table.get(j).unwrap()[tmp_table_input as usize];
            let (_decoded, abs_err) = get_val_and_abs_err(&lwe_secret_key, &lwe_out, tmp_table_output, Scalar::ONE << (Scalar::BITS - 1));
            vec_lut_err[j][bit_idx] = abs_err;
        }
    }

    (time, vec_acc_err, vec_lut_err)
}
