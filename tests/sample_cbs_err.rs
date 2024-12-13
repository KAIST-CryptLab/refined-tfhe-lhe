use auto_base_conv::{blind_rotate_for_msb, convert_to_ggsw_after_blind_rotate, get_max_err_ggsw_bit};
use rand::Rng;
use tfhe::core_crypto::prelude::*;
#[allow(unused)]
use auto_base_conv::{allocate_and_generate_new_glwe_keyswitch_key, convert_lwe_to_glwe_by_trace_with_preprocessing, convert_lwe_to_glwe_by_trace_with_preprocessing_high_prec, convert_standard_glwe_keyswitch_key_to_fourier, gen_all_auto_keys, generate_scheme_switching_key, get_glwe_l2_err, get_glwe_max_err, keygen_pbs, lwe_msb_bit_to_lev, switch_scheme, wopbs_instance::*, wopbs_params::ImprovedWopbsParam, wwlp_cbs_instance::*, FourierGlweKeyswitchKey, HighPrecWWLpCBSParam, WWLpCBSParam};

type Scalar = u64;
const NUM_REPEAT: usize = 1000;

fn main() {
    // CMUX1
    println!("# Sample: {NUM_REPEAT}\n");
    println!("-------- CMUX1 --------");
    sample_cmux_cbs_error(
        *BITWISE_CBS_CMUX1,
        NUM_REPEAT,
    );
    println!();

    // CMUX2
    println!("-------- CMUX2 --------");
    sample_cmux_cbs_error(
        *BITWISE_CBS_CMUX2,
        NUM_REPEAT,
    );
    println!();

    // CMUX3
    println!("-------- CMUX3 --------");
    sample_cmux_cbs_error(
        *BITWISE_CBS_CMUX3,
        NUM_REPEAT,
    );
    println!();
}

#[allow(unused)]
fn sample_cmux_cbs_error(
    param: ImprovedWopbsParam<u64>,
    num_repeat: usize,
) {
    let lwe_dimension = param.lwe_dimension();
    let lwe_modular_std_dev = param.lwe_modular_std_dev();
    let glwe_dimension = param.glwe_dimension();
    let polynomial_size = param.polynomial_size();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pbs_base_log = param.pbs_base_log();
    let pbs_level = param.pbs_level();
    let ks_base_log = param.ks_base_log();
    let ks_level = param.ks_level();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let auto_fft_type = param.fft_type_auto();
    let ss_base_log = param.ss_base_log();
    let ss_level = param.ss_level();
    let cbs_base_log = param.cbs_base_log();
    let cbs_level = param.cbs_level();
    let log_lut_count = param.log_lut_count();
    let ciphertext_modulus = param.ciphertext_modulus();

    println!(
"n: {}, N: {}, k: {}, B_pbs: 2^{}, l_pbs: {}, B_ks: 2^{}, l_ks: {}, B_cbs: 2^{}, l_cbs: {},
B_auto: 2^{}, l_auto: {}, fft_type: {:?}, B_ss: 2^{}, l_ss: {}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_base_log.0, pbs_level.0, ks_base_log.0, ks_level.0, cbs_base_log.0, cbs_level.0,
        auto_base_log.0, auto_level.0, auto_fft_type, ss_base_log.0, ss_level.0,
    );

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

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        auto_fft_type,
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

    let mut cbs_l_infty_err_list = vec![];

    for _ in 0..num_repeat {
        // Set input LWE ciphertext
        let mut rng = rand::thread_rng();
        let msg = rng.gen_range(0..2);
        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            Plaintext(msg << (u64::BITS - 1)),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut ggsw = GgswCiphertext::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);

        let mut acc_glev = GlweCiphertextList::new(0u64, glwe_size, polynomial_size, GlweCiphertextCount(cbs_level.0), ciphertext_modulus);

        let mut lwe_ks = LweCiphertext::new(0u64, ksk.output_lwe_size(), ciphertext_modulus);
        keyswitch_lwe_ciphertext(&ksk, &lwe, &mut lwe_ks);

        blind_rotate_for_msb(
            &lwe_ks,
            &mut acc_glev,
            bsk,
            log_lut_count,
            cbs_base_log,
            cbs_level,
            1,
            ciphertext_modulus,
        );

        convert_to_ggsw_after_blind_rotate(
            &acc_glev,
            &mut ggsw,
            0,
            &auto_keys,
            ss_key,
            ciphertext_modulus,
        );

        let err = get_max_err_ggsw_bit(&glwe_sk, ggsw.as_view(), msg);
        cbs_l_infty_err_list.push(err);
    }

    let mut sum_err = 0u64;
    let mut max_err = 0u64;
    for err in cbs_l_infty_err_list.iter() {
        sum_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (sum_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("Infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());
}


#[allow(unused)]
fn sample_wwlp_cbs_err(
    param: WWLpCBSParam<u64>,
    pfks_base_log: DecompositionBaseLog,
    pfks_level: DecompositionLevelCount,
    num_repeat: usize,
) {
    let lwe_dimension = param.lwe_dimension();
    let lwe_modular_std_dev = param.lwe_modular_std_dev();
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pbs_base_log = param.pbs_base_log();
    let pbs_level = param.pbs_level();
    let ks_base_log = param.ks_base_log();
    let ks_level = param.ks_level();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type_auto = param.fft_type_auto();
    let ss_base_log = param.ss_base_log();
    let ss_level = param.ss_level();
    let cbs_base_log = param.cbs_base_log();
    let cbs_level = param.cbs_level();

    println!(
"n: {}, N: {}, k: {}, B_pbs: 2^{}, l_pbs: {}, B_ks: 2^{}, l_ks: {}, B_cbs: 2^{}, l_cbs: {},
B_pfks: 2^{}, l_pfks: {},
B_auto: 2^{}, l_auto: {}, fft_type: {:?}, B_ss: 2^{}, l_ss: {}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_base_log.0, pbs_level.0, ks_base_log.0, ks_level.0, cbs_base_log.0, cbs_level.0,
        pfks_base_log.0, pfks_level.0,
        auto_base_log.0, auto_level.0, fft_type_auto, ss_base_log.0, ss_level.0,
    );
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
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

    let glwe_sk_poly_list = glwe_sk.as_polynomial_list();

    let pfpksk_list = allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &lwe_sk,
        &glwe_sk,
        pfks_base_log,
        pfks_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type_auto,
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

    let mut cbs_l_infty_err_list = vec![];
    let mut cbs_l2_err_list = vec![];
    let mut ep_l_infty_err_list = vec![];
    let mut ep_l2_err_list = vec![];

    let mut wwlp_cbs_l_infty_err_list = vec![];
    let mut wwlp_cbs_l2_err_list = vec![];
    let mut wwlp_ep_l_infty_err_list = vec![];
    let mut wwlp_ep_l2_err_list = vec![];

    let mut rng = rand::thread_rng();

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..2) as Scalar;

        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk_after_ks,
            Plaintext(msg << (Scalar::BITS - 1)),
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        /* Original CBS */
        let mut lev = LweCiphertextList::new(Scalar::ZERO, lwe_sk.lwe_dimension().to_lwe_size(), LweCiphertextCount(cbs_level.0), ciphertext_modulus);
        lwe_msb_bit_to_lev(&lwe, &mut lev, bsk, cbs_base_log, cbs_level, LutCountLog(0));

        let mut max_l_infty_err = Scalar::ZERO;
        let mut max_l2_err = f64::default();

        let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);
        for (k, (lwe, mut ggsw_level_matrix)) in lev.iter()
            .zip(ggsw.iter_mut())
            .enumerate()
        {
            let level = k + 1;
            let log_scale = Scalar::BITS as usize - level * cbs_base_log.0;

            for (i, (pfpksk, mut glwe)) in pfpksk_list.iter()
                .zip(ggsw_level_matrix.as_mut_glwe_list().iter_mut())
                .enumerate()
            {
                private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                    &pfpksk,
                    &mut glwe,
                    &lwe,
                );

                let correct_val_list = if msg == 0 {
                    PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0))
                } else {
                    if i < glwe_dimension.0 {
                        let sk_i = glwe_sk_poly_list.get(i);
                        PlaintextList::from_container((0..polynomial_size.0).map(|j| {
                            let val = *sk_i.as_ref().get(j).unwrap();
                            val.wrapping_neg() << log_scale
                        }).collect::<Vec<Scalar>>())
                    } else {
                        PlaintextList::from_container((0..polynomial_size.0).map(|j| {
                            if j == 0 {Scalar::ONE << log_scale} else {Scalar::ZERO}
                        }).collect::<Vec<Scalar>>())
                    }
                };

                let l_infty_err = get_glwe_max_err(&glwe_sk, &glwe, &correct_val_list);
                let l2_err = get_glwe_l2_err(&glwe_sk, &glwe, &correct_val_list);

                max_l_infty_err = std::cmp::max(max_l_infty_err, l_infty_err);
                max_l2_err = if max_l2_err < l2_err {l2_err} else {max_l2_err};
            }
        }

        cbs_l_infty_err_list.push(max_l_infty_err);
        cbs_l2_err_list.push(max_l2_err);

        let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);

        let pt = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        let mut glwe = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut glwe,
            &pt,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );
        let mut out = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        add_external_product_assign(&mut out, &fourier_ggsw, &glwe);

        let ep_max_err = get_glwe_max_err(&glwe_sk, &out, &pt);
        let ep_l2_err = get_glwe_l2_err(&glwe_sk, &out, &pt);

        ep_l_infty_err_list.push(ep_max_err);
        ep_l2_err_list.push(ep_l2_err);


        /* WWL+ CBS */
        let mut lev = LweCiphertextList::new(Scalar::ZERO, lwe_sk.lwe_dimension().to_lwe_size(), LweCiphertextCount(cbs_level.0), ciphertext_modulus);
        lwe_msb_bit_to_lev(&lwe, &mut lev, bsk, cbs_base_log, cbs_level, LutCountLog(3));

        let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(cbs_level.0), ciphertext_modulus);
        for (lwe, mut glwe) in lev.iter().zip(glev.iter_mut()) {
            convert_lwe_to_glwe_by_trace_with_preprocessing(&lwe, &mut glwe, &auto_keys);
        }

        let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);
        switch_scheme(&glev, &mut ggsw, ss_key);

        let mut max_l_infty_err = Scalar::ZERO;
        let mut max_l2_err = f64::default();

        for (k, ggsw_level_matrix) in ggsw.iter().enumerate() {
            let level = k + 1;
            let log_scale = Scalar::BITS as usize - level * cbs_base_log.0;

            for (i, glwe) in ggsw_level_matrix.as_glwe_list().iter().enumerate() {
                let correct_val_list = if msg == 0 {
                    PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0))
                } else {
                    if i < glwe_dimension.0 {
                        let sk_i = glwe_sk_poly_list.get(i);
                        PlaintextList::from_container((0..polynomial_size.0).map(|j| {
                            let val = *sk_i.as_ref().get(j).unwrap();
                            val.wrapping_neg() << log_scale
                        }).collect::<Vec<Scalar>>())
                    } else {
                        PlaintextList::from_container((0..polynomial_size.0).map(|j| {
                            if j == 0 {Scalar::ONE << log_scale} else {Scalar::ZERO}
                        }).collect::<Vec<Scalar>>())
                    }
                };

                let l_infty_err = get_glwe_max_err(&glwe_sk, &glwe, &correct_val_list);
                let l2_err = get_glwe_l2_err(&glwe_sk, &glwe, &correct_val_list);

                max_l_infty_err = std::cmp::max(max_l_infty_err, l_infty_err);
                max_l2_err = if max_l2_err < l2_err {l2_err} else {max_l2_err};
            }
        }

        wwlp_cbs_l_infty_err_list.push(max_l_infty_err);
        wwlp_cbs_l2_err_list.push(max_l2_err);

        let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);

        let pt = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        let mut glwe = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut glwe,
            &pt,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );
        let mut out = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        add_external_product_assign(&mut out, &fourier_ggsw, &glwe);

        let ep_max_err = get_glwe_max_err(&glwe_sk, &out, &pt);
        let ep_l2_err = get_glwe_l2_err(&glwe_sk, &out, &pt);

        wwlp_ep_l_infty_err_list.push(ep_max_err);
        wwlp_ep_l2_err_list.push(ep_l2_err);
    }

    println!("Original cbs error");
    println!("CBS output error");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in cbs_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in cbs_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());

    println!("External product error");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in ep_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in ep_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());

    println!("Patched WWL+ cbs error");
    println!("CBS output error");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in wwlp_cbs_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in wwlp_cbs_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());

    println!("External product error");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in wwlp_ep_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in wwlp_ep_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}


#[allow(unused)]
fn sample_high_prec_wwlp_cbs_err(
    param: HighPrecWWLpCBSParam<u64>,
    pfks_base_log: DecompositionBaseLog,
    pfks_level: DecompositionLevelCount,
    num_repeat: usize,
) {
    let lwe_dimension = param.lwe_dimension();
    let lwe_modular_std_dev = param.lwe_modular_std_dev();
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let large_glwe_dimension = param.large_glwe_dimension();
    let large_glwe_modular_std_dev = param.large_glwe_modular_std_dev();
    let pbs_base_log = param.pbs_base_log();
    let pbs_level = param.pbs_level();
    let ks_base_log = param.ks_base_log();
    let ks_level = param.ks_level();
    let glwe_ds_to_large_base_log = param.glwe_ds_to_large_base_log();
    let glwe_ds_to_large_level = param.glwe_ds_to_large_level();
    let fft_type_to_large = param.fft_type_to_large();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type_auto = param.fft_type_auto();
    let glwe_ds_from_large_base_log = param.glwe_ds_from_large_base_log();
    let glwe_ds_from_large_level = param.glwe_ds_from_large_level();
    let fft_type_from_large = param.fft_type_from_large();
    let ss_base_log = param.ss_base_log();
    let ss_level = param.ss_level();
    let cbs_base_log = param.cbs_base_log();
    let cbs_level = param.cbs_level();

    println!(
"n: {}, N: {}, k: {}, B_pbs: 2^{}, l_pbs: {}, B_ks: 2^{}, l_ks: {}, B_cbs: 2^{}, l_cbs: {},
B_pfks: 2^{}, l_pfks: {},
B_auto: 2^{}, l_auto: {}, fft_type_auto: {:?},
B_to_large: 2^{}, l_to_large: {}, fft_type_to_large: {:?},
B_from_large: 2^{}, l_from_large: {}, fft_type_from_large: {:?},
B_ss: 2^{}, l_ss: {}\n",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_base_log.0, pbs_level.0, ks_base_log.0, ks_level.0, cbs_base_log.0, cbs_level.0,
        pfks_base_log.0, pfks_level.0,
        auto_base_log.0, auto_level.0, fft_type_auto,
        glwe_ds_to_large_base_log.0, glwe_ds_to_large_level.0, fft_type_to_large,
        glwe_ds_from_large_base_log.0, glwe_ds_from_large_level.0, fft_type_from_large,
        ss_base_log.0, ss_level.0,
    );
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
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

    let glwe_sk_poly_list = glwe_sk.as_polynomial_list();

    let pfpksk_list = allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &lwe_sk,
        &glwe_sk,
        pfks_base_log,
        pfks_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let large_glwe_sk = GlweSecretKey::generate_new_binary(large_glwe_dimension, polynomial_size, &mut secret_generator);
    let large_glwe_size = large_glwe_dimension.to_glwe_size();

    let glwe_dsk_to_large = allocate_and_generate_new_glwe_keyswitch_key(
        &glwe_sk,
        &large_glwe_sk,
        glwe_ds_to_large_base_log,
        glwe_ds_to_large_level,
        large_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_dsk_to_large = FourierGlweKeyswitchKey::new(
        glwe_size,
        large_glwe_size,
        polynomial_size,
        glwe_ds_to_large_base_log,
        glwe_ds_to_large_level,
        fft_type_to_large,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&glwe_dsk_to_large, &mut fourier_glwe_dsk_to_large);

    let glwe_dsk_from_large = allocate_and_generate_new_glwe_keyswitch_key(
        &large_glwe_sk,
        &glwe_sk,
        glwe_ds_from_large_base_log,
        glwe_ds_from_large_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_glwe_dsk_from_large = FourierGlweKeyswitchKey::new(
        large_glwe_size,
        glwe_size,
        polynomial_size,
        glwe_ds_from_large_base_log,
        glwe_ds_from_large_level,
        fft_type_from_large,
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&glwe_dsk_from_large, &mut fourier_glwe_dsk_from_large);

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type_auto,
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

    let mut cbs_l_infty_err_list = vec![];
    let mut cbs_l2_err_list = vec![];
    let mut ep_l_infty_err_list = vec![];
    let mut ep_l2_err_list = vec![];

    let mut wwlp_cbs_l_infty_err_list = vec![];
    let mut wwlp_cbs_l2_err_list = vec![];
    let mut wwlp_ep_l_infty_err_list = vec![];
    let mut wwlp_ep_l2_err_list = vec![];

    let mut rng = rand::thread_rng();

    for _ in 0..num_repeat {
        let msg = rng.gen_range(0..2) as Scalar;

        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk_after_ks,
            Plaintext(msg << (Scalar::BITS - 1)),
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        /* Original CBS */
        let mut lev = LweCiphertextList::new(Scalar::ZERO, lwe_sk.lwe_dimension().to_lwe_size(), LweCiphertextCount(cbs_level.0), ciphertext_modulus);
        lwe_msb_bit_to_lev(&lwe, &mut lev, bsk, cbs_base_log, cbs_level, LutCountLog(0));

        let mut max_l_infty_err = Scalar::ZERO;
        let mut max_l2_err = f64::default();

        let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);
        for (k, (lwe, mut ggsw_level_matrix)) in lev.iter()
            .zip(ggsw.iter_mut())
            .enumerate()
        {
            let level = k + 1;
            let log_scale = Scalar::BITS as usize - level * cbs_base_log.0;

            for (i, (pfpksk, mut glwe)) in pfpksk_list.iter()
                .zip(ggsw_level_matrix.as_mut_glwe_list().iter_mut())
                .enumerate()
            {
                private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                    &pfpksk,
                    &mut glwe,
                    &lwe,
                );

                let correct_val_list = if msg == 0 {
                    PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0))
                } else {
                    if i < glwe_dimension.0 {
                        let sk_i = glwe_sk_poly_list.get(i);
                        PlaintextList::from_container((0..polynomial_size.0).map(|j| {
                            let val = *sk_i.as_ref().get(j).unwrap();
                            val.wrapping_neg() << log_scale
                        }).collect::<Vec<Scalar>>())
                    } else {
                        PlaintextList::from_container((0..polynomial_size.0).map(|j| {
                            if j == 0 {Scalar::ONE << log_scale} else {Scalar::ZERO}
                        }).collect::<Vec<Scalar>>())
                    }
                };

                let l_infty_err = get_glwe_max_err(&glwe_sk, &glwe, &correct_val_list);
                let l2_err = get_glwe_l2_err(&glwe_sk, &glwe, &correct_val_list);

                max_l_infty_err = std::cmp::max(max_l_infty_err, l_infty_err);
                max_l2_err = if max_l2_err < l2_err {l2_err} else {max_l2_err};
            }
        }

        cbs_l_infty_err_list.push(max_l_infty_err);
        cbs_l2_err_list.push(max_l2_err);

        let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);

        let pt = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        let mut glwe = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut glwe,
            &pt,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );
        let mut out = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        add_external_product_assign(&mut out, &fourier_ggsw, &glwe);

        let ep_max_err = get_glwe_max_err(&glwe_sk, &out, &pt);
        let ep_l2_err = get_glwe_l2_err(&glwe_sk, &out, &pt);

        ep_l_infty_err_list.push(ep_max_err);
        ep_l2_err_list.push(ep_l2_err);


        /* High Prec WWL+ CBS */
        let mut lev = LweCiphertextList::new(Scalar::ZERO, lwe_sk.lwe_dimension().to_lwe_size(), LweCiphertextCount(cbs_level.0), ciphertext_modulus);
        lwe_msb_bit_to_lev(&lwe, &mut lev, bsk, cbs_base_log, cbs_level, LutCountLog(3));

        let mut glev = GlweCiphertextList::new(Scalar::ZERO, glwe_size, polynomial_size, GlweCiphertextCount(cbs_level.0), ciphertext_modulus);
        for (lwe, mut glwe) in lev.iter().zip(glev.iter_mut()) {
            convert_lwe_to_glwe_by_trace_with_preprocessing_high_prec(&lwe, &mut glwe, &fourier_glwe_dsk_to_large, &fourier_glwe_dsk_from_large, &auto_keys);
        }

        let mut ggsw = GgswCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, cbs_base_log, cbs_level, ciphertext_modulus);
        switch_scheme(&glev, &mut ggsw, ss_key);

        let mut max_l_infty_err = Scalar::ZERO;
        let mut max_l2_err = f64::default();

        for (k, ggsw_level_matrix) in ggsw.iter().enumerate() {
            let level = k + 1;
            let log_scale = Scalar::BITS as usize - level * cbs_base_log.0;

            for (i, glwe) in ggsw_level_matrix.as_glwe_list().iter().enumerate() {
                let correct_val_list = if msg == 0 {
                    PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0))
                } else {
                    if i < glwe_dimension.0 {
                        let sk_i = glwe_sk_poly_list.get(i);
                        PlaintextList::from_container((0..polynomial_size.0).map(|j| {
                            let val = *sk_i.as_ref().get(j).unwrap();
                            val.wrapping_neg() << log_scale
                        }).collect::<Vec<Scalar>>())
                    } else {
                        PlaintextList::from_container((0..polynomial_size.0).map(|j| {
                            if j == 0 {Scalar::ONE << log_scale} else {Scalar::ZERO}
                        }).collect::<Vec<Scalar>>())
                    }
                };

                let l_infty_err = get_glwe_max_err(&glwe_sk, &glwe, &correct_val_list);
                let l2_err = get_glwe_l2_err(&glwe_sk, &glwe, &correct_val_list);

                max_l_infty_err = std::cmp::max(max_l_infty_err, l_infty_err);
                max_l2_err = if max_l2_err < l2_err {l2_err} else {max_l2_err};
            }
        }

        wwlp_cbs_l_infty_err_list.push(max_l_infty_err);
        wwlp_cbs_l2_err_list.push(max_l2_err);

        let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);

        let pt = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        let mut glwe = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut glwe,
            &pt,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );
        let mut out = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        add_external_product_assign(&mut out, &fourier_ggsw, &glwe);

        let ep_max_err = get_glwe_max_err(&glwe_sk, &out, &pt);
        let ep_l2_err = get_glwe_l2_err(&glwe_sk, &out, &pt);

        wwlp_ep_l_infty_err_list.push(ep_max_err);
        wwlp_ep_l2_err_list.push(ep_l2_err);
    }

    println!("Original cbs error");
    println!("CBS output error");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in cbs_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in cbs_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());

    println!("External product error");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in ep_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in ep_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());


    println!("Patched high prec WWL+ cbs error");
    println!("CBS output error");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in wwlp_cbs_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in wwlp_cbs_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());

    println!("External product error");
    let mut avg_err = Scalar::ZERO;
    let mut max_err = Scalar::ZERO;
    for err in wwlp_ep_l_infty_err_list.iter() {
        avg_err += err;
        max_err = std::cmp::max(max_err, *err);
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("- infinity norm: (Avg) {:.2} bits (Max) {:.2} bits", avg_err.log2(), max_err.log2());

    let mut avg_err = 0f64;
    let mut max_err = 0f64;
    for err in wwlp_ep_l2_err_list.iter() {
        avg_err += err;
        max_err = if max_err < *err {*err} else {max_err};
    }
    let avg_err = (avg_err as f64) / num_repeat as f64;
    let max_err = max_err as f64;
    println!("-       l2 norm: (Avg) {:.2} bits (Max) {:.2} bits\n", avg_err.log2(), max_err.log2());
}
