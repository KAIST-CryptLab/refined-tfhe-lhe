use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use refined_tfhe_lhe::{get_val_and_abs_err, generate_accumulator};

fn main() {
    /*
    let lwe_dimension = LweDimension(768);
    let lwe_modular_std_dev = StandardDev(0.000006692125069956277);
    // let polynomial_size = PolynomialSize(512);
    // let glwe_dimension = GlweDimension(3);
    // let glwe_modular_std_dev = StandardDev(0.000000000002573000821792597679153983627);
    // let polynomial_size = PolynomialSize(2048);
    // let glwe_dimension = GlweDimension(1);
    // let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let glwe_dimension = GlweDimension(3);
    let polynomial_size = PolynomialSize(512);
    let glwe_modular_std_dev = StandardDev(9.315272083503367e-10);
    let pbs_base_log = DecompositionBaseLog(9);
    let pbs_level = DecompositionLevelCount(3);
    let ks_base_log = DecompositionBaseLog(3);
    let ks_level = DecompositionLevelCount(5);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    println!();
    */

    /*
    let lwe_dimension = LweDimension(630);
    let lwe_modular_std_dev = StandardDev(2.0f64.powi(-15));
    let polynomial_size = PolynomialSize(1024);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(2.0f64.powi(-25));
    let ks_level = DecompositionLevelCount(5);
    let ks_base_log = DecompositionBaseLog(3);
    let ciphertext_modulus = CiphertextModulus::<u32>::new_native();

    // 5_5_6_2
    let pbs_level = DecompositionLevelCount(5);
    let pbs_base_log = DecompositionBaseLog(5);

    test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    println!();

    // 6_4_6_3
    let pbs_level = DecompositionLevelCount(6);
    let pbs_base_log = DecompositionBaseLog(4);
    test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    */

    // DEFAULT_BOOLEAN
    // let lwe_dimension = LweDimension(664);
    // let lwe_modular_std_dev = StandardDev(0.00003808282923459771);
    // let polynomial_size = PolynomialSize(512);
    // let glwe_dimension = GlweDimension(2);
    // let glwe_modular_std_dev = StandardDev(0.00000004990272175010415);
    // let pbs_base_log = DecompositionBaseLog(6);
    // let pbs_level = DecompositionLevelCount(3);
    // let ks_level = DecompositionLevelCount(3);
    // let ks_base_log = DecompositionBaseLog(4);
    // let ciphertext_modulus = CiphertextModulus::<u32>::new_native();

    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);

    // PARAM_M3_C3
    // let lwe_dimension = LweDimension(864);
    // let glwe_dimension = GlweDimension(1);
    // let polynomial_size = PolynomialSize(8192);
    // let lwe_modular_std_dev = StandardDev(0.000000757998020150446);
    // let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    // let pbs_base_log = DecompositionBaseLog(15);
    // let pbs_level = DecompositionLevelCount(2);
    // let ks_level = DecompositionLevelCount(6);
    // let ks_base_log = DecompositionBaseLog(3);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);

    // PARAM_M4_C4
    // let lwe_dimension = LweDimension(996);
    // let glwe_dimension = GlweDimension(1);
    // let polynomial_size = PolynomialSize(32768);
    // let lwe_modular_std_dev = StandardDev(0.00000006767666038309478);
    // let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    // let pbs_base_log = DecompositionBaseLog(15);
    // let pbs_level = DecompositionLevelCount(2);
    // let ks_level = DecompositionLevelCount(7);
    // let ks_base_log = DecompositionBaseLog(3);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);

    // PARAM_M3_C1
    let lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ks_level = DecompositionLevelCount(5);
    let ks_base_log = DecompositionBaseLog(3);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);

    // PARAM_M4_C1
    let lwe_dimension = LweDimension(808);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(4096);
    let lwe_modular_std_dev = StandardDev(0.0000021124945159091033);
    let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    let pbs_base_log = DecompositionBaseLog(22);
    let pbs_level = DecompositionLevelCount(1);
    let ks_level = DecompositionLevelCount(5);
    let ks_base_log = DecompositionBaseLog(3);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);

    // let lwe_dimension = LweDimension(768);
    // let lwe_modular_std_dev = StandardDev(0.000006692125069956277);
    // let polynomial_size = PolynomialSize(1024);
    // let glwe_dimension = GlweDimension(1);
    // let glwe_modular_std_dev = StandardDev(0.00000004053919869756513);
    // let pbs_base_log = DecompositionBaseLog(23);
    // let pbs_level = DecompositionLevelCount(1);
    // let ks_base_log = DecompositionBaseLog(3);
    // let ks_level = DecompositionLevelCount(5);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    // println!();

    // shortint parameters: message_2_carry_2_ks_pbs
    // let lwe_dimension = LweDimension(742);
    // let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    // let polynomial_size = PolynomialSize(2048);
    // let glwe_dimension = GlweDimension(1);
    // let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    // let pbs_base_log = DecompositionBaseLog(23);
    // let pbs_level = DecompositionLevelCount(1);
    // let ks_level = DecompositionLevelCount(5);
    // let ks_base_log = DecompositionBaseLog(3);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // println!("message_2_carry_2_ks_pbs");
    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    // println!();

    // 2-encoding parameters
    // let lwe_dimension = LweDimension(668);
    // let lwe_modular_std_dev = StandardDev(0.0000204);
    // let polynomial_size = PolynomialSize(256);
    // let glwe_dimension = GlweDimension(6);
    // let glwe_modular_std_dev = StandardDev(0.00000000000345);
    // let pbs_base_log = DecompositionBaseLog(18);
    // let pbs_level = DecompositionLevelCount(1);
    // let ks_level = DecompositionLevelCount(4);
    // let ks_base_log = DecompositionBaseLog(3);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // println!("2-encoding");
    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    // println!();

    // shortint parameters: message_3_carry_3_ks_pbs
    // let lwe_dimension = LweDimension(864);
    // let lwe_modular_std_dev = StandardDev(0.000000757998020150446);
    // let polynomial_size = PolynomialSize(8192);
    // let glwe_dimension = GlweDimension(1);
    // let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    // let pbs_base_log = DecompositionBaseLog(15);
    // let pbs_level = DecompositionLevelCount(2);
    // let ks_level = DecompositionLevelCount(6);
    // let ks_base_log = DecompositionBaseLog(3);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // println!("message_3_carry_3_ks_pbs");
    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    // println!();

    // shortint parameters: message_4_carry_4_ks_pbs
    // let lwe_dimension = LweDimension(996);
    // let lwe_modular_std_dev = StandardDev(0.00000006767666038309478);
    // let polynomial_size = PolynomialSize(32768);
    // let glwe_dimension = GlweDimension(1);
    // let glwe_modular_std_dev = StandardDev(0.0000000000000000002168404344971009);
    // let pbs_base_log = DecompositionBaseLog(15);
    // let pbs_level = DecompositionLevelCount(2);
    // let ks_level = DecompositionLevelCount(7);
    // let ks_base_log = DecompositionBaseLog(3);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // println!("message_4_carry_4_ks_pbs");
    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    // println!();

    // wopbs parameters: wopbs_message_2_carry_2_ks_pbs
    // let lwe_dimension = LweDimension(769);
    // let lwe_modular_std_dev = StandardDev(0.0000043131554647504185);
    // let polynomial_size = PolynomialSize(2048);
    // let glwe_dimension = GlweDimension(1);
    // let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    // let pbs_level = DecompositionLevelCount(2);
    // let pbs_base_log = DecompositionBaseLog(15);
    // let ks_level = DecompositionLevelCount(2);
    // let ks_base_log = DecompositionBaseLog(6);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // println!("wopbs_message_2_carry_2_ks_pbs");
    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    // println!();

    // wopbs parameters: wopbs_message_3_carry_3_ks_pbs
    // let lwe_dimension = LweDimension(873);
    // let lwe_modular_std_dev = StandardDev(0.0000006428797112843789);
    // let polynomial_size = PolynomialSize(2048);
    // let glwe_dimension = GlweDimension(1);
    // let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    // let pbs_level = DecompositionLevelCount(4);
    // let pbs_base_log = DecompositionBaseLog(9);
    // let ks_level = DecompositionLevelCount(1);
    // let ks_base_log = DecompositionBaseLog(10);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // println!("wopbs_message_3_carry_3_ks_pbs");
    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    // println!();

    // wopbs parameters: wopbs_message_4_carry_4_ks_pbs
    // let lwe_dimension = LweDimension(953);
    // let lwe_modular_std_dev = StandardDev(0.0000001486733969411098);
    // let polynomial_size = PolynomialSize(2048);
    // let glwe_dimension = GlweDimension(1);
    // let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    // let pbs_level = DecompositionLevelCount(4);
    // let pbs_base_log = DecompositionBaseLog(9);
    // let ks_level = DecompositionLevelCount(1);
    // let ks_base_log = DecompositionBaseLog(11);
    // let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    // println!("wopbs_message_4_carry_4_ks_pbs");
    // test_negacyclic_pbs(lwe_dimension, lwe_modular_std_dev, polynomial_size, glwe_dimension, glwe_modular_std_dev, pbs_base_log, pbs_level, ks_base_log, ks_level, ciphertext_modulus);
    // println!();

}

fn test_negacyclic_pbs<Scalar: UnsignedTorus + CastFrom<usize> + CastInto<usize> + CastInto<f64>>(
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: impl DispersionParameter,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: impl DispersionParameter,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
) {
    println!(
        "n: {}, N: {}, k: {}, B_pbs: 2^{}, l_pbs: {}, B_ks: 2^{}, l_ks: {}",
        lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_base_log.0, pbs_level.0, ks_base_log.0, ks_level.0
    );

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Set keys
    let small_lwe_sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    let glwe_sk = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let lwe_secret_key = big_lwe_sk;
    let lwe_secret_key_after_ks = small_lwe_sk;

    let ksk = allocate_and_generate_new_lwe_keyswitch_key(&lwe_secret_key, &lwe_secret_key_after_ks, ks_base_log, ks_level, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    let std_bootstrap_key = allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_secret_key_after_ks,
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

    // Set plaintext and encrypt
    let modulus_bit = 1;
    let delta = Scalar::ONE << (Scalar::BITS - 1 - modulus_bit);

    let input_message1 = Scalar::ONE;

    let plaintext1 = Plaintext(input_message1 * delta);
    let lwe_ciphertext_in1: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
        &lwe_secret_key_after_ks,
        plaintext1,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // Set accumulator
    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        2,
        ciphertext_modulus,
        delta,
        |i| i,
    );

    // Perform negacyclic PBS
    let mut lwe_ciphertext_out1 = LweCiphertext::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );
    programmable_bootstrap_lwe_ciphertext(
        &lwe_ciphertext_in1,
        &mut lwe_ciphertext_out1,
        &accumulator,
        &fourier_bsk,
    );

    let num_repeat = if polynomial_size.0 <= 2048 {10} else {10};
    let now = Instant::now();
    for _ in 0..num_repeat {
        let mut lwe_ciphertext_out1 = LweCiphertext::new(
            Scalar::ZERO,
            lwe_secret_key.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );
        programmable_bootstrap_lwe_ciphertext(
            &lwe_ciphertext_in1,
            &mut lwe_ciphertext_out1,
            &accumulator,
            &fourier_bsk,
        );
    }
    println!("GenPBS time: {} ms", now.elapsed().as_micros() as f64 / (num_repeat * 1000) as f64);

    // Check result
    let correct_val = Scalar::ONE;
    let (_, abs_err) = get_val_and_abs_err(&lwe_secret_key, &lwe_ciphertext_out1, correct_val, delta);

    // Keyswitch
    let mut ct_out1 = LweCiphertextOwned::new(
        Scalar::ZERO,
        ksk.output_lwe_size(),
        ciphertext_modulus,
    );

    let now = Instant::now();
    for _ in 0..num_repeat {
        keyswitch_lwe_ciphertext(&ksk, &lwe_ciphertext_out1, &mut ct_out1);
    }
    println!("KS time    : {} ms", now.elapsed().as_micros() as f64 / (num_repeat * 1000) as f64);

    // Check result
    let correct_val = Scalar::ONE;
    let (_, abs_err_ks) = get_val_and_abs_err(&lwe_secret_key_after_ks, &ct_out1, correct_val, delta);

    let abs_err: f64 = abs_err.cast_into();
    let abs_err_ks: f64 = abs_err_ks.cast_into();
    println!("PBS: {:.2} bits -> KS: {:.2} bits", abs_err.log2(), abs_err_ks.log2());
}