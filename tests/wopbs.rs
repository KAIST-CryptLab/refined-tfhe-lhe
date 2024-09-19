use auto_base_conv::{
    gen_all_auto_keys,
    generate_scheme_switching_key,
    get_max_err_ggsw_bit,
    improved_wopbs_multi_bits,
    FftType,
};
use concrete_fft::c64;
use tfhe::core_crypto::prelude::*;

type Scalar = u64;

fn main() {
    let lwe_dimension = LweDimension(768);
    let lwe_modular_std_dev = StandardDev(0.000006692125069956277);
    let polynomial_size = PolynomialSize(2048);
    let glwe_dimension = GlweDimension(1);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(15);
    let pbs_level = DecompositionLevelCount(2);
    let ks_base_log = DecompositionBaseLog(3);
    let ks_level = DecompositionLevelCount(5);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let cbs_base_log = DecompositionBaseLog(3);
    let cbs_level = DecompositionLevelCount(5);
    let auto_base_log = DecompositionBaseLog(12);
    let auto_level = DecompositionLevelCount(3);
    let fft_type = FftType::Split16;
    let ss_base_log = DecompositionBaseLog(9);
    let ss_level = DecompositionLevelCount(4);
    let log_lut_count = LutCountLog(2);

    let glwe_size = glwe_dimension.to_glwe_size();

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
    let glwe_secret_key = GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk = glwe_secret_key.clone().into_lwe_secret_key();

    let lwe_secret_key = big_lwe_sk;
    let lwe_secret_key_after_ks = small_lwe_sk;

    let ksk = allocate_and_generate_new_lwe_keyswitch_key(&lwe_secret_key, &lwe_secret_key_after_ks, ks_base_log, ks_level, lwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

    let std_bootstrap_key = allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_secret_key_after_ks,
        &glwe_secret_key,
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

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type,
        &glwe_secret_key,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let ss_key = generate_scheme_switching_key(
        &glwe_secret_key,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let ss_key = ss_key.as_view();

    // Set plaintext and encrypt
    let modulus_bit = 6;
    let log_delta = Scalar::BITS - modulus_bit;
    let delta = Scalar::ONE << log_delta;

    let mut ggsw_list_out = GgswCiphertextList::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, GgswCiphertextCount(modulus_bit as usize), CiphertextModulus::new_native());

    let mut fourier_ggsw_list_out = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            modulus_bit as usize * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * cbs_level.0
        ],
        modulus_bit as usize,
        glwe_size,
        polynomial_size,
        cbs_base_log,
        cbs_level,
    );

    let num_extract_bits = 3usize;
    println!("num_extract_bits: {num_extract_bits}");
    for msg in 0..(1 << modulus_bit) {
        let pt = Plaintext(msg * delta);
        let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(&lwe_secret_key, pt, glwe_modular_std_dev, ciphertext_modulus, &mut encryption_generator);

        improved_wopbs_multi_bits(
            &lwe_in,
            &mut ggsw_list_out,
            &mut fourier_ggsw_list_out,
            num_extract_bits,
            &ksk,
            fourier_bsk,
            &auto_keys,
            ss_key,
            log_lut_count,
        );
        println!();

        println!("msg: {msg} = 0b{msg:b}");
        for (bit_idx, ggsw) in ggsw_list_out.iter().enumerate() {
            let extract_bit = (msg & (1 << bit_idx)) >> bit_idx;
            let correct_val = if bit_idx % num_extract_bits == num_extract_bits - 1 {
                extract_bit
            } else {
                let mask_idx = (bit_idx / num_extract_bits) * num_extract_bits + (num_extract_bits - 1);
                let mask_bit = (msg & (1 << mask_idx)) >> mask_idx;
                extract_bit ^ mask_bit
            };
            let err = get_max_err_ggsw_bit(&glwe_secret_key, ggsw, correct_val);
            println!("[{bit_idx}] {correct_val} | {:.3} bits", (err as f64).log2());
        }
        println!();
    }
}
