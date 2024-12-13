use crate::aes_params::*;
use crate::FftType;
use tfhe::core_crypto::prelude::*;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref AES_TIGHT: AesParam<u64> = AesParam::new(
        LweDimension(768), // lwe_dimension
        StandardDev(0.00000702047462940120), // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        StandardDev(0.00000000000000029403601535432533), // glwe_modular_std_dev
        DecompositionBaseLog(23), // pbs_base_log
        DecompositionLevelCount(1), // pbs_level
        DecompositionBaseLog(4), // glwe_ds_base_log
        DecompositionLevelCount(3), // glwe_ds_level
        PolynomialSize(256), // common_polynomial_size
        FftType::Vanilla, // fft_type_ds
        DecompositionBaseLog(13), // auto_base_log
        DecompositionLevelCount(3), // auto_level
        FftType::Split(41), // fft_type_auto
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(2), // cbs_base_log
        DecompositionLevelCount(7), // cbs_level
        LutCountLog(3), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
    );

    pub static ref AES_HALF_CBS: AesHalfCBSParam<u64> = AesHalfCBSParam::new(
        LweDimension(768), // lwe_dimension
        StandardDev(0.00000702047462940120), // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        StandardDev(0.00000000000000029403601535432533), // glwe_modular_std_dev
        DecompositionBaseLog(23), // pbs_base_log
        DecompositionLevelCount(1), // pbs_level
        DecompositionBaseLog(4), // glwe_ds_base_log
        DecompositionLevelCount(3), // glwe_ds_level
        PolynomialSize(256), // common_polynomial_size
        FftType::Vanilla, // fft_type_ds
        DecompositionBaseLog(13), // auto_base_log
        DecompositionLevelCount(3), // auto_level
        FftType::Split(42), // fft_type_auto
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(2), // cbs_base_log
        DecompositionLevelCount(7), // cbs_level
        LutCountLog(3), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        DecompositionBaseLog(6), // half_cbs_auto_base_log
        DecompositionLevelCount(8), // half_cbs_auto_level
        FftType::Split(35), // half_cbs_fft_type
        DecompositionBaseLog(19), // half_cbs_ss_base_log
        DecompositionLevelCount(2), // half_cbs_ss_level
        DecompositionBaseLog(4), // half_cbs_base_log
        DecompositionLevelCount(6), // half_cbs_level
    );
}