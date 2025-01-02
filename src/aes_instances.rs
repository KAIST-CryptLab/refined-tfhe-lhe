use crate::lwe_std_dev_param::*;
use crate::aes_params::*;
use crate::FftType;
use tfhe::core_crypto::prelude::*;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref AES_SET_1: AesParam<u64> = AesParam::new(
        LweDimension(768), // lwe_dimension
        STD_DEV_768, // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        STD_DEV_2048,
        DecompositionBaseLog(23), // pbs_base_log
        DecompositionLevelCount(1), // pbs_level
        DecompositionBaseLog(4), // glwe_ds_base_log
        DecompositionLevelCount(3), // glwe_ds_level
        PolynomialSize(256), // common_polynomial_size
        FftType::Vanilla, // fft_type_ds
        DecompositionBaseLog(12), // auto_base_log
        DecompositionLevelCount(3), // auto_level
        FftType::Vanilla, // fft_type_auto
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(2), // cbs_base_log
        DecompositionLevelCount(6), // cbs_level
        LutCountLog(3), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
    );

    pub static ref AES_SET_2: AesParam<u64> = AesParam::new(
        LweDimension(768), // lwe_dimension
        STD_DEV_768,
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        STD_DEV_2048,
        DecompositionBaseLog(15), // pbs_base_log
        DecompositionLevelCount(2), // pbs_level
        DecompositionBaseLog(4), // glwe_ds_base_log
        DecompositionLevelCount(3), // glwe_ds_level
        PolynomialSize(256), // common_polynomial_size
        FftType::Vanilla, // fft_type_ds
        DecompositionBaseLog(7), // auto_base_log
        DecompositionLevelCount(6), // auto_level
        FftType::Split(34), // fft_type_auto
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(4), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
    );

    pub static ref AES_HALF_CBS_SET_1: AesHalfCBSParam<u64> = AesHalfCBSParam::new(
        LweDimension(768), // lwe_dimension
        STD_DEV_768, // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        DecompositionBaseLog(23), // pbs_base_log
        DecompositionLevelCount(1), // pbs_level
        DecompositionBaseLog(4), // glwe_ds_base_log
        DecompositionLevelCount(3), // glwe_ds_level
        PolynomialSize(256), // common_polynomial_size
        FftType::Vanilla, // fft_type_ds
        DecompositionBaseLog(12), // auto_base_log
        DecompositionLevelCount(3), // auto_level
        FftType::Vanilla, // fft_type_auto
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(2), // cbs_base_log
        DecompositionLevelCount(6), // cbs_level
        LutCountLog(3), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        GlweDimension(3), // half_cbs_glwe_dimension
        PolynomialSize(1024), // half_cbs_polynomial_size
        STD_DEV_3072, // half_cbs_glwe_std_modular_std_dev
        DecompositionBaseLog(4), // half_cbs_glwe_ds_base_log
        DecompositionLevelCount(3), // half_cbs_glwe_ds_level
        FftType::Vanilla, // half_cbs_fft_type_ds
        DecompositionBaseLog(15), // half_cbs_auto_base_log
        DecompositionLevelCount(3), // half_cbs_auto_level
        FftType::Split(42), // half_cbs_fft_type
        DecompositionBaseLog(13), // half_cbs_ss_base_log
        DecompositionLevelCount(3), // half_cbs_ss_level
        DecompositionBaseLog(7), // half_cbs_base_log
        DecompositionLevelCount(3), // half_cbs_level
    );

    pub static ref AES_HALF_CBS_SET_2: AesHalfCBSParam<u64> = AesHalfCBSParam::new(
        LweDimension(768), // lwe_dimension
        STD_DEV_768, // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        DecompositionBaseLog(15), // pbs_base_log
        DecompositionLevelCount(2), // pbs_level
        DecompositionBaseLog(4), // glwe_ds_base_log
        DecompositionLevelCount(3), // glwe_ds_level
        PolynomialSize(256), // common_polynomial_size
        FftType::Vanilla, // fft_type_ds
        DecompositionBaseLog(7), // auto_base_log
        DecompositionLevelCount(6), // auto_level
        FftType::Split(34), // fft_type_auto
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(4), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        GlweDimension(3), // half_cbs_glwe_dimension
        PolynomialSize(1024), // half_cbs_polynomial_size
        STD_DEV_3072, // half_cbs_glwe_std_modular_std_dev
        DecompositionBaseLog(4), // half_cbs_glwe_ds_base_log
        DecompositionLevelCount(3), // half_cbs_glwe_ds_level
        FftType::Vanilla, // half_cbs_fft_type_ds
        DecompositionBaseLog(15), // half_cbs_auto_base_log
        DecompositionLevelCount(3), // half_cbs_auto_level
        FftType::Split(42), // half_cbs_fft_type
        DecompositionBaseLog(13), // half_cbs_ss_base_log
        DecompositionLevelCount(3), // half_cbs_ss_level
        DecompositionBaseLog(7), // half_cbs_base_log
        DecompositionLevelCount(3), // half_cbs_level
    );
}
