use crate::int_lhe_params::*;
use crate::FftType;
use crate::lwe_std_dev_param::*;
use tfhe::core_crypto::prelude::*;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref WOPBS_1_1: WopbsParam<u64> = WopbsParam::new(
        LweDimension(653), // lwe_dimension
        StandardDev(0.00003604499526942373), // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        StandardDev(0.00000000000000029403601535432533), // glwe_modular_std_dev
        DecompositionBaseLog(15), // pbs_base_log
        DecompositionLevelCount(2), // pbs_level
        DecompositionBaseLog(5), // ks_base_log
        DecompositionLevelCount(2), // ks_level
        DecompositionBaseLog(15), // pfks_base_log
        DecompositionLevelCount(2), // pfks_base_log
        DecompositionBaseLog(5), // cbs_base_log
        DecompositionLevelCount(3), // cbs_level
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        2,
    );

    pub static ref WOPBS_2_2: WopbsParam<u64> = WopbsParam::new(
        LweDimension(769), // lwe_dimension
        STD_DEV_769, // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        DecompositionBaseLog(15), // pbs_base_log
        DecompositionLevelCount(2), // pbs_level
        DecompositionBaseLog(6), // ks_base_log
        DecompositionLevelCount(2), // ks_level
        DecompositionBaseLog(15), // pfks_base_log
        DecompositionLevelCount(2), // pfks_level
        DecompositionBaseLog(5), // cbs_base_log
        DecompositionLevelCount(3), // cbs_level
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4,
    );

    pub static ref WOPBS_3_3: WopbsParam<u64> = WopbsParam::new(
        LweDimension(873), // lwe_dimension
        STD_DEV_873, // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        DecompositionBaseLog(9), // pbs_base_log
        DecompositionLevelCount(4), // pbs_level
        DecompositionBaseLog(10), // ks_base_log
        DecompositionLevelCount(1), // ks_level
        DecompositionBaseLog(9), // pfks_base_log
        DecompositionLevelCount(4), // pfks_level
        DecompositionBaseLog(6), // cbs_base_log
        DecompositionLevelCount(3), // cbs_level
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        6,
    );

    pub static ref WOPBS_4_4: WopbsParam<u64> = WopbsParam::new(
        LweDimension(953), // lwe_dimension
        STD_DEV_953, // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        DecompositionBaseLog(9), // pbs_base_log
        DecompositionLevelCount(4), // pbs_level
        DecompositionBaseLog(11), // ks_base_log
        DecompositionLevelCount(1), // ks_level
        DecompositionBaseLog(9), // pfks_base_log
        DecompositionLevelCount(4), // pfks_level
        DecompositionBaseLog(4), // cbs_base_log
        DecompositionLevelCount(6), // cbs_level
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        8,
    );


    pub static ref BITWISE_CBS_CMUX1: IntLheParam<u64> = IntLheParam::new(
        LweDimension(636), // lwe_dimension
        STD_DEV_636, // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        DecompositionBaseLog(23), // pbs_base_log
        DecompositionLevelCount(1), // pbs_level
        DecompositionBaseLog(2), // ks_base_log
        DecompositionLevelCount(5), // ks_level
        DecompositionBaseLog(8), // auto_base_log
        DecompositionLevelCount(5), // auto_level
        FftType::Vanilla, // fft_type_auto
        DecompositionBaseLog(25), // ss_base_log
        DecompositionLevelCount(1), // ss_level
        DecompositionBaseLog(3), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        1,
    );


    pub static ref BITWISE_CBS_CMUX2: IntLheParam<u64> = IntLheParam::new(
        LweDimension(636), // lwe_dimension
        STD_DEV_636, // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        DecompositionBaseLog(15), // pbs_base_log
        DecompositionLevelCount(2), // pbs_level
        DecompositionBaseLog(2), // ks_base_log
        DecompositionLevelCount(5), // ks_level
        DecompositionBaseLog(7), // auto_base_log
        DecompositionLevelCount(6), // auto_level
        FftType::Vanilla, // fft_type_auto
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(4), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        1,
    );


    pub static ref BITWISE_CBS_CMUX3: IntLheParam<u64> = IntLheParam::new(
        LweDimension(636), // lwe_dimension
        STD_DEV_636, // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        DecompositionBaseLog(15), // pbs_base_log
        DecompositionLevelCount(2), // pbs_level
        DecompositionBaseLog(2), // ks_base_log
        DecompositionLevelCount(5), // ks_level
        DecompositionBaseLog(7), // auto_base_log
        DecompositionLevelCount(6), // auto_level
        FftType::Split(35), // fft_type_auto
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(4), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        1,
    );


    pub static ref INT_LHE_BASE_16: IntLheParam<u64> = IntLheParam::new(
        LweDimension(769), // lwe_dimension
        STD_DEV_769, // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        DecompositionBaseLog(15), // pbs_base_log
        DecompositionLevelCount(2), // pbs_level
        DecompositionBaseLog(4), // ks_base_log
        DecompositionLevelCount(3), // ks_level
        DecompositionBaseLog(7), // auto_base_log
        DecompositionLevelCount(7), // auto_level
        FftType::Split(35), // fft_type_auto
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(4), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4,
    );

    pub static ref INT_LHE_BASE_64: HighPrecIntLheParam<u64> = HighPrecIntLheParam::new(
        LweDimension(873), // lwe_dimension
        STD_DEV_873, // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        GlweDimension(2), // large_glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        STD_DEV_4096, // large_glwe_modular_std_dev
        DecompositionBaseLog(11), // pbs_base_log
        DecompositionLevelCount(3), // pbs_level
        DecompositionBaseLog(7), // ks_base_log
        DecompositionLevelCount(2), // ks_level
        DecompositionBaseLog(15), // glwe_ds_to_large_base_log
        DecompositionLevelCount(3), // glwe_ds_to_large_level
        FftType::Split(42), // fft_type_to_large
        DecompositionBaseLog(12), // auto_base_log
        DecompositionLevelCount(4), // auto_level
        FftType::Split(40), // fft_type_auto
        DecompositionBaseLog(12), // glwe_ds_from_large_base_log
        DecompositionLevelCount(3), // glwe_ds_from_large_level
        FftType::Split(42), // fft_type_from_large
        DecompositionBaseLog(10), // ss_base_log
        DecompositionLevelCount(4), // ss_level
        DecompositionBaseLog(5), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        6, // message_size
    );

    pub static ref INT_LHE_BASE_256: HighPrecIntLheParam<u64> = HighPrecIntLheParam::new(
        LweDimension(953), // lwe_dimension
        STD_DEV_953, // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        GlweDimension(2), // large_glwe_dimension
        STD_DEV_2048, // glwe_modular_std_dev
        STD_DEV_4096, // large_glwe_modular_std_dev
        DecompositionBaseLog(9), // pbs_base_log
        DecompositionLevelCount(4), // pbs_level
        DecompositionBaseLog(7), // ks_base_log
        DecompositionLevelCount(2), // ks_level
        DecompositionBaseLog(15), // glwe_ds_to_large_base_log
        DecompositionLevelCount(3), // glwe_ds_to_large_level
        FftType::Split(42), // fft_type_to_large
        DecompositionBaseLog(9), // auto_base_log
        DecompositionLevelCount(6), // auto_level
        FftType::Split(37), // fft_type_auto
        DecompositionBaseLog(10), // glwe_ds_from_large_base_log
        DecompositionLevelCount(4), // glwe_ds_from_large_level
        FftType::Split(38), // fft_type_from_large
        DecompositionBaseLog(10), // ss_base_log
        DecompositionLevelCount(4), // ss_level
        DecompositionBaseLog(3), // cbs_base_log
        DecompositionLevelCount(8), // cbs_level
        LutCountLog(3), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        8,
    );
}
