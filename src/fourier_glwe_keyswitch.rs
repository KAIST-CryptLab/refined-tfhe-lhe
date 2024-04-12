use aligned_vec::{avec, ABox};
use tfhe::core_crypto::{
    prelude::*,
    algorithms::polynomial_algorithms::polynomial_wrapping_add_assign,
    fft_impl::fft64::{
        c64,
        crypto::ggsw::FourierGgswCiphertextListView,
    },
};

use crate::GlweKeyswitchKey;

pub(crate) struct WrapperFourierGgswCiphertextList<C: Container<Element=c64>> {
    fourier: FourierGgswCiphertextList<C>,
    polynomial_size: PolynomialSize,
}

impl<C: Container<Element=c64>> WrapperFourierGgswCiphertextList<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        count: usize,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            count
                * polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
        );

        let fourier = FourierGgswCiphertextList::new(
            data,
            count,
            GlweSize(1),
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        );

        Self {
            fourier: fourier,
            polynomial_size: polynomial_size,
        }
    }

    pub fn as_fourier_ggsw_ciphertext_list_view(&self) -> FourierGgswCiphertextListView {
        self.fourier.as_view()
    }
}


pub struct FourierGlweKeyswitchKey64<C: Container<Element=c64>>
{
    fourier_upper: WrapperFourierGgswCiphertextList<C>,
    fourier_lower: WrapperFourierGgswCiphertextList<C>,
    input_glwe_size: GlweSize,
    output_glwe_size: GlweSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
}

impl<C: Container<Element=c64>> FourierGlweKeyswitchKey64<C> {
    pub fn from_container(
        data_upper: C,
        data_lower: C,
        input_glwe_size: GlweSize,
        output_glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
    ) -> Self {
        let wrapper_ggsw_count = input_glwe_size.to_glwe_dimension().0 * output_glwe_size.0;

        assert_eq!(
            data_upper.container_len(),
            wrapper_ggsw_count
                * polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
        );
        assert_eq!(
            data_lower.container_len(),
            wrapper_ggsw_count
                * polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
        );

        Self {
            fourier_upper: WrapperFourierGgswCiphertextList::from_container(
                data_upper,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                wrapper_ggsw_count,
            ),
            fourier_lower: WrapperFourierGgswCiphertextList::from_container(
                data_lower,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                wrapper_ggsw_count,
            ),
            input_glwe_size: input_glwe_size,
            output_glwe_size: output_glwe_size,
            decomp_base_log: decomp_base_log,
            decomp_level_count: decomp_level_count,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier_lower.polynomial_size
    }

    pub fn input_glwe_size(&self) -> GlweSize {
        self.input_glwe_size
    }

    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    pub fn decomp_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomp_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn fourier_upper(&self) -> FourierGgswCiphertextListView {
        self.fourier_upper.as_fourier_ggsw_ciphertext_list_view()
    }

    pub fn fourier_lower(&self) -> FourierGgswCiphertextListView {
        self.fourier_lower.as_fourier_ggsw_ciphertext_list_view()
    }
}

pub type FourierGlweKeyswitchKey64Owned = FourierGlweKeyswitchKey64<ABox<[c64]>>;

impl FourierGlweKeyswitchKey64Owned {
    pub fn new(
        input_glwe_size: GlweSize,
        output_glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
    ) -> Self {
        let wrapper_ggsw_count = input_glwe_size.to_glwe_dimension().0 * output_glwe_size.0;

        let data_upper = avec![
            c64::default();
            wrapper_ggsw_count
                * polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
        ].into_boxed_slice();
        let data_lower = avec![
            c64::default();
            wrapper_ggsw_count
                * polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
        ].into_boxed_slice();

        Self {
            fourier_upper: WrapperFourierGgswCiphertextList::from_container(
                data_upper,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                wrapper_ggsw_count,
            ),
            fourier_lower: WrapperFourierGgswCiphertextList::from_container(
                data_lower,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                wrapper_ggsw_count,
            ),
            input_glwe_size: input_glwe_size,
            output_glwe_size: output_glwe_size,
            decomp_base_log: decomp_base_log,
            decomp_level_count: decomp_level_count,
        }
    }
}

pub fn convert_standard_glwe_keyswitch_key_64_to_fourier<Scalar, InputCont, OutputCont>(
    input_ksk: &GlweKeyswitchKey<InputCont>,
    output_ksk: &mut FourierGlweKeyswitchKey64<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=c64>,
{
    assert_eq!(Scalar::BITS, 64);
    assert_eq!(input_ksk.polynomial_size(), output_ksk.polynomial_size());
    assert_eq!(input_ksk.input_glwe_dimension().to_glwe_size(), output_ksk.input_glwe_size());
    assert_eq!(input_ksk.output_glwe_dimension().to_glwe_size(), output_ksk.output_glwe_size());
    assert_eq!(input_ksk.decomp_base_log(), output_ksk.decomp_base_log());
    assert_eq!(input_ksk.decomp_level_count(), output_ksk.decomp_level_count());

    let polynomial_size = output_ksk.polynomial_size();
    let input_glwe_size = output_ksk.input_glwe_size();
    let output_glwe_size = output_ksk.output_glwe_size();
    let decomp_base_log = output_ksk.decomp_base_log();
    let decomp_level = output_ksk.decomp_level_count();
    let ciphertext_modulus = input_ksk.ciphertext_modulus();

    let poly_count = input_glwe_size.to_glwe_dimension().0 * output_glwe_size.0 * decomp_level.0;

    let mut data_upper = PolynomialList::new(Scalar::ZERO, polynomial_size, PolynomialCount(poly_count));
    let mut data_lower = PolynomialList::new(Scalar::ZERO, polynomial_size, PolynomialCount(poly_count));

    for ((val_upper, val_lower), val)
    in data_upper.as_mut().iter_mut()
        .zip(data_lower.as_mut().iter_mut())
        .zip(input_ksk.as_ref().iter())
    {
        *val_upper = (*val) >> 32;
        *val_lower = ((*val) << 32) >> 32;
    }

    let data_upper = GgswCiphertextList::from_container(
        data_upper.as_ref(),
        GlweSize(1),
        polynomial_size,
        decomp_base_log,
        decomp_level,
        ciphertext_modulus,
    );
    let data_lower = GgswCiphertextList::from_container(
        data_lower.as_ref(),
        GlweSize(1),
        polynomial_size,
        decomp_base_log,
        decomp_level,
        ciphertext_modulus,
    );

    let fourier_upper = &mut output_ksk.fourier_upper.fourier;
    for (ggsw, mut fourier_ggsw) in data_upper.iter().zip(fourier_upper.as_mut_view().into_ggsw_iter()) {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }

    let fourier_lower = &mut output_ksk.fourier_lower.fourier;
    for (ggsw, mut fourier_ggsw) in data_lower.iter().zip(fourier_lower.as_mut_view().into_ggsw_iter()) {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }
}

pub fn keyswitch_glwe_ciphertext_64<Scalar, KSKeyCont, InputCont, OutputCont>(
    glwe_keyswitch_key: &FourierGlweKeyswitchKey64<KSKeyCont>,
    input: &GlweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KSKeyCont: Container<Element=c64>,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    assert!(Scalar::BITS <= 64);
    assert_eq!(
        glwe_keyswitch_key.input_glwe_size(),
        input.glwe_size(),
    );
    assert_eq!(
        glwe_keyswitch_key.output_glwe_size(),
        output.glwe_size(),
    );
    assert_eq!(
        glwe_keyswitch_key.polynomial_size(),
        input.polynomial_size(),
    );
    assert_eq!(
        glwe_keyswitch_key.polynomial_size(),
        output.polynomial_size(),
    );
    assert_eq!(
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
    );

    let polynomial_size = glwe_keyswitch_key.polynomial_size();
    let output_glwe_size = glwe_keyswitch_key.output_glwe_size();
    let ciphertext_modulus = input.ciphertext_modulus();

    output.as_mut().fill(Scalar::ZERO);
    output.get_mut_body().as_mut().clone_from_slice(input.get_body().as_ref());

    let fourier_upper = glwe_keyswitch_key.fourier_upper();
    let fourier_lower = glwe_keyswitch_key.fourier_lower();

    for (glev_idx, input_mask_poly) in input.get_mask().as_polynomial_list().iter().enumerate() {
        let (glev_upper, _) = fourier_upper.split_at((glev_idx+1) * output_glwe_size.0);
        let (_, glev_upper) = glev_upper.split_at(glev_idx * output_glwe_size.0);

        let (glev_lower, _) = fourier_lower.split_at((glev_idx+1) * output_glwe_size.0);
        let (_, glev_lower) = glev_lower.split_at(glev_idx * output_glwe_size.0);

        let wrapper_input_poly = GlweCiphertext::from_container(
            input_mask_poly.as_ref(),
            polynomial_size,
            ciphertext_modulus,
        );

        let mut buf = GlweCiphertext::new(Scalar::ZERO, output_glwe_size, polynomial_size, ciphertext_modulus);

        for ((wrapper_ggsw_upper, wrapper_ggsw_lower), mut buf_poly)
        in glev_upper.as_view().into_ggsw_iter()
            .zip(glev_lower.as_view().into_ggsw_iter())
            .zip(buf.as_mut_polynomial_list().iter_mut())
        {
            let mut tmp_poly = GlweCiphertext::new(Scalar::ZERO, GlweSize(1), polynomial_size, ciphertext_modulus);

            add_external_product_assign(&mut tmp_poly, &wrapper_ggsw_upper, &wrapper_input_poly);
            glwe_ciphertext_cleartext_mul_assign(&mut tmp_poly, Cleartext(Scalar::ONE << 32));
            add_external_product_assign(&mut tmp_poly, &wrapper_ggsw_lower, &wrapper_input_poly);

            let tmp_poly = Polynomial::from_container(tmp_poly.as_ref());
            polynomial_wrapping_add_assign(&mut buf_poly, &tmp_poly);
        }

        glwe_ciphertext_add_assign(output, &buf);
    }
}
