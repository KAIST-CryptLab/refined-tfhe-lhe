use aligned_vec::{avec, ABox};
use tfhe::core_crypto::{
    algorithms::slice_algorithms::slice_wrapping_add_assign, fft_impl::fft64::{
        c64,
        crypto::ggsw::FourierGgswCiphertextListView,
    }, prelude::*
};

use crate::GlweKeyswitchKey;

pub(crate) struct WrapperFourierPolyList<C: Container<Element=c64>> {
    fourier: FourierGgswCiphertextList<C>,
    polynomial_size: PolynomialSize,
}

impl<C: Container<Element=c64>> WrapperFourierPolyList<C> {
    pub fn from_container(
        data: C,
        polynomial_size: PolynomialSize,
        wrapper_base_log: DecompositionBaseLog,
        count: usize,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            count
                * polynomial_size.to_fourier_polynomial_size().0
        );

        let fourier = FourierGgswCiphertextList::new(
            data,
            count,
            GlweSize(1),
            polynomial_size,
            wrapper_base_log,
            DecompositionLevelCount(1),
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
    fourier_upper: WrapperFourierPolyList<C>,
    fourier_lower: WrapperFourierPolyList<C>,
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
        let count = input_glwe_size.to_glwe_dimension().0 * output_glwe_size.0 * decomp_level_count.0;

        assert_eq!(
            data_upper.container_len(),
            count
                * polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
        );
        assert_eq!(
            data_lower.container_len(),
            count
                * polynomial_size.to_fourier_polynomial_size().0
                * decomp_level_count.0
        );

        Self {
            fourier_upper: WrapperFourierPolyList::from_container(
                data_upper,
                polynomial_size,
                decomp_base_log,
                count,
            ),
            fourier_lower: WrapperFourierPolyList::from_container(
                data_lower,
                polynomial_size,
                decomp_base_log,
                count,
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
        let count = input_glwe_size.to_glwe_dimension().0 * output_glwe_size.0 * decomp_level_count.0;

        let data_upper = avec![
            c64::default();
            count
                * polynomial_size.to_fourier_polynomial_size().0
        ].into_boxed_slice();
        let data_lower = avec![
            c64::default();
            count
                * polynomial_size.to_fourier_polynomial_size().0
        ].into_boxed_slice();

        let wrapper_base_log = DecompositionBaseLog(decomp_base_log.0 + 1);
        Self {
            fourier_upper: WrapperFourierPolyList::from_container(
                data_upper,
                polynomial_size,
                wrapper_base_log,
                count,
            ),
            fourier_lower: WrapperFourierPolyList::from_container(
                data_lower,
                polynomial_size,
                wrapper_base_log,
                count,
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

    let wrapper_base_log = DecompositionBaseLog(decomp_base_log.0 + 1);
    let wrapper_level = DecompositionLevelCount(1);

    let data_upper = GgswCiphertextList::from_container(
        data_upper.as_ref(),
        GlweSize(1),
        polynomial_size,
        wrapper_base_log,
        wrapper_level,
        ciphertext_modulus,
    );
    let data_lower = GgswCiphertextList::from_container(
        data_lower.as_ref(),
        GlweSize(1),
        polynomial_size,
        wrapper_base_log,
        wrapper_level,
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
    let ks_base_log = glwe_keyswitch_key.decomp_base_log();
    let ks_level = glwe_keyswitch_key.decomp_level_count();
    let ciphertext_modulus = input.ciphertext_modulus();

    output.as_mut().fill(Scalar::ZERO);
    output.get_mut_body().as_mut().clone_from_slice(input.get_body().as_ref());

    let fourier_upper = glwe_keyswitch_key.fourier_upper();
    let fourier_lower = glwe_keyswitch_key.fourier_lower();

    let decomposer = SignedDecomposer::new(
        ks_base_log,
        ks_level,
    );

    let glev_poly_count = output_glwe_size.0 * ks_level.0;
    for (glev_idx, input_mask_poly) in input.get_mask().as_polynomial_list().iter().enumerate() {
        let (glev_upper, _) = fourier_upper.split_at((glev_idx+1) * glev_poly_count);
        let (_, glev_upper) = glev_upper.split_at(glev_idx * glev_poly_count);

        let (glev_lower, _) = fourier_lower.split_at((glev_idx+1) * glev_poly_count);
        let (_, glev_lower) = glev_lower.split_at(glev_idx * glev_poly_count);

        let mut input_mask_poly_decomp = PolynomialList::new(Scalar::ZERO, polynomial_size, PolynomialCount(ks_level.0));

        for (i, val) in input_mask_poly.iter().enumerate() {
            let decomposition_iter = decomposer.decompose(*val);

            for (j, decomp_val) in decomposition_iter.into_iter().enumerate() {
                *input_mask_poly_decomp.get_mut(j).as_mut().get_mut(i).unwrap() = decomp_val.value();
            }
        }

        let mut buf = GlweCiphertext::new(Scalar::ZERO, output_glwe_size, polynomial_size, ciphertext_modulus);

        for (k, mut buf_poly) in buf.as_mut_polynomial_list().iter_mut().enumerate() {
            let (ggsw_upper_block, _) = glev_upper.split_at((k+1) * ks_level.0);
            let (_, ggsw_upper_block) = ggsw_upper_block.split_at(k * ks_level.0);

            let (ggsw_lower_block, _) = glev_lower.split_at((k+1) * ks_level.0);
            let (_, ggsw_lower_block) = ggsw_lower_block.split_at(k * ks_level.0);

            for ((ggsw_upper, ggsw_lower), decomp_input_poly)
            in ggsw_upper_block.as_view().into_ggsw_iter().rev()
                .zip(ggsw_lower_block.as_view().into_ggsw_iter().rev())
                .zip(input_mask_poly_decomp.iter())
            {
                let wrapper_glwe = GlweCiphertext::from_container(
                    (0..polynomial_size.0).map(|i| {
                        let val = *decomp_input_poly.as_ref().get(i).unwrap();
                        val << Scalar::BITS - ggsw_upper.decomposition_base_log().0
                    }).collect::<Vec<Scalar>>(),
                    polynomial_size,
                    ciphertext_modulus,
                );

                let mut tmp = GlweCiphertext::new(Scalar::ZERO, GlweSize(1), polynomial_size, ciphertext_modulus);

                add_external_product_assign(&mut tmp, &ggsw_upper, &wrapper_glwe);
                glwe_ciphertext_cleartext_mul_assign(&mut tmp, Cleartext(Scalar::ONE << 32));
                add_external_product_assign(&mut tmp, &ggsw_lower, &wrapper_glwe);

                slice_wrapping_add_assign(buf_poly.as_mut(), tmp.as_ref());
            }
        }
        // for ((ggsw_upper, ggsw_lower), mut buf_poly)
        // in glev_upper.as_view().into_ggsw_iter()
        //     .zip(glev_lower.as_view().into_ggsw_iter())
        //     .zip(buf.as_mut_polynomial_list().iter_mut())
        // {
        //     let mut buf_poly = GlweCiphertext::from_container(
        //         buf_poly.as_mut(),
        //         polynomial_size,
        //         ciphertext_modulus,
        //     );

        //     add_external_product_assign(&mut buf_poly, &ggsw_upper, &input_mask_poly);
        //     glwe_ciphertext_cleartext_mul_assign(&mut buf_poly, Cleartext(Scalar::ONE << 32));
        //     add_external_product_assign(&mut buf_poly, &ggsw_lower, &input_mask_poly);
        // }

        glwe_ciphertext_add_assign(output, &buf);
    }
}
