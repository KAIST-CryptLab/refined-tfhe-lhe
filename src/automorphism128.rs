use std::collections::HashMap;
use aligned_vec::{avec, ABox};
use tfhe::core_crypto::{
    prelude::*,
    fft_impl::fft128,
};
use crate::{glwe_ciphertext_mod_down_from_non_native_power_of_two_to_native, utils::*};

// The following codes generalize rlweExpand
// from https://github.com/KULeuven-COSIC/SortingHat
// to automorphism on arbitrary GLWE dimension
// on u128 space with fft128
pub struct Automorph128Key<C: Container<Element=f64>> {
    ksks: Fourier128GgswCiphertext<C>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    auto_k: usize,
}

impl Automorph128Key<ABox<[f64]>> {
    pub fn allocate(
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        auto_k: usize,
    ) -> Self {
        let glwe_size = glwe_dimension.to_glwe_size();
        let container_len = polynomial_size.to_fourier_polynomial_size().0
            * decomp_level_count.0
            * glwe_size.0
            * glwe_size.0;
        let boxed_re0 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_re1 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_im0 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_im1 = avec![0.0f64; container_len].into_boxed_slice();

        let ksks = Fourier128GgswCiphertext::from_container(
            boxed_re0,
            boxed_re1,
            boxed_im0,
            boxed_im1,
            polynomial_size,
            glwe_size,
            decomp_base_log,
            decomp_level_count,
        );

        Automorph128Key {
            ksks: ksks,
            decomp_base_log,
            decomp_level_count,
            glwe_dimension,
            polynomial_size,
            auto_k: auto_k,
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Fill this object with the appropriate key switching key
    /// that is used for the automorphism operation
    /// where after_key is {S_i(X)} and before_key is computed as {S_i(X^k)}.
    pub fn fill_with_automorph_key<G: ByteRandomGenerator>(
        &mut self,
        before_key: &mut GlweSecretKeyOwned<u128>,
        after_key: &GlweSecretKeyOwned<u128>,
        k: usize,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<G>,
    ) {
        debug_assert!(self.glwe_dimension == before_key.glwe_dimension());
        debug_assert!(self.glwe_dimension == after_key.glwe_dimension());
        debug_assert!(self.polynomial_size == before_key.polynomial_size());
        debug_assert!(self.polynomial_size == after_key.polynomial_size());

        let mut before_poly_list = PolynomialList::new(
            0u128,
            self.polynomial_size,
            PolynomialCount(self.glwe_dimension.0),
        );
        for (mut before_poly, after_poly) in before_poly_list.iter_mut()
            .zip(after_key.as_polynomial_list().iter())
        {
            let out = eval_x_k(after_poly.as_view(), k);
            before_poly.as_mut().clone_from_slice(out.as_ref());
        }
        *before_key = GlweSecretKey::from_container(before_poly_list.into_container(), self.polynomial_size);

        self.fill_with_keyswitch_key(before_key, after_key, noise_parameters, generator);
        self.auto_k = k;
    }

    /// Fill this object with the appropriate keyswitching key
    /// that transforms ciphertexts under before_key to ciphertexts under after_key.
    pub fn fill_with_keyswitch_key<G: ByteRandomGenerator>(
        &mut self,
        before_key: &GlweSecretKeyOwned<u128>,
        after_key: &GlweSecretKeyOwned<u128>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<G>
    ) {
        debug_assert!(self.glwe_dimension == before_key.glwe_dimension());
        debug_assert!(self.glwe_dimension == after_key.glwe_dimension());
        debug_assert!(self.polynomial_size == before_key.polynomial_size());
        debug_assert!(self.polynomial_size == after_key.polynomial_size());

        let glwe_dimension = self.glwe_dimension;
        let glwe_size = glwe_dimension.to_glwe_size();
        let polynomial_size = self.polynomial_size;
        let decomp_level_count = self.decomp_level_count;
        let decomp_base_log = self.decomp_base_log;
        let ciphertext_modulus = CiphertextModulus::new_native();

        let before_key_poly_list = before_key.as_polynomial_list();
        let mut standard_ksks = GgswCiphertext::new(0u128, glwe_size, polynomial_size, decomp_base_log, decomp_level_count, ciphertext_modulus);
        for (idx, mut glwe) in standard_ksks.as_mut_glwe_list().iter_mut().enumerate() {
            let row = idx % glwe_size.0;
            let level = idx / glwe_size.0 + 1;

            if row < glwe_size.0 - 1 {
                let sk_poly = before_key_poly_list.get(row);
                let pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                    sk_poly.as_ref().get(i).unwrap().wrapping_neg() << (u128::BITS as usize - level * decomp_base_log.0)
                }).collect::<Vec<u128>>());
                encrypt_glwe_ciphertext(&after_key, &mut glwe, &pt, noise_parameters, generator);
            }
        }

        let fft = Fft128::new(polynomial_size);
        let fft = fft.as_view();
        self.ksks.fill_with_forward_fourier(&standard_ksks, fft)
    }

    pub fn keyswitch_ciphertext(
        &self,
        mut after: GlweCiphertextMutView<u128>,
        before: GlweCiphertextView<u128>,
    ) {
        let glwe_size = self.glwe_dimension.to_glwe_size();
        let polynomial_size = self.polynomial_size;

        let fft = Fft128::new(polynomial_size);
        let fft = fft.as_view();

        after.as_mut().fill(0u128);
        after.get_mut_body().as_mut().clone_from_slice(before.get_body().as_ref());

        let mut buffers = ComputationBuffers::new();
        buffers.resize(
            fft128::crypto::ggsw::add_external_product_assign_scratch::<u128>(
                glwe_size,
                polynomial_size,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        fft128::crypto::ggsw::add_external_product_assign(
            &mut after,
            &self.ksks,
            &before,
            fft,
            buffers.stack(),
        );
    }

    pub fn auto(
        &self,
        after: GlweCiphertextMutView<u128>,
        before: GlweCiphertextView<u128>,
    ) {
        let mut before_power = GlweCiphertextOwned::new(0u128, before.glwe_size(), before.polynomial_size(), before.ciphertext_modulus());
        for (mut poly_power, poly) in before_power.as_mut_polynomial_list().iter_mut().zip(before.as_polynomial_list().iter()) {
            poly_power.as_mut().clone_from_slice(eval_x_k(poly, self.auto_k).as_ref());
        }

        self.keyswitch_ciphertext(after, before_power.as_view());
    }
}

pub fn gen_all_auto128_keys<G: ByteRandomGenerator>(
    decomp_base_log: DecompositionBaseLog,
    decomp_level: DecompositionLevelCount,
    glwe_secret_key: &GlweSecretKeyOwned<u128>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<G>,
) -> HashMap<usize, Automorph128Key<ABox<[f64]>>> {
    let glwe_dimension = glwe_secret_key.glwe_dimension();
    let polynomial_size = glwe_secret_key.polynomial_size();

    let mut hm = HashMap::new();
    for i in 1..=(polynomial_size.0).ilog2() as usize {
        let k = polynomial_size.0 / (1 << (i - 1)) + 1;
        let mut glwe_ksk = Automorph128Key::allocate(decomp_base_log, decomp_level, glwe_dimension, polynomial_size, i);
        let mut before_key = glwe_secret_key.clone();

        glwe_ksk.fill_with_automorph_key(&mut before_key, &glwe_secret_key, k, noise_parameters, generator);
        hm.insert(k, glwe_ksk);
    }

    hm
}

pub fn trace128(
    glwe_in: GlweCiphertextView<u128>,
    auto_key_map: &HashMap<usize, Automorph128Key<ABox<[f64]>>>,
) -> GlweCiphertextOwned<u128> {
    let n = glwe_in.polynomial_size().0;
    let mut buf = GlweCiphertext::new(0u128, glwe_in.glwe_size(), glwe_in.polynomial_size(), glwe_in.ciphertext_modulus());
    let mut out = GlweCiphertext::new(0u128, glwe_in.glwe_size(), glwe_in.polynomial_size(), glwe_in.ciphertext_modulus());
    out.as_mut().clone_from_slice(glwe_in.as_ref());

    for i in 1..=n.ilog2() {
        let k = n / (1 << (i - 1)) + 1;
        let auto_key = auto_key_map.get(&k).unwrap();
        auto_key.auto(buf.as_mut_view(), out.as_view());
        glwe_ciphertext_add_assign(&mut out, &buf);
    }

    out
}

pub fn trace128_and_rescale_to_native<Scalar: UnsignedInteger + CastFrom<u128>>(
    glwe_in: GlweCiphertextView<u128>,
    auto_key_map: &HashMap<usize, Automorph128Key<ABox<[f64]>>>,
) -> GlweCiphertextOwned<Scalar> {
    assert!(
        glwe_in.ciphertext_modulus().is_non_native_power_of_two(),
        "input ciphertext modulus is not non-native power_of_two",
    );

    assert!(
        Scalar::BITS <= 64,
        "output ciphertext modulus should be <= 2^64",
    );

    let trace = trace128(glwe_in, auto_key_map);
    let mut out = GlweCiphertext::new(Scalar::ZERO, glwe_in.glwe_size(), glwe_in.polynomial_size(), CiphertextModulus::<Scalar>::new_native());
    glwe_ciphertext_mod_down_from_non_native_power_of_two_to_native(&trace, &mut out);

    out
}
