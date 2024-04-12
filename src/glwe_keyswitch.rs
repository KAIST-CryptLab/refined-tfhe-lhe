use tfhe::core_crypto::{
    prelude::polynomial_algorithms::*,
    prelude::*,
};

pub struct GlweKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    input_glwe_dimension: GlweDimension,
    output_glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus::<C::Element>,
}

pub type GlweKeyswitchKeyOwned<Scalar> = GlweKeyswitchKey<Vec<Scalar>>;

impl<T: UnsignedInteger, C: Container<Element=T>> AsRef<[T]> for GlweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element=T>> AsMut<[T]> for GlweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element=Scalar>> GlweKeyswitchKey<C>
{
    pub fn from_container(
        container: C,
        input_glwe_dimension: GlweDimension,
        output_glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus::<Scalar>,
    ) -> GlweKeyswitchKey<C> {
        Self {
            data: container,
            input_glwe_dimension: input_glwe_dimension,
            output_glwe_dimension: output_glwe_dimension,
            polynomial_size: polynomial_size,
            decomp_base_log: decomp_base_log,
            decomp_level_count: decomp_level_count,
            ciphertext_modulus: ciphertext_modulus,
        }
    }

    pub fn input_glwe_dimension(&self) -> GlweDimension {
        self.input_glwe_dimension
    }

    pub fn output_glwe_dimension(&self) -> GlweDimension {
        self.output_glwe_dimension
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn decomp_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomp_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus::<Scalar> {
        self.ciphertext_modulus
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_polynomial_list(&self) -> PolynomialList<&'_ [Scalar]> {
        PolynomialList::from_container(self.data.as_ref(), self.polynomial_size)
    }

    pub fn glev_poly_count(&self) -> usize {
        let output_glwe_size = self.output_glwe_dimension().to_glwe_size().0;
        let decomp_level_count = self.decomp_level_count().0;

        output_glwe_size * decomp_level_count
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element=Scalar>> GlweKeyswitchKey<C> {
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialList<&'_ mut [Scalar]> {
        PolynomialList::from_container(self.data.as_mut(), self.polynomial_size)
    }
}

impl<Scalar: UnsignedInteger> GlweKeyswitchKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        input_glwe_dimension: GlweDimension,
        output_glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus::<Scalar>,
    ) -> GlweKeyswitchKeyOwned<Scalar> {
        let input_glwe_size = input_glwe_dimension.to_glwe_size().0;
        let output_glwe_size = output_glwe_dimension.to_glwe_size().0;

        Self::from_container(
            vec![fill_with; input_glwe_size * output_glwe_size * polynomial_size.0 * decomp_level_count.0],
            input_glwe_dimension,
            output_glwe_dimension,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

pub fn allocate_and_generate_new_glwe_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    input_glwe_sk: &GlweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> GlweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element=Scalar>,
    OutputKeyCont: Container<Element=Scalar>,
    Gen: ByteRandomGenerator,
{
    let polynomial_size = input_glwe_sk.polynomial_size();
    let input_glwe_dimension = input_glwe_sk.glwe_dimension();
    let output_glwe_dimension = output_glwe_sk.glwe_dimension();

    let mut new_glwe_keyswitch_key = GlweKeyswitchKey::new(
        Scalar::ZERO,
        input_glwe_dimension,
        output_glwe_dimension,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        ciphertext_modulus,
    );

    generate_glwe_keyswitch_key(
        input_glwe_sk,
        output_glwe_sk,
        &mut new_glwe_keyswitch_key,
        noise_parameters,
        ciphertext_modulus,
        generator,
    );

    new_glwe_keyswitch_key
}

pub fn generate_glwe_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, KSKeyCont, Gen>(
    input_glwe_sk: &GlweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    glwe_keyswitch_key: &mut GlweKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element=Scalar>,
    OutputKeyCont: Container<Element=Scalar>,
    KSKeyCont: ContainerMut<Element=Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(glwe_keyswitch_key.input_glwe_dimension(), input_glwe_sk.glwe_dimension());
    assert_eq!(glwe_keyswitch_key.output_glwe_dimension(), output_glwe_sk.glwe_dimension());
    assert_eq!(glwe_keyswitch_key.polynomial_size(), input_glwe_sk.polynomial_size());
    assert_eq!(glwe_keyswitch_key.polynomial_size(), output_glwe_sk.polynomial_size());

    let output_glwe_size = glwe_keyswitch_key.output_glwe_dimension().to_glwe_size();
    let polynomial_size = glwe_keyswitch_key.polynomial_size();
    let decomp_base_log = glwe_keyswitch_key.decomp_base_log().0;
    let decomp_level_count = glwe_keyswitch_key.decomp_level_count().0;

    for (input_sk_i, mut glwe_ks_chunk) in input_glwe_sk.as_polynomial_list().iter()
        .zip(glwe_keyswitch_key.as_mut_polynomial_list().chunks_exact_mut(output_glwe_size.0 * decomp_level_count))
    {
        for k in 0..decomp_level_count {
            let level = k + 1;
            let log_scale = Scalar::BITS - decomp_base_log * level;

            let scaled_pt = PlaintextList::from_container((0..polynomial_size.0).map(|i| {
                (*input_sk_i.as_ref().get(i).unwrap()).wrapping_neg() << log_scale
            }).collect::<Vec<Scalar>>());

            let mut buf_glwe = GlweCiphertext::new(Scalar::ZERO, output_glwe_size, polynomial_size, ciphertext_modulus);
            encrypt_glwe_ciphertext(&output_glwe_sk, &mut buf_glwe, &scaled_pt, noise_parameters, generator);

            for (j, poly) in buf_glwe.as_polynomial_list().iter().enumerate() {
                glwe_ks_chunk.get_mut(j * decomp_level_count + k).as_mut().clone_from_slice(poly.as_ref());
            }
        }
    }
}

pub fn standard_keyswitch_glwe_ciphertext<Scalar, KSKeyCont, InputCont, OutputCont>(
    glwe_keyswitch_key: &GlweKeyswitchKey<KSKeyCont>,
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KSKeyCont: Container<Element=Scalar>,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    assert_eq!(
        glwe_keyswitch_key.input_glwe_dimension(),
        input_glwe_ciphertext.glwe_size().to_glwe_dimension(),
    );
    assert_eq!(
        glwe_keyswitch_key.output_glwe_dimension(),
        output_glwe_ciphertext.glwe_size().to_glwe_dimension(),
    );
    assert_eq!(
        glwe_keyswitch_key.polynomial_size(),
        input_glwe_ciphertext.polynomial_size(),
    );
    assert_eq!(
        glwe_keyswitch_key.polynomial_size(),
        output_glwe_ciphertext.polynomial_size(),
    );
    assert_eq!(
        glwe_keyswitch_key.ciphertext_modulus(),
        input_glwe_ciphertext.ciphertext_modulus(),
    );
    assert_eq!(
        glwe_keyswitch_key.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus(),
    );
    assert!(glwe_keyswitch_key.ciphertext_modulus().is_compatible_with_native_modulus());

    let polynomial_size = glwe_keyswitch_key.polynomial_size();
    let output_glwe_size = glwe_keyswitch_key.output_glwe_dimension().to_glwe_size();
    let decomp_base_log = glwe_keyswitch_key.decomp_base_log();
    let decomp_level = glwe_keyswitch_key.decomp_level_count();
    let ciphertext_modulus = glwe_keyswitch_key.ciphertext_modulus();

    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);
    output_glwe_ciphertext.get_mut_body().as_mut().clone_from_slice(input_glwe_ciphertext.get_body().as_ref());

    let decomposer = SignedDecomposer::new(
        decomp_base_log,
        decomp_level,
    );

    let glev_poly_count = glwe_keyswitch_key.glev_poly_count();
    for (glev_poly_list, input_mask_poly) in glwe_keyswitch_key.as_polynomial_list().chunks_exact(glev_poly_count)
        .zip(input_glwe_ciphertext.get_mask().as_polynomial_list().iter())
    {
        let mut input_mask_poly_decomp = PolynomialList::new(Scalar::ZERO, polynomial_size, PolynomialCount(decomp_level.0));

        for (i, val) in input_mask_poly.iter().enumerate() {
            let decomposition_iter = decomposer.decompose(*val);

            for (j, decomp_val) in decomposition_iter.into_iter().enumerate() {
                *input_mask_poly_decomp.get_mut(j).as_mut().get_mut(i).unwrap() = decomp_val.value();
            }
        }

        let mut buf = GlweCiphertext::new(Scalar::ZERO, output_glwe_size, polynomial_size, ciphertext_modulus);
        for (mut buf_poly, glev_block) in buf.as_mut_polynomial_list().iter_mut()
            .zip(glev_poly_list.chunks_exact(decomp_level.0))
        {
            for (decomp_poly, glev_block_poly) in input_mask_poly_decomp.iter().zip(glev_block.iter().rev()) {
                polynomial_wrapping_add_mul_assign(&mut buf_poly, &decomp_poly, &glev_block_poly);
            }
        }
        glwe_ciphertext_add_assign(output_glwe_ciphertext, &buf);
    }
}
