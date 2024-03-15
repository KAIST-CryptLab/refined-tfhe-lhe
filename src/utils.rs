use tfhe::core_crypto::{
    prelude::*,
    algorithms::polynomial_algorithms::polynomial_wrapping_monic_monomial_div_assign,
};

/* -------- Error Tracking -------- */
pub fn get_val_and_bit_err<Scalar, C>(
    lwe_secret_key: &LweSecretKey<Vec<Scalar>>,
    lwe_ctxt: &LweCiphertext<C>,
    correct_val: Scalar,
    delta: Scalar,
) -> (Scalar, u32)
where
    Scalar: UnsignedInteger,
    C: Container<Element=Scalar>,
{
    let decrypted_u64 = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_ctxt).0;
    let err = {
        let correct_val = correct_val * delta;
        let d0 = decrypted_u64.wrapping_sub(correct_val);
        let d1 = correct_val.wrapping_sub(decrypted_u64);
        std::cmp::min(d0, d1)
    };
    let bit_err = if err != Scalar::ZERO {Scalar::BITS as u32 - err.leading_zeros()} else {0};
    let rounding = (decrypted_u64 & (delta >> 1)) << 1;
    let decoded = (decrypted_u64.wrapping_add(rounding)) / delta;

    return (decoded, bit_err);
}

pub fn get_val_and_abs_err<Scalar, C>(
    lwe_secret_key: &LweSecretKey<Vec<Scalar>>,
    lwe_ctxt: &LweCiphertext<C>,
    correct_val: Scalar,
    delta: Scalar,
) -> (Scalar, Scalar)
where
    Scalar: UnsignedInteger,
    C: Container<Element=Scalar>,
{
    let decrypted_u64 = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_ctxt).0;
    let err = {
        let correct_val = correct_val * delta;
        let d0 = decrypted_u64.wrapping_sub(correct_val);
        let d1 = correct_val.wrapping_sub(decrypted_u64);
        std::cmp::min(d0, d1)
    };
    let rounding = (decrypted_u64 & (delta >> 1)) << 1;
    let decoded = (decrypted_u64.wrapping_add(rounding)) / delta;

    return (decoded, err);
}

/* -------- GLWE -------- */
pub fn glwe_ciphertext_monic_monomial_div_assign<Scalar, ContMut>(
    glwe: &mut GlweCiphertext<ContMut>,
    monomial_degree: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    ContMut: ContainerMut<Element=Scalar>,
{
    for mut poly in glwe.as_mut_polynomial_list().iter_mut() {
        polynomial_wrapping_monic_monomial_div_assign(&mut poly, monomial_degree);
    }
}

pub fn glwe_clone_from<Scalar: UnsignedInteger>(mut dst: GlweCiphertextMutView<Scalar>, src: GlweCiphertextView<Scalar>) {
    debug_assert!(dst.glwe_size() == src.glwe_size());
    debug_assert!(dst.polynomial_size() == src.polynomial_size());
    dst.as_mut().clone_from_slice(src.as_ref());
}

pub fn encode_bits_into_glwe_ciphertext<Scalar, G>(
    glwe_secret_key: &GlweSecretKeyOwned<Scalar>,
    bit_list: &[Scalar],
    ggsw_bit_decomp_base_log: DecompositionBaseLog,
    ggsw_bit_decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<G>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> Vec<GlweCiphertextListOwned<Scalar>>
where
    Scalar: UnsignedTorus,
    G: ByteRandomGenerator,
{
    let glwe_size = glwe_secret_key.glwe_dimension().to_glwe_size();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let num_glwe_list = bit_list.len() / polynomial_size.0;
    let num_glwe_list = if bit_list.len() % polynomial_size.0 == 0 {num_glwe_list} else {num_glwe_list + 1};

    let mut vec_glwe_list = vec![GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        GlweCiphertextCount(ggsw_bit_decomp_level_count.0),
        ciphertext_modulus,
    ); num_glwe_list];

    for (idx, glwe_list) in vec_glwe_list.iter_mut().enumerate() {
        for (k, mut glwe) in glwe_list.iter_mut().enumerate() {
            let log_scale = Scalar::BITS - ggsw_bit_decomp_base_log.0 * (k + 1) - log2(polynomial_size.0);
            let pt = PlaintextList::from_container(
                (0..polynomial_size.0).map(|i| {
                    let bit_idx = idx * polynomial_size.0 + i;
                    if bit_idx < bit_list.len() {
                        bit_list[bit_idx] << log_scale
                    } else {
                        Scalar::ZERO
                    }
                }).collect::<Vec<Scalar>>()
            );

            encrypt_glwe_ciphertext(&glwe_secret_key, &mut glwe, &pt, noise_parameters, generator);
        }
    }

    vec_glwe_list
}

/* -------- Automorphism -------- */
#[inline]
pub const fn log2(input: usize) -> usize {
    core::mem::size_of::<usize>() * 8 - (input.leading_zeros() as usize) - 1
}

/// Evaluate f(x) on x^k, where k is odd
pub(crate) fn eval_x_k<Scalar>(poly: PolynomialView<'_, Scalar>, k: usize) -> PolynomialOwned<Scalar>
where
    Scalar: UnsignedTorus,
{
    let mut out = PolynomialOwned::new(Scalar::ZERO, poly.polynomial_size());
    eval_x_k_in_memory(&mut out, poly, k);
    out
}

/// Evaluate f(x) on x^k, where k is odd
pub(crate) fn eval_x_k_in_memory<Scalar>(out: &mut PolynomialOwned<Scalar>, poly: PolynomialView<'_, Scalar>, k: usize)
where
    Scalar: UnsignedTorus,
{
    assert_eq!(k % 2, 1);
    assert!(poly.polynomial_size().0.is_power_of_two());
    *out.as_mut().get_mut(0).unwrap() = *poly.as_ref().get(0).unwrap();
    for i in 1..poly.polynomial_size().0 {
        // i-th term becomes ik-th term, but reduced by n
        let j = i * k % poly.polynomial_size().0;
        let sign = if ((i * k) / poly.polynomial_size().0) % 2 == 0
        { Scalar::ONE } else { Scalar::MAX };
        let c = *poly.as_ref().get(i).unwrap();
        *out.as_mut().get_mut(j).unwrap() = sign.wrapping_mul(c);
    }
}

/* -------- Macro -------- */
// https://docs.rs/itertools/0.7.8/src/itertools/lib.rs.html#247-269
#[allow(unused_macros)]
macro_rules! izip {
    (@ __closure @ ($a:expr)) => { |a| (a,) };
    (@ __closure @ ($a:expr, $b:expr)) => { |(a, b)| (a, b) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr)) => { |((a, b), c)| (a, b, c) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr)) => { |(((a, b), c), d)| (a, b, c, d) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr)) => { |((((a, b), c), d), e)| (a, b, c, d, e) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr)) => { |(((((a, b), c), d), e), f)| (a, b, c, d, e, f) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr)) => { |((((((a, b), c), d), e), f), g)| (a, b, c, d, e, f, e) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr)) => { |(((((((a, b), c), d), e), f), g), h)| (a, b, c, d, e, f, g, h) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr)) => { |((((((((a, b), c), d), e), f), g), h), i)| (a, b, c, d, e, f, g, h, i) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr)) => { |(((((((((a, b), c), d), e), f), g), h), i), j)| (a, b, c, d, e, f, g, h, i, j) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr)) => { |((((((((((a, b), c), d), e), f), g), h), i), j), k)| (a, b, c, d, e, f, g, h, i, j, k) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr)) => { |(((((((((((a, b), c), d), e), f), g), h), i), j), k), l)| (a, b, c, d, e, f, g, h, i, j, k, l) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr)) => { |((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m)| (a, b, c, d, e, f, g, h, i, j, k, l, m) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr, $n:expr)) => { |(((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m), n)| (a, b, c, d, e, f, g, h, i, j, k, l, m, n) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr, $n:expr, $o:expr)) => { |((((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m), n), o)| (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o) };

    ( $first:expr $(,)?) => {
        {
            #[allow(unused_imports)]
            use $crate::core_crypto::commons::utils::ZipChecked;
            ::core::iter::IntoIterator::into_iter($first)
        }
    };
    ( $first:expr, $($rest:expr),+ $(,)?) => {
        {
            #[allow(unused_imports)]
            use tfhe::core_crypto::commons::utils::ZipChecked;
            ::core::iter::IntoIterator::into_iter($first)
                $(.zip_checked($rest))*
                .map($crate::utils::izip!(@ __closure @ ($first, $($rest),*)))
        }
    };
}

#[allow(unused_imports)]
pub(crate) use izip;
