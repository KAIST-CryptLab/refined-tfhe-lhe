// use tfhe::core_crypto::prelude::{*, polynomial_algorithms::*};
use tfhe::core_crypto::prelude::*;

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
            // use $crate::core_crypto::commons::utils::ZipChecked;
            use tfhe::core_crypto::commons::utils::ZipChecked;
            ::core::iter::IntoIterator::into_iter($first)
                $(.zip_checked($rest))*
                // .map($crate::core_crypto::commons::utils::izip!(@ __closure @ ($first, $($rest),*)))
                .map($crate::utils::izip!(@ __closure @ ($first, $($rest),*)))
        }
    };
}

#[allow(unused_imports)]
pub(crate) use izip;
