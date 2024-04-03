use std::collections::HashMap;
use aligned_vec::ABox;
use tfhe::core_crypto::{
    prelude::*,
    fft_impl::fft64::c64,
    algorithms::slice_algorithms::slice_wrapping_opposite_assign,
};
use crate::{
    mod_switch::*,
    automorphism::{trace_assign, AutomorphKey},
};

pub fn convert_lwe_to_glwe_const<Scalar, InputCont, OutputCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    let lwe_dimension = input.lwe_size().to_lwe_dimension().0;
    let glwe_dimension = output.glwe_size().to_glwe_dimension().0;
    let polynomial_size = output.polynomial_size().0;

    assert_eq!(lwe_dimension, glwe_dimension * polynomial_size);
    assert_eq!(input.ciphertext_modulus(), output.ciphertext_modulus());

    let (lwe_mask, lwe_body) = input.get_mask_and_body();
    let (mut glwe_mask, mut glwe_body) = output.get_mut_mask_and_body();

    // Set body
    *glwe_body.as_mut().get_mut(0).unwrap() = *lwe_body.data;

    // Set mask
    let lwe_mask = lwe_mask.as_ref();
    let glwe_mask = glwe_mask.as_mut();
    for (glwe_poly, lwe_poly) in glwe_mask.chunks_exact_mut(polynomial_size)
        .zip(lwe_mask.chunks_exact(polynomial_size))
    {
        glwe_poly.clone_from_slice(lwe_poly);
        glwe_poly.reverse();
        slice_wrapping_opposite_assign(&mut glwe_poly[0..(polynomial_size - 1)]);
        glwe_poly.rotate_left(polynomial_size - 1);
    }
}


pub fn convert_lwe_to_glwe_by_trace_with_mod_switch<Scalar, InputCont, OutputCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    assert_eq!(input.ciphertext_modulus(), output.ciphertext_modulus());
    assert!(
        input.ciphertext_modulus().is_native_modulus(),
        "only native ciphertext modulus is supported"
    );

    let lwe_size = input.lwe_size();
    let lwe_dimension = lwe_size.to_lwe_dimension();
    let glwe_size = output.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();
    let polynomial_size = output.polynomial_size();

    assert_eq!(lwe_dimension.0, glwe_dimension.0 * polynomial_size.0);

    // LWEtoGLWEConst
    convert_lwe_to_glwe_const(input, output);

    // Clear coefficients except the constant
    trace_with_mod_switch_assign(output, auto_keys);
}


pub fn trace_with_mod_switch<Scalar, InputCont, OutputCont>(
    input: &GlweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    assert_eq!(input.glwe_size(), output.glwe_size());
    assert_eq!(input.polynomial_size(), output.polynomial_size());
    assert_eq!(input.ciphertext_modulus(), output.ciphertext_modulus());

    output.as_mut().clone_from_slice(input.as_ref());
    trace_with_mod_switch_assign(output, auto_keys);
}


pub fn trace_with_mod_switch_assign<Scalar, Cont>(
    input: &mut GlweCiphertext<Cont>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
) where
    Scalar: UnsignedTorus,
    Cont: ContainerMut<Element=Scalar>,
{
    let glwe_size = input.glwe_size();
    let polynomial_size = input.polynomial_size();
    let log_polynomial_size = polynomial_size.0.ilog2() as usize;

    assert!(Scalar::BITS > log_polynomial_size);

    let log_small_q = Scalar::BITS as usize - log_polynomial_size;
    let small_ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_small_q).unwrap();

    // ModDown
    let mut buf_mod_down = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, small_ciphertext_modulus);
    glwe_ciphertext_mod_down_from_native_to_non_native_power_of_two(&input, &mut buf_mod_down);

    // ModUp
    glwe_ciphertext_mod_up_from_non_native_power_of_two_to_native(&buf_mod_down, input);

    // Trace
    trace_assign(input.as_mut_view(), auto_keys);
}
