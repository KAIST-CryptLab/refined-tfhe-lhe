use tfhe::core_crypto::prelude::*;

pub fn glwe_ciphertext_mod_up_from_native_to_non_native_power_of_two<ScalarIn, ScalarOut, InputCont, OutputCont>(
    input: &GlweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
) where
    ScalarIn: UnsignedInteger + CastInto<ScalarOut>,
    ScalarOut: UnsignedInteger,
    InputCont: Container<Element=ScalarIn>,
    OutputCont: ContainerMut<Element=ScalarOut>,
{
    assert!(
        input.ciphertext_modulus().is_native_modulus(),
        "input ciphertext modulus is not native"
    );
    assert!(
        output.ciphertext_modulus().is_non_native_power_of_two(),
        "output ciphertext modulus is not non-native power-of-two"
    );
    assert!(
        ScalarOut::BITS > ScalarIn::BITS,
        "output ciphertext modulus is not greater than input ciphertext modulus"
    );

    let output_ciphertext_modulus = output.ciphertext_modulus();
    for (src, dst) in input.as_ref().iter().zip(output.as_mut().iter_mut()) {
        if *src >> (ScalarIn::BITS - 1) == ScalarIn::ZERO {
            *dst = (*src).cast_into();
        } else {
            let neg_val: ScalarOut = (*src).wrapping_neg().cast_into();
            *dst = neg_val.wrapping_neg();
        }
        *dst = (*dst).wrapping_mul(output_ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
    }
}

pub fn glwe_ciphertext_mod_down_from_non_native_power_of_two_to_native<ScalarIn, ScalarOut, InputCont, OutputCont> (
    input: &GlweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
) where
    ScalarIn: UnsignedInteger + CastInto<ScalarOut>,
    ScalarOut: UnsignedInteger,
    InputCont: Container<Element=ScalarIn>,
    OutputCont: ContainerMut<Element=ScalarOut>,
{
    assert!(
        input.ciphertext_modulus().is_non_native_power_of_two(),
        "input ciphertext modulus is not non-native power-of-two"
    );

    assert!(
        output.ciphertext_modulus().is_native_modulus(),
        "output ciphertext modulus is not native"
    );

    assert!(
        ScalarOut::BITS < ScalarIn::BITS,
        "output ciphertext modulus is not greater than input ciphertext modulus"
    );

    let input_ciphertext_modulus = input.ciphertext_modulus();
    let divisor: ScalarIn = (input_ciphertext_modulus.get_custom_modulus() >> ScalarOut::BITS).cast_into();
    for (src, dst) in input.as_ref().iter().zip(output.as_mut().iter_mut()) {
        let val = (*src).wrapping_div(input_ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        *dst = ((val - val % divisor) / divisor).cast_into();
    }
}

pub fn glwe_ciphertext_mod_down_from_native_to_non_native_power_of_two<Scalar, InputCont, OutputCont> (
    input: &GlweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    assert!(
        input.ciphertext_modulus().is_native_modulus(),
        "input ciphertext modulus is not native"
    );

    assert!(
        output.ciphertext_modulus().is_non_native_power_of_two(),
        "output ciphertext modulus is not non-native power-of-two"
    );

    let output_ciphertext_modulus = output.ciphertext_modulus();
    let divisor = output_ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
    for (src, dst) in input.as_ref().iter().zip(output.as_mut().iter_mut()) {
        *dst = *src - (*src) % divisor;
    }
}

pub fn glwe_ciphertext_mod_up_from_non_native_power_of_two_to_native<Scalar, InputCont, OutputCont> (
    input: &GlweCiphertext<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element=Scalar>,
    OutputCont: ContainerMut<Element=Scalar>,
{
    assert!(
        input.ciphertext_modulus().is_non_native_power_of_two(),
        "input ciphertext modulus is not non-native power-of-two"
    );

    assert!(
        output.ciphertext_modulus().is_native_modulus(),
        "output ciphertext modulus is not native"
    );

    let input_ciphertext_modulus = input.ciphertext_modulus();
    let scaling_factor = input_ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
    for (src, dst) in input.as_ref().iter().zip(output.as_mut().iter_mut()) {
        *dst = (*src).wrapping_div(scaling_factor);
    }
}
