use tfhe::core_crypto::prelude::*;
use hom_trace::{utils::*, rescale::*};

fn main() {
    type SmallQ = u64;
    type LargeQ = u128;

    let log_polynomial_size = 10;
    let log_large_q = SmallQ::BITS as usize + log_polynomial_size;


    let lwe_dimension = LweDimension(742);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let small_ciphertext_modulus = CiphertextModulus::<SmallQ>::new_native();
    let large_ciphertext_modulus = CiphertextModulus::<LargeQ>::try_new_power_of_2(log_large_q).unwrap();

    // Set random generators and buffers
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // Generate keys
    let lwe_sk: LweSecretKey<Vec<SmallQ>> = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);

    let mut lwe_sk_large_q = LweSecretKey::new_empty_key(LargeQ::ZERO, lwe_dimension);
    for (src, dst) in lwe_sk.as_ref().iter().zip(lwe_sk_large_q.as_mut().iter_mut()) {
        *dst = *src as LargeQ;
    }

    let msg = 1 as SmallQ;
    let delta = 1 << (SmallQ::BITS - 2);
    let pt = Plaintext(msg * delta);

    let mut ct = allocate_and_encrypt_new_lwe_ciphertext(&lwe_sk, pt, lwe_modular_std_dev, small_ciphertext_modulus, &mut encryption_generator);

    let dec = decrypt_lwe_ciphertext(&lwe_sk, &ct).0;
    let (_decoded, bit_err) = get_val_and_bit_err(&lwe_sk, &ct, msg, delta);
    let (_decoded, abs_err) = get_val_and_abs_err(&lwe_sk, &ct, msg, delta);
    println!("Input");
    println!("SmallQ: 0x{dec:x} | {bit_err} bits | 0x{abs_err}");

    println!("\nMod Raise");
    let mut ct_large_q = LweCiphertext::new(LargeQ::ZERO, ct.lwe_size(), large_ciphertext_modulus);
    lwe_ciphertext_mod_raise_from_native_to_non_native_power_of_two(&ct, &mut ct_large_q);

    let dec = decrypt_lwe_ciphertext(&lwe_sk_large_q, &ct_large_q).0;
    let dec_lower = (dec & ((1 << SmallQ::BITS) - 1)) as SmallQ;
    let abs_err = {
        let correct_val = msg * delta;
        let d0 = dec_lower.wrapping_sub(correct_val);
        let d1 = correct_val.wrapping_sub(dec_lower);
        std::cmp::min(d0, d1)
    };
    let bit_err = if abs_err != 0 {SmallQ::BITS - abs_err.leading_zeros()} else {0};
    println!("LargeQ lower: 0x{dec_lower:x} | {bit_err} bits | 0x{abs_err}");

    let dec_upper = ((dec >> SmallQ::BITS) as SmallQ) & ((1 << log_polynomial_size) - 1);
    let bit_size = if dec_upper != 0 {SmallQ::BITS - dec_upper.leading_zeros()} else {0};
    println!("LargeQ upper: 0x{dec_upper:x} | {bit_size} bits | 0x{dec_upper:x}");

    // Homomorphic Scalar Mult
    let scalar = 1 << log_polynomial_size;
    println!("\nMult by {}", scalar);
    lwe_ciphertext_cleartext_mul_assign(&mut ct, Cleartext(scalar));
    let (_decoded, bit_err) = get_val_and_bit_err(&lwe_sk, &ct, msg * scalar, delta);
    let (_decoded, abs_err) = get_val_and_abs_err(&lwe_sk, &ct, msg * scalar, delta);
    println!("SmallQ: {bit_err} bits | 0x{abs_err}");

    lwe_ciphertext_cleartext_mul_assign(&mut ct_large_q, Cleartext(scalar as LargeQ));
    let noise = allocate_and_encrypt_new_lwe_ciphertext(&lwe_sk_large_q, Plaintext(0), lwe_modular_std_dev, large_ciphertext_modulus, &mut encryption_generator);
    let dec = decrypt_lwe_ciphertext(&lwe_sk_large_q, &noise).0;
    let bit_err = LargeQ::BITS - dec.leading_zeros();
    println!("Noise: {bit_err} bits");
    lwe_ciphertext_add_assign(&mut ct_large_q, &noise);

    let dec = decrypt_lwe_ciphertext(&lwe_sk_large_q, &ct_large_q).0;
    let dec_lower = (dec & ((1 << SmallQ::BITS) - 1)) as SmallQ;
    let err = {
        let correct_val = msg * scalar * delta;
        let d0 = dec_lower.wrapping_sub(correct_val);
        let d1 = correct_val.wrapping_sub(dec_lower);
        std::cmp::min(d0, d1)
    };
    let bit_err = if err != 0 {SmallQ::BITS - err.leading_zeros()} else {0};
    println!("LargeQ lower: {bit_err} bits | 0x{err}");

    let dec_upper = (dec >> SmallQ::BITS) as SmallQ;
    let bit_size = if dec_upper != 0 {SmallQ::BITS - dec_upper.leading_zeros()} else {0};
    println!("LargeQ upper: {bit_size} bits | 0x{dec_upper:x}");


    // Rescale
    println!("\nRescale");
    let mut ct_rs = LweCiphertext::new(SmallQ::ZERO, ct.lwe_size(), small_ciphertext_modulus);
    lwe_ciphertext_rescale_from_non_native_power_of_two_to_native(&ct_large_q, &mut ct_rs);

    let dec = decrypt_lwe_ciphertext(&lwe_sk, &ct_rs).0;
    let (_decoded, bit_err) = get_val_and_bit_err(&lwe_sk, &ct_rs, msg, delta);
    let (_decoded, abs_err) = get_val_and_abs_err(&lwe_sk, &ct_rs, msg, delta);
    println!("SmallQ: 0x{dec:x} | {bit_err} bits | 0x{abs_err}");
}