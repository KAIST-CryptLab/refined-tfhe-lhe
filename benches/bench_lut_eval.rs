use refined_tfhe_lhe::{get_val_and_abs_err, glwe_ciphertext_monic_monomial_div_assign, int_lhe_instance::INT_LHE_BASE_16, keygen_pbs};
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::Rng;
use tfhe::core_crypto::{
    prelude::*,
    fft_impl::fft64::{
        c64,
        crypto::wop_pbs::{
            vertical_packing_scratch,
            vertical_packing,
        },
    },
};

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets = 
        criterion_benchmark_lut_8_to_4,
        criterion_benchmark_lut_12_to_4,
        criterion_benchmark_lut_16_to_4,
);
criterion_main!(benches);

const MESSAGE_SIZE: usize = 8;

#[allow(unused)]
fn criterion_benchmark_lut_8_to_4(c: &mut Criterion) {
    let mut group = c.benchmark_group("LUT");

    let param_list = [
        (*INT_LHE_BASE_16, 4),
    ];

    for (param, chunk_size) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let glwe_dimension = param.glwe_dimension();
        let polynomial_size = param.polynomial_size();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let ks_base_log = param.ks_base_log();
        let ks_level = param.ks_level();
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let ciphertext_modulus = param.ciphertext_modulus();

        let glwe_size = glwe_dimension.to_glwe_size();
        let chunk_size = *chunk_size as usize;
        let modulus = 1 << chunk_size;
        let delta = 1u64 << (63 - chunk_size);

        println!(
"n: {}, N: {}, k: {}, l_cbs: {}, B_cbs: 2^{}",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, cbs_level.0, cbs_base_log.0,
        );

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_secret_key,
            glwe_secret_key,
            _lwe_secret_key_after_ks,
            _bsk,
            _ksk,
        ) = keygen_pbs(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            &mut secret_generator,
            &mut encryption_generator,
        );

        // Set input LWE ciphertexts
        let mut rng = rand::rng();
        let msg= rng.random_range(0..(1 << MESSAGE_SIZE)) as usize;
        let msg_lower = msg % modulus;
        let msg_upper = msg >> chunk_size;

        let lut_input_size = MESSAGE_SIZE;

        let lut = (0..(1 << lut_input_size)).map(|_| {
            rng.random_range(0..(1 << chunk_size)) as usize
        }).collect::<Vec<usize>>();
        let modified_lut = (0..(1 << lut_input_size)).map(|i| {
            let masked_input = masking_chunk_msb(i, chunk_size);
            lut[masked_input]
        }).collect::<Vec<usize>>();

        let msg_lower_extr = masked_bit_extraction(msg_lower, chunk_size);
        let mut msg_upper_extr = masked_bit_extraction(msg_upper, chunk_size);

        let mut msg_extr = msg_lower_extr;
        msg_extr.append(&mut msg_upper_extr);

        let mut ggsw_list = GgswCiphertextList::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, GgswCiphertextCount(MESSAGE_SIZE), ciphertext_modulus);
        for (bit, mut ggsw) in msg_extr.iter().zip(ggsw_list.iter_mut()) {
            encrypt_constant_ggsw_ciphertext(&glwe_secret_key, &mut ggsw, Plaintext(*bit as u64), glwe_modular_std_dev, &mut encryption_generator);
        }

        let mut fourier_ggsw_list = FourierGgswCiphertextList::new(
            vec![
                c64::default();
                MESSAGE_SIZE * polynomial_size.to_fourier_polynomial_size().0
                    * glwe_size.0
                    * glwe_size.0
                    * cbs_level.0
            ],
            MESSAGE_SIZE,
            glwe_size,
            polynomial_size,
            cbs_base_log,
            cbs_level,
        );
        for (mut fourier_ggsw, ggsw) in fourier_ggsw_list.as_mut_view().into_ggsw_iter().zip(ggsw_list.iter()) {
            convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
        }

        let accumulator = (0..polynomial_size.0).map(|i| {
            if i < (1 << MESSAGE_SIZE) {
                modified_lut[i] as u64 * delta
            } else {
                0u64
            }
        }).collect::<Vec<u64>>();
        let accumulator_plaintext = PlaintextList::from_container(accumulator);
        let mut accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext, ciphertext_modulus);

        group.bench_function(
            BenchmarkId::new(
                "8-to-4 LUT",
                format!("base 2^{}", chunk_size),
            ),
            |b| b.iter(|| {
                for (bit_idx, fourier_ggsw) in fourier_ggsw_list.as_view().into_ggsw_iter().enumerate() {
                    let mut buf = accumulator.clone();
                    glwe_ciphertext_monic_monomial_div_assign(
                        black_box(&mut buf),
                        MonomialDegree(1 << bit_idx),
                    );
                    cmux_assign(
                        black_box(&mut accumulator),
                        black_box(&mut buf),
                        black_box(&fourier_ggsw),
                    );
                }
                
                let mut lwe_out = LweCiphertext::new(0u64, lwe_secret_key.lwe_dimension().to_lwe_size(), ciphertext_modulus);
                extract_lwe_sample_from_glwe_ciphertext(
                    black_box(&accumulator),
                    black_box(&mut lwe_out),
                    MonomialDegree(0),
                );
            }),
        );

        let mut accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext, ciphertext_modulus);
        let mut lwe_out = LweCiphertext::new(0u64, lwe_secret_key.lwe_dimension().to_lwe_size(), ciphertext_modulus);

        for (bit_idx, fourier_ggsw) in fourier_ggsw_list.as_view().into_ggsw_iter().enumerate() {
            let mut buf = accumulator.clone();
            glwe_ciphertext_monic_monomial_div_assign(
                black_box(&mut buf),
                MonomialDegree(1 << bit_idx),
            );
            cmux_assign(
                black_box(&mut accumulator),
                black_box(&mut buf),
                black_box(&fourier_ggsw),
            );
        }

        extract_lwe_sample_from_glwe_ciphertext(
            black_box(&accumulator),
            black_box(&mut lwe_out),
            MonomialDegree(0),
        );

        let correct_val = lut[msg] as u64;
        let (val, _) = get_val_and_abs_err(&lwe_secret_key, &lwe_out, correct_val, delta);
        println!("Correct val: {correct_val}, Decrypted val: {val}");
    }
}

#[allow(unused)]
fn criterion_benchmark_lut_12_to_4(c: &mut Criterion) {
        let mut group = c.benchmark_group("LUT");

    let param_list = [
        (*INT_LHE_BASE_16, 4),
    ];

    for (param, chunk_size) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let glwe_dimension = param.glwe_dimension();
        let polynomial_size = param.polynomial_size();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let ks_base_log = param.ks_base_log();
        let ks_level = param.ks_level();
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let ciphertext_modulus = param.ciphertext_modulus();

        let glwe_size = glwe_dimension.to_glwe_size();
        let chunk_size = *chunk_size as usize;
        let modulus = 1 << chunk_size;
        let delta = 1u64 << (63 - chunk_size);

        println!(
"n: {}, N: {}, k: {}, l_cbs: {}, B_cbs: 2^{}",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, cbs_level.0, cbs_base_log.0,
        );

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_secret_key,
            glwe_secret_key,
            _lwe_secret_key_after_ks,
            _bsk,
            _ksk,
        ) = keygen_pbs(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            &mut secret_generator,
            &mut encryption_generator,
        );
        let _bsk = _bsk.as_view();

        let mut rng = rand::rng();
        let lhs = rng.random_range(0..(1 << (MESSAGE_SIZE))) as usize; // 8-bit
        let rhs = rng.random_range(0..(1 << MESSAGE_SIZE / 2)) as usize; // 4-bit

        let lhs_lower = lhs % modulus;
        let lhs_upper = lhs >> chunk_size;

        let lut_input_size = MESSAGE_SIZE / 2 + MESSAGE_SIZE;
        let lut = (0..(1 << lut_input_size)).map(|i| {
            i % modulus
        }).collect::<Vec<usize>>();
        let modified_lut = (0..(1 << lut_input_size)).map(|i| {
            let i_lhs = i % (1 << MESSAGE_SIZE);
            let i_rhs = i >> MESSAGE_SIZE;

            let masked_i_lhs = masking_chunk_msb(i_lhs, chunk_size);
            let masked_i_rhs = masking_chunk_msb(i_rhs, chunk_size);

            let masked_input = masked_i_lhs + (masked_i_rhs << MESSAGE_SIZE);
            lut[masked_input]
        }).collect::<Vec<usize>>();

        let lhs_lower_extr = masked_bit_extraction(lhs_lower, chunk_size);
        let mut lhs_upper_extr = masked_bit_extraction(lhs_upper, chunk_size);
        let mut rhs_extr = masked_bit_extraction(rhs, chunk_size);

        let mut input_extr = lhs_lower_extr;
        input_extr.append(&mut lhs_upper_extr);
        input_extr.append(&mut rhs_extr);

        let mut ggsw_list = GgswCiphertextList::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, GgswCiphertextCount(lut_input_size), ciphertext_modulus);
        for (bit, mut ggsw) in input_extr.iter().zip(ggsw_list.iter_mut().rev()) {
            encrypt_constant_ggsw_ciphertext(&glwe_secret_key, &mut ggsw, Plaintext(*bit as u64), glwe_modular_std_dev, &mut encryption_generator);
        }

        let mut fourier_ggsw_list = FourierGgswCiphertextList::new(
            vec![
                c64::default();
                lut_input_size * polynomial_size.to_fourier_polynomial_size().0
                    * glwe_size.0
                    * glwe_size.0
                    * cbs_level.0
            ],
            lut_input_size,
            glwe_size,
            polynomial_size,
            cbs_base_log,
            cbs_level,
        );
        for (mut fourier_ggsw, ggsw) in fourier_ggsw_list.as_mut_view().into_ggsw_iter().zip(ggsw_list.iter()) {
            convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
        }

        let num_lut_in_vp = (1 << lut_input_size) / polynomial_size.0;
        let mut modified_lut_list = PolynomialList::new(0u64, polynomial_size, PolynomialCount(num_lut_in_vp));
        let mut lwe_out = LweCiphertext::new(0u64, lwe_secret_key.lwe_dimension().to_lwe_size(), ciphertext_modulus);

        for (cmux_idx, mut cur_lut) in modified_lut_list.iter_mut().enumerate() {
            for (i, val) in cur_lut.iter_mut().enumerate() {
                let input = cmux_idx * polynomial_size.0 + i;
                *val = (modified_lut[input] as u64) * delta;
            }
        }

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        group.bench_function(
            BenchmarkId::new(
                "12-to-4 LUT",
                format!("base 2^{}", chunk_size),
            ),
            |b| b.iter(|| {
                let mut buffer = ComputationBuffers::new();
                buffer.resize(
                    vertical_packing_scratch::<u64>(
                        glwe_size,
                        polynomial_size,
                        PolynomialCount(num_lut_in_vp),
                        lut_input_size, 
                        fft,
                    )
                    .unwrap()
                    .unaligned_bytes_required(),
                );
                let stack = buffer.stack();

                vertical_packing(
                    black_box(modified_lut_list.as_view()),
                    black_box(lwe_out.as_mut_view()),
                    black_box(fourier_ggsw_list.as_view()),
                    black_box(fft),
                    black_box(stack),
                );
            }),
        );

        let correct_val = lut[lhs + (rhs << MESSAGE_SIZE)] as u64;
        let (val, _) = get_val_and_abs_err(&lwe_secret_key, &lwe_out, correct_val, delta);
        println!("Correct val: {correct_val}, Decrypted val: {val}");
    }
}

#[allow(unused)]
fn criterion_benchmark_lut_16_to_4(c: &mut Criterion) {
        let mut group = c.benchmark_group("LUT");

    let param_list = [
        (*INT_LHE_BASE_16, 4),
    ];

    for (param, chunk_size) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let glwe_dimension = param.glwe_dimension();
        let polynomial_size = param.polynomial_size();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let ks_base_log = param.ks_base_log();
        let ks_level = param.ks_level();
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let ciphertext_modulus = param.ciphertext_modulus();

        let glwe_size = glwe_dimension.to_glwe_size();
        let chunk_size = *chunk_size as usize;
        let modulus = 1 << chunk_size;
        let delta = 1u64 << (63 - chunk_size);

        println!(
"n: {}, N: {}, k: {}, l_cbs: {}, B_cbs: 2^{}",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, cbs_level.0, cbs_base_log.0,
        );

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_secret_key,
            glwe_secret_key,
            _lwe_secret_key_after_ks,
            _bsk,
            _ksk,
        ) = keygen_pbs(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            &mut secret_generator,
            &mut encryption_generator,
        );
        let _bsk = _bsk.as_view();

        let mut rng = rand::rng();
        let lhs = rng.random_range(0..(1 << MESSAGE_SIZE)) as usize;
        let rhs = rng.random_range(0..(1 << MESSAGE_SIZE)) as usize;

        let lhs_lower = lhs % modulus;
        let lhs_upper = lhs >> chunk_size;

        let rhs_lower = rhs % modulus;
        let rhs_upper = rhs >> chunk_size;

        let lut_input_size = 2 * MESSAGE_SIZE;
        let lut = (0..(1 << lut_input_size)).map(|i| {
            i % modulus
        }).collect::<Vec<usize>>();
        let modified_lut = (0..(1 << lut_input_size)).map(|i| {
            let i_lhs = i % (1 << MESSAGE_SIZE);
            let i_rhs = i >> MESSAGE_SIZE;

            let masked_i_lhs = masking_chunk_msb(i_lhs, chunk_size);
            let masked_i_rhs = masking_chunk_msb(i_rhs, chunk_size);

            let masked_input = masked_i_lhs + (masked_i_rhs << MESSAGE_SIZE);
            lut[masked_input]
        }).collect::<Vec<usize>>();

        let lhs_lower_extr = masked_bit_extraction(lhs_lower, chunk_size);
        let mut lhs_upper_extr = masked_bit_extraction(lhs_upper, chunk_size);
        let mut rhs_lower_extr = masked_bit_extraction(rhs_lower, chunk_size);
        let mut rhs_upper_extr = masked_bit_extraction(rhs_upper, chunk_size);

        let mut input_extr = lhs_lower_extr;
        input_extr.append(&mut lhs_upper_extr);
        input_extr.append(&mut rhs_lower_extr);
        input_extr.append(&mut rhs_upper_extr);

        let mut ggsw_list = GgswCiphertextList::new(0u64, glwe_size, polynomial_size, cbs_base_log, cbs_level, GgswCiphertextCount(lut_input_size), ciphertext_modulus);
        for (bit, mut ggsw) in input_extr.iter().zip(ggsw_list.iter_mut().rev()) {
            encrypt_constant_ggsw_ciphertext(&glwe_secret_key, &mut ggsw, Plaintext(*bit as u64), glwe_modular_std_dev, &mut encryption_generator);
        }

        let mut fourier_ggsw_list = FourierGgswCiphertextList::new(
            vec![
                c64::default();
                lut_input_size * polynomial_size.to_fourier_polynomial_size().0
                    * glwe_size.0
                    * glwe_size.0
                    * cbs_level.0
            ],
            lut_input_size,
            glwe_size,
            polynomial_size,
            cbs_base_log,
            cbs_level,
        );
        for (mut fourier_ggsw, ggsw) in fourier_ggsw_list.as_mut_view().into_ggsw_iter().zip(ggsw_list.iter()) {
            convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
        }

        let num_lut_in_vp = (1 << lut_input_size) / polynomial_size.0;
        let mut modified_lut_list = PolynomialList::new(0u64, polynomial_size, PolynomialCount(num_lut_in_vp));
        let mut lwe_out = LweCiphertext::new(0u64, lwe_secret_key.lwe_dimension().to_lwe_size(), ciphertext_modulus);

        for (cmux_idx, mut cur_lut) in modified_lut_list.iter_mut().enumerate() {
            for (i, val) in cur_lut.iter_mut().enumerate() {
                let input = cmux_idx * polynomial_size.0 + i;
                *val = (modified_lut[input] as u64) * delta;
            }
        }

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        group.bench_function(
            BenchmarkId::new(
                "16-to-4 LUT",
                format!("base 2^{}", chunk_size),
            ),
            |b| b.iter(|| {
                let mut buffer = ComputationBuffers::new();
                buffer.resize(
                    vertical_packing_scratch::<u64>(
                        glwe_size,
                        polynomial_size,
                        PolynomialCount(num_lut_in_vp),
                        lut_input_size, 
                        fft,
                    )
                    .unwrap()
                    .unaligned_bytes_required(),
                );
                let stack = buffer.stack();

                vertical_packing(
                    black_box(modified_lut_list.as_view()),
                    black_box(lwe_out.as_mut_view()),
                    black_box(fourier_ggsw_list.as_view()),
                    black_box(fft),
                    black_box(stack),
                );
            }),
        );

        let correct_val = lut[lhs + (rhs << MESSAGE_SIZE)] as u64;
        let (val, _) = get_val_and_abs_err(&lwe_secret_key, &lwe_out, correct_val, delta);
        println!("Correct val: {correct_val}, Decrypted val: {val}");
    }
}

fn masked_bit_extraction(input: usize, chunk_size: usize) -> Vec<usize> {
    let modulus = 1 << chunk_size;
    assert!(input < modulus);

    let msb = (input & (1 << (chunk_size - 1))) >> (chunk_size - 1);
    (0..chunk_size).map(|i| {
        if i == chunk_size - 1 {
            msb
        } else {
            msb ^ ((input & (1 << i)) >> i)
        }
    }).collect::<Vec<usize>>()
}

fn masking_chunk_msb(input: usize, chunk_size: usize) -> usize {
    let modulus = 1 << chunk_size;
    assert!(input < (1 << MESSAGE_SIZE));

    let lower = input % modulus;
    let upper = input >> chunk_size;

    let lower_extr = masked_bit_extraction(lower, chunk_size);
    let upper_extr = masked_bit_extraction(upper, chunk_size);

    let mut output = 0;
    for (i, (l, u)) in lower_extr.iter().zip(upper_extr.iter()).enumerate() {
        output += l << i;
        output += u << (i + chunk_size);
    }

    output
}
