use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::Rng;
use tfhe::core_crypto::prelude::*;
use refined_tfhe_lhe::{
    aes_instances::*, allocate_and_generate_new_glwe_keyswitch_key, automorphism::gen_all_auto_keys, blind_rotate_keyed_sboxes, convert_lev_state_to_ggsw, convert_standard_glwe_keyswitch_key_to_fourier, generate_scheme_switching_key, generate_vec_keyed_lut_accumulator, generate_vec_keyed_lut_glev, he_add_round_key, he_mix_columns_precomp, he_shift_rows, he_sub_bytes_8_to_24_by_patched_wwlp_cbs, he_sub_bytes_by_patched_wwlp_cbs, keygen_pbs_with_glwe_ds, keyswitch_lwe_ciphertext_by_glwe_keyswitch, known_rotate_keyed_lut_for_half_cbs, lev_mix_columns_precomp, lev_shift_rows, Aes128Ref, FourierGlweKeyswitchKey, BLOCKSIZE_IN_BIT, BLOCKSIZE_IN_BYTE, BYTESIZE, NUM_ROUNDS
};

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
        criterion_benchmark_aes_half_cbs,
);
criterion_main!(benches);

fn criterion_benchmark_aes_half_cbs(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes evaluation by patched WWL+ circuit bootstrapping");

    let param_list = [
        (*AES_HALF_CBS_SET_1, "AES HalfCBS SET 1"),
        (*AES_HALF_CBS_SET_2, "AES HalfCBS SET 2"),
    ];

    for (param, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let glwe_dimension = param.glwe_dimension();
        let polynomial_size = param.polynomial_size();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let glwe_ds_base_log = param.glwe_ds_base_log();
        let glwe_ds_level = param.glwe_ds_level();
        let common_polynomial_size = param.common_polynomial_size();
        let fft_type_ds = param.fft_type_ds();
        let auto_base_log = param.auto_base_log();
        let auto_level = param.auto_level();
        let fft_type_auto = param.fft_type_auto();
        let ss_base_log = param.ss_base_log();
        let ss_level = param.ss_level();
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let log_lut_count = param.log_lut_count();
        let ciphertext_modulus = param.ciphertext_modulus();

        let half_cbs_glwe_dimension = param.half_cbs_glwe_dimension();
        let half_cbs_polynomial_size = param.half_cbs_polynomial_size();
        let half_cbs_glwe_modular_std_dev = param.half_cbs_glwe_modular_std_dev();
        let half_cbs_glwe_ds_base_log = param.half_cbs_glwe_ds_base_log();
        let half_cbs_glwe_ds_level = param.half_cbs_glwe_ds_level();
        let half_cbs_fft_type_ds = param.half_cbs_fft_type_ds();
        let half_cbs_auto_base_log = param.half_cbs_auto_base_log();
        let half_cbs_auto_level = param.half_cbs_auto_level();
        let half_cbs_fft_type_auto = param.half_cbs_fft_type_auto();
        let half_cbs_ss_base_log = param.half_cbs_ss_base_log();
        let half_cbs_ss_level = param.half_cbs_ss_level();
        let half_cbs_base_log = param.half_cbs_base_log();
        let half_cbs_level = param.half_cbs_level();

        println!(
            "n: {}, lwe_std_dev: {}, N_common: {},
(HalfCBS),
k: {}, N: {}, glwe_std_dev: {}, B_ds: 2^{}, l_ds: 2^{}, fft_ds: {:?},
B_auto: 2^{}, l_auto: {}, fft_auto: {:?}, B_ss: 2^{}, l_ss: {}, B_cbs: 2^{}, l_cbs: {},
(CBS),
k: {}, N: {}, glwe_std_dev: {}, B_ds: 2^{}, l_ds: 2^{}, fft_type_ds: {:?},
B_auto: 2^{}, l_auto: {}, fft_auto: {:?}, B_ss: 2^{}, l_ss: {}, B_cbs: 2^{}, l_cbs: {}, log_lut_count: {}",
            lwe_dimension.0, lwe_modular_std_dev.0, common_polynomial_size.0,
            half_cbs_glwe_dimension.0, half_cbs_polynomial_size.0, half_cbs_glwe_modular_std_dev.0, half_cbs_glwe_ds_base_log.0, half_cbs_glwe_ds_level.0, half_cbs_fft_type_ds,
            half_cbs_auto_base_log.0, half_cbs_auto_level.0, half_cbs_fft_type_auto, half_cbs_ss_base_log.0, half_cbs_ss_level.0, half_cbs_base_log.0, half_cbs_level.0,
            glwe_dimension.0, polynomial_size.0, glwe_modular_std_dev.0, glwe_ds_base_log.0, glwe_ds_level.0, fft_type_ds,
            auto_base_log.0, auto_level.0, fft_type_auto, ss_base_log.0, ss_level.0, cbs_base_log.0, cbs_level.0, log_lut_count.0,
        );
        println!();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_sk,
            glwe_sk,
            lwe_sk_after_ks,
            fourier_bsk,
            fourier_ksk,
        ) = keygen_pbs_with_glwe_ds(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            glwe_ds_base_log,
            glwe_ds_level,
            common_polynomial_size,
            fft_type_ds,
            ciphertext_modulus,
            &mut secret_generator,
            &mut encryption_generator,
        );
        let fourier_bsk = fourier_bsk.as_view();

        let ss_key = generate_scheme_switching_key(
            &glwe_sk,
            ss_base_log,
            ss_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let ss_key = ss_key.as_view();

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            fft_type_auto,
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let half_cbs_glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(half_cbs_glwe_dimension, half_cbs_polynomial_size, &mut secret_generator);
        let half_cbs_lwe_sk = half_cbs_glwe_sk.clone().into_lwe_secret_key();

        let half_cbs_glwe_size = half_cbs_glwe_dimension.to_glwe_size();
        let half_cbs_lwe_size = half_cbs_lwe_sk.lwe_dimension().to_lwe_size();

        let half_cbs_lwe_sk_view = GlweSecretKey::from_container(half_cbs_glwe_sk.as_ref(), common_polynomial_size);
        let lwe_sk_after_ks_view = GlweSecretKey::from_container(lwe_sk_after_ks.as_ref(), common_polynomial_size);

        let half_cbs_standard_glwe_ksk = allocate_and_generate_new_glwe_keyswitch_key(
            &half_cbs_lwe_sk_view,
            &lwe_sk_after_ks_view,
            half_cbs_glwe_ds_base_log,
            half_cbs_glwe_ds_level,
            half_cbs_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut half_cbs_glwe_ksk = FourierGlweKeyswitchKey::new(
            half_cbs_lwe_sk_view.glwe_dimension().to_glwe_size(),
            lwe_sk_after_ks_view.glwe_dimension().to_glwe_size(),
            common_polynomial_size,
            half_cbs_glwe_ds_base_log,
            half_cbs_glwe_ds_level,
            half_cbs_fft_type_ds,
        );
        convert_standard_glwe_keyswitch_key_to_fourier(&half_cbs_standard_glwe_ksk, &mut half_cbs_glwe_ksk);

        let half_cbs_auto_keys = gen_all_auto_keys(
            half_cbs_auto_base_log,
            half_cbs_auto_level,
            half_cbs_fft_type_auto,
            &half_cbs_glwe_sk,
            half_cbs_glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let half_cbs_ss_key = generate_scheme_switching_key(
            &half_cbs_glwe_sk,
            half_cbs_ss_base_log,
            half_cbs_ss_level,
            half_cbs_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let half_cbs_ss_key = half_cbs_ss_key.as_view();

        let large_lwe_size = lwe_sk.lwe_dimension().to_lwe_size();

        // ======== Plain ========
        let mut rng = rand::rng();
        let mut key = [0u8; BLOCKSIZE_IN_BYTE];
        for i in 0..BLOCKSIZE_IN_BYTE {
            key[i] = rng.random_range(0..=u8::MAX);
        }

        let aes = Aes128Ref::new(&key);
        let round_keys = aes.get_round_keys();

        let mut message = [0u8; BLOCKSIZE_IN_BYTE];
        for i in 0..16 {
            message[i] = rng.random_range(0..=255);
        }

        // ======== HE ========
        let mut he_round_keys = Vec::<LweCiphertextListOwned<u64>>::with_capacity(NUM_ROUNDS + 1);
        for r in 0..=NUM_ROUNDS {
            let mut lwe_list_rk = if r <= 2 {
                LweCiphertextList::new(
                    0u64,
                    half_cbs_lwe_size,
                    LweCiphertextCount(BLOCKSIZE_IN_BIT),
                    ciphertext_modulus,
                )
            } else {
                LweCiphertextList::new(
                    0u64,
                    large_lwe_size,
                    LweCiphertextCount(BLOCKSIZE_IN_BIT),
                    ciphertext_modulus,
                )
            };

            let rk = PlaintextList::from_container((0..BLOCKSIZE_IN_BIT).map(|i| {
                let byte_idx = i / BYTESIZE;
                let bit_idx = i % BYTESIZE;
                let round_key_byte = round_keys[r][byte_idx];
                let round_key_bit = (round_key_byte & (1 << bit_idx)) >> bit_idx;
                (round_key_bit as u64) << 63
            }).collect::<Vec<u64>>());
            if r <= 2 {
                encrypt_lwe_ciphertext_list(
                    &half_cbs_lwe_sk,
                    &mut lwe_list_rk,
                    &rk,
                    half_cbs_glwe_modular_std_dev,
                    &mut encryption_generator,
                );
            } else {
                encrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &mut lwe_list_rk,
                    &rk,
                    glwe_modular_std_dev,
                    &mut encryption_generator,
                );
            }

            he_round_keys.push(lwe_list_rk);
        }

        let mut he_state = LweCiphertextList::new(
            0u64,
            large_lwe_size,
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );
        let mut he_state_mult_by_2 = LweCiphertextList::new(
            0u64,
            large_lwe_size,
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );
        let mut he_state_mult_by_3 = LweCiphertextList::new(
            0u64,
            large_lwe_size,
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );
        let mut he_state_ks = LweCiphertextList::new(
            0u64,
            lwe_sk_after_ks.lwe_dimension().to_lwe_size(),
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );

        let mut half_cbs_he_state = LweCiphertextList::new(
            0u64,
            half_cbs_lwe_size,
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );
        let mut half_cbs_he_state_mult_by_2 = LweCiphertextList::new(
            0u64,
            half_cbs_lwe_size,
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );
        let mut half_cbs_he_state_mult_by_3 = LweCiphertextList::new(
            0u64,
            half_cbs_lwe_size,
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );

        let mut lev_state = Vec::<LweCiphertextListOwned<u64>>::with_capacity(BLOCKSIZE_IN_BIT);
        let mut lev_state_mult_by_2 = Vec::<LweCiphertextListOwned<u64>>::with_capacity(BLOCKSIZE_IN_BIT);
        let mut lev_state_mult_by_3 = Vec::<LweCiphertextListOwned<u64>>::with_capacity(BLOCKSIZE_IN_BIT);

        for _ in 0..BLOCKSIZE_IN_BIT {
            lev_state.push(LweCiphertextList::new(0u64, half_cbs_lwe_size, LweCiphertextCount(half_cbs_level.0), ciphertext_modulus));
            lev_state_mult_by_2.push(LweCiphertextList::new(0u64, half_cbs_lwe_size, LweCiphertextCount(half_cbs_level.0), ciphertext_modulus));
            lev_state_mult_by_3.push(LweCiphertextList::new(0u64, half_cbs_lwe_size, LweCiphertextCount(half_cbs_level.0), ciphertext_modulus));
        }

        for (bit_idx, mut he_bit) in he_state.iter_mut().enumerate() {
            let byte_idx = bit_idx / 8;
            let pt = (message[byte_idx] & (1 << bit_idx)) >> bit_idx;
            *he_bit.get_mut_body().data += (pt as u64) << 63;
        }

        let vec_keyed_sbox_glev_round_1 = generate_vec_keyed_lut_glev(
            aes.get_keyed_sbox(0),
            half_cbs_base_log,
            half_cbs_level,
            &half_cbs_glwe_sk,
            half_cbs_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let vec_keyed_sbox_mult_by_2_glev_round_1 = generate_vec_keyed_lut_glev(
            aes.get_keyed_sbox_mult_by_2(0),
            half_cbs_base_log,
            half_cbs_level,
            &half_cbs_glwe_sk,
            half_cbs_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let vec_keyed_sbox_mult_by_3_glev_round_1 = generate_vec_keyed_lut_glev(
            aes.get_keyed_sbox_mult_by_3(0),
            half_cbs_base_log,
            half_cbs_level,
            &half_cbs_glwe_sk,
            half_cbs_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let vec_keyed_sbox_acc_round_2 = generate_vec_keyed_lut_accumulator(
            aes.get_keyed_sbox(1),
            u64::BITS as usize - 1,
            &half_cbs_glwe_sk,
            half_cbs_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let vec_keyed_sbox_mult_by_2_acc_round_2 = generate_vec_keyed_lut_accumulator(
            aes.get_keyed_sbox_mult_by_2(1),
            u64::BITS as usize - 1,
            &half_cbs_glwe_sk,
            half_cbs_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let vec_keyed_sbox_mult_by_3_acc_round_2 = generate_vec_keyed_lut_accumulator(
            aes.get_keyed_sbox_mult_by_3(1),
            u64::BITS as usize - 1,
            &half_cbs_glwe_sk,
            half_cbs_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        // Bench
        he_state.as_mut().fill(0u64);
        for (bit_idx, mut he_bit) in he_state.iter_mut().enumerate() {
            let byte_idx = bit_idx / 8;
            let pt = (message[byte_idx] & (1 << bit_idx)) >> bit_idx;
            *he_bit.get_mut_body().data += (pt as u64) << 63;
        }

        { // r = 1
            // Keyed-LUT
            group.bench_function(
                BenchmarkId::new(
                    format!("Round 1 Keyed-LUT"),
                    id,
                ),
                |b| b.iter(|| {
                    known_rotate_keyed_lut_for_half_cbs(
                        black_box(message),
                        black_box(&vec_keyed_sbox_glev_round_1),
                        black_box(&mut lev_state),
                    );
                    known_rotate_keyed_lut_for_half_cbs(
                        black_box(message),
                        black_box(&vec_keyed_sbox_mult_by_2_glev_round_1),
                        black_box(&mut lev_state_mult_by_2),
                    );
                    known_rotate_keyed_lut_for_half_cbs(
                        black_box(message),
                        black_box(&vec_keyed_sbox_mult_by_3_glev_round_1),
                        black_box(&mut lev_state_mult_by_3),
                    );
                }),
            );

            // Linear
            group.bench_function(
                BenchmarkId::new(
                    format!("Round 1 ShiftRows and MixColumns"),
                    id,
                ),
                |b| b.iter(|| {
                    lev_shift_rows(black_box(&mut lev_state));
                    lev_shift_rows(black_box(&mut lev_state_mult_by_2));
                    lev_shift_rows(black_box(&mut lev_state_mult_by_3));
                    lev_mix_columns_precomp(
                        black_box(&mut lev_state),
                        black_box(&lev_state_mult_by_2),
                        black_box(&lev_state_mult_by_3),
                    );
                }),
            );
        }

        { // r = 2
            // Keyed LUT by HalfCBS
            group.bench_function(
                BenchmarkId::new(
                    format!("Round 2 HalfCBS Keyed-LUT"),
                    id,
                ),
                |b| b.iter(|| {
                    let mut ggsw_state = GgswCiphertextList::new(0u64, half_cbs_glwe_size, half_cbs_polynomial_size, half_cbs_base_log, half_cbs_level, GgswCiphertextCount(BLOCKSIZE_IN_BIT), ciphertext_modulus);

                    convert_lev_state_to_ggsw(
                        black_box(&lev_state),
                        black_box(&mut ggsw_state),
                        black_box(&half_cbs_auto_keys),
                        black_box(half_cbs_ss_key),
                    );

                    blind_rotate_keyed_sboxes(
                        black_box(&ggsw_state),
                        black_box(&vec_keyed_sbox_acc_round_2),
                        black_box(&vec_keyed_sbox_mult_by_2_acc_round_2),
                        black_box(&vec_keyed_sbox_mult_by_3_acc_round_2),
                        black_box(&mut half_cbs_he_state),
                        black_box(&mut half_cbs_he_state_mult_by_2),
                        black_box(&mut half_cbs_he_state_mult_by_3),
                    );
                }),
            );

            // Linear
            group.bench_function(
                BenchmarkId::new(
                    format!("Round 2 ShiftRows, MixColumns, AddRoundKey"),
                    id,
                ),
                |b| b.iter(|| {
                    he_shift_rows(black_box(&mut half_cbs_he_state));
                    he_shift_rows(black_box(&mut half_cbs_he_state_mult_by_2));
                    he_shift_rows(black_box(&mut half_cbs_he_state_mult_by_3));

                    he_mix_columns_precomp(
                        black_box(&mut half_cbs_he_state),
                        black_box(&half_cbs_he_state_mult_by_2),
                        black_box(&half_cbs_he_state_mult_by_3),
                    );

                    he_add_round_key(black_box(&mut half_cbs_he_state), black_box(&he_round_keys[2]));
                }),
            );
        }

        for r in 3..NUM_ROUNDS {
            // LWE KS
            group.bench_function(
                BenchmarkId::new(
                    format!("Round {r} LWE Keyswitching"),
                    id,
                ),
                |b| b.iter(|| {
                    if r == 3 {
                        for (lwe, mut lwe_ks) in half_cbs_he_state.iter().zip(he_state_ks.iter_mut()) {
                            keyswitch_lwe_ciphertext_by_glwe_keyswitch(
                                black_box(&lwe),
                                black_box(&mut lwe_ks),
                                black_box(&half_cbs_glwe_ksk),
                            );
                        }
                    } else {
                        for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
                            keyswitch_lwe_ciphertext_by_glwe_keyswitch(
                                black_box(&lwe),
                                black_box(&mut lwe_ks),
                                black_box(&fourier_ksk),
                            );
                        }
                    }
                })
            );

            // SubBytes
            group.bench_function(
                BenchmarkId::new(
                    format!("Round {r} SubBytes"),
                    id,
                ),
                |b| b.iter(|| {
                    he_sub_bytes_8_to_24_by_patched_wwlp_cbs(
                        black_box(&he_state_ks),
                        black_box(&mut he_state),
                        black_box(&mut he_state_mult_by_2),
                        black_box(&mut he_state_mult_by_3),
                        black_box(fourier_bsk),
                        black_box(&auto_keys),
                        black_box(ss_key),
                        black_box(cbs_base_log),
                        black_box(cbs_level),
                        black_box(log_lut_count),
                    );
                })
            );

            // Linear
            group.bench_function(
                BenchmarkId::new(
                    format!("Round {r} ShiftRows, MixColumns, AddRoundKey"),
                    id,
                ),
                |b| b.iter(|| {
                    // ShiftRows
                    he_shift_rows(black_box(&mut he_state));
                    he_shift_rows(black_box(&mut he_state_mult_by_2));
                    he_shift_rows(black_box(&mut he_state_mult_by_3));

                    // MixColumns
                    he_mix_columns_precomp(
                        black_box(&mut he_state),
                        black_box(&he_state_mult_by_2),
                        black_box(&he_state_mult_by_3),
                    );

                    // AddRoundKey
                    he_add_round_key(
                        black_box(&mut he_state),
                        black_box(&he_round_keys[r]),
                    );
                })
            );
        }

        // LWE KS
        group.bench_function(
            BenchmarkId::new(
                format!("Final Round LWE Keyswitching"),
                id,
            ),
            |b| b.iter(|| {
                for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
                    keyswitch_lwe_ciphertext_by_glwe_keyswitch(
                        black_box(&lwe),
                        black_box(&mut lwe_ks),
                        black_box(&fourier_ksk),
                    );
                }
            }));

        // SubBytes
        group.bench_function(
            BenchmarkId::new(
                format!("Final Round SubBytes"),
                id,
            ),
            |b| b.iter(|| {
                he_sub_bytes_by_patched_wwlp_cbs(
                    black_box(&he_state_ks),
                    black_box(&mut he_state),
                    black_box(fourier_bsk),
                    black_box(&auto_keys),
                    black_box(ss_key),
                    black_box(cbs_base_log),
                    black_box(cbs_level),
                    black_box(log_lut_count),
                );
            })
        );

        group.bench_function(
            BenchmarkId::new(
                format!("Final Round ShiftRows, AddRoundKey"),
                id,
            ),
            |b| b.iter(|| {
                // ShiftRows
                he_shift_rows(&mut he_state);

                // AddRoundKey
                he_add_round_key(&mut he_state, &he_round_keys[NUM_ROUNDS]);
            })
        );
    }
}
