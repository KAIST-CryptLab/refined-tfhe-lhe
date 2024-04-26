use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::Rng;
use tfhe::core_crypto::prelude::*;
use hom_trace::{
    automorphism::gen_all_auto_keys, byte_array_to_mat, generate_scheme_switching_key, get_he_state_error, he_add_round_key, he_mix_columns, he_shift_rows, he_sub_bytes_by_patched_wwllp_cbs, keygen_pbs, Aes128Ref, FftType, BLOCKSIZE_IN_BIT, BLOCKSIZE_IN_BYTE, BYTESIZE, NUM_ROUNDS
};

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets =
        criterion_benchmark_aes,
);
criterion_main!(benches);

const FFT_TYPE: FftType = FftType::Split16;

#[allow(unused)]
struct WWLLpCBSParam<Scalar: UnsignedInteger> {
    lwe_dimension: LweDimension,
    lwe_modular_std_dev: StandardDev,
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    glwe_modular_std_dev: StandardDev,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    refresh_base_log: DecompositionBaseLog,
    refresh_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    auto_base_log: DecompositionBaseLog,
    auto_level: DecompositionLevelCount,
    ss_base_log: DecompositionBaseLog,
    ss_level: DecompositionLevelCount,
    cbs_base_log: DecompositionBaseLog,
    cbs_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
    ciphertext_modulus: CiphertextModulus::<Scalar>,
}

fn criterion_benchmark_aes(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes evaluation by patched WWLL+ circuit bootstrapping");

    // Set-I: WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS
    let set1 = WWLLpCBSParam {
        lwe_dimension: LweDimension(769),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        refresh_base_log: DecompositionBaseLog(23),
        refresh_level: DecompositionLevelCount(1),
        ks_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(6),
        auto_base_log: DecompositionBaseLog(7),
        auto_level: DecompositionLevelCount(7),
        ss_base_log: DecompositionBaseLog(8),
        ss_level: DecompositionLevelCount(6),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(5),
        log_lut_count: LutCountLog(2),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    // Set-II: N = 1024, k = 2
    let set2 = WWLLpCBSParam {
        lwe_dimension: LweDimension(769),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        refresh_base_log: DecompositionBaseLog(23),
        refresh_level: DecompositionLevelCount(1),
        ks_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(6),
        auto_base_log: DecompositionBaseLog(7),
        auto_level: DecompositionLevelCount(7),
        ss_base_log: DecompositionBaseLog(8),
        ss_level: DecompositionLevelCount(6),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(5),
        log_lut_count: LutCountLog(2),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    // Set-III: N = 512, k = 4
    let set3 = WWLLpCBSParam {
        lwe_dimension: LweDimension(769),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        refresh_base_log: DecompositionBaseLog(23),
        refresh_level: DecompositionLevelCount(1),
        ks_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(6),
        auto_base_log: DecompositionBaseLog(7),
        auto_level: DecompositionLevelCount(7),
        ss_base_log: DecompositionBaseLog(8),
        ss_level: DecompositionLevelCount(6),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(5),
        log_lut_count: LutCountLog(2),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    // Set-IV: N = 256, k = 8
    let set4 = WWLLpCBSParam {
        lwe_dimension: LweDimension(769),
        glwe_dimension: GlweDimension(8),
        polynomial_size: PolynomialSize(256),
        lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        refresh_base_log: DecompositionBaseLog(23),
        refresh_level: DecompositionLevelCount(1),
        ks_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(6),
        auto_base_log: DecompositionBaseLog(7),
        auto_level: DecompositionLevelCount(7),
        ss_base_log: DecompositionBaseLog(8),
        ss_level: DecompositionLevelCount(6),
        cbs_level: DecompositionLevelCount(3),
        cbs_base_log: DecompositionBaseLog(5),
        log_lut_count: LutCountLog(2),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
    };

    let param_list = [
        (set1, "set 1"),
        (set2, "set 2"),
        (set3, "set 3"),
        (set4, "set 4"),
    ];

    for (param, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension;
        let lwe_modular_std_dev = param.lwe_modular_std_dev;
        let glwe_dimension = param.glwe_dimension;
        let polynomial_size = param.polynomial_size;
        let glwe_modular_std_dev = param.glwe_modular_std_dev;
        let pbs_base_log = param.pbs_base_log;
        let pbs_level = param.pbs_level;
        let ks_base_log = param.ks_base_log;
        let ks_level = param.ks_level;
        let auto_base_log = param.auto_base_log;
        let auto_level = param.auto_level;
        let ss_base_log = param.ss_base_log;
        let ss_level = param.ss_level;
        let cbs_base_log = param.cbs_base_log;
        let cbs_level = param.cbs_level;
        let log_lut_count = param.log_lut_count;
        let ciphertext_modulus = param.ciphertext_modulus;

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_sk,
            glwe_sk,
            _lwe_sk_after_ks,
            fourier_bsk,
            ksk,
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
            FFT_TYPE,
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        // ======== Plain ========
        let mut rng = rand::thread_rng();
        let mut key = [0u8; BLOCKSIZE_IN_BYTE];
        for i in 0..BLOCKSIZE_IN_BYTE {
            key[i] = rng.gen_range(0..=u8::MAX);
        }

        let aes = Aes128Ref::new(&key);
        let round_keys = aes.get_round_keys();

        let mut message = [0u8; BLOCKSIZE_IN_BYTE];
        for i in 0..16 {
            message[i] = rng.gen_range(0..=255);
        }
        let correct_output = byte_array_to_mat(aes.encrypt_block(message));

        // ======== HE ========
        let mut he_round_keys = Vec::<LweCiphertextListOwned<u64>>::with_capacity(NUM_ROUNDS + 1);
        for r in 0..=NUM_ROUNDS {
            let mut lwe_list_rk = LweCiphertextList::new(
                0u64,
                fourier_bsk.output_lwe_dimension().to_lwe_size(),
                LweCiphertextCount(BLOCKSIZE_IN_BIT),
                ciphertext_modulus,
            );

            let rk = PlaintextList::from_container((0..BLOCKSIZE_IN_BIT).map(|i| {
                let byte_idx = i / BYTESIZE;
                let bit_idx = i % BYTESIZE;
                let round_key_byte = round_keys[r][byte_idx];
                let round_key_bit = (round_key_byte & (1 << bit_idx)) >> bit_idx;
                (round_key_bit as u64) << 63
            }).collect::<Vec<u64>>());
            encrypt_lwe_ciphertext_list(
                &lwe_sk,
                &mut lwe_list_rk,
                &rk,
                glwe_modular_std_dev,
                &mut encryption_generator,
            );

            he_round_keys.push(lwe_list_rk);
        }

        let mut he_state = LweCiphertextList::new(
            0u64,
            fourier_bsk.output_lwe_dimension().to_lwe_size(),
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );
        let mut he_state_ks = LweCiphertextList::new(
            0u64,
            ksk.output_lwe_size(),
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            ciphertext_modulus,
        );

        // Bench
        group.bench_function(
            BenchmarkId::new(
                "AES evaluation",
                format!("{id}"),
            ),
            |b| b.iter(|| {
                he_state.as_mut().fill(0u64);
                for (bit_idx, mut he_bit) in he_state.iter_mut().enumerate() {
                    let byte_idx = bit_idx / 8;
                    let pt = (message[byte_idx] & (1 << bit_idx)) >> bit_idx;
                    *he_bit.get_mut_body().data += (pt as u64) << 63;
                }

                // AddRoundKey
                he_add_round_key(
                    black_box(&mut he_state),
                    black_box(&he_round_keys[0]),
                );

                for r in 1..NUM_ROUNDS {
                    // LWE KS
                    for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
                        keyswitch_lwe_ciphertext(
                            black_box(&ksk),
                            black_box(&lwe),
                            black_box(&mut lwe_ks),
                        );
                    }

                    // SubBytes
                    he_sub_bytes_by_patched_wwllp_cbs(
                        black_box(&he_state_ks),
                        black_box(&mut he_state),
                        black_box(fourier_bsk),
                        black_box(&auto_keys),
                        black_box(ss_key),
                        black_box(cbs_base_log),
                        black_box(cbs_level),
                        black_box(log_lut_count),
                    );

                    // ShiftRows
                    he_shift_rows(black_box(&mut he_state));

                    // MixColumns
                    he_mix_columns(black_box(&mut he_state));

                    // AddRoundKey
                    he_add_round_key(
                        black_box(&mut he_state),
                        black_box(&he_round_keys[r]),
                    );
                }

                // LWE KS
                for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
                    keyswitch_lwe_ciphertext(
                        black_box(&ksk),
                        black_box(&lwe),
                        black_box(&mut lwe_ks),
                    );
                }

                // SubBytes
                he_sub_bytes_by_patched_wwllp_cbs(
                    black_box(&he_state_ks),
                    black_box(&mut he_state),
                    black_box(fourier_bsk),
                    black_box(&auto_keys),
                    black_box(ss_key),
                    black_box(cbs_base_log),
                    black_box(cbs_level),
                    black_box(log_lut_count),
                );

                // ShiftRows
                he_shift_rows(&mut he_state);

                // AddRoundKey
                he_add_round_key(&mut he_state, &he_round_keys[NUM_ROUNDS]);
            })
        );

        let (_, max_err) = get_he_state_error(&he_state, correct_output, &lwe_sk);

        println!(
            "n: {}, N: {}, k: {}, l_pbs: {}, B_pbs: 2^{}, l_cbs: {}, B_cbs: 2^{}
l_auto: {}, B_auto: 2^{}, l_ss: {}, B_ss: 2^{}, log_lut_count: {},
max err: {:.2} bits",
            lwe_dimension.0, polynomial_size.0, glwe_dimension.0, pbs_level.0, pbs_base_log.0, cbs_level.0, cbs_base_log.0,
            auto_level.0, auto_base_log.0, ss_level.0, ss_base_log.0, log_lut_count.0,
            (max_err as f64).log2(),
        );
        println!();
    }
}