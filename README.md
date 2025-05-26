# Refined TFHE Leveled Homomorphic Evaluation and Its Application
This is an implementation of '[Refined TFHE Leveled Homomorphic Evaluation and Its Application](https://eprint.iacr.org/2024/1318)'.

## Contents
We implement:
- benchmarks for
  - FFT-based circuit bootstrapping (Sec. 3.2)
    - [bench_bitwise_cbs.rs](benches/bench_bitwise_cbs.rs)
  - AES evaluation (Sec. 4.2)
    - [bench_aes.rs](benches/bench_aes.rs)
    - [bench_aes_half_cbs.rs](benches/bench_aes_half_cbs.rs)
  - Integer input LHE mode (Sec. 5.2) and LUT (Sec. 5.3)
    - [bench_integer_input_lhs.rs](benches/bench_integer_input_lhe.rs)
    - [bench_lut_eval.rs](benches/bench_lut_eval.rs)
- [error analysis](error_analysis) for the parameters used in the paper

## How to Use
- bench: `cargo bench --bench 'benchmark_name'`
  - Current sample size is set to 1000 (except AES benchmark). It can be changed by modifying `config = Criterion::default().sample_size(1000);`
  - To use AVX512: `cargo +nightly bench --bench 'benchamrk_name' --features=nightly-avx512`
- error analysis: check [README.md](error_analysis/README.md)