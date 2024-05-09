# Automorphism-based LWE to GLWE Conversion
This is an implementation of 'Automorphism-based LWE(s) to GLWE Conversion without Phase Amplification for TFHE on FFT Domains'.

## Contents
We implement:
- tests for
  - several keyswitching methods and conversion methods
  - sampling output errors
  - AES reference implementation and TFHE evaluation
- benchmarks for
  - LWE(s) to GLWE conversion methods (Sec. 3.5)
  - circuit bootstrapping methods for WoP-PBS (Sec. 4.2)
  - AES evaluation (Sec. 4.3)

## How to use
- tests: `cargo test --release --test 'test_name'`
- bench: `cargo bench --bench 'benchmark_name'`
  - Current sample size is set to 1000. It can be changed by modifying `config = Criterion::default().sample_size(1000);`