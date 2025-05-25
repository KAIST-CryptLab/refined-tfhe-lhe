use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;
use refined_tfhe_lhe::int_lhe_instance::*;


criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets =
        criterion_benchmark_cmux,
);
criterion_main!(benches);

#[allow(unused)]
fn criterion_benchmark_cmux(c: &mut Criterion) {
    let mut group = c.benchmark_group("wopbs");

    let param_list = [
        (*BITWISE_CBS_CMUX1, "CMUX1"),
        (*BITWISE_CBS_CMUX2, "CMUX2"),
        (*BITWISE_CBS_CMUX3, "CMUX3"),
        (*INT_LHE_BASE_16, "INT_LHE_BASE_16"),
    ];

    for (param, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension();
        let glwe_dimension = param.glwe_dimension();
        let polynomial_size = param.polynomial_size();
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let ciphertext_modulus = param.ciphertext_modulus();

        let glwe_size = glwe_dimension.to_glwe_size();

        let mut fourier_ggsw = FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);
        let mut ct0 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
        let mut ct1 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

        group.bench_function(
            BenchmarkId::new(
                "CMux",
                id,
            ),
            |b| b.iter(|| {
                cmux_assign(black_box(&mut ct0), black_box(&mut ct1), black_box(&fourier_ggsw));
            }),
        );
    }
}
