use std::fmt::{Display, Formatter};

use criterion::{Bencher, BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::prelude::*;

use rizin_rs::RzCore;

struct Input<'a> {
    arch: Option<&'a str>,
    cpu: Option<&'a str>,
}

impl<'a> Display for Input<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}-{}",
            self.arch.unwrap_or(""),
            self.cpu.unwrap_or(""),
        ))
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::rng();
    let data = (0..128).map(|_| rng.next_u32()).collect::<Vec<_>>();
    let core = RzCore::new();

    let mut bench_analysis_op = |inp: Input| {
        inp.arch
            .map(|arch| core.config_set("analysis.arch", arch).unwrap());
        inp.cpu
            .map(|cpu| core.config_set("analysis.cpu", cpu).unwrap());

        c.bench_with_input(
            BenchmarkId::new("analysis_op", &inp),
            &data,
            |b: &mut Bencher, i| {
                b.iter(|| {
                    for x in i {
                        let b = x.to_le_bytes();
                        let _ = std::hint::black_box(core.analysis_op(
                            &b,
                            0,
                            rizin_sys::RZ_ANALYSIS_OP_MASK_DISASM
                                | rizin_sys::RZ_ANALYSIS_OP_MASK_IL,
                        ));
                    }
                })
            },
        );
    };

    bench_analysis_op(Input {
        arch: None,
        cpu: None,
    });
    bench_analysis_op(Input {
        arch: Some("pic"),
        cpu: Some("pic16"),
    });
    bench_analysis_op(Input {
        arch: Some("pic"),
        cpu: Some("pic18"),
    });
    bench_analysis_op(Input {
        arch: Some("tricore"),
        cpu: None,
    });
    bench_analysis_op(Input {
        arch: Some("h8300"),
        cpu: Some("h8300"),
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
