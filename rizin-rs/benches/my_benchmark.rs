use std::fmt::{Display, Formatter};

use criterion::{black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};
use rand::prelude::*;

use rizin_rs::wrapper::Core;

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
    let mut rng = rand::thread_rng();
    let data = (0..128).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    let core = Core::new();

    let mut f = |inp: Input| {
        inp.arch
            .map(|arch| core.set("analysis.arch", arch).unwrap());
        inp.cpu.map(|cpu| core.set("analysis.cpu", cpu).unwrap());

        c.bench_with_input(
            BenchmarkId::new("analysis_op", &inp),
            &data,
            |b: &mut Bencher, i| {
                b.iter(|| {
                    for x in i {
                        let b = x.to_le_bytes();
                        let _ = black_box(core.analysis_op(&b, 0));
                    }
                })
            },
        );
    };

    f(Input {
        arch: None,
        cpu: None,
    });
    f(Input {
        arch: Some("pic"),
        cpu: Some("pic16"),
    });
    f(Input {
        arch: Some("pic"),
        cpu: Some("pic18"),
    });
    f(Input {
        arch: Some("tricore"),
        cpu: None,
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
