//! Benchmarks: AeroPack vs zstd vs gzip on typical payloads.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use fm_aero_code_2::encoder::compressor::{aero_pack, aero_unpack};

fn generate_text(size: usize) -> Vec<u8> {
    let words = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
        "lorem", "ipsum", "dolor", "sit", "amet", "consectetur",
    ];
    let mut out = Vec::with_capacity(size);
    let mut seed: u64 = 0xDEADBEEF;
    while out.len() < size {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let w = words[(seed as usize) % words.len()];
        out.extend_from_slice(w.as_bytes());
        out.push(b' ');
    }
    out.truncate(size);
    out
}

fn generate_random(size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut seed: u64 = 0x1234567890ABCDEF;
    for _ in 0..size {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((seed >> 33) as u8);
    }
    out
}

fn bench_aeropack_compress(c: &mut Criterion) {
    let mut group = c.benchmark_group("aeropack_compress");
    for size in [1024usize, 16 * 1024, 256 * 1024, 1024 * 1024].iter() {
        let text = generate_text(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("text", size), &text, |b, data| {
            b.iter(|| {
                let _ = aero_pack(data).unwrap();
            });
        });
        let rnd = generate_random(*size);
        group.bench_with_input(BenchmarkId::new("random", size), &rnd, |b, data| {
            b.iter(|| {
                let _ = aero_pack(data).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_aeropack_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("aeropack_roundtrip");
    for size in [16 * 1024usize, 256 * 1024].iter() {
        let text = generate_text(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("text", size), &text, |b, data| {
            b.iter(|| {
                let packed = aero_pack(data).unwrap();
                let unpacked = aero_unpack(&packed.data).unwrap();
                assert_eq!(unpacked.len(), data.len());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_aeropack_compress, bench_aeropack_roundtrip);
criterion_main!(benches);