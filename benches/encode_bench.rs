use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use fm_aero_code_2::crypto::CipherKind;
use fm_aero_code_2::encoder::pipeline::{encode_payload, CompressionMode, EncodeOptions};

fn opts() -> EncodeOptions {
    EncodeOptions {
        cipher: CipherKind::None,
        password: String::new(),
        pad: true,
        compression: CompressionMode::LosslessPriority,
        original_name: "bench.bin".into(),
        center_logo: None,
        signing_key: None,
        hmac_enabled: true,
        auto_lossless_media: true,
        recipient_key: None,
        recipients: Vec::new(),
        gps: None,
        resilience_level: 0,
        border: false,
        gamma: false,
        mask: false,
    }
}

fn gen_text(size: usize) -> Vec<u8> {
    let words = ["the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog"];
    let mut out = Vec::with_capacity(size);
    let mut seed: u64 = 0xDEADBEEF;
    while out.len() < size {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.extend_from_slice(words[(seed as usize) % words.len()].as_bytes());
        out.push(b\x27 \x27);
    }
    out.truncate(size);
    out
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_payload");
    for size in [128usize, 512, 2048].iter() {
        let data = gen_text(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("text", size), &data, |b, d| {
            b.iter(|| { let _ = encode_payload(d, &opts()); });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);