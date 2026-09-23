use fm_aero_code_2::crypto::CipherKind;
use fm_aero_code_2::encoder::pipeline::{encode_payload, EncodeOptions, CompressionMode};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("fm_encode <in> <out.png> [--password P] [--recipient HEX] [--lossless]");
        std::process::exit(1);
    }
    let mut o = EncodeOptions::default();
    o.original_name = Path::new(&a[1]).file_name().and_then(|n| n.to_str()).unwrap_or("payload.bin").into();
    let mut i = 3;
    while i < a.len() {
        match a[i].as_str() {
            "--password" if i + 1 < a.len() => { o.password = a[i + 1].clone(); o.cipher = CipherKind::SealV1; i += 2; }
            "--recipient" if i + 1 < a.len() => { o.recipient_key = Some(a[i + 1].clone()); o.cipher = CipherKind::SealV2; i += 2; }
            "--recipients" if i + 1 < a.len() => {
                o.recipients = a[i + 1].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                o.cipher = CipherKind::SealV2; i += 2;
            }
            "--lossless" => { o.compression = CompressionMode::Lossless; i += 1; }
            _ => i += 1,
        }
    }
    let p = std::fs::read(&a[1])?;
    let r = encode_payload(&p, &o)?;
    r.image.save(&a[2])?;
    println!("Saved {} ({} B) type={} cipher={} ratio={:.2}",
        a[2], p.len(), r.data_type.label(), r.cipher.label(), r.ratio);
    Ok(())
}