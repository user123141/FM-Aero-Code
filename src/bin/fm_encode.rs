use fm_aero_code_2::crypto::CipherKind;
use fm_aero_code_2::encoder::pipeline::{encode_payload, CompressionMode, EncodeOptions};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("Usage: fm_encode <in> <out.png> [--password P] [--recipient HEX] [--lossless] [--border] [--gamma] [--mask]");
        std::process::exit(1);
    }
    let mut o = EncodeOptions::default();
    let mut dual_meta: Option<String> = None;
    o.original_name = Path::new(&a[1]).file_name().and_then(|n| n.to_str())
        .unwrap_or("payload.bin").into();
    let mut i = 3;
    while i < a.len() {
        match a[i].as_str() {
            "--password" if i + 1 < a.len() => { o.password = a[i + 1].clone(); o.cipher = CipherKind::SealV1; i += 2; }
            "--recipient" if i + 1 < a.len() => { o.recipient_key = Some(a[i + 1].clone()); o.cipher = CipherKind::SealV2; i += 2; }
            "--recipients" if i + 1 < a.len() => {
                o.recipients = a[i + 1].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                o.cipher = CipherKind::SealV2;
                i += 2;
            }
            "--lossless" => { o.compression = CompressionMode::Lossless; i += 1; }
            "--dual-meta" if i + 1 < a.len() => { dual_meta = Some(a[i + 1].clone()); i += 2; }
            "--border" => { o.border = true; i += 1; }
            "--gamma" => { o.gamma = true; i += 1; }
            "--mask" => { o.mask = true; i += 1; }
            _ => i += 1,
        }
    }
    let p = std::fs::read(&a[1])?;

    if let Some(meta_path) = dual_meta {
        let meta = std::fs::read(&meta_path)?;
        let stego_opts = fm_aero_code_2::steganography::StegoOptions {
            password: String::new(),
            original_name: std::path::Path::new(&meta_path).file_name()
                .and_then(|n| n.to_str()).unwrap_or("meta.bin").to_string(),
            mode: fm_aero_code_2::steganography::StegoMode::DualB,
            author: String::new(),
            license: String::new(),
            signing_seed: None,
        };
        let layered = fm_aero_code_2::layered::encode_layered(&p, &meta, &o, &stego_opts)?;
        layered.image.save(&a[2])?;
        println!("Saved LAYERED {}", a[2]);
        println!("  AeroGlint payload: {} B (ratio {:.2})", p.len(), layered.aero.ratio);
        println!("  Stego metadata:    {} B (DualB / B-channel LSB)", meta.len());
    } else {
        let r = encode_payload(&p, &o)?;
        r.image.save(&a[2])?;
        println!("Saved {} ({} B) type={} cipher={} ratio={:.2}",
            a[2], p.len(), r.data_type.label(), r.cipher.label(), r.ratio);
    }
    Ok(())
}
