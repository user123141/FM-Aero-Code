//! fm_split - encode file into N fixed print pages.

use anyhow::Result;
use std::path::PathBuf;
use fm_aero_code_2::crypto::CipherKind;
use fm_aero_code_2::encoder::pipeline::{encode_aeroflow, CompressionMode, EncodeOptions};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: fm_split <in> <out_dir> <N_pages> [--password P] [--resilience]");
        std::process::exit(1);
    }
    let in_path = PathBuf::from(&args[1]);
    let out_dir = PathBuf::from(&args[2]);
    let _n_pages: usize = args[3].parse().unwrap_or(4);
    let mut password = String::new();
    let mut resilience = false;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--password" if i + 1 < args.len() => { password = args[i + 1].clone(); i += 2; }
            "--resilience" => { resilience = true; i += 1; }
            _ => i += 1,
        }
    }

    std::fs::create_dir_all(&out_dir)?;
    let payload = std::fs::read(&in_path)?;
    let name = in_path.file_name().and_then(|n| n.to_str()).unwrap_or("payload.bin").to_string();

    let opts = EncodeOptions {
        cipher: if password.is_empty() { CipherKind::None } else { CipherKind::SealV1 },
        password,
        pad: true,
        compression: CompressionMode::LosslessPriority,
        original_name: name.clone(),
        center_logo: None,
        signing_key: None,
        hmac_enabled: true,
        auto_lossless_media: true,
        recipient_key: None,
        recipients: Vec::new(),
        gps: None,
        resilience,
    };

    let f = encode_aeroflow(&payload, &opts)?;
    println!("Encoding {} -> {} pages (resilience={})", name, f.frames.len(), f.resilience_enabled);
    for (idx, frame) in f.frames.iter().enumerate() {
        let kind = if idx < 200 || !f.resilience_enabled { "data" } else { "parity" };
        let out = out_dir.join(format!("{}_page{:05}_{}.png", &name, idx, kind));
        frame.save(&out)?;
        if idx < 5 || idx == f.frames.len() - 1 {
            println!("  [{}/{}] {}", idx + 1, f.frames.len(), out.display());
        }
    }
    println!("Saved {} pages to {}", f.frames.len(), out_dir.display());
    Ok(())
}