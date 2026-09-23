use anyhow::Result;
use std::path::PathBuf;
use fm_aero_code_2::crypto::CipherKind;
use fm_aero_code_2::encoder::pipeline::{encode_aeroflow, CompressionMode, EncodeOptions};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: fm_split <in> <out_dir> [--password P] [--resilience 0-4] [--gamma] [--mask] [--border]");
        std::process::exit(1);
    }
    let in_path = PathBuf::from(&args[1]);
    let out_dir = PathBuf::from(&args[2]);
    let mut password = String::new();
    let mut resilience_level: u8 = 0;
    let mut gamma = false;
    let mut mask = false;
    let mut border = false;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--password" if i + 1 < args.len() => { password = args[i + 1].clone(); i += 2; }
            "--resilience" if i + 1 < args.len() => {
                resilience_level = args[i + 1].parse().unwrap_or(0).min(4);
                i += 2;
            }
            "--gamma" => { gamma = true; i += 1; }
            "--mask" => { mask = true; i += 1; }
            "--border" => { border = true; i += 1; }
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
        resilience_level,
        border,
        gamma,
        mask,
    };
    let f = encode_aeroflow(&payload, &opts)?;
    println!("Input: {} ({} B)", name, payload.len());
    println!("Pages: {}", f.frames.len());
    println!("Groups: {} ({} data + {} parity)",
             f.num_groups, f.data_pages_per_group, f.parity_pages_per_group);
    for (idx, frame) in f.frames.iter().enumerate() {
        let kind = if idx % (f.data_pages_per_group + f.parity_pages_per_group) < f.data_pages_per_group {
            "data"
        } else {
            "parity"
        };
        let out = out_dir.join(format!("{}_p{:05}_{}.png", &name, idx, kind));
        frame.save(&out)?;
    }
    println!("Saved {} pages to {}", f.frames.len(), out_dir.display());
    Ok(())
}