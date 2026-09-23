//! fm_stego - DCT steganography CLI.
//!
//! Usage:
//!   fm_stego embed   <carrier.png> <payload> <out.png> [--password P]
//!   fm_stego extract <stego.png>   <out>     [--password P]
//!   fm_stego capacity <image.png>

use anyhow::{anyhow, Result};
use fm_aero_code_2::steganography::{embed, extract, capacity_bytes, StegoOptions};

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  fm_stego embed   <carrier.png> <payload> <out.png> [--password P]");
        eprintln!("  fm_stego extract <stego.png>   <out>     [--password P]");
        eprintln!("  fm_stego capacity <image.png>");
        std::process::exit(1);
    }
    let cmd = a[1].as_str();

    if cmd == "capacity" {
        if a.len() < 3 { return Err(anyhow!("missing image")); }
        let img = image::open(&a[2])?;
        let (w, h) = (img.width(), img.height());
        let cap = capacity_bytes(w, h);
        println!("Image {}x{}: capacity {} B ({:.2} KB)", w, h, cap, cap as f64 / 1024.0);
        return Ok(());
    }

    // Parse optional --password
    let mut password = String::new();
    let mut i = 2;
    while i < a.len() {
        if a[i] == "--password" && i + 1 < a.len() {
            password = a[i + 1].clone();
            i += 2;
        } else { i += 1; }
    }

    match cmd {
        "embed" => {
            if a.len() < 5 { return Err(anyhow!("embed needs carrier, payload, out")); }
            let carrier = image::open(&a[2])?;
            let payload = std::fs::read(&a[3])?;
            let name = std::path::Path::new(&a[3]).file_name()
                .and_then(|n| n.to_str()).unwrap_or("payload.bin").to_string();
            let opts = StegoOptions {
                password: password.clone(),
                original_name: name.clone(),
            };
            let r = embed(&carrier, &payload, &opts)?;
            r.image.save(&a[4])?;
            println!("Embedded {} B into {}x{} -> {}",
                payload.len(), r.image.width(), r.image.height(), a[4]);
            println!("FEC stream: {} B / capacity {} B ({:.1}% used)",
                r.fec_bytes, r.capacity_bytes,
                100.0 * r.fec_bytes as f64 / r.capacity_bytes as f64);
            println!("Cipher: {}", r.cipher.label());
            Ok(())
        }
        "extract" => {
            if a.len() < 4 { return Err(anyhow!("extract needs stego and out")); }
            let stego = image::open(&a[2])?;
            let payload = extract(&stego, &password)?;
            std::fs::write(&a[3], &payload)?;
            println!("Extracted {} B -> {}", payload.len(), a[3]);
            Ok(())
        }
        _ => Err(anyhow!("unknown command: {}", cmd)),
    }
}