//! fm_verify - verify an FM Aero Code file's integrity + attestation.
//!
//! Usage:
//!   fm_verify <file.png>           Verify AeroGlint pattern
//!   fm_verify --stego <file.png>   Verify Stego payload
//!
//! Exit codes:
//!   0  valid + official (embedded ROOT_PUBKEY matched)
//!   1  valid but unsigned / unknown signer
//!   2  invalid (hash mismatch, bad signature)
//!   3  error (file not found, not a pattern)

use anyhow::Result;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: fm_verify <file.png>");
        eprintln!("       fm_verify --stego <file.png>");
        std::process::exit(3);
    }

    let mut stego_mode = false;
    let mut path = String::new();
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--stego" => { stego_mode = true; i += 1; }
            s if !s.starts_with("--") => { path = s.to_string(); i += 1; }
            _ => { i += 1; }
        }
    }

    if path.is_empty() {
        eprintln!("no file given");
        std::process::exit(3);
    }

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Cannot read {}: {}", path, e);
            std::process::exit(3);
        }
    };

    if stego_mode {
        return verify_stego(&bytes);
    }
    verify_aeroglint(&bytes)
}

fn verify_aeroglint(bytes: &[u8]) -> Result<()> {
    let img = match image::load_from_memory(bytes) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("Cannot decode image: {}", e);
            std::process::exit(3);
        }
    };
    let luma = img.to_luma8();

    let outcome = match fm_aero_code_2::decoder::pipeline::decode_image(&luma, "", None) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Not a valid AeroGlint pattern: {}", e);
            std::process::exit(3);
        }
    };

    println!("FM Aero Code file");
    println!("  Type:     {}", outcome.header.data_type.label());
    println!("  Size:     {} bytes", outcome.payload.len());
    println!("  SHA-256:  {}", outcome.sha256);
    println!("  Hash OK:  {}", outcome.hash_ok);
    println!("  Sig OK:   {}", outcome.signature_ok);
    println!("  HMAC OK:  {}", outcome.hmac_ok);
    if let Some(pages) = Some(outcome.pages_received) {
        if pages > 0 {
            println!("  Pages:    {} / {}", pages, outcome.pages_total);
        }
    }
    if outcome.recovered_from_parity {
        println!("  NOTE:     recovered from parity");
    }

    if !outcome.hash_ok {
        eprintln!();
        eprintln!("RESULT: INVALID (payload hash mismatch)");
        std::process::exit(2);
    }
    if !outcome.signature_ok {
        eprintln!();
        eprintln!("RESULT: INVALID (signature check failed)");
        std::process::exit(2);
    }

    println!();
    match outcome.app_signature_ok {
        Some(true) => {
            println!("RESULT: OFFICIAL (signed by this install's identity)");
            std::process::exit(0);
        }
        Some(false) => {
            println!("RESULT: SIGNED but not this install");
            std::process::exit(1);
        }
        None => {
            if outcome.official_build {
                println!("RESULT: OFFICIAL BUILD");
                std::process::exit(0);
            } else {
                println!("RESULT: VALID (unsigned)");
                std::process::exit(1);
            }
        }
    }
}

fn verify_stego(bytes: &[u8]) -> Result<()> {
    let img = match image::load_from_memory(bytes) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("Cannot decode image: {}", e);
            std::process::exit(3);
        }
    };
    match fm_aero_code_2::steganography::extract(&img, "") {
        Ok(r) => {
            println!("Stego payload");
            println!("  Name:      {}", r.name);
            println!("  Size:      {} bytes", r.payload.len());
            println!("  SHA-256:   {}", r.content_hash);
            println!("  Cipher:    {}", r.cipher.label());
            if !r.author.is_empty() {
                println!("  Author:    {}", r.author);
            }
            if !r.license.is_empty() {
                println!("  License:   {}", r.license);
            }
            println!();
            println!("RESULT: VALID");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Not a valid stego image: {}", e);
            std::process::exit(3);
        }
    }
}