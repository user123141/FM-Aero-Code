//! fm_audio - audio steganography CLI (MDCT-QIM + BitPerfect LSB).
//!
//! Usage:
//!   fm_audio embed    <carrier.wav> <payload> <out.wav> [--password P] [--bitperfect] [--author X] [--license X] [--sign HEX64]
//!   fm_audio extract  <stego.wav>   <out>     [--password P]
//!   fm_audio capacity <carrier.wav> [--bitperfect]
//!   fm_audio inspect  <wav>
//!   fm_audio keygen

use anyhow::{anyhow, Result};
use fm_aero_code_2::audio::{
    capacity_bytes, embed_wav, extract_wav, read_wav, write_wav,
    AudioEmbedOptions, AudioMode,
};

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  fm_audio embed    <carrier.wav> <payload> <out.wav> [--password P] [--bitperfect] [--author X] [--license X] [--sign HEX64]");
        eprintln!("  fm_audio extract  <stego.wav>   <out>     [--password P]");
        eprintln!("  fm_audio verify   <stego.wav>             [--password P]");
        eprintln!("  fm_audio capacity <carrier.wav> [--bitperfect]");
        eprintln!("  fm_audio inspect  <wav>");
        eprintln!("  fm_audio keygen");
        std::process::exit(1);
    }

    let cmd = a[1].as_str();

    if cmd == "keygen" {
        let (seed, pk) = fm_aero_code_2::steganography::generate_signing_keypair();
        println!("seed (hex):   {}", seed);
        println!("pubkey (hex): {}", pk);
        return Ok(());
    }

    // Parse common flags
    let mut password = String::new();
    let mut bitperfect = false;
    let mut author = String::new();
    let mut license = String::new();
    let mut sign_seed = String::new();
    let mut i = 2usize;
    while i < a.len() {
        match a[i].as_str() {
            "--password" if i + 1 < a.len() => { password = a[i+1].clone(); i += 2; }
            "--bitperfect" => { bitperfect = true; i += 1; }
            "--author" if i + 1 < a.len() => { author = a[i+1].clone(); i += 2; }
            "--license" if i + 1 < a.len() => { license = a[i+1].clone(); i += 2; }
            "--sign" if i + 1 < a.len() => { sign_seed = a[i+1].clone(); i += 2; }
            _ => i += 1,
        }
    }
    let mode = if bitperfect { AudioMode::BitPerfect } else { AudioMode::Robust };

    match cmd {
        "capacity" | "inspect" => {
            if a.len() < 3 { return Err(anyhow!("missing wav path")); }
            let bytes = std::fs::read(&a[2])?;
            let wav = read_wav(&bytes)?;
            println!("File:       {}", a[2]);
            println!("Sample rate: {} Hz", wav.sample_rate);
            println!("Channels:    {}", wav.channels);
            println!("Bit depth:   {} bits", wav.bits_per_sample);
            println!("Frames:      {}", wav.frames());
            let dur = wav.frames() as f64 / wav.sample_rate.max(1) as f64;
            println!("Duration:    {:.2} s", dur);
            if cmd == "capacity" {
                let cap_r = capacity_bytes(&wav, AudioMode::Robust);
                let cap_b = capacity_bytes(&wav, AudioMode::BitPerfect);
                println!("Capacity (Robust MDCT):      {} B ({:.1} KB)", cap_r, cap_r as f64 / 1024.0);
                println!("Capacity (BitPerfect LSB):   {} B ({:.1} KB)", cap_b, cap_b as f64 / 1024.0);
            }
            Ok(())
        }
        "embed" => {
            if a.len() < 5 { return Err(anyhow!("embed needs: <carrier.wav> <payload> <out.wav>")); }
            let carrier_bytes = std::fs::read(&a[2])?;
            let payload = std::fs::read(&a[3])?;
            let carrier = read_wav(&carrier_bytes)?;
            let name = std::path::Path::new(&a[3]).file_name()
                .and_then(|n| n.to_str()).unwrap_or("payload.bin").to_string();

            let seed: Option<[u8; 32]> = if sign_seed.trim().len() == 64 {
                let b = hex::decode(sign_seed.trim())?;
                if b.len() == 32 { let mut arr = [0u8;32]; arr.copy_from_slice(&b); Some(arr) } else { None }
            } else { None };

            let opts = AudioEmbedOptions {
                password: password.clone(),
                mode,
                author: author.clone(),
                license: license.clone(),
                signing_seed: seed,
                original_name: name.clone(),
            };

            let out = embed_wav(&carrier, &payload, &opts)?;
            let wav_bytes = write_wav(&out.wav)?;
            std::fs::write(&a[4], &wav_bytes)?;

            println!("Embedded {} B into {}x{} {}Hz WAV -> {}", payload.len(),
                out.wav.channels, out.wav.bits_per_sample, out.wav.sample_rate, a[4]);
            println!("Mode:        {}", out.mode.label());
            println!("FEC stream:  {} B / capacity {} B ({:.1}% used)",
                out.fec_bytes, out.capacity_bytes,
                100.0 * out.fec_bytes as f64 / out.capacity_bytes.max(1) as f64);
            println!("Cipher:      {}", out.cipher.label());
            if out.signed { println!("Signed by:   {}", &out.signer_pubkey[..16.min(out.signer_pubkey.len())]); }
            println!("Output WAV:  {:.2} MB", wav_bytes.len() as f64 / 1024.0 / 1024.0);
            Ok(())
        }
        "verify" => {
            if a.len() < 3 { return Err(anyhow!("verify needs: <stego.wav>")); }
            let stego_bytes = std::fs::read(&a[2])?;
            let stego = read_wav(&stego_bytes)?;
            let r = extract_wav(&stego, &password)?;
            println!("FM Aero Code 2 - audio payload");
            println!("  Name:      {}", if r.name.is_empty() { "(unnamed)" } else { &r.name });
            println!("  Size:      {} bytes", r.payload.len());
            println!("  SHA-256:   {}", r.content_hash);
            println!("  Cipher:    {}", r.cipher.label());
            if !r.author.is_empty() { println!("  Author:    {}", r.author); }
            if !r.license.is_empty() { println!("  License:   {}", r.license); }
            if r.timestamp > 0 { println!("  Timestamp: {}", fm_aero_code_2::types::fmt_unix(r.timestamp)); }
            match r.signature_ok {
                Some(true)  => println!("  Signature: VALID"),
                Some(false) => { println!("  Signature: INVALID"); std::process::exit(2); }
                None        => println!("  Signature: (unsigned)"),
            }
            Ok(())
        }
        "extract" => {
            if a.len() < 4 { return Err(anyhow!("extract needs: <stego.wav> <out>")); }
            let stego_bytes = std::fs::read(&a[2])?;
            let stego = read_wav(&stego_bytes)?;
            let r = extract_wav(&stego, &password)?;
            std::fs::write(&a[3], &r.payload)?;
            println!("Extracted {} B -> {}", r.payload.len(), a[3]);
            if !r.name.is_empty() { println!("Original name: {}", r.name); }
            println!("Cipher:        {}", r.cipher.label());
            println!("SHA-256:       {}", r.content_hash);
            if !r.author.is_empty() { println!("Author:        {}", r.author); }
            if !r.license.is_empty() { println!("License:       {}", r.license); }
            if r.timestamp > 0 { println!("Timestamp:     {}", fm_aero_code_2::types::fmt_unix(r.timestamp)); }
            if let Some(ok) = r.signature_ok {
                println!("Signature:     {}", if ok { "VALID" } else { "INVALID" });
                if !r.signer_pubkey.is_empty() {
                    println!("Signer pubkey: {}", &r.signer_pubkey[..16.min(r.signer_pubkey.len())]);
                }
            }
            Ok(())
        }
        _ => Err(anyhow!("unknown command: {}", cmd)),
    }
}