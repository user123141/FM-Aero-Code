//! fm_sign - add / list / verify multi-signatures on encoded PNG files.
//!
//! Usage:
//!   fm_sign list   <file.png>
//!   fm_sign add    <file.png> --purpose <role> --seed <hex64>
//!   fm_sign verify <file.png>
//!   fm_sign --help
//!
//! The FMEX block lives in the stream between the AeroHeader and the
//! payload. Adding a signature rewrites the FMEX block; existing
//! signatures with the same purpose+pubkey are replaced.

use anyhow::{anyhow, Result};
use fm_aero_code_2::decoder::pipeline::split_header_payload_ms;
use fm_aero_code_2::multisig::{make_author_signature, verify_signature, MultiSigBlock};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_help();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "list" => list(&args)?,
        "add" => add(&args)?,
        "verify" => verify(&args)?,
        "--help" | "-h" => print_help(),
        other => {
            eprintln!("Unknown command: {}", other);
            print_help();
            std::process::exit(1);
        }
    }
    Ok(())
}

fn print_help() {
    println!("fm_sign - multi-signature tool for FM Aero Code files");
    println!();
    println!("Commands:");
    println!("  list   <file.png>                                  Show signatures");
    println!("  add    <file.png> --purpose <role> --seed <hex64>  Add a signature");
    println!("  verify <file.png>                                  Verify all signatures");
    println!("  --help                                             This message");
    println!();
    println!("Roles: author, validator, witness, timestamper, ...");
}

fn load_stream(path: &str) -> Result<(Vec<u8>, Vec<u8>, Option<MultiSigBlock>)> {
    let bytes = std::fs::read(path).map_err(|e| anyhow!("read {}: {}", path, e))?;
    let (h, payload, ms) = split_header_payload_ms(&bytes)
        .map_err(|e| anyhow!("parse {}: {}", path, e))?;
    // Reconstruct clean stream (header + payload, no FMEX)
    let mut clean = Vec::with_capacity(128 + payload.len());
    clean.extend_from_slice(&h.to_bytes());
    clean.extend_from_slice(&payload);
    Ok((clean, payload, ms))
}

fn list(args: &[String]) -> Result<()> {
    let path = args.get(2).ok_or_else(|| anyhow!("missing file"))?;
    let bytes = std::fs::read(path)?;
    let (h, _payload, ms) = split_header_payload_ms(&bytes)?;
    println!("File: {}", path);
    println!("Type: {}", h.data_type.label());
    println!("Size: {} bytes (declared)", h.original_size);
    println!();
    match ms {
        Some(block) => {
            if block.signatures.is_empty() {
                println!("No signatures.");
            } else {
                println!("Signatures ({}):", block.signatures.len());
                for s in &block.signatures {
                    let short = if s.pubkey_hex.len() >= 16 {
                        &s.pubkey_hex[..16]
                    } else {
                        &s.pubkey_hex
                    };
                    println!("  [{}] {}", s.purpose, short);
                }
            }
            if let Some(chain) = block.anchor_chain.as_ref() {
                println!("Anchor: {}", chain);
                if let Some(tx) = block.anchor_tx.as_ref() {
                    println!("  tx: {}", tx);
                }
            }
            if let Some(server) = block.tsa_server.as_ref() {
                println!("TSA: {}", server);
            }
        }
        None => println!("No FMEX block (no signatures)."),
    }
    Ok(())
}

fn add(args: &[String]) -> Result<()> {
    let path = args
        .get(2)
        .ok_or_else(|| anyhow!("missing file"))?
        .to_string();

    let mut purpose = "author".to_string();
    let mut seed_hex = String::new();
    let mut i = 3usize;
    while i < args.len() {
        match args[i].as_str() {
            "--purpose" if i + 1 < args.len() => {
                purpose = args[i + 1].clone();
                i += 2;
            }
            "--seed" if i + 1 < args.len() => {
                seed_hex = args[i + 1].clone();
                i += 2;
            }
            _ => i += 1,
        }
    }

    if seed_hex.len() != 64 {
        return Err(anyhow!("--seed must be 64 hex chars (32-byte seed)"));
    }
    let seed_bytes = hex::decode(&seed_hex).map_err(|e| anyhow!("bad hex: {}", e))?;
    if seed_bytes.len() != 32 {
        return Err(anyhow!("seed must decode to 32 bytes"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let (clean, payload, existing_ms) = load_stream(&path)?;
    let sig = make_author_signature(&clean, &seed, &purpose);
    let sig_pubkey_short = if sig.pubkey_hex.len() >= 16 {
        sig.pubkey_hex[..16].to_string()
    } else {
        sig.pubkey_hex.clone()
    };

    // Merge with existing signatures
    let mut block = existing_ms.unwrap_or_default();
    block
        .signatures
        .retain(|s| !(s.pubkey_hex == sig.pubkey_hex && s.purpose == sig.purpose));
    block.signatures.push(sig);

    // Rebuild file: header + fmex + payload
    // Need original header bytes вЂ” extract from clean.
    if clean.len() < 128 {
        return Err(anyhow!("stream too short for header"));
    }
    let header_bytes = &clean[..128];
    let fmex = block.encode_block();

    let mut out = Vec::with_capacity(128 + fmex.len() + payload.len());
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(&fmex);
    out.extend_from_slice(&payload);

    std::fs::write(&path, out).map_err(|e| anyhow!("write {}: {}", path, e))?;

    println!("added [{}] signature from {}", purpose, sig_pubkey_short);
    println!("total signatures now: {}", block.signatures.len());
    Ok(())
}

fn verify(args: &[String]) -> Result<()> {
    let path = args.get(2).ok_or_else(|| anyhow!("missing file"))?;
    let (clean, _payload, ms) = load_stream(path)?;

    match ms {
        None => {
            println!("No signatures found.");
            Ok(())
        }
        Some(block) => {
            if block.signatures.is_empty() {
                println!("FMEX block present but empty.");
                return Ok(());
            }
            println!("Verifying {} signature(s):", block.signatures.len());
            let mut all_ok = true;
            for s in &block.signatures {
                let ok = verify_signature(&clean, s);
                if !ok {
                    all_ok = false;
                }
                let short = if s.pubkey_hex.len() >= 16 {
                    &s.pubkey_hex[..16]
                } else {
                    &s.pubkey_hex
                };
                println!(
                    "  [{}] {} -> {}",
                    s.purpose,
                    short,
                    if ok { "VALID" } else { "INVALID" }
                );
            }
            println!();
            if all_ok {
                println!("All signatures valid.");
            } else {
                println!("One or more signatures INVALID.");
                std::process::exit(2);
            }
            Ok(())
        }
    }
}