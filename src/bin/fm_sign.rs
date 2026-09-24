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
        "tsa" => tsa(&args)?,
        "ots" => ots(&args)?,
        "zkp-prove" => zkp_prove_cmd(&args)?,
        "zkp-verify" => zkp_verify_cmd(&args)?,
        "ots-upgrade" => ots_upgrade_cmd(&args)?,
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
    println!("Time-stamp:");
    println!("  tsa  <file.png> [--url URL]   RFC 3161 TSA request");
    println!("  ots  <file.png>               OpenTimestamps stamp");
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


fn tsa(args: &[String]) -> Result<()> {
    use fm_aero_code_2::decoder::pipeline::split_header_payload_ms;
    let path = args.get(2).ok_or_else(|| anyhow!("missing file"))?.to_string();
    let mut url = "http://freetsa.org/tsr".to_string();
    let mut i = 3usize;
    while i < args.len() {
        if args[i] == "--url" && i + 1 < args.len() {
            url = args[i + 1].clone();
            i += 2;
        } else { i += 1; }
    }

    let bytes = std::fs::read(&path)?;
    let (h, payload, existing_ms) = split_header_payload_ms(&bytes)?;
    let mut clean = Vec::with_capacity(128 + payload.len());
    clean.extend_from_slice(&h.to_bytes());
    clean.extend_from_slice(&payload);

    let hash = fm_aero_code_2::tsa::sha256(&clean);
    println!("TSA server: {}", url);
    println!("Message hash: {}", hex::encode(hash));
    let token = fm_aero_code_2::tsa::request(&hash, &url)?;
    println!("Received {} bytes", token.len());

    let mut block = existing_ms.unwrap_or_default();
    block.tsa_server = Some(url.clone());
    block.tsa_token_b64 = Some(base64_enc(&token));

    let fmex = block.encode_block();
    let mut out = Vec::with_capacity(128 + fmex.len() + payload.len());
    out.extend_from_slice(&h.to_bytes());
    out.extend_from_slice(&fmex);
    out.extend_from_slice(&payload);
    std::fs::write(&path, out)?;

    let tsr_path = format!("{}.tsr", path);
    std::fs::write(&tsr_path, &token)?;
    println!("Wrote {}", tsr_path);
    Ok(())
}

fn ots(args: &[String]) -> Result<()> {
    let path = args.get(2).ok_or_else(|| anyhow!("missing file"))?;
    match fm_aero_code_2::tsa::try_opentimestamps(path)? {
        Some(p) => println!("Wrote {}", p),
        None => println!("ots CLI not found (install from opentimestamps.org)"),
    }
    Ok(())
}

fn base64_enc(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn zkp_prove_cmd(args: &[String]) -> Result<()> {
    use fm_aero_code_2::crypto::zkp_prove;
    let path = args.get(2).ok_or_else(|| anyhow!("missing file"))?;
    let mut seed_hex = String::new();
    let mut i = 3usize;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" if i + 1 < args.len() => { seed_hex = args[i + 1].clone(); i += 2; }
            _ => i += 1,
        }
    }
    if seed_hex.len() != 64 { return Err(anyhow!("--seed must be 64 hex chars")); }
    let seed_bytes = hex::decode(&seed_hex)?;
    if seed_bytes.len() != 32 { return Err(anyhow!("seed must decode to 32 bytes")); }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let bytes = std::fs::read(path)?;
    let hash = fm_aero_code_2::tsa::sha256(&bytes);

    let proof = zkp_prove(&seed, &hash)?;
    let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    println!("ZKP proof generated");
    println!("  pubkey: {}", hex::encode(vk.to_bytes()));
    println!("  r:      {}", hex::encode(proof.r_bytes));
    println!("  z:      {}", hex::encode(proof.z_bytes));
    println!("  file_hash: {}", hex::encode(hash));
    Ok(())
}

fn zkp_verify_cmd(args: &[String]) -> Result<()> {
    use fm_aero_code_2::crypto::{zkp_verify, ZkProof};
    let path = args.get(2).ok_or_else(|| anyhow!("missing file"))?;
    let mut pk_hex = String::new();
    let mut r_hex = String::new();
    let mut z_hex = String::new();
    let mut i = 3usize;
    while i < args.len() {
        match args[i].as_str() {
            "--pubkey" if i + 1 < args.len() => { pk_hex = args[i + 1].clone(); i += 2; }
            "--r" if i + 1 < args.len() => { r_hex = args[i + 1].clone(); i += 2; }
            "--z" if i + 1 < args.len() => { z_hex = args[i + 1].clone(); i += 2; }
            _ => i += 1,
        }
    }
    let pk_b = hex::decode(&pk_hex)?; let r_b = hex::decode(&r_hex)?; let z_b = hex::decode(&z_hex)?;
    if pk_b.len() != 32 || r_b.len() != 32 || z_b.len() != 32 {
        return Err(anyhow!("pubkey / r / z must each be 32 bytes (64 hex)"));
    }
    let mut pk = [0u8; 32]; pk.copy_from_slice(&pk_b);
    let mut r = [0u8; 32]; r.copy_from_slice(&r_b);
    let mut z = [0u8; 32]; z.copy_from_slice(&z_b);

    let bytes = std::fs::read(path)?;
    let hash = fm_aero_code_2::tsa::sha256(&bytes);

    let proof = ZkProof { r_bytes: r, z_bytes: z };
    if zkp_verify(&proof, &pk, &hash) {
        println!("ZKP: VALID (prover knows the private key)");
    } else {
        println!("ZKP: INVALID");
        std::process::exit(2);
    }
    Ok(())
}

fn ots_upgrade_cmd(args: &[String]) -> Result<()> {
    let path = args.get(2).ok_or_else(|| anyhow!("missing .ots file"))?;
    match fm_aero_code_2::tsa::ots_upgrade(path)? {
        Some(h) => println!("Bitcoin block height: {}", h),
        None => println!("Not yet anchored to Bitcoin (retry later)"),
    }
    Ok(())
}
