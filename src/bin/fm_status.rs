//! fm_status - attestation status + trust management + root export/import.
//!
//! Usage:
//!   fm_status                          - full status
//!   fm_status --trust                  - trust registry details
//!   fm_status --identity               - this install's identity
//!   fm_status --export-root            - hex + b64 + fingerprint
//!   fm_status --export-root-qr <file>  - write QR PNG
//!   fm_status --import-root <key>      - add to fm_trust.local.json
//!   fm_status --fingerprint <key>      - decode any pubkey

use anyhow::Result;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");

    match cmd {
        "--trust" => show_trust()?,
        "--identity" => show_identity()?,
        "--export-root" => export_root()?,
        "--export-root-qr" => {
            let out = args.get(2).map(|s| s.as_str()).unwrap_or("root_qr.png");
            export_root_qr(out)?;
        }
        "--import-root" => {
            if args.len() < 3 {
                anyhow::bail!("usage: fm_status --import-root <hex|b64>");
            }
            import_root(&args[2])?;
        }
        "--fingerprint" => {
            if args.len() < 3 {
                anyhow::bail!("usage: fm_status --fingerprint <hex|b64>");
            }
            show_fingerprint(&args[2])?;
        }
        "--help" | "-h" => print_help(),
        "" => show_all()?,
        other => {
            eprintln!("Unknown command: {}", other);
            eprintln!("Try: fm_status --help");
            std::process::exit(1);
        }
    }
    Ok(())
}

fn print_help() {
    println!("fm_status - FM Aero Code 2 attestation & trust tool");
    println!();
    println!("Commands:");
    println!("  (no args)                       Full status");
    println!("  --trust                         Trust registry details");
    println!("  --identity                      This install's identity");
    println!("  --export-root                   hex + b64 + fingerprint of ROOT_PUBKEY");
    println!("  --export-root-qr <out.png>      Write QR PNG of ROOT_PUBKEY");
    println!("  --import-root <hex|b64>         Add pubkey to fm_trust.local.json");
    println!("  --fingerprint <hex|b64>         Decode any pubkey");
    println!("  --help, -h                      This message");
}

fn show_all() -> Result<()> {
    println!("FM Aero Code 2 - status");
    println!();

    println!("Build:");
    match fm_aero_code_2::build_info::ROOT_PUBKEY_HEX {
        Some(h) => {
            println!("  ROOT_PUBKEY = {}", h);
            if let Some(pk) = fm_aero_code_2::build_info::ROOT_PUBKEY {
                println!(
                    "  fingerprint = {}",
                    fm_aero_code_2::identity::fingerprint(&pk)
                );
            }
        }
        None => println!("  ROOT_PUBKEY = (none) - build without fm_root.key"),
    }
    match fm_aero_code_2::build_info::BUILD_TOKEN_HEX {
        Some(h) => {
            let short = if h.len() >= 24 { &h[..24] } else { h };
            println!("  BUILD_TOKEN = {}...", short);
        }
        None => println!("  BUILD_TOKEN = (none)"),
    }
    println!();

    let id = fm_aero_code_2::identity::AppIdentity::load_or_create()?;
    println!("This install:");
    println!("  pubkey_hex  = {}", id.pubkey_hex());
    println!("  pubkey_b64  = {}", id.pubkey_b64());
    println!("  fingerprint = {}", id.fingerprint());
    println!("  attested    = {}", id.attested);
    println!("  attester    = {:?}", id.attester_name);
    println!();

    let reg = fm_aero_code_2::trust::TrustRegistry::load();
    println!(
        "Trust ({} roots, signature_ok={}, tampered={}):",
        reg.roots.len(),
        reg.signature_ok,
        reg.warned_tampered
    );
    for r in reg.roots.iter().take(20) {
        let lvl = match r.level {
            fm_aero_code_2::trust::TrustLevel::Signed => "signed",
            fm_aero_code_2::trust::TrustLevel::Local => "local",
            fm_aero_code_2::trust::TrustLevel::BuildEmbedded => "embedded",
        };
        let fp = fm_aero_code_2::identity::parse_pubkey(&r.pubkey_hex)
            .map(|pk| fm_aero_code_2::identity::fingerprint(&pk))
            .unwrap_or_default();
        println!("  [{}] {} ({})", lvl, r.name, fp);
    }
    Ok(())
}

fn show_trust() -> Result<()> {
    let reg = fm_aero_code_2::trust::TrustRegistry::load();
    println!("signature_ok    = {}", reg.signature_ok);
    println!("warned_tampered = {}", reg.warned_tampered);
    println!("roots ({}):", reg.roots.len());
    for r in &reg.roots {
        let lvl = match r.level {
            fm_aero_code_2::trust::TrustLevel::Signed => "signed",
            fm_aero_code_2::trust::TrustLevel::Local => "local",
            fm_aero_code_2::trust::TrustLevel::BuildEmbedded => "embedded",
        };
        println!("  [{}] {}", lvl, r.name);
        println!("        hex: {}", r.pubkey_hex);
        println!(
            "        b64: {}",
            fm_aero_code_2::identity::pubkey_b64(&r.pubkey)
        );
        println!(
            "        fp:  {}",
            fm_aero_code_2::identity::fingerprint(&r.pubkey)
        );
    }
    Ok(())
}

fn show_identity() -> Result<()> {
    let id = fm_aero_code_2::identity::AppIdentity::load_or_create()?;
    println!("pubkey_hex  = {}", id.pubkey_hex());
    println!("pubkey_b64  = {}", id.pubkey_b64());
    println!("fingerprint = {}", id.fingerprint());
    println!("attested    = {}", id.attested);
    println!("attester    = {:?}", id.attester_name);
    Ok(())
}

fn export_root() -> Result<()> {
    let Some(pk) = fm_aero_code_2::build_info::ROOT_PUBKEY else {
        anyhow::bail!("No ROOT_PUBKEY (build without fm_root.key)");
    };
    println!("# Share this root with anyone who should trust your files");
    println!("hex: {}", hex::encode(pk));
    println!("b64: {}", fm_aero_code_2::identity::pubkey_b64(&pk));
    println!(
        "fingerprint: {}",
        fm_aero_code_2::identity::fingerprint(&pk)
    );
    Ok(())
}

fn export_root_qr(path: &str) -> Result<()> {
    let Some(pk) = fm_aero_code_2::build_info::ROOT_PUBKEY else {
        anyhow::bail!("No ROOT_PUBKEY (build without fm_root.key)");
    };
    let b64 = fm_aero_code_2::identity::pubkey_b64(&pk);
    let fp = fm_aero_code_2::identity::fingerprint(&pk);
    let code = qrcode::QrCode::new(b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("qr: {}", e))?;
    let img = code
        .render::<image::Luma<u8>>()
        .min_dimensions(320, 320)
        .quiet_zone(true)
        .build();
    img.save(path)
        .map_err(|e| anyhow::anyhow!("save: {}", e))?;
    println!("Wrote QR to: {}", path);
    println!("  fingerprint: {}", fp);
    println!("  pubkey b64:  {}", b64);
    println!();
    println!("Share this PNG. Anyone can scan it with the FM Aero Code app");
    println!("to add your key as a trusted root (fm_trust.local.json).");
    Ok(())
}

fn import_root(s: &str) -> Result<()> {
    let Some(pk) = fm_aero_code_2::identity::parse_pubkey(s) else {
        anyhow::bail!("invalid pubkey (need 64 hex chars or 44 base64)");
    };
    let hexstr = hex::encode(pk);
    let fp = fm_aero_code_2::identity::fingerprint(&pk);

    let path = fm_aero_code_2::trust::TrustRegistry::local_path();
    let mut existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.is_empty() {
        existing = "{\"v\":1,\"roots\":[]}".to_string();
    }

    let entry = format!(
        "{{\"name\":\"imported-{}\",\"pubkey\":\"{}\"}}",
        &fp[..8],
        hexstr
    );

    if let Some(idx) = existing.rfind(']') {
        let head = &existing[..idx];
        let tail = &existing[idx..];
        let trimmed = head.trim_end();
        let mut new = trimmed.to_string();
        if !new.ends_with('[') && !new.ends_with(',') {
            new.push(',');
        }
        new.push_str(&entry);
        new.push_str(tail);
        std::fs::write(&path, new)?;
        println!("imported: {} ({})", hexstr, fp);
        println!("added to: {}", path.display());
    } else {
        anyhow::bail!("could not parse fm_trust.local.json");
    }
    Ok(())
}

fn show_fingerprint(s: &str) -> Result<()> {
    let Some(pk) = fm_aero_code_2::identity::parse_pubkey(s) else {
        anyhow::bail!("invalid pubkey");
    };
    println!("hex: {}", hex::encode(pk));
    println!("b64: {}", fm_aero_code_2::identity::pubkey_b64(&pk));
    println!(
        "fingerprint: {}",
        fm_aero_code_2::identity::fingerprint(&pk)
    );
    Ok(())
}