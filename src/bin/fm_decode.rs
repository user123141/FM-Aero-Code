use fm_aero_code_2::decoder::pipeline::{decode_image, try_multi_recipient};
use fm_aero_code_2::crypto::recipient_from_seed;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 2 {
        eprintln!("fm_decode <in.png> [out] [--password P] [--secret HEX]");
        std::process::exit(1);
    }
    let mut out: Option<String> = None;
    let mut pw = String::new();
    let mut secret_hex = String::new();
    let mut i = 2;
    while i < a.len() {
        match a[i].as_str() {
            "--password" if i + 1 < a.len() => { pw = a[i + 1].clone(); i += 2; }
            "--secret" if i + 1 < a.len() => { secret_hex = a[i + 1].clone(); i += 2; }
            s if !s.starts_with("--") => { out = Some(s.into()); i += 1; }
            _ => i += 1,
        }
    }

    if !secret_hex.is_empty() {
        let bytes = std::fs::read(&a[1])?;
        let sk = hex::decode(secret_hex.trim())?;
        if sk.len() != 32 { anyhow::bail!("secret must be 32 bytes"); }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&sk);
        let kp = recipient_from_seed(arr);
        let r = try_multi_recipient(&bytes, &kp.secret, &kp.public)?;
        let target = out.unwrap_or_else(|| if r.original_filename.is_empty() { "decoded.bin".into() } else { r.original_filename.clone() });
        std::fs::write(&target, &r.payload)?;
        println!("Saved {} ({} B) type={}", target, r.payload.len(), r.header.data_type.label());
        return Ok(());
    }

    let img = image::open(&a[1])?.to_luma8();
    let r = decode_image(&img, &pw, None)?;
    let target = out.unwrap_or_else(|| if r.original_filename.is_empty() { "decoded.bin".into() } else { r.original_filename.clone() });
    std::fs::write(&target, &r.payload)?;
    println!("Saved {} ({} B) type={}", target, r.payload.len(), r.header.data_type.label());
    if !r.hash_ok { println!("WARN: hash mismatch"); }
    Ok(())
}