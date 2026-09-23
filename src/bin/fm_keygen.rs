use fm_aero_code_2::crypto::{generate_keypair, generate_recipient};
use std::io::Write;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let kind = args.get(1).map(|s| s.as_str()).unwrap_or("all");
    if kind == "x25519" || kind == "all" {
        let kp = generate_recipient();
        println!("X25519 public: {}", hex::encode(kp.public.as_bytes()));
        println!("X25519 secret: {}", hex::encode(kp.secret.to_bytes()));
    }
    if kind == "ed25519" || kind == "all" {
        let (sk, vk) = generate_keypair();
        println!("Ed25519 public: {}", hex::encode(vk.to_bytes()));
        println!("Ed25519 secret: {}", hex::encode(sk.to_bytes()));
    }
    if kind == "write" {
        let kp = generate_recipient();
        let mut f = std::fs::File::create("fm_recipient.pub")?;
        writeln!(f, "{}", hex::encode(kp.public.as_bytes()))?;
        let mut f = std::fs::File::create("fm_recipient.sec")?;
        writeln!(f, "{}", hex::encode(kp.secret.to_bytes()))?;
        println!("Wrote fm_recipient.pub and fm_recipient.sec");
    }
    Ok(())
}