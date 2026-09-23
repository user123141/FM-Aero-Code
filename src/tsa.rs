//! RFC 3161 Time-Stamp client + OpenTimestamps helper.

use anyhow::{anyhow, Result};

fn wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = Vec::with_capacity(2 + len + 4);
    out.push(tag);
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        out.push(0x83);
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(content);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

pub fn build_request(hash: &[u8; 32]) -> Vec<u8> {
    // AlgorithmIdentifier SHA-256
    let oid = [0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    let null = [0x05u8, 0x00];
    let mut alg_body = Vec::new();
    alg_body.extend_from_slice(&oid);
    alg_body.extend_from_slice(&null);
    let alg_id = wrap(0x30, &alg_body);

    let mut msg_body = Vec::new();
    msg_body.extend_from_slice(&alg_id);
    msg_body.extend_from_slice(&wrap(0x04, hash));
    let msg_imprint = wrap(0x30, &msg_body);

    let version = [0x02u8, 0x01, 0x01];

    // nonce
    let nonce_bytes = {
        use rand::RngCore;
        let mut b = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut b);
        b[0] &= 0x7F;
        let start = b.iter().position(|&x| x != 0).unwrap_or(7);
        b[start..].to_vec()
    };
    let nonce = wrap(0x02, &nonce_bytes);

    // certReq TRUE
    let cert_req = [0x01u8, 0x01, 0xFF];

    let mut body = Vec::new();
    body.extend_from_slice(&version);
    body.extend_from_slice(&msg_imprint);
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&cert_req);
    wrap(0x30, &body)
}

pub fn request(hash: &[u8; 32], url: &str) -> Result<Vec<u8>> {
    let body = build_request(hash);

    // Try curl first (universal, no TLS trouble)
    if let Ok(v) = try_curl(url, &body) {
        return Ok(v);
    }
    // Fallback: ureq
    match try_ureq(url, &body) {
        Ok(v) => Ok(v),
        Err(e) => Err(anyhow!("TSA failed (curl + ureq): {}", e)),
    }
}

fn try_curl(url: &str, body: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("curl")
        .args(&[
            "-sS", "-X", "POST",
            "-H", "Content-Type: application/timestamp-query",
            "-H", "Accept: application/timestamp-reply",
            "--data-binary", "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("curl spawn: {}", e))?;
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| anyhow!("stdin"))?;
        stdin.write_all(body)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!("curl exit"));
    }
    if out.stdout.is_empty() {
        return Err(anyhow!("curl empty"));
    }
    Ok(out.stdout)
}

fn try_ureq(url: &str, body: &[u8]) -> Result<Vec<u8>> {
    use std::time::Duration;
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).build();
    let resp = agent.post(url)
        .set("Content-Type", "application/timestamp-query")
        .set("Accept", "application/timestamp-reply")
        .send_bytes(body)
        .map_err(|e| anyhow!("ureq: {}", e))?;
    if resp.status() != 200 {
        return Err(anyhow!("HTTP {}", resp.status()));
    }
    let mut buf = Vec::new();
    std::io::copy(&mut resp.into_reader(), &mut buf)?;
    Ok(buf)
}

pub fn try_opentimestamps(file_path: &str) -> Result<Option<String>> {
    use std::process::Command;
    let check = if cfg!(target_os = "windows") {
        Command::new("where").arg("ots").output()
    } else {
        Command::new("which").arg("ots").output()
    };
    match check {
        Ok(o) if o.status.success() => {}
        _ => return Ok(None),
    }
    let status = Command::new("ots").args(&["stamp", file_path]).status()
        .map_err(|e| anyhow!("ots spawn: {}", e))?;
    if !status.success() {
        return Err(anyhow!("ots failed"));
    }
    let p = format!("{}.ots", file_path);
    if std::path::Path::new(&p).exists() { Ok(Some(p)) } else { Ok(None) }
}