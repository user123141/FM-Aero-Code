//! Page-level Reed-Solomon resilience (parameterized).

use anyhow::{anyhow, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Add parity shards. All shards must be same length.
pub fn add_parity_n(data: &[Vec<u8>], data_count: usize, parity_count: usize) -> Result<Vec<Vec<u8>>> {
    if parity_count == 0 { return Ok(Vec::new()); }
    if data.is_empty() { return Ok(Vec::new()); }
    let shard_size = data.iter().map(|p| p.len()).max().unwrap_or(0);
    if shard_size == 0 { return Err(anyhow!("empty shards")); }
    let total = data_count + parity_count;
    if total > 255 { return Err(anyhow!("too many shards: {}", total)); }

    let rs = ReedSolomon::new(data_count, parity_count)
        .map_err(|e| anyhow!("rs init: {:?}", e))?;

    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total);
    for i in 0..data_count {
        let mut sh = vec![0u8; shard_size];
        if i < data.len() {
            let n = data[i].len().min(shard_size);
            sh[..n].copy_from_slice(&data[i][..n]);
        }
        shards.push(sh);
    }
    for _ in 0..parity_count {
        shards.push(vec![0u8; shard_size]);
    }

    rs.encode(&mut shards).map_err(|e| anyhow!("rs encode: {:?}", e))?;
    Ok(shards[data_count..].to_vec())
}

/// Recover missing shards. `present` is a list of (slot_index, bytes).
pub fn recover_group_n(present: &[(usize, Vec<u8>)], data_count: usize, parity_count: usize)
    -> Result<Vec<Vec<u8>>>
{
    if present.is_empty() { return Err(anyhow!("no shards")); }
    let total = data_count + parity_count;
    let shard_size = present.iter().map(|(_, p)| p.len()).max().unwrap_or(0);
    if shard_size == 0 { return Err(anyhow!("empty shards")); }

    let rs = ReedSolomon::new(data_count, parity_count)
        .map_err(|e| anyhow!("rs init: {:?}", e))?;

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total];
    for (idx, bytes) in present {
        if *idx >= total { return Err(anyhow!("slot {} out of range", idx)); }
        let mut sh = vec![0u8; shard_size];
        let n = bytes.len().min(shard_size);
        sh[..n].copy_from_slice(&bytes[..n]);
        shards[*idx] = Some(sh);
    }

    rs.reconstruct(&mut shards)
        .map_err(|e| anyhow!("rs reconstruct: {:?}", e))?;

    let mut out: Vec<Vec<u8>> = Vec::with_capacity(data_count);
    for i in 0..data_count {
        out.push(shards[i].clone().ok_or_else(|| anyhow!("slot {} still missing", i))?);
    }
    Ok(out)
}

// Backward compat with old 200+50 interface
pub const DATA_PAGES: usize = 200;
pub const PARITY_PAGES: usize = 0;
pub const GROUP_SIZE: usize = 200;

pub fn add_parity(data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    add_parity_n(data, DATA_PAGES, PARITY_PAGES)
}

pub fn recover_group(present: &[(usize, Vec<u8>)]) -> Result<Vec<Vec<u8>>> {
    recover_group_n(present, DATA_PAGES, PARITY_PAGES)
}