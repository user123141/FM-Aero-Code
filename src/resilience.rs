//! Page-level Reed-Solomon resilience.
//!
//! Groups data pages into blocks of DATA_PAGES, computes PARITY_PAGES
//! parity pages via RS. Decoder can restore any DATA_PAGES pages from
//! DATA_PAGES + PARITY_PAGES valid pages (assuming parity bytes correct).
//!
//! Uses reed-solomon-erasure crate (Galois field 256).

use anyhow::{anyhow, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

pub const DATA_PAGES: usize = 200;
pub const PARITY_PAGES: usize = 50;
pub const GROUP_SIZE: usize = DATA_PAGES + PARITY_PAGES;

/// Given a group of data pages, compute PARITY_PAGES parity pages.
/// All pages must have the same length (they are padded to max).
pub fn add_parity(data_pages: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    if data_pages.is_empty() { return Ok(Vec::new()); }
    let shard_size = data_pages.iter().map(|p| p.len()).max().unwrap_or(0);
    if shard_size == 0 { return Err(anyhow!("empty pages")); }

    let rs = ReedSolomon::new(DATA_PAGES, PARITY_PAGES)
        .map_err(|e| anyhow!("rs init: {:?}", e))?;

    // Build shards: data_pages (padded) + parity placeholders
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(GROUP_SIZE);
    for i in 0..DATA_PAGES {
        let mut sh = vec![0u8; shard_size];
        if i < data_pages.len() {
            let n = data_pages[i].len().min(shard_size);
            sh[..n].copy_from_slice(&data_pages[i][..n]);
        }
        shards.push(sh);
    }
    for _ in 0..PARITY_PAGES {
        shards.push(vec![0u8; shard_size]);
    }

    rs.encode(&mut shards).map_err(|e| anyhow!("rs encode: {:?}", e))?;

    // Return parity shards
    let parity: Vec<Vec<u8>> = shards[DATA_PAGES..].to_vec();
    Ok(parity)
}

/// Reconstruct missing pages. `present` is a vector of (page_slot_index, bytes).
/// Any slot not in `present` is treated as erasure.
pub fn recover_group(present: &[(usize, Vec<u8>)]) -> Result<Vec<Vec<u8>>> {
    if present.is_empty() { return Err(anyhow!("no pages")); }
    let shard_size = present.iter().map(|(_, p)| p.len()).max().unwrap_or(0);
    if shard_size == 0 { return Err(anyhow!("empty pages")); }

    let rs = ReedSolomon::new(DATA_PAGES, PARITY_PAGES)
        .map_err(|e| anyhow!("rs init: {:?}", e))?;

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; GROUP_SIZE];
    for (idx, bytes) in present {
        if *idx >= GROUP_SIZE { return Err(anyhow!("slot {} out of range", idx)); }
        let mut sh = vec![0u8; shard_size];
        let n = bytes.len().min(shard_size);
        sh[..n].copy_from_slice(&bytes[..n]);
        shards[*idx] = Some(sh);
    }

    rs.reconstruct(&mut shards)
        .map_err(|e| anyhow!("rs reconstruct: {:?}", e))?;

    // Extract DATA_PAGES data shards
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(DATA_PAGES);
    for i in 0..DATA_PAGES {
        out.push(shards[i].clone().ok_or_else(|| anyhow!("slot {} missing after recover", i))?);
    }
    Ok(out)
}