//! Batch encode/decode with recursive traversal and rayon parallelism.
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use anyhow::Result;
use rayon::prelude::*;
use walkdir::WalkDir;
use fm_aero_code_2::crypto::CipherKind;
use fm_aero_code_2::decoder::pipeline::decode_from_bytes;
use fm_aero_code_2::encoder::pipeline::{encode_payload, EncodeOptions, CompressionMode};

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 {
        eprintln!("fm_batch encode|decode <in> <out> [--password P] [--recursive] [--jobs N]");
        std::process::exit(1);
    }
    let mode = a[1].clone();
    let in_dir = PathBuf::from(&a[2]);
    let out_dir = PathBuf::from(&a[3]);
    fs::create_dir_all(&out_dir)?;

    let mut opts = EncodeOptions { cipher: CipherKind::SealV1, compression: CompressionMode::LosslessPriority, ..Default::default() };
    let mut recursive = false;
    let mut jobs = 0usize;
    let mut i = 4;
    while i < a.len() {
        match a[i].as_str() {
            "--password" if i + 1 < a.len() => { opts.password = a[i + 1].clone(); i += 2; }
            "--recursive" => { recursive = true; i += 1; }
            "--jobs" if i + 1 < a.len() => { jobs = a[i + 1].parse().unwrap_or(0); i += 2; }
            _ => i += 1,
        }
    }
    if jobs > 0 {
        let _ = rayon::ThreadPoolBuilder::new().num_threads(jobs).build_global();
    }
    let depth = if recursive { usize::MAX } else { 1 };
    let files: Vec<PathBuf> = WalkDir::new(&in_dir).max_depth(depth).into_iter()
        .filter_map(|e| e.ok()).filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf()).collect();
    println!("Found {} files", files.len());

    let errs = Mutex::new(Vec::<String>::new());
    let mode_ref = &mode;
    files.par_iter().for_each(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
        let stem = Path::new(&name).file_stem().and_then(|s| s.to_str()).unwrap_or("out").to_string();
        match mode_ref.as_str() {
            "encode" => {
                let data = match fs::read(p) { Ok(d) => d, Err(e) => { errs.lock().unwrap().push(format!("{}: {}", name, e)); return; } };
                let mut local = opts.clone();
                local.original_name = name.clone();
                match encode_payload(&data, &local) {
                    Ok(r) => {
                        let out = out_dir.join(format!("{}.png", stem));
                        if r.image.save(&out).is_ok() { println!("OK  {} -> {}", name, out.display()); }
                    }
                    Err(e) => errs.lock().unwrap().push(format!("{}: {}", name, e)),
                }
            }
            "decode" => {
                let bytes = match fs::read(p) { Ok(b) => b, Err(e) => { errs.lock().unwrap().push(format!("{}: {}", name, e)); return; } };
                match decode_from_bytes(&bytes, &opts.password, None) {
                    Ok(r) => {
                        let target = out_dir.join(if r.original_filename.is_empty() { format!("{}.bin", stem) } else { r.original_filename.clone() });
                        if fs::write(&target, &r.payload).is_ok() { println!("OK  {} -> {}", name, target.display()); }
                    }
                    Err(e) => errs.lock().unwrap().push(format!("{}: {}", name, e)),
                }
            }
            _ => errs.lock().unwrap().push(format!("unknown mode: {}", mode_ref)),
        }
    });

    let e = errs.into_inner().unwrap();
    if !e.is_empty() {
        println!("\nErrors ({}):", e.len());
        for x in e { println!("  {}", x); }
    }
    Ok(())
}