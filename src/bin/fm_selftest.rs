//! Self-test CLI: encode/decode round-trip without files.

use fm_aero_code_2::selftest::{selftest_string, selftest_string_with_password};

fn main() -> anyhow::Result<()> {
    let ascii_128 = "X".repeat(128);
    let ascii_500 = "A".repeat(500);
    let ascii_2000 = "B".repeat(2000);

    // Pseudo-random (incompressible) data - forces multi-page path
    let mut rng_state: u64 = 0x123456789ABCDEF0;
    let mut random_bytes = Vec::with_capacity(5000);
    for _ in 0..5000 {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        random_bytes.push((rng_state >> 33) as u8);
    }
    let random_str = String::from_utf8_lossy(&random_bytes).to_string();

    let tests: Vec<(&str, &str)> = vec![
        ("empty",      ""),
        ("one_byte",   "a"),
        ("hello",      "Hello, FM Aero Code 2!"),
        ("ascii_128",  ascii_128.as_str()),
        ("ascii_500",  ascii_500.as_str()),
        ("ascii_2000", ascii_2000.as_str()),
        ("text_multi", "The quick brown fox jumps over the lazy dog. 0123456789."),
        ("random_5k",  random_str.as_str()),
    ];

    println!("=== Round-trip self-tests (no password) ===");
    let mut pass = 0;
    let mut fail = 0;
    for (name, s) in &tests {
        match selftest_string(s) {
            Ok(r) => {
                let status = if r.match_ok { "OK" } else { "MISMATCH" };
                let kind = if r.multi_page { "APNG" } else { "PNG" };
                println!("  [{}] {}: input={} B -> {}={} B -> decoded={} B grid={}x{}",
                    status, name, r.input_bytes, kind, r.png_bytes, r.decoded_bytes,
                    r.png_width, r.png_height);
                if r.match_ok { pass += 1; } else { fail += 1; }
            }
            Err(e) => {
                println!("  [ERROR] {}: {}", name, e);
                fail += 1;
            }
        }
    }

    println!();
    println!("=== Round-trip with password ===");
    match selftest_string_with_password("secret data 12345", "hunter2") {
        Ok(r) => {
            let status = if r.match_ok { "OK" } else { "MISMATCH" };
            println!("  [{}] pw_test: input={} B -> png={} B -> decoded={} B",
                status, r.input_bytes, r.png_bytes, r.decoded_bytes);
            if r.match_ok { pass += 1; } else { fail += 1; }
        }
        Err(e) => { println!("  [ERROR] pw_test: {}", e); fail += 1; }
    }

    println!();
    println!("Total: {} pass / {} fail", pass, fail);
    if fail > 0 { std::process::exit(1); }
    Ok(())
}
