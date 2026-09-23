//! FM Aero Code 2 application icon.
//!
//! Simple "AERO" text in gray on transparent background.
//! Uses a 5x7 bitmap font for A, E, R, O glyphs.

use eframe::egui;

pub fn load_icon() -> egui::IconData {
    let size: u32 = 256;
    let mut rgba = vec![0u8; (size * size * 4) as usize];

    // 5x7 bitmaps: each row is a byte, only low 5 bits used.
    let glyphs: [[u8; 7]; 4] = [
        [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
        [0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001],
        [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
    ];

    let glyph_w: u32 = 5;
    let glyph_h: u32 = 7;
    let gap: u32 = 1;
    let scale: u32 = 10;
    let total_w = (glyph_w * 4 + gap * 3) * scale;
    let total_h = glyph_h * scale;
    let start_x = (size - total_w) / 2;
    let start_y = (size - total_h) / 2;

    let gray: u8 = 200;
    for (gi, glyph) in glyphs.iter().enumerate() {
        for row in 0..7u32 {
            for col in 0..5u32 {
                if (glyph[row as usize] >> (4 - col)) & 1 == 1 {
                    let bx0 = start_x + (gi as u32 * (glyph_w + gap) + col) * scale;
                    let by0 = start_y + row * scale;
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = bx0 + dx;
                            let py = by0 + dy;
                            if px < size && py < size {
                                let i = ((py * size + px) * 4) as usize;
                                rgba[i] = gray;
                                rgba[i + 1] = gray;
                                rgba[i + 2] = gray + 5;
                                rgba[i + 3] = 255;
                            }
                        }
                    }
                }
            }
        }
    }

    egui::IconData { rgba, width: size, height: size }
}