//! Print rendering for A4/Letter/Legal sheets.
//!
//! Takes encoded patterns (128x128 grayscale) and produces a print-ready
//! image at 300 DPI with margins and labels, then serializes to
//! PNG / HTML / SVG / PDF.

use anyhow::{anyhow, Result};
use image::{GrayImage, RgbImage, Rgb};
use png::{BitDepth, ColorType, Encoder};
use base64::Engine as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize { A4, Letter, Legal }

impl Default for PageSize { fn default() -> Self { Self::A4 } }

impl PageSize {
    pub fn width_px(&self) -> u32 {
        match self { Self::A4 => 2480, Self::Letter => 2550, Self::Legal => 2550 }
    }
    pub fn height_px(&self) -> u32 {
        match self { Self::A4 => 3508, Self::Letter => 3300, Self::Legal => 4200 }
    }
    pub fn css_name(&self) -> &'static str {
        match self { Self::A4 => "A4", Self::Letter => "letter", Self::Legal => "legal" }
    }
}

const DPI_PPM: u32 = 11811; // pixels per meter at 300 DPI

fn blit_scaled(dst: &mut RgbImage, src: &GrayImage, x0: u32, y0: u32, scale: u32) {
    let (dw, dh) = (dst.width(), dst.height());
    for (x, y, p) in src.enumerate_pixels() {
        let v = if p.0[0] < 128 { 0 } else { 255 };
        let c = Rgb([v, v, v]);
        for sy in 0..scale {
            for sx in 0..scale {
                let px = x0 + x * scale + sx;
                let py = y0 + y * scale + sy;
                if px < dw && py < dh { dst.put_pixel(px, py, c); }
            }
        }
    }
}

pub fn render_single_print(img: &GrayImage, label: &str, size: PageSize) -> Result<RgbImage> {
    let (pw, ph) = (size.width_px(), size.height_px());
    let margin = 150u32;
    let avail_w = pw - 2 * margin;
    let avail_h = ph - 2 * margin - 200;
    let scale = ((avail_w as f64 / img.width() as f64)
        .min(avail_h as f64 / img.height() as f64)).floor() as u32;
    let scale = scale.max(1);
    let nw = img.width() * scale;
    let nh = img.height() * scale;
    let mut out = RgbImage::from_pixel(pw, ph, Rgb([255, 255, 255]));
    let x0 = (pw - nw) / 2;
    let y0 = margin;
    blit_scaled(&mut out, img, x0, y0, scale);
    draw_text(&mut out, margin, y0 + nh + 60, label);
    Ok(out)
}

pub fn render_flow_sheet_annotated(
    frames: &[GrayImage],
    ranges: Option<&[(usize, usize)]>,
    title: &str,
    size: PageSize,
) -> Result<RgbImage> {
    if frames.is_empty() { return Err(anyhow!("no frames")); }
    let (pw, ph) = (size.width_px(), size.height_px());
    let margin = 120u32;
    let gap = 40u32;
    let cols = 3u32;
    let rows = ((frames.len() as u32) + cols - 1) / cols;
    let cell_w = (pw - 2 * margin - (cols - 1) * gap) / cols;
    let cell_h = (ph - 2 * margin - (rows - 1) * gap - 150) / rows.max(1);
    let mut out = RgbImage::from_pixel(pw, ph, Rgb([255, 255, 255]));

    for (i, f) in frames.iter().enumerate() {
        let cx = i as u32 % cols;
        let cy = i as u32 / cols;
        let x0 = margin + cx * (cell_w + gap);
        let y0 = margin + cy * (cell_h + gap);
        let scale = ((cell_w as f64 / f.width() as f64)
            .min(cell_h as f64 / f.height() as f64)).floor() as u32;
        let scale = scale.max(1);
        let nw = f.width() * scale;
        let nh = f.height() * scale;
        let ox = x0 + (cell_w - nw) / 2;
        let oy = y0 + (cell_h - nh) / 2;
        blit_scaled(&mut out, f, ox, oy, scale);
        let tag = format!("#{}/{}", i + 1, frames.len());
        draw_text(&mut out, x0 + 4, y0 + 4, &tag);
        if let Some(r) = ranges {
            if let Some(&(s, e)) = r.get(i) {
                let range_str = format!("{}..{}", s, e);
                let rw = range_str.len() as u32 * 8;
                draw_text(&mut out, x0 + cell_w - rw, y0 + 4, &range_str);
            }
        }
    }
    draw_text(&mut out, margin, ph - 100, title);
    Ok(out)
}

pub fn write_print_png_to_vec(img: &RgbImage) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut e = Encoder::new(&mut buf, img.width(), img.height());
        e.set_color(ColorType::Rgb);
        e.set_depth(BitDepth::Eight);
        e.set_pixel_dims(Some(png::PixelDimensions {
            xppu: DPI_PPM, yppu: DPI_PPM, unit: png::Unit::Meter,
        }));
        let mut w = e.write_header()?;
        w.write_image_data(img.as_raw())?;
        w.finish()?;
    }
    Ok(buf)
}

pub fn write_print_html(img: &RgbImage, title: &str, size: PageSize) -> Result<Vec<u8>> {
    let png_bytes = write_print_png_to_vec(img)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png_bytes);
    let page_w = size.width_px() as f64 / 300.0;
    let page_h = size.height_px() as f64 / 300.0;
    let html = format!(
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n<title>{t}</title>\n<style>\n\
@page {{ size: {c}; margin: 0; }}\n\
* {{ margin:0; padding:0; box-sizing:border-box; }}\n\
html, body {{ background:#fff; }}\n\
img {{ display:block; width:{pw}in; height:{ph}in; image-rendering:pixelated; }}\n\
@media screen {{ body {{ background:#222; }} img {{ margin:20px auto; box-shadow:0 0 20px #000; }} .hint {{ color:#ccc; font:13px sans-serif; text-align:center; padding:12px; }} }}\n\
@media print {{ .hint {{ display:none; }} img {{ margin:0; box-shadow:none; }} }}\n\
</style></head>\n<body>\n\
<div class=\"hint\">Press Ctrl+P (Cmd+P on Mac) to print. Page size: {cu}.</div>\n\
<img src=\"data:image/png;base64,{b}\" alt=\"pattern\">\n\
<script>window.addEventListener('load',()=>setTimeout(()=>window.print(),300));</script>\n\
</body></html>",
        t = html_escape(title), c = size.css_name(),
        cu = size.css_name().to_uppercase(),
        pw = page_w, ph = page_h, b = b64,
    );
    Ok(html.into_bytes())
}

pub fn write_print_svg(img: &RgbImage, title: &str, size: PageSize) -> Result<Vec<u8>> {
    let png_bytes = write_print_png_to_vec(img)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png_bytes);
    let w_mm = size.width_px() as f64 / 300.0 * 25.4;
    let h_mm = size.height_px() as f64 / 300.0 * 25.4;
    let svg = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"\n\
     width=\"{w:.3}mm\" height=\"{h:.3}mm\" viewBox=\"0 0 {pw} {ph}\">\n\
  <title>{t}</title>\n\
  <image x=\"0\" y=\"0\" width=\"{pw}\" height=\"{ph}\" preserveAspectRatio=\"none\" xlink:href=\"data:image/png;base64,{b}\"/>\n\
</svg>",
        w = w_mm, h = h_mm, pw = size.width_px(), ph = size.height_px(),
        t = html_escape(title), b = b64
    );
    Ok(svg.into_bytes())
}

pub fn write_print_pdf(img: &RgbImage, title: &str, size: PageSize) -> Result<Vec<u8>> {
    let _ = size;
    let rgb = img.as_raw();
    let compressed = miniz_oxide::deflate::compress_to_vec(rgb, 6);
    let w = img.width();
    let h = img.height();
    let page_w = w as f64 * 72.0 / 300.0;
    let page_h = h as f64 * 72.0 / 300.0;

    let mut buf: Vec<u8> = Vec::new();
    let mut offsets: Vec<usize> = vec![0];
    macro_rules! w { ($($a:tt)*) => { { use std::io::Write; write!(buf, $($a)*)?; } } }
    macro_rules! wb { ($b:expr) => { buf.extend_from_slice($b) } }

    wb!(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    offsets.push(buf.len());
    w!("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets.push(buf.len());
    w!("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    offsets.push(buf.len());
    w!("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {:.3} {:.3}] /Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>\nendobj\n",
        page_w, page_h);

    let content = format!("q\n{:.3} 0 0 {:.3} 0 0 cm\n/Im0 Do\nQ\n", page_w, page_h);
    offsets.push(buf.len());
    w!("4 0 obj\n<< /Length {} >>\nstream\n", content.len());
    wb!(content.as_bytes());
    w!("\nendstream\nendobj\n");

    offsets.push(buf.len());
    w!("5 0 obj\n<< /Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length {} >>\nstream\n",
        w, h, compressed.len());
    wb!(&compressed);
    w!("\nendstream\nendobj\n");

    offsets.push(buf.len());
    let esc_title = title.replace('\\', "\\\\").replace('(', "\\(").replace(')', "\\)");
    w!("6 0 obj\n<< /Title ({}) /Producer (FM Aero Code 2) >>\nendobj\n", esc_title);

    let xref_off = buf.len();
    w!("xref\n0 {}\n", offsets.len());
    w!("0000000000 65535 f \n");
    for i in 1..offsets.len() {
        w!("{:010} 00000 n \n", offsets[i]);
    }
    w!("trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{}\n%%EOF\n",
        offsets.len(), xref_off);
    Ok(buf)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Minimal 5x7 pixel font for labels and page numbers.
fn draw_text(img: &mut RgbImage, x: u32, y: u32, text: &str) {
    let mut cx = x;
    for ch in text.chars() {
        let g = glyph_5x7(ch);
        for (ry, row) in g.iter().enumerate() {
            for rx in 0..5 {
                if (row >> (4 - rx)) & 1 == 1 {
                    let px = cx + rx as u32;
                    let py = y + ry as u32;
                    if px < img.width() && py < img.height() {
                        img.put_pixel(px, py, Rgb([0, 0, 0]));
                    }
                }
            }
        }
        cx += 7;
    }
}

fn glyph_5x7(c: char) -> [u8; 7] {
    match c {
        '0' => [0b01110,0b10001,0b10011,0b10101,0b11001,0b10001,0b01110],
        '1' => [0b00100,0b01100,0b00100,0b00100,0b00100,0b00100,0b01110],
        '2' => [0b01110,0b10001,0b00001,0b00010,0b00100,0b01000,0b11111],
        '3' => [0b11111,0b00010,0b00100,0b00010,0b00001,0b10001,0b01110],
        '4' => [0b00010,0b00110,0b01010,0b10010,0b11111,0b00010,0b00010],
        '5' => [0b11111,0b10000,0b11110,0b00001,0b00001,0b10001,0b01110],
        '6' => [0b00110,0b01000,0b10000,0b11110,0b10001,0b10001,0b01110],
        '7' => [0b11111,0b00001,0b00010,0b00100,0b01000,0b01000,0b01000],
        '8' => [0b01110,0b10001,0b10001,0b01110,0b10001,0b10001,0b01110],
        '9' => [0b01110,0b10001,0b10001,0b01111,0b00001,0b00010,0b01100],
        '#' => [0b01010,0b11111,0b01010,0b01010,0b11111,0b01010,0b01010],
        '.' => [0,0,0,0,0,0b00100,0],
        ',' => [0,0,0,0,0,0b00100,0b01000],
        '-' => [0,0,0,0b11111,0,0,0],
        '_' => [0,0,0,0,0,0,0b11111],
        ':' => [0,0b00100,0,0,0b00100,0,0],
        '/' => [0b00001,0b00010,0b00010,0b00100,0b01000,0b01000,0b10000],
        ' ' => [0;7],
        _ => glyph_letter(c),
    }
}

fn glyph_letter(c: char) -> [u8; 7] {
    let up = c.to_ascii_uppercase();
    match up {
        'A' => [0b01110,0b10001,0b10001,0b11111,0b10001,0b10001,0b10001],
        'B' => [0b11110,0b10001,0b10001,0b11110,0b10001,0b10001,0b11110],
        'C' => [0b01110,0b10001,0b10000,0b10000,0b10000,0b10001,0b01110],
        'D' => [0b11110,0b10001,0b10001,0b10001,0b10001,0b10001,0b11110],
        'E' => [0b11111,0b10000,0b10000,0b11110,0b10000,0b10000,0b11111],
        'F' => [0b11111,0b10000,0b10000,0b11110,0b10000,0b10000,0b10000],
        'G' => [0b01110,0b10001,0b10000,0b10111,0b10001,0b10001,0b01110],
        'H' => [0b10001,0b10001,0b10001,0b11111,0b10001,0b10001,0b10001],
        'I' => [0b01110,0b00100,0b00100,0b00100,0b00100,0b00100,0b01110],
        'J' => [0b00111,0b00010,0b00010,0b00010,0b00010,0b10010,0b01100],
        'K' => [0b10001,0b10010,0b10100,0b11000,0b10100,0b10010,0b10001],
        'L' => [0b10000,0b10000,0b10000,0b10000,0b10000,0b10000,0b11111],
        'M' => [0b10001,0b11011,0b10101,0b10101,0b10001,0b10001,0b10001],
        'N' => [0b10001,0b11001,0b10101,0b10011,0b10001,0b10001,0b10001],
        'O' => [0b01110,0b10001,0b10001,0b10001,0b10001,0b10001,0b01110],
        'P' => [0b11110,0b10001,0b10001,0b11110,0b10000,0b10000,0b10000],
        'Q' => [0b01110,0b10001,0b10001,0b10001,0b10101,0b10010,0b01101],
        'R' => [0b11110,0b10001,0b10001,0b11110,0b10100,0b10010,0b10001],
        'S' => [0b01111,0b10000,0b10000,0b01110,0b00001,0b00001,0b11110],
        'T' => [0b11111,0b00100,0b00100,0b00100,0b00100,0b00100,0b00100],
        'U' => [0b10001,0b10001,0b10001,0b10001,0b10001,0b10001,0b01110],
        'V' => [0b10001,0b10001,0b10001,0b10001,0b10001,0b01010,0b00100],
        'W' => [0b10001,0b10001,0b10001,0b10101,0b10101,0b11011,0b10001],
        'X' => [0b10001,0b10001,0b01010,0b00100,0b01010,0b10001,0b10001],
        'Y' => [0b10001,0b10001,0b01010,0b00100,0b00100,0b00100,0b00100],
        'Z' => [0b11111,0b00001,0b00010,0b00100,0b01000,0b10000,0b11111],
        _ => [0b11111,0b00001,0b00010,0b00100,0b01000,0b00000,0b01000],
    }
}