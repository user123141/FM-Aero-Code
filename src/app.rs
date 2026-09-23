use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use crate::encoder::pipeline::ProgressState;
use std::time::{Duration, Instant};

use eframe::egui;
use egui::{Color32, RichText, ScrollArea, Vec2};

use crate::crypto::{generate_recipient, CipherKind};
use crate::decoder::pipeline::{decode_from_bytes, peek_header_from_bytes};
use crate::encoder::apng::write_apng_to_vec;
use crate::encoder::pipeline::{encode_aeroflow, encode_payload, CompressionMode, EncodeOptions};
use crate::settings::Settings;
use crate::types::DataType;
use crate::VERSION;

const MIN_ZOOM: f32 = 0.05;
const MAX_ZOOM: f32 = 32.0;
const PREVIEW_MAX_FRAMES: usize = 128;
const PREVIEW_FRAME_MS: u64 = 100;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode { AeroGlint, Stego }

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab { Pattern, Decoded, Keys, Stego, About }

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrintKind { Png, Html, Svg, Pdf }
impl PrintKind {
    fn label(&self) -> &'static str {
        match self { Self::Png => "PNG", Self::Html => "HTML", Self::Svg => "SVG", Self::Pdf => "PDF" }
    }
    fn ext(&self) -> &'static str {
        match self { Self::Png => "png", Self::Html => "html", Self::Svg => "svg", Self::Pdf => "pdf" }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrintSize { A4, Letter, Legal }

enum Msg {
    Log(String),
    Error(String),
    Preview {
        frames: Vec<(Vec<u8>, u32, u32)>,
        bytes: Vec<u8>,
        name: String,
        is_apng: bool,
        page_count: usize,
    },
    Decoded { payload: Vec<u8>, dt: DataType, name: String, sha: String, ok: bool },
}

struct DecodedView {
    name: String,
    sha: String,
    ok: bool,
    kind: &'static str,
    text: Option<String>,
    bytes: Vec<u8>,
    texture: Option<egui::TextureHandle>,
    dim: (u32, u32),
}

pub struct FmAeroApp {
    input: String,
    text_payload: String,
    password: String,
    cipher: CipherKind,
    use_encryption: bool,
    compression: CompressionMode,
    use_recipient: bool,
    recipient_pub: String,
    recipient_pub_gen: String,
    recipient_sec_gen: String,
    show_secret: bool,
    photo_bytes: Option<Vec<u8>>,
    photo_name: String,
    resilience_level: u8,
    border: bool,
    gamma: bool,
    mask: bool,
    print_size: PrintSize,
    print_kind: PrintKind,
    tab: Tab,
    mode: Mode,
    log: Vec<String>,
    busy: bool,
    show_log: bool,
    encoded: Option<(Vec<u8>, String, bool)>,
    frames: Vec<egui::TextureHandle>,
    preview_dim: (u32, u32),
    frame_index: usize,
    frame_started: Instant,
    autoplay: bool,
    page_count: usize,
    decoded: Option<DecodedView>,
    zoom: f32,
    pan: Vec2,
    op_started: Option<Instant>,
    last_duration: Option<f32>,
    progress_state: Option<Arc<ProgressState>>,
    last_speed_pps: Option<f32>,
    last_speed_bps: Option<f32>,
    settings: Settings,
    rx: Receiver<Msg>,
    tx: Sender<Msg>,
    use_stars: bool,
    star_density: u16,
    use_nebula: bool,
    frame_pattern: u8,
    stego_carrier: Option<Vec<u8>>,
    stego_carrier_name: String,
    stego_payload: Option<Vec<u8>>,
    stego_payload_name: String,
    stego_output: Option<(Vec<u8>, String)>,
    stego_extract_src: Option<Vec<u8>>,
    stego_extract_src_name: String,
    stego_text: String,
    stego_last_msg: String,
    stego_preview_tex: Option<egui::TextureHandle>,
    stego_carrier_tex: Option<egui::TextureHandle>,
    stego_preview_dirty: bool,
}

impl FmAeroApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut v = egui::Visuals::dark();
        v.panel_fill = Color32::from_rgb(18, 18, 20);
        v.window_fill = Color32::from_rgb(28, 28, 30);
        v.extreme_bg_color = Color32::from_rgb(10, 10, 12);
        v.selection.bg_fill = Color32::from_rgb(10, 132, 255);
        cc.egui_ctx.set_visuals(v);
        let (tx, rx) = channel();
        let settings = Settings::load();
        let cipher = match settings.cipher_kind {
            2 => CipherKind::SealV2,
            1 => CipherKind::SealV1,
            _ => CipherKind::SealV1,
        };
        Self {
            input: String::new(),
            text_payload: "Hello, FM Aero Code 2!".into(),
            password: String::new(),
            cipher,
            use_encryption: settings.cipher_kind != 0,
            compression: match settings.compression {
                0 => CompressionMode::Auto,
                1 => CompressionMode::Lossless,
                _ => CompressionMode::LosslessPriority,
            },
            use_recipient: false,
            recipient_pub: String::new(),
            recipient_pub_gen: String::new(),
            recipient_sec_gen: String::new(),
            show_secret: false,
            photo_bytes: None,
            photo_name: String::new(),
            resilience_level: settings.resilience,
            border: settings.border,
            gamma: false,
            mask: false,
            print_size: PrintSize::A4,
            print_kind: PrintKind::Png,
            tab: Tab::Pattern,
            mode: Mode::AeroGlint,
            log: vec!["Ready.".into()],
            busy: false,
            show_log: true,
            encoded: None,
            frames: Vec::new(),
            preview_dim: (0, 0),
            frame_index: 0,
            frame_started: Instant::now(),
            autoplay: true,
            page_count: 0,
            decoded: None,
            zoom: 1.0,
            pan: Vec2::ZERO,
            op_started: None,
            last_duration: None,
            progress_state: None,
            last_speed_pps: None,
            last_speed_bps: None,
            use_stars: false,
            star_density: 60,
            use_nebula: false,
            frame_pattern: 0,
            stego_carrier: None,
            stego_carrier_name: String::new(),
            stego_payload: None,
            stego_payload_name: String::new(),
            stego_output: None,
            stego_extract_src: None,
            stego_extract_src_name: String::new(),
            stego_text: String::new(),
            stego_last_msg: String::new(),
            stego_preview_tex: None,
            stego_carrier_tex: None,
            stego_preview_dirty: false,
            settings,
            rx, tx,
        }
    }

    fn push(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
        if self.log.len() > 500 {
            let n = self.log.len() - 500;
            self.log.drain(0..n);
        }
    }

    fn save_settings(&mut self) {
        self.settings.cipher_kind = if self.use_encryption {
            match self.cipher {
                CipherKind::SealV2 => 2,
                _ => 1,
            }
        } else { 0 };
        self.settings.compression = match self.compression {
            CompressionMode::Auto => 0,
            CompressionMode::Lossless => 1,
            CompressionMode::LosslessPriority => 2,
        };
        self.settings.resilience = self.resilience_level;
        self.settings.border = self.border;
        self.settings.save();
    }

    fn encode(&mut self) {
        let data: Vec<u8> = if self.input.is_empty() {
            self.text_payload.clone().into_bytes()
        } else {
            match std::fs::read(&self.input) {
                Ok(b) => b,
                Err(e) => { self.push(format!("read error: {}", e)); return; }
            }
        };
        let name = if self.input.is_empty() { "message.txt".to_string() }
            else { Path::new(&self.input).file_name().and_then(|n| n.to_str())
                   .unwrap_or("payload.bin").to_string() };
        let pw = if self.use_encryption { self.password.clone() } else { String::new() };
        let cipher = if self.use_encryption { self.cipher } else { CipherKind::None };
        let recipient = if self.use_recipient { Some(self.recipient_pub.clone()) } else { None };
        let cm = self.compression;
        let photo = self.photo_bytes.clone();
        let resilience_level = self.resilience_level;
        let border = self.border;
        let gamma = self.gamma;
        let mask = self.mask;
        let use_stars = self.use_stars;
        let star_density = self.star_density;
        let use_nebula = self.use_nebula;
        let frame_pattern = self.frame_pattern;
        if !self.input.is_empty() {
            self.settings.add_recent(&self.input);
        }
        self.save_settings();
        let tx = self.tx.clone();
        let progress = Arc::new(ProgressState::new());
        self.progress_state = Some(progress.clone());
        self.busy = true;
        self.op_started = Some(Instant::now());
        self.push(format!("Encoding {} ({})...", name, crate::types::human_bytes(data.len())));
        std::thread::spawn(move || {
            let t0 = std::time::Instant::now();
            let opts = EncodeOptions {
                cipher,
                password: pw,
                pad: true,
                compression: cm,
                original_name: name.clone(),
                center_logo: photo,
                signing_key: None,
                hmac_enabled: true,
                auto_lossless_media: true,
                recipient_key: recipient,
                recipients: Vec::new(),
                gps: None,
                resilience_level,
                border,
                gamma,
                mask,
                progress: Some(progress.clone()),
                stars: use_stars,
                star_density,
                nebula: use_nebula,
                frame_pattern,
            };
            match encode_payload(&data, &opts) {
                Ok(r) => {
                    let (w, h) = (r.image.width(), r.image.height());
                    let px: Vec<u8> = r.image.pixels()
                        .flat_map(|p| [p.0[0], p.0[0], p.0[0], 255u8])
                        .collect();
                    let mut png = Vec::new();
                    {
                        use image::ImageEncoder;
                        use image::codecs::png::PngEncoder;
                        let _ = PngEncoder::new(&mut png).write_image(
                            r.image.as_raw(), w, h, image::ExtendedColorType::L8);
                    }
                    let elapsed = t0.elapsed().as_secs_f32();
                    let _ = tx.send(Msg::Log(format!(
                        "Encoded {}x{} in {:.2}s | {} -> {}",
                        w, h, elapsed, crate::types::human_bytes(r.payload_bytes), crate::types::human_bytes(png.len()))));
                    let _ = tx.send(Msg::Preview {
                        frames: vec![(px, w, h)],
                        bytes: png,
                        name: "output.aero2.png".into(),
                        is_apng: false,
                        page_count: 1,
                    });
                }
                Err(_) => {
                    match encode_aeroflow(&data, &opts) {
                        Ok(f) => {
                            let page_count = f.page_count;
                            match write_apng_to_vec(&f.frames, 4) {
                                Ok(apng) => {
                                    let cap = f.frames.len().min(PREVIEW_MAX_FRAMES);
                                    let mut frames_px = Vec::with_capacity(cap);
                                    for fr in f.frames.iter().take(cap) {
                                        let (w, h) = (fr.width(), fr.height());
                                        let px: Vec<u8> = fr.pixels()
                                            .flat_map(|p| [p.0[0], p.0[0], p.0[0], 255u8])
                                            .collect();
                                        frames_px.push((px, w, h));
                                    }
                                    let elapsed = t0.elapsed().as_secs_f32();
                                    let pps = if elapsed > 0.0 { page_count as f32 / elapsed } else { 0.0 };
                                    let _ = tx.send(Msg::Log(format!(
                                        "Encoded APNG {} pages in {:.2}s ({:.0} p/s) | {} -> {}",
                                        page_count, elapsed, pps,
                                        crate::types::human_bytes(f.payload_bytes),
                                        crate::types::human_bytes(apng.len()))));
                                    let _ = tx.send(Msg::Preview {
                                        frames: frames_px,
                                        bytes: apng,
                                        name: "output.aero2.apng.png".into(),
                                        is_apng: true,
                                        page_count,
                                    });
                                }
                                Err(e) => { let _ = tx.send(Msg::Error(format!("apng: {}", e))); }
                            }
                        }
                        Err(e) => { let _ = tx.send(Msg::Error(format!("{}", e))); }
                    }
                }
            }
        });
    }

    fn decode_from_file(&mut self) {
        let path = self.input.clone();
        if path.is_empty() { self.push("no file selected"); return; }
        let pw = if self.use_encryption { self.password.clone() } else { String::new() };
        let tx = self.tx.clone();
        let progress = Arc::new(ProgressState::new());
        self.progress_state = Some(progress.clone());
        self.busy = true;
        self.op_started = Some(Instant::now());
        self.push("Decoding from file...");
        std::thread::spawn(move || {
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => { let _ = tx.send(Msg::Error(format!("read: {}", e))); return; }
            };
            decode_worker(bytes, pw, tx);
        });
    }

    fn decode_from_ram(&mut self) {
        let Some((bytes, _, _)) = self.encoded.clone() else {
            self.push("no encoded pattern in RAM");
            return;
        };
        let pw = if self.use_encryption { self.password.clone() } else { String::new() };
        let tx = self.tx.clone();
        let progress = Arc::new(ProgressState::new());
        self.progress_state = Some(progress.clone());
        self.busy = true;
        self.op_started = Some(Instant::now());
        self.push("Decoding from RAM...");
        std::thread::spawn(move || { decode_worker(bytes, pw, tx); });
    }

    fn do_print(&mut self) {
        let Some((bytes, name, is_apng)) = self.encoded.clone() else {
            self.push("no pattern to print");
            return;
        };
        let kind = self.print_kind;
        let size = match self.print_size {
            PrintSize::A4 => crate::encoder::print::PageSize::A4,
            PrintSize::Letter => crate::encoder::print::PageSize::Letter,
            PrintSize::Legal => crate::encoder::print::PageSize::Legal,
        };
        let stem = name.trim_end_matches(".png").trim_end_matches(".apng.png");
        let out_name = format!("{}.{}", stem, kind.ext());
        let Some(path) = rfd::FileDialog::new().set_file_name(&out_name).save_file() else {
            return;
        };
        self.busy = true;
        self.push(format!("Rendering {} print...", kind.label()));
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let run = || -> anyhow::Result<Vec<u8>> {
                use crate::encoder::print::*;
                let frames: Vec<image::GrayImage> = if is_apng {
                    crate::decoder::apng_reader::load_apng_frames_from_bytes(&bytes)?
                } else {
                    vec![crate::decoder::apng_reader::load_luma_from_bytes(&bytes)?]
                };
                let sheet = if frames.len() > 1 {
                    render_flow_sheet_annotated(&frames, None, "FM Aero Code 2", size)?
                } else {
                    render_single_print(&frames[0], "FM Aero Code 2", size)?
                };
                let data = match kind {
                    PrintKind::Png => write_print_png_to_vec(&sheet)?,
                    PrintKind::Html => write_print_html(&sheet, "FM Aero Code 2", size)?,
                    PrintKind::Svg => write_print_svg(&sheet, "FM Aero Code 2", size)?,
                    PrintKind::Pdf => write_print_pdf(&sheet, "FM Aero Code 2", size)?,
                };
                Ok(data)
            };
            match run() {
                Ok(data) => {
                    if std::fs::write(&path, &data).is_ok() {
                        let _ = tx.send(Msg::Log(format!("[OK] Saved print: {} ({:.1} KB)",
                            path.display(), data.len() as f64 / 1024.0)));
                    } else {
                        let _ = tx.send(Msg::Error("write print failed".into()));
                    }
                }
                Err(e) => { let _ = tx.send(Msg::Error(format!("print: {}", e))); }
            }
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Log(s) => {
                    if let Some(t) = self.op_started.take() {
                        self.last_duration = Some(t.elapsed().as_secs_f32());
                    }
                    self.busy = false;
                    self.push(s);
                }
                Msg::Error(e) => {
                    if let Some(t) = self.op_started.take() {
                        self.last_duration = Some(t.elapsed().as_secs_f32());
                    }
                    self.busy = false;
                    self.push(format!("ERROR: {}", e));
                }
                Msg::Preview { frames, bytes, name, is_apng, page_count } => {
                    self.busy = false;
                    self.frames.clear();
                    let mut first_dim = (0u32, 0u32);
                    for (i, (pixels, w, h)) in frames.into_iter().enumerate() {
                        if i == 0 { first_dim = (w, h); }
                        let ci = egui::ColorImage::from_rgba_unmultiplied(
                            [w as usize, h as usize], &pixels);
                        self.frames.push(ctx.load_texture(
                            format!("frame_{}", i), ci, egui::TextureOptions::NEAREST));
                    }
                    self.preview_dim = first_dim;
                    self.frame_index = 0;
                    self.frame_started = Instant::now();
                    self.encoded = Some((bytes, name, is_apng));
                    self.page_count = page_count;
                    self.tab = Tab::Pattern;
                    self.zoom = 1.0;
                    self.pan = Vec2::ZERO;
                }
                Msg::Decoded { payload, dt, name, sha, ok } => {
                    self.busy = false;
                    let kind = dt.label();
                    let (text, texture, dim) = match dt {
                        DataType::Text => (Some(String::from_utf8_lossy(&payload).into_owned()), None, (0, 0)),
                        DataType::Image => {
                            if let Ok(img) = image::load_from_memory(&payload) {
                                let rgba = img.to_rgba8();
                                let (w, h) = (rgba.width(), rgba.height());
                                let ci = egui::ColorImage::from_rgba_unmultiplied(
                                    [w as usize, h as usize], rgba.as_raw());
                                (None, Some(ctx.load_texture("decoded", ci,
                                    egui::TextureOptions::LINEAR)), (w, h))
                            } else { (None, None, (0, 0)) }
                        }
                        _ => (None, None, (0, 0)),
                    };
                    self.decoded = Some(DecodedView {
                        name: if name.is_empty() { "decoded.bin".into() } else { name },
                        sha, ok, kind, text, bytes: payload, texture, dim,
                    });
                    self.tab = Tab::Decoded;
                }
            }
        }
        if self.autoplay && self.frames.len() > 1 {
            if self.frame_started.elapsed() >= Duration::from_millis(PREVIEW_FRAME_MS) {
                self.frame_index = (self.frame_index + 1) % self.frames.len();
                self.frame_started = Instant::now();
            }
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        if self.busy { ctx.request_repaint_after(Duration::from_millis(80)); }
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let (ctrl_e, ctrl_d, ctrl_s, ctrl_o) = ctx.input(|i| (
            i.modifiers.ctrl && i.key_pressed(egui::Key::E),
            i.modifiers.ctrl && i.key_pressed(egui::Key::D),
            i.modifiers.ctrl && i.key_pressed(egui::Key::S),
            i.modifiers.ctrl && i.key_pressed(egui::Key::O),
        ));
        if ctrl_o {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                self.input = p.display().to_string();
            }
        }
        if ctrl_e && !self.busy {
            let ready = !self.input.is_empty() || !self.text_payload.is_empty();
            if ready { self.encode(); }
        }
        if ctrl_d && !self.busy && !self.input.is_empty() {
            self.decode_from_file();
        }
        if ctrl_s && !self.busy {
            if let Some((bytes, name, _)) = self.encoded.clone() {
                if let Some(p) = rfd::FileDialog::new().set_file_name(&name).save_file() {
                    if std::fs::write(&p, &bytes).is_ok() {
                        self.push(format!("saved {}", p.display()));
                    }
                }
            }
        }
        let dropped: Vec<egui::DroppedFile> = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(f) = dropped.first() {
            if let Some(p) = &f.path {
                self.input = p.display().to_string();
                self.push(format!("dropped: {}", self.input));
            }
        }
    }

    fn tick_progress(&mut self) {
        let Some(ps) = self.progress_state.clone() else { return; };
        let (done, total) = ps.snapshot();
        if total == 0 { return; }
        let (bytes_done, _) = ps.bytes_snapshot();
        let elapsed = self.op_started.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0);
        if done > 0 && elapsed > 0.2 {
            self.last_speed_pps = Some(done as f32 / elapsed);
            self.last_speed_bps = Some(bytes_done as f32 / elapsed);
        }
    }
    fn stego_encode(&mut self) {
        let Some(carrier_bytes) = self.stego_carrier.clone() else {
            self.push("stego: load a carrier photo first"); return;
        };
        // payload from file, else from text
        let (payload, name) = if let Some(p) = self.stego_payload.clone() {
            (p, self.stego_payload_name.clone())
        } else if !self.stego_text.is_empty() {
            (self.stego_text.as_bytes().to_vec(), "message.txt".to_string())
        } else {
            self.push("stego: no payload (load a file or type text)"); return;
        };
        let password = if self.use_encryption && !self.password.is_empty() {
            self.password.clone()
        } else { String::new() };
        // Capacity pre-check
        if let Ok(c) = image::load_from_memory(&carrier_bytes) {
            let cap = crate::steganography::capacity_bytes(c.width(), c.height());
            let est = payload.len() * 255 / 223 + 32;
            if est > cap {
                self.push(format!("stego: payload {} B (with FEC ~{} B) > capacity {} B",
                    payload.len(), est, cap));
                return;
            }
        }
        self.push(format!("Embedding {} B into carrier...", payload.len()));
        let t0 = Instant::now();
        match image::load_from_memory(&carrier_bytes) {
            Ok(carrier) => {
                let opts = crate::steganography::StegoOptions {
                    password: password.clone(),
                    original_name: name.clone(),
                };
                match crate::steganography::embed(&carrier, &payload, &opts) {
                    Ok(out) => {
                        let elapsed = t0.elapsed().as_secs_f32();
                        let (w, h) = (out.image.width(), out.image.height());
                        let mut png: Vec<u8> = Vec::new();
                        {
                            use image::ImageEncoder;
                            use image::codecs::png::PngEncoder;
                            let _ = PngEncoder::new(&mut png).write_image(
                                out.image.as_raw(), w, h, image::ExtendedColorType::Rgb8);
                        }
                        let pct = 100.0 * out.fec_bytes as f64 / out.capacity_bytes as f64;
                        let msg = format!(
                            "Stego OK in {:.3}s: {}x{} | payload {} B -> stream {} B / cap {} B ({:.1}%)",
                            elapsed, w, h, out.payload_bytes, out.fec_bytes, out.capacity_bytes, pct);
                        self.push(msg.clone());
                        self.stego_last_msg = msg;
                        self.stego_output = Some((png, "stego.png".to_string()));
                        self.stego_preview_dirty = true;
                    }
                    Err(e) => self.push(format!("stego error: {}", e)),
                }
            }
            Err(e) => self.push(format!("carrier decode: {}", e)),
        }
    }

    fn stego_decode(&mut self) {
        // Priority: explicit extract src > saved stego output > carrier
        let (src_bytes, src_label) = if let Some(s) = self.stego_extract_src.clone() {
            (s, self.stego_extract_src_name.clone())
        } else if let Some((bytes, _)) = self.stego_output.clone() {
            if bytes.len() >= 8 && bytes[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
                (bytes, "last embedded output".to_string())
            } else if let Some(c) = self.stego_carrier.clone() {
                (c, self.stego_carrier_name.clone())
            } else {
                self.push("stego: no image to extract from"); return;
            }
        } else if let Some(c) = self.stego_carrier.clone() {
            (c, self.stego_carrier_name.clone())
        } else {
            self.push("stego: no image to extract from"); return;
        };
        let password = if self.use_encryption && !self.password.is_empty() {
            self.password.clone()
        } else { String::new() };
        self.push(format!("Extracting payload from {}...", src_label));
        let t0 = Instant::now();
        match image::load_from_memory(&src_bytes) {
            Ok(img) => match crate::steganography::extract(&img, &password) {
                Ok(payload) => {
                    let elapsed = t0.elapsed().as_secs_f32();
                    let name = format!("extracted_{}.bin", payload.len());
                    let msg = format!("Extracted {} B in {:.3}s", payload.len(), elapsed);
                    self.push(msg.clone());
                    self.stego_last_msg = msg;
                    self.stego_output = Some((payload, name));
                }
                Err(e) => self.push(format!("extract error: {}", e)),
            },
            Err(e) => self.push(format!("image decode: {}", e)),
        }
    }

    fn stego_test_roundtrip(&mut self) {
        let Some(carrier_bytes) = self.stego_carrier.clone() else {
            self.push("test: load a carrier photo first"); return;
        };
        let (payload, name) = if let Some(p) = self.stego_payload.clone() {
            (p, self.stego_payload_name.clone())
        } else if !self.stego_text.is_empty() {
            (self.stego_text.as_bytes().to_vec(), "message.txt".to_string())
        } else {
            self.push("test: no payload (load a file or type text)"); return;
        };
        let password = if self.use_encryption && !self.password.is_empty() {
            self.password.clone()
        } else { String::new() };
        self.push(format!("Test round-trip: {} B...", payload.len()));
        let t0 = Instant::now();
        let Ok(carrier) = image::load_from_memory(&carrier_bytes) else {
            self.push("test: carrier decode failed"); return;
        };
        let opts = crate::steganography::StegoOptions {
            password: password.clone(),
            original_name: name,
        };
        let out = match crate::steganography::embed(&carrier, &payload, &opts) {
            Ok(o) => o,
            Err(e) => { self.push(format!("test: embed failed: {}", e)); return; }
        };
        let dyn_img = image::DynamicImage::ImageRgb8(out.image.clone());
        let extracted = match crate::steganography::extract(&dyn_img, &password) {
            Ok(e) => e,
            Err(e) => { self.push(format!("test: extract failed: {}", e)); return; }
        };
        let elapsed = t0.elapsed().as_secs_f32();
        if extracted == payload {
            self.push(format!("Test PASS in {:.3}s: {} B round-tripped OK", elapsed, payload.len()));
        } else {
            self.push(format!("Test FAIL in {:.3}s: got {} B, expected {} B",
                elapsed, extracted.len(), payload.len()));
        }
    }

    fn ui_stego_side(&mut self, ui: &mut egui::Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(6.0);
            ui.heading("Steganography");
            ui.label(RichText::new("Hide data inside a normal photo. Photo looks unchanged.").weak());
            ui.add_space(6.0);
            ui.separator();

            ui.heading("Carrier photo");
            ui.horizontal(|ui| {
                if ui.button("Load photo").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("image", &["png", "jpg", "jpeg", "bmp", "webp"])
                        .pick_file() {
                        if let Ok(b) = std::fs::read(&p) {
                            self.stego_carrier_name = p.file_name()
                                .and_then(|n| n.to_str()).unwrap_or("cover").to_string();
                            self.stego_carrier = Some(b);
                            self.stego_carrier_tex = None;
                        }
                    }
                }
                if self.stego_carrier.is_some() {
                    if ui.small_button("x").clicked() {
                        self.stego_carrier = None;
                        self.stego_carrier_tex = None;
                        self.stego_carrier_name.clear();
                    }
                }
            });
            if !self.stego_carrier_name.is_empty() {
                ui.label(RichText::new(format!("[{}]", self.stego_carrier_name)).weak());
            }

            ui.add_space(6.0);
            ui.separator();
            ui.heading("Payload");
            ui.horizontal(|ui| {
                if ui.button("Load file").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        if let Ok(b) = std::fs::read(&p) {
                            self.stego_payload_name = p.file_name()
                                .and_then(|n| n.to_str()).unwrap_or("secret.bin").to_string();
                            self.stego_payload = Some(b);
                        }
                    }
                }
                if self.stego_payload.is_some() {
                    if ui.small_button("x").clicked() {
                        self.stego_payload = None;
                        self.stego_payload_name.clear();
                    }
                }
            });
            if let Some(p) = self.stego_payload.as_ref() {
                ui.label(RichText::new(format!("[{}] {} B",
                    self.stego_payload_name, p.len())).weak());
            } else {
                ui.label(RichText::new("or type text:").weak());
                ui.add(egui::TextEdit::multiline(&mut self.stego_text)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .hint_text("secret message"));
            }

            ui.add_space(6.0);
            ui.separator();
            ui.heading("Options");
            ui.checkbox(&mut self.use_encryption, "Encrypt (uses password from Encryption panel)");

            if let Some(c) = self.stego_carrier.as_ref() {
                if let Ok(img) = image::load_from_memory(c) {
                    let cap = crate::steganography::capacity_bytes(img.width(), img.height());
                    let payload_len = self.stego_payload.as_ref().map(|p| p.len())
                        .unwrap_or_else(|| self.stego_text.len());
                    let est = payload_len * 255 / 223 + 32;
                    let frac = if cap > 0 { (est as f32) / (cap as f32) } else { 0.0 };
                    let color = if frac > 1.0 {
                        Color32::from_rgb(255, 120, 120)
                    } else if frac > 0.85 {
                        Color32::from_rgb(255, 200, 100)
                    } else {
                        Color32::from_rgb(120, 220, 140)
                    };
                    ui.add_space(4.0);
                    ui.label(RichText::new(format!("{}x{} - capacity {} B",
                        img.width(), img.height(), cap)).weak());
                    ui.add(egui::ProgressBar::new(frac.min(1.0))
                        .desired_width(ui.available_width())
                        .fill(color)
                        .text(format!("{}/{} B ({:.0}%)", est, cap, frac * 100.0)));
                }
            }

            ui.add_space(8.0);
            let ready = self.stego_carrier.is_some()
                && (self.stego_payload.is_some() || !self.stego_text.is_empty())
                && !self.busy;
            ui.add_enabled_ui(ready, |ui| {
                if ui.add_sized([ui.available_width(), 36.0],
                    egui::Button::new(RichText::new("EMBED into photo").strong())).clicked() {
                    self.stego_encode();
                }
                if ui.add_sized([ui.available_width(), 30.0],
                    egui::Button::new("Test round-trip (verify)")).clicked() {
                    self.stego_test_roundtrip();
                }
            });

            ui.add_space(8.0);
            ui.separator();
            ui.heading("Extract");
            ui.horizontal(|ui| {
                if ui.button("Load stego image").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("image", &["png", "jpg", "jpeg", "bmp"])
                        .pick_file() {
                        if let Ok(b) = std::fs::read(&p) {
                            self.stego_extract_src_name = p.file_name()
                                .and_then(|n| n.to_str()).unwrap_or("stego.png").to_string();
                            self.stego_extract_src = Some(b);
                        }
                    }
                }
                if ui.small_button("Clear").clicked() {
                    self.stego_extract_src = None;
                    self.stego_extract_src_name.clear();
                }
            });
            if !self.stego_extract_src_name.is_empty() {
                ui.label(RichText::new(format!("source: {}", self.stego_extract_src_name)).weak());
            } else {
                ui.label(RichText::new("(empty - will use last embedded output)").weak());
            }
            let can_ex = (self.stego_extract_src.is_some()
                || self.stego_output.is_some()
                || self.stego_carrier.is_some()) && !self.busy;
            ui.add_enabled_ui(can_ex, |ui| {
                if ui.add_sized([ui.available_width(), 36.0],
                    egui::Button::new(RichText::new("EXTRACT payload").strong())).clicked() {
                    self.stego_decode();
                }
            });

            if let Some((bytes, name)) = self.stego_output.as_ref() {
                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new(format!("Output: {} ({:.1} KB)",
                    name, bytes.len() as f64 / 1024.0)).weak());
                if ui.add_sized([ui.available_width(), 32.0],
                    egui::Button::new("Save output")).clicked() {
                    let n = name.clone();
                    let b = bytes.clone();
                    if let Some(p) = rfd::FileDialog::new().set_file_name(&n).save_file() {
                        if std::fs::write(&p, &b).is_ok() {
                            self.push(format!("saved {}", p.display()));
                        }
                    }
                }
            }
        });
    }

    fn ui_stego_center(&mut self, ui: &mut egui::Ui) {
        // Build textures
        if self.stego_carrier_tex.is_none() {
            if let Some(c) = self.stego_carrier.as_ref() {
                if let Ok(img) = image::load_from_memory(c) {
                    let rgba = img.to_rgba8();
                    let (w, h) = (rgba.width(), rgba.height());
                    let ci = egui::ColorImage::from_rgba_unmultiplied(
                        [w as usize, h as usize], rgba.as_raw());
                    self.stego_carrier_tex = Some(ui.ctx().load_texture(
                        "stego_carrier", ci, egui::TextureOptions::LINEAR));
                }
            }
        }
        if self.stego_preview_dirty {
            if let Some((bytes, _)) = self.stego_output.as_ref() {
                if bytes.len() > 8 && bytes[0..8] == [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A] {
                    if let Ok(img) = image::load_from_memory(bytes) {
                        let rgba = img.to_rgba8();
                        let (w, h) = (rgba.width(), rgba.height());
                        let ci = egui::ColorImage::from_rgba_unmultiplied(
                            [w as usize, h as usize], rgba.as_raw());
                        self.stego_preview_tex = Some(ui.ctx().load_texture(
                            "stego_preview", ci, egui::TextureOptions::LINEAR));
                        self.stego_preview_dirty = false;
                    }
                }
            }
        }

        let avail_w = ui.available_width();
        let have = self.stego_carrier_tex.is_some() || self.stego_preview_tex.is_some();
        if !have {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Load a photo and click EMBED to see preview").weak());
            });
            return;
        }

        ui.horizontal_top(|ui| {
            let col_w = (avail_w - 20.0) / 2.0;
            ui.vertical(|ui| {
                ui.set_min_width(col_w);
                ui.set_max_width(col_w);
                ui.label(RichText::new("Carrier").strong());
                if let Some(tex) = self.stego_carrier_tex.as_ref() {
                    let tw = col_w.min(360.0);
                    ui.add(egui::Image::new((tex.id(), egui::vec2(tw, tw * 0.7)))
                        .maintain_aspect_ratio(true));
                } else {
                    ui.label(RichText::new("(none)").weak());
                }
            });
            ui.vertical(|ui| {
                ui.set_min_width(col_w);
                ui.set_max_width(col_w);
                ui.label(RichText::new("Stego output").strong());
                if let Some(tex) = self.stego_preview_tex.as_ref() {
                    let tw = col_w.min(360.0);
                    ui.add(egui::Image::new((tex.id(), egui::vec2(tw, tw * 0.7)))
                        .maintain_aspect_ratio(true));
                } else {
                    ui.label(RichText::new("(embed to generate)").weak());
                }
            });
        });

        if !self.stego_last_msg.is_empty() {
            ui.add_space(10.0);
            ui.separator();
            ui.colored_label(Color32::from_rgb(120, 200, 255),
                RichText::new(&self.stego_last_msg).strong());
        }
    }

    fn ui_side(&mut self, ui: &mut egui::Ui) {
        // Mode toggle at top of left panel
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let w = (ui.available_width() - 8.0) / 2.0;
            let ag = ui.add_sized([w, 34.0],
                egui::SelectableLabel::new(self.mode == Mode::AeroGlint, "AeroGlint"));
            if ag.clicked() { self.mode = Mode::AeroGlint; }
            let st = ui.add_sized([w, 34.0],
                egui::SelectableLabel::new(self.mode == Mode::Stego, "Stego"));
            if st.clicked() { self.mode = Mode::Stego; }
        });
        ui.separator();

        if self.mode == Mode::Stego {
            self.ui_stego_side(ui);
            return;
        }

        ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(6.0);
            ui.heading("Source");
            ui.horizontal(|ui| {
                if ui.button("Browse (Ctrl+O)").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.input = p.display().to_string();
                    }
                }
                if ui.button("Clear").clicked() { self.input.clear(); }
            });
            ui.add(egui::TextEdit::singleline(&mut self.input)
                .hint_text("path or drag file here").desired_width(f32::INFINITY));

            if !self.settings.recent_files.is_empty() && self.input.is_empty() {
                ui.add_space(2.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Recent:").weak());
                    let recent_clone: Vec<String> = self.settings.recent_files.clone();
                    for path in recent_clone.iter() {
                        let label = Path::new(path).file_name()
                            .and_then(|n| n.to_str()).unwrap_or(path.as_str()).to_string();
                        if ui.small_button(label).clicked() {
                            self.input = path.clone();
                        }
                    }
                });
            }

            ui.add_space(4.0);
            ui.label(RichText::new("Or type text:").weak());
            ui.add(egui::TextEdit::multiline(&mut self.text_payload)
                .desired_rows(3).desired_width(f32::INFINITY));

            ui.add_space(8.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.heading("Encrypt");
                ui.checkbox(&mut self.use_encryption, "");
            });
            if self.use_encryption {
                let mode_label = if self.use_recipient && !self.recipient_pub.is_empty() {
                    "AeroSeal v2 (recipient)"
                } else if self.cipher == CipherKind::SealV2 {
                    "AeroSeal v2"
                } else {
                    "AeroSeal v1 (password)"
                };
                ui.label(RichText::new(format!("Mode: {}", mode_label))
                    .color(Color32::from_rgb(120, 200, 255)));

                ui.horizontal(|ui| {
                    ui.label("Cipher:");
                    egui::ComboBox::from_id_salt("cipher_mode")
                        .selected_text(match self.cipher {
                            CipherKind::SealV1 => "AeroSeal v1",
                            CipherKind::SealV2 => "AeroSeal v2",
                            CipherKind::None => "None",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.cipher, CipherKind::SealV1, "AeroSeal v1 (password)");
                            ui.selectable_value(&mut self.cipher, CipherKind::SealV2, "AeroSeal v2 (X25519)");
                        });
                });
                ui.label(RichText::new("Password").weak());
                ui.horizontal(|ui| {
                    let w = ui.available_width() - 60.0;
                    ui.add(egui::TextEdit::singleline(&mut self.password)
                        .password(true).desired_width(w)
                        .hint_text("password"));
                    if ui.small_button("Copy").clicked() {
                        let pw = self.password.clone();
                        ui.output_mut(|o| o.copied_text = pw);
                    }
                });
                ui.checkbox(&mut self.use_recipient, "Use recipient key (v2)");
                if self.use_recipient {
                    ui.add(egui::TextEdit::singleline(&mut self.recipient_pub)
                        .hint_text("64 hex X25519 public").desired_width(f32::INFINITY));
                }
            }

            ui.add_space(8.0);
            ui.separator();
            ui.heading("Compression");
            egui::ComboBox::from_id_salt("cm")
                .selected_text(self.compression.label())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.compression, CompressionMode::LosslessPriority, "Lossless Priority");
                    ui.selectable_value(&mut self.compression, CompressionMode::Auto, "Auto");
                    ui.selectable_value(&mut self.compression, CompressionMode::Lossless, "Lossless");
                });

            ui.add_space(8.0);
            ui.separator();
            ui.heading("Transport");
            ui.horizontal(|ui| {
                ui.label("Resilience:");
                let label = match self.resilience_level {
                    1 => "Low (5%)", 2 => "Balanced (10%)",
                    3 => "High (25%)", 4 => "Extreme (50%)",
                    _ => "Off",
                };
                egui::ComboBox::from_id_salt("res_level")
                    .selected_text(label)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.resilience_level, 0, "Off");
                        ui.selectable_value(&mut self.resilience_level, 1, "Low (5%)");
                        ui.selectable_value(&mut self.resilience_level, 2, "Balanced (10%)");
                        ui.selectable_value(&mut self.resilience_level, 3, "High (25%)");
                        ui.selectable_value(&mut self.resilience_level, 4, "Extreme (50%)");
                    });
            });
            ui.checkbox(&mut self.border, "Detection border (camera / print)");

            ui.add_space(6.0);
            ui.label(RichText::new("Soft decorations (visual only)").strong());
            ui.checkbox(&mut self.use_stars, "Stars");
            if self.use_stars {
                ui.horizontal(|ui| {
                    ui.label("density:");
                    let mut d = self.star_density as f32;
                    ui.add(egui::Slider::new(&mut d, 10.0..=500.0).show_value(false));
                    self.star_density = d as u16;
                    ui.label(format!("{}", self.star_density));
                });
            }
            ui.checkbox(&mut self.use_nebula, "Nebula");
            ui.horizontal(|ui| {
                ui.label("frame:");
                egui::ComboBox::from_id_salt("frame_pat")
                    .selected_text(match self.frame_pattern { 1=>"Ring", 2=>"Cross", 3=>"Checker", _=>"None" })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.frame_pattern, 0, "None");
                        ui.selectable_value(&mut self.frame_pattern, 1, "Ring");
                        ui.selectable_value(&mut self.frame_pattern, 2, "Cross");
                        ui.selectable_value(&mut self.frame_pattern, 3, "Checker");
                    });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.heading("Center logo");
            ui.horizontal(|ui| {
                let label = if self.photo_bytes.is_some() { "Change" } else { "Add logo" };
                if ui.button(label).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("image", &["png", "jpg", "jpeg", "bmp", "webp"])
                        .pick_file()
                    {
                        if let Ok(b) = std::fs::read(&p) {
                            self.photo_bytes = Some(b);
                            self.photo_name = p.file_name()
                                .and_then(|n| n.to_str()).unwrap_or("logo").into();
                        }
                    }
                }
                if self.photo_bytes.is_some() {
                    ui.label(RichText::new(format!("[{}]", self.photo_name)).weak());
                    if ui.small_button("x").clicked() {
                        self.photo_bytes = None;
                        self.photo_name.clear();
                    }
                }
            });

            ui.add_space(12.0);
            ui.separator();
            let ready = !self.input.is_empty() || !self.text_payload.is_empty();
            ui.add_enabled_ui(ready && !self.busy, |ui| {
                if ui.add_sized([ui.available_width(), 38.0],
                    egui::Button::new(RichText::new("ENCODE (Ctrl+E)").strong())).clicked() {
                    self.encode();
                }
            });
            let can_decode = !self.input.is_empty() && !self.busy;
            ui.add_enabled_ui(can_decode, |ui| {
                if ui.add_sized([ui.available_width(), 38.0],
                    egui::Button::new("DECODE file (Ctrl+D)")).clicked() {
                    self.decode_from_file();
                }
            });
            let can_ram = self.encoded.is_some() && !self.busy;
            ui.add_enabled_ui(can_ram, |ui| {
                if ui.add_sized([ui.available_width(), 38.0],
                    egui::Button::new("DECODE from RAM")).clicked() {
                    self.decode_from_ram();
                }
            });

            if let Some((bytes, name, is_apng)) = self.encoded.clone() {
                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new(format!(
                    "Pattern: {} {} ({:.1} KB)",
                    if is_apng { "APNG" } else { "PNG" },
                    name, bytes.len() as f64 / 1024.0)).weak());
                if ui.add_sized([ui.available_width(), 34.0],
                    egui::Button::new("Save PNG (Ctrl+S)")).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_file_name(&name).save_file()
                    {
                        if std::fs::write(&p, &bytes).is_ok() {
                            self.push(format!("saved {}", p.display()));
                        }
                    }
                }

                ui.add_space(6.0);
                ui.label(RichText::new("Print for A4:").strong());
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("print_kind")
                        .selected_text(self.print_kind.label())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.print_kind, PrintKind::Png, "PNG");
                            ui.selectable_value(&mut self.print_kind, PrintKind::Html, "HTML");
                            ui.selectable_value(&mut self.print_kind, PrintKind::Svg, "SVG");
                            ui.selectable_value(&mut self.print_kind, PrintKind::Pdf, "PDF");
                        });
                    egui::ComboBox::from_id_salt("print_size")
                        .selected_text(match self.print_size {
                            PrintSize::A4 => "A4",
                            PrintSize::Letter => "Letter",
                            PrintSize::Legal => "Legal",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.print_size, PrintSize::A4, "A4");
                            ui.selectable_value(&mut self.print_size, PrintSize::Letter, "Letter");
                            ui.selectable_value(&mut self.print_size, PrintSize::Legal, "Legal");
                        });
                });
                if ui.add_sized([ui.available_width(), 34.0],
                    egui::Button::new("Save print...")).clicked() {
                    self.do_print();
                }
            }
        });
    }

    fn ui_center(&mut self, ui: &mut egui::Ui) {
        if self.mode == Mode::Stego {
            self.ui_stego_center(ui);
            return;
        }
        match self.tab {
            Tab::Pattern => {
                if self.frames.is_empty() {
                    ui.centered_and_justified(|ui| {
                        ui.label(RichText::new("No pattern yet. Click ENCODE.").size(18.0).weak());
                    });
                    return;
                }
                ui.horizontal(|ui| {
                    let total = self.page_count.max(1);
                    let previewing = self.frames.len();
                    ui.label(RichText::new(format!(
                        "Page {}/{} (total {}, preview {})",
                        self.frame_index + 1, previewing, total, previewing)).weak());
                    if previewing > 1 {
                        ui.separator();
                        if ui.button("<").clicked() {
                            self.frame_index = if self.frame_index == 0 { previewing - 1 } else { self.frame_index - 1 };
                        }
                        if ui.button(">").clicked() {
                            self.frame_index = (self.frame_index + 1) % previewing;
                        }
                        ui.checkbox(&mut self.autoplay, "Play");
                    }
                });
                ui.separator();
                if let Some(tex) = self.frames.get(self.frame_index).cloned() {
                    let (w, h) = self.preview_dim;
                    let (resp, painter) = ui.allocate_painter(
                        ui.available_size(), egui::Sense::click_and_drag());
                    let sc = ui.input(|i| i.raw_scroll_delta.y);
                    if sc.abs() > 0.0 {
                        self.zoom = (self.zoom * (sc * 0.01).exp()).clamp(MIN_ZOOM, MAX_ZOOM);
                    }
                    if resp.dragged() { self.pan += resp.drag_delta(); }
                    let c = resp.rect.center() + self.pan;
                    let size = egui::vec2(w as f32, h as f32) * self.zoom;
                    let r = egui::Rect::from_center_size(c, size);
                    painter.image(tex.id(), r,
                        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        Color32::WHITE);
                }
            }
            Tab::Decoded => {
                if let Some(d) = &self.decoded {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("Type: {}", d.kind)).strong());
                        ui.separator();
                        ui.label(format!("{} B", d.bytes.len()));
                        ui.separator();
                        let sha_short = if d.sha.len() >= 16 { &d.sha[..16] } else { &d.sha };
                        ui.label(RichText::new(sha_short).weak());
                        if !d.ok {
                            ui.colored_label(Color32::from_rgb(255, 120, 120), "HASH MISMATCH");
                        }
                    });
                    ui.separator();
                    if let Some(text) = &d.text {
                        ScrollArea::both().show(ui, |ui| {
                            ui.add(egui::Label::new(RichText::new(text).monospace()));
                        });
                    } else if let Some(tex) = &d.texture {
                        let (w, h) = d.dim;
                        let (resp, painter) = ui.allocate_painter(
                            ui.available_size(), egui::Sense::click_and_drag());
                        if resp.dragged() { self.pan += resp.drag_delta(); }
                        let size = egui::vec2(w as f32, h as f32) * self.zoom;
                        let c = resp.rect.center() + self.pan;
                        let r = egui::Rect::from_center_size(c, size);
                        painter.image(tex.id(), r,
                            egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                            Color32::WHITE);
                    } else {
                        ui.label("Binary data. Use Save As.");
                    }
                    ui.separator();
                    if ui.button("Save As...").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .set_file_name(&d.name).save_file()
                        {
                            let _ = std::fs::write(&p, &d.bytes);
                        }
                    }
                } else {
                    ui.centered_and_justified(|ui| ui.label("Nothing decoded yet"));
                }
            }
            Tab::Keys => {
                ui.heading("Key management");
                ui.separator();
                if ui.button("Generate X25519 keypair").clicked() {
                    let kp = generate_recipient();
                    self.recipient_pub_gen = hex::encode(kp.public.as_bytes());
                    self.recipient_sec_gen = hex::encode(kp.secret.to_bytes());
                }
                ui.add_space(6.0);
                ui.label("Public (share):");
                ui.add(egui::TextEdit::singleline(&mut self.recipient_pub_gen).desired_width(f32::INFINITY));
                ui.label("Secret (keep private):");
                let sec_display = if self.show_secret { self.recipient_sec_gen.clone() }
                                  else { "*".repeat(self.recipient_sec_gen.len().min(64)) };
                let mut s = sec_display;
                ui.add(egui::TextEdit::singleline(&mut s).desired_width(f32::INFINITY));
                ui.checkbox(&mut self.show_secret, "Show secret");
                if ui.button("Use generated public as recipient").clicked() {
                    self.recipient_pub = self.recipient_pub_gen.clone();
                    self.use_recipient = true;
                    self.use_encryption = true;
                    self.cipher = CipherKind::SealV2;
                }
            }
            Tab::Stego => {
                ui.horizontal_top(|ui| {
                    // ================= LEFT: controls =================
                    ui.vertical(|ui| {
                        ui.set_min_width(340.0);
                        ui.set_max_width(340.0);
                        ScrollArea::vertical().show(ui, |ui| {
                            ui.heading("Steganography");
                            ui.label(RichText::new("Hide any data inside a normal photo. Photo looks unchanged.").weak());
                            ui.add_space(6.0);
                            ui.separator();

                            ui.heading("Carrier photo");
                            ui.horizontal(|ui| {
                                if ui.button("Load photo").clicked() {
                                    if let Some(p) = rfd::FileDialog::new()
                                        .add_filter("image", &["png", "jpg", "jpeg", "bmp", "webp"])
                                        .pick_file() {
                                        if let Ok(b) = std::fs::read(&p) {
                                            self.stego_carrier_name = p.file_name()
                                                .and_then(|n| n.to_str()).unwrap_or("cover").to_string();
                                            self.stego_carrier = Some(b);
                                            self.stego_carrier_tex = None;
                                        }
                                    }
                                }
                                if self.stego_carrier.is_some() {
                                    if ui.small_button("x").clicked() {
                                        self.stego_carrier = None;
                                        self.stego_carrier_tex = None;
                                        self.stego_carrier_name.clear();
                                    }
                                }
                            });
                            if !self.stego_carrier_name.is_empty() {
                                ui.label(RichText::new(format!("[{}]", self.stego_carrier_name)).weak());
                            }

                            ui.add_space(6.0);
                            ui.separator();
                            ui.heading("Payload");
                            ui.horizontal(|ui| {
                                if ui.button("Load file").clicked() {
                                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                                        if let Ok(b) = std::fs::read(&p) {
                                            self.stego_payload_name = p.file_name()
                                                .and_then(|n| n.to_str()).unwrap_or("secret.bin").to_string();
                                            self.stego_payload = Some(b);
                                        }
                                    }
                                }
                                if self.stego_payload.is_some() {
                                    if ui.small_button("x").clicked() {
                                        self.stego_payload = None;
                                        self.stego_payload_name.clear();
                                    }
                                }
                            });
                            if let Some(p) = self.stego_payload.as_ref() {
                                ui.label(RichText::new(format!("[{}] {} B",
                                    self.stego_payload_name, p.len())).weak());
                            } else {
                                ui.label(RichText::new("or type text:").weak());
                                ui.add(egui::TextEdit::multiline(&mut self.stego_text)
                                    .desired_rows(3)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("secret message"));
                            }

                            ui.add_space(6.0);
                            ui.separator();
                            ui.heading("Options");
                            ui.checkbox(&mut self.use_encryption, "Encrypt (uses password from Encryption panel)");

                            if let Some(c) = self.stego_carrier.as_ref() {
                                if let Ok(img) = image::load_from_memory(c) {
                                    let cap = crate::steganography::capacity_bytes(img.width(), img.height());
                                    let payload_len = self.stego_payload.as_ref().map(|p| p.len())
                                        .unwrap_or_else(|| self.stego_text.len());
                                    let est = payload_len * 255 / 223 + 32;
                                    let frac = if cap > 0 { (est as f32) / (cap as f32) } else { 0.0 };
                                    let color = if frac > 1.0 {
                                        Color32::from_rgb(255, 120, 120)
                                    } else if frac > 0.85 {
                                        Color32::from_rgb(255, 200, 100)
                                    } else {
                                        Color32::from_rgb(120, 220, 140)
                                    };
                                    ui.add_space(4.0);
                                    ui.label(RichText::new(format!("{}x{} - capacity {} B",
                                        img.width(), img.height(), cap)).weak());
                                    ui.add(egui::ProgressBar::new(frac.min(1.0))
                                        .desired_width(ui.available_width())
                                        .fill(color)
                                        .text(format!("{}/{} B ({:.0}%)", est, cap, frac * 100.0)));
                                }
                            }

                            ui.add_space(8.0);
                            let ready = self.stego_carrier.is_some()
                                && (self.stego_payload.is_some() || !self.stego_text.is_empty())
                                && !self.busy;
                            ui.add_enabled_ui(ready, |ui| {
                                if ui.add_sized([ui.available_width(), 36.0],
                                    egui::Button::new(RichText::new("EMBED into photo").strong())).clicked() {
                                    self.stego_encode();
                                }
                                if ui.add_sized([ui.available_width(), 30.0],
                                    egui::Button::new("Test round-trip (verify)")).clicked() {
                                    self.stego_test_roundtrip();
                                }
                            });

                            ui.add_space(8.0);
                            ui.separator();
                            ui.heading("Extract");
                            ui.horizontal(|ui| {
                                if ui.button("Load stego image").clicked() {
                                    if let Some(p) = rfd::FileDialog::new()
                                        .add_filter("image", &["png", "jpg", "jpeg", "bmp"])
                                        .pick_file() {
                                        if let Ok(b) = std::fs::read(&p) {
                                            self.stego_extract_src_name = p.file_name()
                                                .and_then(|n| n.to_str()).unwrap_or("stego.png").to_string();
                                            self.stego_extract_src = Some(b);
                                        }
                                    }
                                }
                                if ui.small_button("Clear").clicked() {
                                    self.stego_extract_src = None;
                                    self.stego_extract_src_name.clear();
                                }
                            });
                            if !self.stego_extract_src_name.is_empty() {
                                ui.label(RichText::new(format!("source: {}", self.stego_extract_src_name)).weak());
                            } else {
                                ui.label(RichText::new("(empty - will use last embedded output)").weak());
                            }
                            let can_ex = (self.stego_extract_src.is_some()
                                || self.stego_output.is_some()
                                || self.stego_carrier.is_some()) && !self.busy;
                            ui.add_enabled_ui(can_ex, |ui| {
                                if ui.add_sized([ui.available_width(), 36.0],
                                    egui::Button::new(RichText::new("EXTRACT payload").strong())).clicked() {
                                    self.stego_decode();
                                }
                            });

                            if let Some((bytes, name)) = self.stego_output.as_ref() {
                                ui.add_space(8.0);
                                ui.separator();
                                ui.label(RichText::new(format!("Output: {} ({:.1} KB)",
                                    name, bytes.len() as f64 / 1024.0)).weak());
                                if ui.add_sized([ui.available_width(), 32.0],
                                    egui::Button::new("Save output")).clicked() {
                                    let n = name.clone();
                                    let b = bytes.clone();
                                    if let Some(p) = rfd::FileDialog::new().set_file_name(&n).save_file() {
                                        if std::fs::write(&p, &b).is_ok() {
                                            self.push(format!("saved {}", p.display()));
                                        }
                                    }
                                }
                            }
                        });
                    });

                    ui.separator();

                    // ================= RIGHT: preview =================
                    ui.vertical(|ui| {
                        ScrollArea::vertical().show(ui, |ui| {
                            ui.heading("Preview");
                            ui.add_space(4.0);

                            if self.stego_carrier_tex.is_none() {
                                if let Some(c) = self.stego_carrier.as_ref() {
                                    if let Ok(img) = image::load_from_memory(c) {
                                        let rgba = img.to_rgba8();
                                        let (w, h) = (rgba.width(), rgba.height());
                                        let ci = egui::ColorImage::from_rgba_unmultiplied(
                                            [w as usize, h as usize], rgba.as_raw());
                                        self.stego_carrier_tex = Some(ui.ctx().load_texture(
                                            "stego_carrier", ci, egui::TextureOptions::LINEAR));
                                    }
                                }
                            }
                            if self.stego_preview_dirty {
                                if let Some((bytes, _)) = self.stego_output.as_ref() {
                                    if bytes.len() > 8
                                        && bytes[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
                                        if let Ok(img) = image::load_from_memory(bytes) {
                                            let rgba = img.to_rgba8();
                                            let (w, h) = (rgba.width(), rgba.height());
                                            let ci = egui::ColorImage::from_rgba_unmultiplied(
                                                [w as usize, h as usize], rgba.as_raw());
                                            self.stego_preview_tex = Some(ui.ctx().load_texture(
                                                "stego_preview", ci, egui::TextureOptions::LINEAR));
                                            self.stego_preview_dirty = false;
                                        }
                                    }
                                }
                            }

                            let avail_w = ui.available_width();
                            let have_any = self.stego_carrier_tex.is_some() || self.stego_preview_tex.is_some();
                            if !have_any {
                                ui.add_space(80.0);
                                ui.centered_and_justified(|ui| {
                                    ui.label(RichText::new(
                                        "Load a photo and click EMBED to see preview").weak());
                                });
                            } else {
                                ui.horizontal_top(|ui| {
                                    let col_w = (avail_w - 16.0) / 2.0;
                                    ui.vertical(|ui| {
                                        ui.set_min_width(col_w);
                                        ui.set_max_width(col_w);
                                        ui.label(RichText::new("Carrier").strong());
                                        if let Some(tex) = self.stego_carrier_tex.as_ref() {
                                            let tw = col_w.min(340.0);
                                            let th = tw * 0.72;
                                            ui.add(egui::Image::new((tex.id(), egui::vec2(tw, th)))
                                                .maintain_aspect_ratio(true));
                                        } else {
                                            ui.label(RichText::new("(none)").weak());
                                        }
                                    });
                                    ui.vertical(|ui| {
                                        ui.set_min_width(col_w);
                                        ui.set_max_width(col_w);
                                        ui.label(RichText::new("Stego output").strong());
                                        if let Some(tex) = self.stego_preview_tex.as_ref() {
                                            let tw = col_w.min(340.0);
                                            let th = tw * 0.72;
                                            ui.add(egui::Image::new((tex.id(), egui::vec2(tw, th)))
                                                .maintain_aspect_ratio(true));
                                        } else {
                                            ui.label(RichText::new("(embed to generate)").weak());
                                        }
                                    });
                                });
                            }

                            if !self.stego_last_msg.is_empty() {
                                ui.add_space(10.0);
                                ui.separator();
                                ui.colored_label(
                                    Color32::from_rgb(120, 200, 255),
                                    RichText::new(&self.stego_last_msg).strong()
                                );
                            }
                        });
                    });
                });
            }
            Tab::About => {
                ui.heading("FM Aero Code 2");
                ui.label(RichText::new(format!("Version {}", VERSION))
                    .color(Color32::from_rgb(120, 200, 255)));
                ui.separator();
                ui.label(RichText::new("Author: Maksym Skorina").strong());
                ui.add_space(8.0);
                ui.label("Fast Memory optical storage via AeroGlint Spectrum Protocol.");
                ui.add_space(8.0);
                ui.label(RichText::new("Keyboard shortcuts:").strong());
                ui.label("Ctrl+O - open file");
                ui.label("Ctrl+E - encode");
                ui.label("Ctrl+D - decode");
                ui.label("Ctrl+S - save pattern");
                ui.label("Drag file into window - set as input");
                ui.add_space(8.0);
                if ui.button("Open GitHub repo").clicked() {
                    let _ = webbrowser::open("https://github.com/user123141/FM-Aero-Code");
                }
            }
        }
    }
}

fn decode_worker(bytes: Vec<u8>, pw: String, tx: Sender<Msg>) {
    let t0 = Instant::now();
    match peek_header_from_bytes(&bytes) {
        Ok(h) => {
            let _ = tx.send(Msg::Log(format!(
                "Header: cipher={} type={} size={} pages={}",
                h.cipher.label(), h.data_type.label(),
                h.original_size, h.page_total)));
        }
        Err(e) => {
            let _ = tx.send(Msg::Error(format!("not a pattern: {}", e)));
            return;
        }
    }
    match decode_from_bytes(&bytes, &pw, None) {
        Ok(r) => {
            let elapsed = t0.elapsed().as_secs_f32();
            let _ = tx.send(Msg::Log(format!(
                "Decoded {} B in {:.2}s | hash_ok={} sig_ok={} hmac_ok={} pages={}{}",
                r.payload.len(), elapsed,
                r.hash_ok, r.signature_ok, r.hmac_ok,
                r.pages_received,
                if r.recovered_from_parity { " [recovered from parity]" } else { "" })));
            let _ = tx.send(Msg::Decoded {
                payload: r.payload,
                dt: r.header.data_type,
                name: r.original_filename,
                sha: r.sha256,
                ok: r.hash_ok,
            });
        }
        Err(e) => { let _ = tx.send(Msg::Error(format!("{}", e))); }
    }
}

impl eframe::App for FmAeroApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_shortcuts(ctx);
        self.poll(ctx);
        self.tick_progress();
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("FM Aero Code 2");
                ui.label(RichText::new(format!("v{}", VERSION))
                    .color(Color32::from_rgb(120, 200, 255)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.busy {
                        let el = self.op_started.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0);
                        let (done, total) = self.progress_state.as_ref().map(|p| p.snapshot()).unwrap_or((0, 0));
                        let (bytes_done, _bt) = self.progress_state.as_ref().map(|p| p.bytes_snapshot()).unwrap_or((0, 0));
                        ui.add(egui::Spinner::new());
                        if total > 0 {
                            let frac = (done as f32) / (total as f32);
                            let eta = if done > 0 { el * (total as f32 - done as f32) / (done as f32) } else { 0.0 };
                            let pps = if el > 0.2 { (done as f32) / el } else { 0.0 };
                            let bps = if el > 0.2 { (bytes_done as f32) / el } else { 0.0 };
                            ui.add(egui::ProgressBar::new(frac)
                                .desired_width(220.0)
                                .text(format!("{}/{} ({:.0}%)", done, total, frac * 100.0)));
                            ui.label(format!("ETA {:.0}s", eta));
                            ui.label(format!("{:.0} pps", pps));
                            ui.label(format!("{}/s", crate::types::human_bytes(bps as usize)));
                        } else {
                            ui.label(format!("Working... {:.1}s", el));
                            ui.add(egui::ProgressBar::new(0.0).animate(true).desired_width(140.0));
                        }
                        ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
                    } else if let Some(d) = self.last_duration {
                        let pps = self.last_speed_pps.map(|s| format!(" | {:.0} pps", s)).unwrap_or_default();
                        let bps = self.last_speed_bps.map(|s| format!(" | {}/s", crate::types::human_bytes(s as usize))).unwrap_or_default();
                        ui.label(egui::RichText::new(format!("Last: {:.2}s{}{}", d, pps, bps)).weak());
                    }
                    ui.toggle_value(&mut self.show_log, "Log");
                });
            });
        });
        egui::SidePanel::left("left").default_width(400.0).resizable(false)
            .show(ctx, |ui| { self.ui_side(ui); });
        if self.show_log {
            egui::TopBottomPanel::bottom("log")
                .default_height(180.0).resizable(true)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Log").strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Clear").clicked() { self.log.clear(); }
                            if ui.button("Copy all").clicked() {
                                let txt = self.log.join("\n");
                                ui.output_mut(|o| o.copied_text = txt);
                            }
                        });
                    });
                    ScrollArea::vertical().stick_to_bottom(true)
                        .auto_shrink([false, false]).show(ui, |ui| {
                        for line in &self.log {
                            let c = if line.starts_with("ERROR") {
                                Color32::from_rgb(255, 120, 120)
                            } else if line.contains("[OK]") || line.contains("hash_ok=true") {
                                Color32::from_rgb(120, 220, 140)
                            } else {
                                Color32::from_gray(200)
                            };
                            ui.monospace(RichText::new(line).color(c));
                        }
                    });
                });
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            self.ui_center(ui);
        });
    }
}