use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui;
use egui::{Color32, RichText, ScrollArea, Vec2};

use crate::crypto::{generate_recipient, CipherKind};
use crate::decoder::pipeline::{decode_from_bytes, peek_header_from_bytes};
use crate::encoder::apng::write_apng_to_vec;
use crate::encoder::pipeline::{encode_aeroflow, encode_payload, CompressionMode, EncodeOptions};
use crate::types::DataType;
use crate::VERSION;

const MIN_ZOOM: f32 = 0.05;
const MAX_ZOOM: f32 = 32.0;
const PREVIEW_MAX_FRAMES: usize = 128;
const PREVIEW_FRAME_MS: u64 = 100;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab { Pattern, Decoded, Keys, About }

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
    tab: Tab,
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
    rx: Receiver<Msg>,
    tx: Sender<Msg>,
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
        Self {
            input: String::new(),
            text_payload: "Hello, FM Aero Code 2!".into(),
            password: String::new(),
            cipher: CipherKind::SealV1,
            compression: CompressionMode::LosslessPriority,
            use_recipient: false,
            recipient_pub: String::new(),
            recipient_pub_gen: String::new(),
            recipient_sec_gen: String::new(),
            show_secret: false,
            photo_bytes: None,
            photo_name: String::new(),
            resilience_level: 0,
            border: false,
            gamma: false,
            mask: false,
            tab: Tab::Pattern,
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
        let pw = self.password.clone();
        let recipient = if self.use_recipient { Some(self.recipient_pub.clone()) } else { None };
        let cm = self.compression;
        let photo = self.photo_bytes.clone();
        let resilience_level = self.resilience_level;
        let border = self.border;
        let gamma = self.gamma;
        let mask = self.mask;
        let tx = self.tx.clone();
        self.busy = true;
        self.push(format!("Encoding {} ({} B)...", name, data.len()));
        std::thread::spawn(move || {
            let opts = EncodeOptions {
                cipher: if pw.is_empty() && recipient.is_none() { CipherKind::None }
                        else if recipient.is_some() { CipherKind::SealV2 }
                        else { CipherKind::SealV1 },
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
                    let _ = tx.send(Msg::Log(format!(
                        "Encoded single-page: {}x{} | input {} B -> PNG {} B",
                        w, h, r.payload_bytes, png.len())));
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
                                    let _ = tx.send(Msg::Log(format!(
                                        "Encoded APNG {} pages | input {} B -> APNG {} B",
                                        page_count, f.payload_bytes, apng.len())));
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
        let pw = self.password.clone();
        let tx = self.tx.clone();
        self.busy = true;
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
        let pw = self.password.clone();
        let tx = self.tx.clone();
        self.busy = true;
        self.push("Decoding from RAM...");
        std::thread::spawn(move || { decode_worker(bytes, pw, tx); });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Log(s) => { self.busy = false; self.push(s); }
                Msg::Error(e) => { self.busy = false; self.push(format!("ERROR: {}", e)); }
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

    fn ui_side(&mut self, ui: &mut egui::Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(6.0);
            ui.heading("Source");
            ui.horizontal(|ui| {
                if ui.button("Browse...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.input = p.display().to_string();
                    }
                }
                if ui.button("Clear").clicked() { self.input.clear(); }
            });
            ui.add(egui::TextEdit::singleline(&mut self.input)
                .hint_text("path or drop file").desired_width(f32::INFINITY));
            ui.add_space(4.0);
            ui.label(RichText::new("Or type text:").weak());
            ui.add(egui::TextEdit::multiline(&mut self.text_payload)
                .desired_rows(3).desired_width(f32::INFINITY));

            ui.add_space(8.0);
            ui.separator();
            ui.heading("Security");
            let mode_label = if self.use_recipient && !self.recipient_pub.is_empty() {
                "AeroSeal v2 (recipient)"
            } else if !self.password.is_empty() {
                "AeroSeal v1 (password)"
            } else {
                "None (no encryption)"
            };
            ui.label(RichText::new(format!("Mode: {}", mode_label))
                .color(Color32::from_rgb(120, 200, 255)));
            ui.label(RichText::new("Password").weak());
            ui.add(egui::TextEdit::singleline(&mut self.password)
                .password(true).desired_width(f32::INFINITY)
                .hint_text("empty = no encryption"));
            ui.checkbox(&mut self.use_recipient, "Use recipient key (AeroSeal v2)");
            if self.use_recipient {
                ui.add(egui::TextEdit::singleline(&mut self.recipient_pub)
                    .hint_text("64 hex chars X25519 public").desired_width(f32::INFINITY));
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
                    1 => "Low (5%)",
                    2 => "Balanced (10%)",
                    3 => "High (25%)",
                    4 => "Extreme (50%)",
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

            ui.add_space(8.0);
            ui.separator();
            ui.heading("Spectral camouflage");
            ui.label(RichText::new("Photo overlaid in low frequencies - looks like the photo, contains data").weak());
            ui.horizontal(|ui| {
                let label = if self.photo_bytes.is_some() { "Change photo" } else { "Add photo" };
                if ui.button(label).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("image", &["png", "jpg", "jpeg", "bmp", "webp"])
                        .pick_file()
                    {
                        if let Ok(b) = std::fs::read(&p) {
                            self.photo_bytes = Some(b);
                            self.photo_name = p.file_name()
                                .and_then(|n| n.to_str()).unwrap_or("photo").into();
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
                    egui::Button::new(RichText::new("ENCODE").strong())).clicked() {
                    self.encode();
                }
            });
            let can_decode = !self.input.is_empty() && !self.busy;
            ui.add_enabled_ui(can_decode, |ui| {
                if ui.add_sized([ui.available_width(), 38.0],
                    egui::Button::new("DECODE file")).clicked() {
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
                    egui::Button::new("Save...")).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_file_name(&name).save_file()
                    {
                        if std::fs::write(&p, &bytes).is_ok() {
                            self.push(format!("saved {}", p.display()));
                        }
                    }
                }
            }
        });
    }

    fn ui_center(&mut self, ui: &mut egui::Ui) {
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
                        "Page {}/{} ({} total, preview {})",
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
                }
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
                ui.label(RichText::new("Technologies:").strong());
                ui.label("- AeroPack v20 (BWT+MTF+RLE+DPCM3+BCJ)");
                ui.label("- AeroGlint Spectrum (2D OFDM over FFT)");
                ui.label("- Reed-Solomon RS(255,223) FEC + page-level resilience");
                ui.label("- AeroSeal v1 (XChaCha20+Argon2id+HMAC)");
                ui.label("- AeroSeal v2 (X25519 ephemeral)");
                ui.label("- Ed25519 signatures");
                ui.label("- Spectral camouflage (photo in low-freq)");
                ui.label("- Gamma pre-emphasis");
                ui.label("- Circle mask");
                ui.label("- Detection border + finder patterns");
                ui.add_space(8.0);
                if ui.button("Open GitHub repo").clicked() {
                    let _ = webbrowser::open("https://github.com/user123141/FM-Aero-Code");
                }
            }
        }
    }
}

fn decode_worker(bytes: Vec<u8>, pw: String, tx: Sender<Msg>) {
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
            let _ = tx.send(Msg::Log(format!(
                "Decoded: {} B, hash_ok={}, sig_ok={}, hmac_ok={}{}",
                r.payload.len(), r.hash_ok, r.signature_ok, r.hmac_ok,
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
        self.poll(ctx);
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("FM Aero Code 2");
                ui.label(RichText::new(format!("v{}", VERSION))
                    .color(Color32::from_rgb(120, 200, 255)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.busy { ui.add(egui::Spinner::new()); ui.label("Working..."); }
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
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Pattern, "Pattern");
                ui.selectable_value(&mut self.tab, Tab::Decoded, "Decoded");
                ui.selectable_value(&mut self.tab, Tab::Keys, "Keys");
                ui.selectable_value(&mut self.tab, Tab::About, "About");
            });
            ui.separator();
            self.ui_center(ui);
        });
    }
}