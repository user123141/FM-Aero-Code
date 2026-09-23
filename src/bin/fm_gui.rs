#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use eframe::egui;
use fm_aero_code_2::app::FmAeroApp;
use fm_aero_code_2::icon::load_icon;

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("FM Aero Code 2")
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([1000.0, 700.0])
            .with_icon(load_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "FM Aero Code 2",
        opts,
        Box::new(|cc| Ok(Box::new(FmAeroApp::new(cc)))),
    )
}