//! `lancer-wireshark-ui` — native egui frontend.
//!
//! Three-pane Lancer-standard layout:
//!   [ inputs | packet list | packet detail ]
//!
//! Run via `lancer_wireshark_ui::launch()`.

pub mod app;
pub mod theme;
pub mod widgets;
pub mod ipc;
pub mod dialogs;

use anyhow::Result;

pub fn launch() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_title("lancer-wireshark")
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "lancer-wireshark",
        options,
        Box::new(|cc| {
            theme::install(cc);
            Box::new(app::App::new(cc))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe: {e}"))?;
    Ok(())
}
