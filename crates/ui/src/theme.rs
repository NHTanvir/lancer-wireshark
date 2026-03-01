//! Dark/light theming and persistent preferences.

use eframe::CreationContext;

pub fn install(cc: &CreationContext<'_>) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_rounding = 6.0.into();
    visuals.menu_rounding = 4.0.into();
    cc.egui_ctx.set_visuals(visuals);
}
