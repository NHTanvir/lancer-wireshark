//! Reusable widgets — packet list virtual scroller, hex view, tree node renderer.

use egui::{Color32, RichText, Ui};
use epan::proto::ProtoItem;

pub fn render_hex(ui: &mut Ui, bytes: &[u8]) {
    let text = wsutil::format_hexdump(bytes);
    ui.add(
        egui::TextEdit::multiline(&mut text.as_str())
            .desired_rows(8)
            .font(egui::TextStyle::Monospace)
            .lock_focus(false)
            .desired_width(f32::INFINITY),
    );
}

pub fn render_tree(ui: &mut Ui, item: &ProtoItem, reg: &epan::Registry, depth: usize) {
    let label = item.label.clone().unwrap_or_else(|| {
        reg.field(item.field)
            .map(|f| f.display_name.to_string())
            .unwrap_or_default()
    });
    let display = if matches!(item.value, epan::proto::FieldValue::None) {
        label.clone()
    } else {
        let d = reg.field(item.field).map(|f| f.display).unwrap_or(epan::proto::FieldDisplay::BaseNone);
        let vals = reg.field(item.field).and_then(|f| f.vals);
        format!("{label}: {}", item.value.display(d, vals))
    };
    if item.children.is_empty() {
        ui.label(RichText::new(display).color(Color32::from_rgb(220, 220, 220)));
    } else {
        let id = ui.make_persistent_id((depth, item.abs_offset, &label));
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, depth < 2)
            .show_header(ui, |ui| {
                ui.label(RichText::new(display).strong());
            })
            .body(|ui| {
                for c in &item.children {
                    render_tree(ui, c, reg, depth + 1);
                }
            });
    }
}
