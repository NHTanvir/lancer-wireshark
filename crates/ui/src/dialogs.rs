//! Dialog windows: Conversations, IO Graph, Follow Stream.

use egui::{Context, Window};
use egui_plot::{Bar, BarChart, Plot};

#[derive(Default)]
pub struct ConversationsDialog {
    pub open: bool,
    pub rows: Vec<ConvRow>,
}

#[derive(Debug, Clone)]
pub struct ConvRow {
    pub a: String,
    pub b: String,
    pub packets: u64,
    pub bytes: u64,
}

impl ConversationsDialog {
    pub fn show(&mut self, ctx: &Context) {
        if !self.open {
            return;
        }
        let mut open = self.open;
        Window::new("Conversations").open(&mut open).default_size([700.0, 400.0]).show(ctx, |ui| {
            egui_extras::TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .column(egui_extras::Column::auto())
                .column(egui_extras::Column::auto())
                .column(egui_extras::Column::auto())
                .column(egui_extras::Column::remainder())
                .header(20.0, |mut h| {
                    h.col(|ui| { ui.strong("Side A"); });
                    h.col(|ui| { ui.strong("Side B"); });
                    h.col(|ui| { ui.strong("Packets"); });
                    h.col(|ui| { ui.strong("Bytes"); });
                })
                .body(|mut body| {
                    for row in &self.rows {
                        body.row(20.0, |mut r| {
                            r.col(|ui| { ui.label(&row.a); });
                            r.col(|ui| { ui.label(&row.b); });
                            r.col(|ui| { ui.label(format!("{}", row.packets)); });
                            r.col(|ui| { ui.label(format!("{}", row.bytes)); });
                        });
                    }
                });
        });
        self.open = open;
    }
}

#[derive(Default)]
pub struct IoGraphDialog {
    pub open: bool,
    pub buckets: Vec<(f64, u64)>,
    pub interval_label: String,
}

impl IoGraphDialog {
    pub fn show(&mut self, ctx: &Context) {
        if !self.open {
            return;
        }
        let mut open = self.open;
        let title = if self.interval_label.is_empty() { "IO Graph".to_string() } else { format!("IO Graph ({})", self.interval_label) };
        Window::new(title).open(&mut open).default_size([720.0, 360.0]).show(ctx, |ui| {
            let bars: Vec<Bar> = self
                .buckets
                .iter()
                .map(|(t, n)| Bar::new(*t, *n as f64))
                .collect();
            let chart = BarChart::new(bars).color(egui::Color32::from_rgb(80, 160, 255));
            Plot::new("iograph").show(ui, |plot_ui| {
                plot_ui.bar_chart(chart);
            });
        });
        self.open = open;
    }
}

#[derive(Default)]
pub struct FollowStreamDialog {
    pub open: bool,
    pub title: String,
    pub body: String,
}

impl FollowStreamDialog {
    pub fn show(&mut self, ctx: &Context) {
        if !self.open {
            return;
        }
        let mut open = self.open;
        Window::new(format!("Follow Stream — {}", self.title))
            .open(&mut open)
            .default_size([800.0, 500.0])
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.body.as_str())
                            .desired_rows(20)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    );
                });
            });
        self.open = open;
    }
}
