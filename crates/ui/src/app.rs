//! Main `App` struct holding capture state and rendering the three-pane layout.

use eframe::{App as EApp, CreationContext, Frame};
use egui::{CentralPanel, Context, ScrollArea, SidePanel, TopBottomPanel};
use epan::{Engine, PInfo, ProtoTree};
use std::sync::{Arc, Mutex};

pub struct App {
    engine: Arc<Engine>,
    packets: Arc<Mutex<Vec<PacketRecord>>>,
    selected: Option<usize>,
    filter_text: String,
    open_path: Option<String>,
    status: String,
    cross_tool: Option<crate::ipc::CrossToolServer>,
    conv_dialog: crate::dialogs::ConversationsDialog,
    iograph_dialog: crate::dialogs::IoGraphDialog,
    follow_dialog: crate::dialogs::FollowStreamDialog,
}

pub struct PacketRecord {
    pub pinfo: PInfo,
    pub tree: ProtoTree,
    pub bytes: Vec<u8>,
}

impl App {
    pub fn new(_cc: &CreationContext<'_>) -> Self {
        let engine = Arc::new(Engine::new());
        let cross_tool = crate::ipc::CrossToolServer::start().ok();
        Self {
            engine,
            packets: Arc::new(Mutex::new(Vec::new())),
            selected: None,
            filter_text: String::new(),
            open_path: None,
            status: "Ready.".into(),
            cross_tool,
            conv_dialog: Default::default(),
            iograph_dialog: Default::default(),
            follow_dialog: Default::default(),
        }
    }

    fn load_file(&mut self, path: String) {
        let engine = self.engine.clone();
        let store = self.packets.clone();
        self.open_path = Some(path.clone());
        self.status = format!("Loading {path}…");
        std::thread::spawn(move || {
            let mut packets = Vec::new();
            if let Ok(mut src) = lancer_wireshark_capture::open_offline(&path) {
                while let Ok(Some(frame)) = src.next() {
                    let mut pinfo = PInfo::new(frame.number, (frame.ts_secs, frame.ts_nanos), frame.captured_len, frame.original_len);
                    pinfo.interface_id = frame.interface_id;
                    pinfo.link_type = frame.link_type;
                    let mut tree = ProtoTree::new();
                    let tvb = epan::Tvb::new(&frame.data);
                    if let Some(d) = engine.registry.dissector("frame") { d.dissect(&tvb, &mut pinfo, &mut tree); }
                    if let Some(d) = engine.registry.dissector("eth") { d.dissect(&tvb, &mut pinfo, &mut tree); }
                    packets.push(PacketRecord {
                        pinfo,
                        tree,
                        bytes: frame.data,
                    });
                }
            }
            if let Ok(mut g) = store.lock() {
                *g = packets;
            }
        });
    }
}

// `lancer_wireshark_capture` is a direct workspace dependency — no stub needed.

impl App {
    fn populate_conversations(&mut self) {
        let mut rows = std::collections::HashMap::<(String, String), (u64, u64)>::new();
        if let Ok(g) = self.packets.lock() {
            for p in g.iter() {
                let a = p.pinfo.src_addr.map(|a| a.to_string()).unwrap_or_default();
                let b = p.pinfo.dst_addr.map(|a| a.to_string()).unwrap_or_default();
                if a.is_empty() || b.is_empty() { continue; }
                let (k1, k2) = if a < b { (a.clone(), b.clone()) } else { (b.clone(), a.clone()) };
                let e = rows.entry((k1, k2)).or_insert((0, 0));
                e.0 += 1;
                e.1 += p.pinfo.original_len as u64;
            }
        }
        self.conv_dialog.rows = rows
            .into_iter()
            .map(|((a, b), (n, by))| crate::dialogs::ConvRow { a, b, packets: n, bytes: by })
            .collect();
        self.conv_dialog.rows.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    }

    fn populate_iograph(&mut self) {
        let mut buckets = std::collections::BTreeMap::<i64, u64>::new();
        if let Ok(g) = self.packets.lock() {
            for p in g.iter() {
                *buckets.entry(p.pinfo.timestamp_secs).or_insert(0) += 1;
            }
        }
        self.iograph_dialog.buckets = buckets.into_iter().map(|(t, n)| (t as f64, n)).collect();
        self.iograph_dialog.interval_label = "1s".into();
    }

    fn populate_follow(&mut self) {
        let mut body = String::new();
        if let Ok(g) = self.packets.lock() {
            if let Some(idx) = self.selected {
                if let Some(p) = g.get(idx) {
                    body.push_str(&wsutil::format_hexdump(&p.bytes));
                    self.follow_dialog.title = format!("packet {}", p.pinfo.frame_number);
                }
            }
        }
        self.follow_dialog.body = body;
    }
}

impl EApp for App {
    fn update(&mut self, ctx: &Context, _: &mut Frame) {
        TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("Capture files", &["pcap", "pcapng", "pcap.gz", "pcapng.gz", "pcap.zst"])
                            .pick_file()
                        {
                            self.load_file(p.display().to_string());
                        }
                        ui.close_menu();
                    }
                    if ui.button("Quit").clicked() {
                        std::process::exit(0);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("Conversations…").clicked() {
                        self.populate_conversations();
                        self.conv_dialog.open = true;
                        ui.close_menu();
                    }
                    if ui.button("IO Graph…").clicked() {
                        self.populate_iograph();
                        self.iograph_dialog.open = true;
                        ui.close_menu();
                    }
                    if ui.button("Follow Stream…").clicked() {
                        self.populate_follow();
                        self.follow_dialog.open = true;
                        ui.close_menu();
                    }
                });
                ui.menu_button("Settings", |ui| {
                    if ui.button("Toggle theme").clicked() {
                        let v = if ctx.style().visuals.dark_mode { egui::Visuals::light() } else { egui::Visuals::dark() };
                        ctx.set_visuals(v);
                        ui.close_menu();
                    }
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.status = "lancer-wireshark — Rust clone of wireshark".into();
                        ui.close_menu();
                    }
                });
                ui.separator();
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.filter_text);
            });
        });

        SidePanel::left("inputs").resizable(true).default_width(220.0).show(ctx, |ui| {
            ui.heading("Capture");
            ui.label("Files / interfaces");
            ui.separator();
            if ui.button("List interfaces").clicked() {
                self.status = "Listing interfaces (see CLI: --cli -D)".into();
            }
            if let Some(p) = &self.open_path {
                ui.label(format!("Open: {p}"));
            }
            ui.separator();
            ui.label(format!("Packets: {}", self.packets.lock().map(|g| g.len()).unwrap_or(0)));
            if let Some(s) = &self.cross_tool {
                ui.label(format!("Cross-tool port: {}", s.port));
            }
        });

        SidePanel::right("detail").resizable(true).default_width(420.0).show(ctx, |ui| {
            ui.heading("Packet detail");
            ScrollArea::vertical().show(ui, |ui| {
                if let Some(idx) = self.selected {
                    if let Ok(g) = self.packets.lock() {
                        if let Some(p) = g.get(idx) {
                            for item in &p.tree.items {
                                crate::widgets::render_tree(ui, item, &self.engine.registry, 0);
                            }
                            ui.separator();
                            ui.heading("Bytes");
                            crate::widgets::render_hex(ui, &p.bytes);
                        }
                    }
                } else {
                    ui.label("Select a packet on the left.");
                }
            });
        });

        CentralPanel::default().show(ctx, |ui| {
            ScrollArea::both().show(ui, |ui| {
                egui_extras::TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .column(egui_extras::Column::auto())
                    .column(egui_extras::Column::auto())
                    .column(egui_extras::Column::auto())
                    .column(egui_extras::Column::auto())
                    .column(egui_extras::Column::auto())
                    .column(egui_extras::Column::remainder())
                    .header(22.0, |mut h| {
                        h.col(|ui| { ui.strong("No."); });
                        h.col(|ui| { ui.strong("Time"); });
                        h.col(|ui| { ui.strong("Source"); });
                        h.col(|ui| { ui.strong("Destination"); });
                        h.col(|ui| { ui.strong("Length"); });
                        h.col(|ui| { ui.strong("Info"); });
                    })
                    .body(|mut body| {
                        if let Ok(g) = self.packets.lock() {
                            for (i, p) in g.iter().enumerate() {
                                body.row(20.0, |mut row| {
                                    row.col(|ui| { if ui.label(format!("{}", p.pinfo.frame_number)).clicked() { self.selected = Some(i); } });
                                    row.col(|ui| { ui.label(format!("{}.{:09}", p.pinfo.timestamp_secs, p.pinfo.timestamp_nanos)); });
                                    row.col(|ui| { ui.label(p.pinfo.src_addr.map(|a| a.to_string()).unwrap_or_else(|| "-".into())); });
                                    row.col(|ui| { ui.label(p.pinfo.dst_addr.map(|a| a.to_string()).unwrap_or_else(|| "-".into())); });
                                    row.col(|ui| { ui.label(format!("{}", p.pinfo.captured_len)); });
                                    row.col(|ui| { ui.label(p.pinfo.info.clone()); });
                                });
                            }
                        }
                    });
            });
        });

        TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                ui.separator();
                ui.label(format!("Packets: {}", self.packets.lock().map(|g| g.len()).unwrap_or(0)));
            });
        });

        self.conv_dialog.show(ctx);
        self.iograph_dialog.show(ctx);
        self.follow_dialog.show(ctx);
    }
}
