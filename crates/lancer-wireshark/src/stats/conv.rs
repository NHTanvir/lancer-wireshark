//! `-z conv,<type>` — conversation table (eth / ip / ipv6 / tcp / udp).

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;

pub struct ConvStat {
    kind: String,
    by_pair: Mutex<HashMap<(String, String), (u64, u64)>>, // (packets, bytes)
}

impl ConvStat {
    pub fn new(args: Vec<String>) -> Self {
        let kind = args.first().cloned().unwrap_or_else(|| "ip".into());
        Self { kind, by_pair: Mutex::new(HashMap::new()) }
    }
}

impl Tap for ConvStat {
    fn name(&self) -> &'static str { "conv" }
    fn on_event(&self, ev: &TapEvent) {
        match (self.kind.as_str(), ev) {
            ("ip", TapEvent::Ip { src, dst, len, .. }) => {
                let key = (ip_str(src), ip_str(dst));
                let mut g = self.by_pair.lock();
                let e = g.entry(key).or_insert((0, 0));
                e.0 += 1;
                e.1 += *len as u64;
            }
            ("tcp", TapEvent::Tcp { src_port, dst_port, len, .. }) => {
                let key = (src_port.to_string(), dst_port.to_string());
                let mut g = self.by_pair.lock();
                let e = g.entry(key).or_insert((0, 0));
                e.0 += 1;
                e.1 += *len as u64;
            }
            ("udp", TapEvent::Udp { src_port, dst_port, len }) => {
                let key = (src_port.to_string(), dst_port.to_string());
                let mut g = self.by_pair.lock();
                let e = g.entry(key).or_insert((0, 0));
                e.0 += 1;
                e.1 += *len as u64;
            }
            _ => {}
        }
    }
}

impl StatsCommand for ConvStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Conversations ({}):", self.kind)?;
        writeln!(out, "{:<40} {:<40} {:>10} {:>14}", "Side A", "Side B", "Packets", "Bytes")?;
        let mut rows: Vec<_> = self.by_pair.lock().iter().map(|(k, v)| (k.clone(), *v)).collect();
        rows.sort_by(|a, b| b.1.1.cmp(&a.1.1));
        for ((a, b), (p, by)) in rows {
            writeln!(out, "{:<40} {:<40} {:>10} {:>14}", a, b, p, by)?;
        }
        Ok(())
    }
}

fn ip_str(ip: &IpAddr) -> String {
    ip.to_string()
}
