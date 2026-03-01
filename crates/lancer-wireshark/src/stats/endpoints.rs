//! `-z endpoints,<type>` — per-endpoint packet/byte counts.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};
use parking_lot::Mutex;
use std::collections::HashMap;

pub struct EndpointsStat {
    kind: String,
    by_endpoint: Mutex<HashMap<String, (u64, u64)>>,
}

impl EndpointsStat {
    pub fn new(args: Vec<String>) -> Self {
        let kind = args.first().cloned().unwrap_or_else(|| "ip".into());
        Self { kind, by_endpoint: Mutex::new(HashMap::new()) }
    }
}

impl Tap for EndpointsStat {
    fn name(&self) -> &'static str { "endpoints" }
    fn on_event(&self, ev: &TapEvent) {
        match (self.kind.as_str(), ev) {
            ("ip", TapEvent::Ip { src, dst, len, .. }) => {
                let mut g = self.by_endpoint.lock();
                let e = g.entry(src.to_string()).or_insert((0, 0));
                e.0 += 1;
                e.1 += *len as u64;
                let e = g.entry(dst.to_string()).or_insert((0, 0));
                e.0 += 1;
                e.1 += *len as u64;
            }
            _ => {}
        }
    }
}

impl StatsCommand for EndpointsStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Endpoints ({}):", self.kind)?;
        writeln!(out, "{:<40} {:>10} {:>14}", "Endpoint", "Packets", "Bytes")?;
        let mut rows: Vec<_> = self.by_endpoint.lock().iter().map(|(k, v)| (k.clone(), *v)).collect();
        rows.sort_by(|a, b| b.1.1.cmp(&a.1.1));
        for (ep, (p, by)) in rows {
            writeln!(out, "{:<40} {:>10} {:>14}", ep, p, by)?;
        }
        Ok(())
    }
}
