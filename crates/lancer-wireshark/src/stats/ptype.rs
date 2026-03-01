//! `-z ptype,tree` — IP protocol distribution (TCP / UDP / ICMP / etc.).

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};
use parking_lot::Mutex;
use std::collections::HashMap;

pub struct PtypeStat { inner: Mutex<HashMap<u8, u64>> }
impl PtypeStat { pub fn new() -> Self { Self { inner: Mutex::new(HashMap::new()) } } }
impl Tap for PtypeStat {
    fn name(&self) -> &'static str { "ptype,tree" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Ip { proto, .. } = ev {
            *self.inner.lock().entry(*proto).or_insert(0) += 1;
        }
    }
}
impl StatsCommand for PtypeStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut v: Vec<_> = self.inner.lock().iter().map(|(k, v)| (*k, *v)).collect();
        v.sort();
        for (k, n) in v {
            let label = match k { 1 => "ICMP", 6 => "TCP", 17 => "UDP", 47 => "GRE", 50 => "ESP", 58 => "ICMPv6", _ => "Other" };
            writeln!(out, "{label:<8} ({k:>3}) {n}")?;
        }
        Ok(())
    }
}
