//! `-z hosts` — IP/host list.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};
use parking_lot::Mutex;
use std::collections::HashSet;

pub struct HostsStat {
    inner: Mutex<HashSet<String>>,
}

impl HostsStat {
    pub fn new(_args: Vec<String>) -> Self {
        Self { inner: Mutex::new(HashSet::new()) }
    }
}

impl Tap for HostsStat {
    fn name(&self) -> &'static str { "hosts" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Ip { src, dst, .. } = ev {
            let mut g = self.inner.lock();
            g.insert(src.to_string());
            g.insert(dst.to_string());
        }
    }
}

impl StatsCommand for HostsStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut hosts: Vec<_> = self.inner.lock().iter().cloned().collect();
        hosts.sort();
        for h in hosts {
            writeln!(out, "{h}")?;
        }
        Ok(())
    }
}
