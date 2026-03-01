//! `-z ja3,tree` / `-z ja4,tree` — fingerprint distribution.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};
use parking_lot::Mutex;
use std::collections::HashMap;

pub struct Ja3Stat { inner: Mutex<HashMap<String, u64>> }
impl Ja3Stat { pub fn new() -> Self { Self { inner: Mutex::new(HashMap::new()) } } }
impl Tap for Ja3Stat {
    fn name(&self) -> &'static str { "ja3,tree" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Tls { ja3: Some(s), .. } = ev {
            *self.inner.lock().entry(s.clone()).or_insert(0) += 1;
        }
    }
}
impl StatsCommand for Ja3Stat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut v: Vec<_> = self.inner.lock().iter().map(|(k, v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        for (k, n) in v { writeln!(out, "{n:>6}  {k}")?; }
        Ok(())
    }
}

pub struct Ja4Stat { inner: Mutex<HashMap<String, u64>> }
impl Ja4Stat { pub fn new() -> Self { Self { inner: Mutex::new(HashMap::new()) } } }
impl Tap for Ja4Stat {
    fn name(&self) -> &'static str { "ja4,tree" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Tls { ja4: Some(s), .. } = ev {
            *self.inner.lock().entry(s.clone()).or_insert(0) += 1;
        }
    }
}
impl StatsCommand for Ja4Stat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut v: Vec<_> = self.inner.lock().iter().map(|(k, v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        for (k, n) in v { writeln!(out, "{n:>6}  {k}")?; }
        Ok(())
    }
}
