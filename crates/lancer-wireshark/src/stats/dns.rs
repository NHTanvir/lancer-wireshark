//! `-z dns,tree` — DNS query distribution.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};
use parking_lot::Mutex;
use std::collections::HashMap;

pub struct DnsStat { queries: Mutex<HashMap<String, u64>>, responses: Mutex<HashMap<u8, u64>> }

impl DnsStat {
    pub fn new(_args: Vec<String>) -> Self {
        Self { queries: Mutex::new(HashMap::new()), responses: Mutex::new(HashMap::new()) }
    }
}

impl Tap for DnsStat {
    fn name(&self) -> &'static str { "dns,tree" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Dns { query, response_code, .. } = ev {
            if let Some(q) = query {
                *self.queries.lock().entry(q.clone()).or_insert(0) += 1;
            }
            if let Some(rc) = response_code {
                *self.responses.lock().entry(*rc).or_insert(0) += 1;
            }
        }
    }
}

impl StatsCommand for DnsStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "DNS queries:")?;
        let mut q: Vec<_> = self.queries.lock().iter().map(|(k, v)| (k.clone(), *v)).collect();
        q.sort_by(|a, b| b.1.cmp(&a.1));
        for (k, v) in q.into_iter().take(50) {
            writeln!(out, "  {v:>6}  {k}")?;
        }
        writeln!(out, "DNS response codes:")?;
        let mut r: Vec<_> = self.responses.lock().iter().map(|(k, v)| (*k, *v)).collect();
        r.sort();
        for (k, v) in r { writeln!(out, "  rcode={k:<3} {v}")?; }
        Ok(())
    }
}
