//! `-z http,tree` / `-z http_req,tree` / `-z http_srv,tree` / `-z http_stat`.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};
use parking_lot::Mutex;
use std::collections::HashMap;

pub struct HttpStat {
    methods: Mutex<HashMap<String, u64>>,
    statuses: Mutex<HashMap<u16, u64>>,
}
impl HttpStat {
    pub fn new(_args: Vec<String>) -> Self {
        Self { methods: Mutex::new(HashMap::new()), statuses: Mutex::new(HashMap::new()) }
    }
}
impl Tap for HttpStat {
    fn name(&self) -> &'static str { "http,tree" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Http { method, status, .. } = ev {
            if let Some(m) = method { *self.methods.lock().entry(m.clone()).or_insert(0) += 1; }
            if let Some(s) = status { *self.statuses.lock().entry(*s).or_insert(0) += 1; }
        }
    }
}
impl StatsCommand for HttpStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "HTTP requests by method:")?;
        let mut m: Vec<_> = self.methods.lock().iter().map(|(k, v)| (k.clone(), *v)).collect();
        m.sort_by(|a, b| b.1.cmp(&a.1));
        for (k, v) in m { writeln!(out, "  {k:<10} {v}")?; }
        writeln!(out, "HTTP responses by status:")?;
        let mut s: Vec<_> = self.statuses.lock().iter().map(|(k, v)| (*k, *v)).collect();
        s.sort();
        for (k, v) in s { writeln!(out, "  {k:<6} {v}")?; }
        Ok(())
    }
}

pub struct HttpReqStat { paths: Mutex<HashMap<String, u64>> }
impl HttpReqStat { pub fn new() -> Self { Self { paths: Mutex::new(HashMap::new()) } } }
impl Tap for HttpReqStat {
    fn name(&self) -> &'static str { "http_req,tree" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Http { host, path, .. } = ev {
            let key = format!("{}{}", host.clone().unwrap_or_default(), path.clone().unwrap_or_default());
            *self.paths.lock().entry(key).or_insert(0) += 1;
        }
    }
}
impl StatsCommand for HttpReqStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut v: Vec<_> = self.paths.lock().iter().map(|(k, v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        for (k, n) in v { writeln!(out, "{n:>6}  {k}")?; }
        Ok(())
    }
}

pub struct HttpSrvStat { hosts: Mutex<HashMap<String, u64>> }
impl HttpSrvStat { pub fn new() -> Self { Self { hosts: Mutex::new(HashMap::new()) } } }
impl Tap for HttpSrvStat {
    fn name(&self) -> &'static str { "http_srv,tree" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Http { host: Some(h), .. } = ev {
            *self.hosts.lock().entry(h.clone()).or_insert(0) += 1;
        }
    }
}
impl StatsCommand for HttpSrvStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut v: Vec<_> = self.hosts.lock().iter().map(|(k, v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        for (k, n) in v { writeln!(out, "{n:>6}  {k}")?; }
        Ok(())
    }
}

pub struct HttpStatusStat { by_status: Mutex<HashMap<u16, u64>> }
impl HttpStatusStat { pub fn new() -> Self { Self { by_status: Mutex::new(HashMap::new()) } } }
impl Tap for HttpStatusStat {
    fn name(&self) -> &'static str { "http_stat" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Http { status: Some(s), .. } = ev {
            *self.by_status.lock().entry(*s).or_insert(0) += 1;
        }
    }
}
impl StatsCommand for HttpStatusStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut v: Vec<_> = self.by_status.lock().iter().map(|(k, v)| (*k, *v)).collect();
        v.sort();
        for (k, n) in v { writeln!(out, "{k}  {n}")?; }
        Ok(())
    }
}
