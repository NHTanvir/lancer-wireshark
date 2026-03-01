//! `-z io,stat,<interval>` — packets / bytes per time bucket.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};
use parking_lot::Mutex;

pub struct IoStat {
    interval_secs: f64,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    buckets: Vec<(f64, u64, u64)>, // (bucket_start_secs, packets, bytes)
}

impl IoStat {
    pub fn new(args: Vec<String>) -> Self {
        let interval = args
            .first()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(1.0);
        Self {
            interval_secs: interval,
            inner: Mutex::new(Inner::default()),
        }
    }
}

impl Tap for IoStat {
    fn name(&self) -> &'static str { "io,stat" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Frame { ts_secs, ts_nanos, captured_len, .. } = ev {
            let t = *ts_secs as f64 + *ts_nanos as f64 / 1_000_000_000.0;
            let bucket = (t / self.interval_secs).floor() * self.interval_secs;
            let mut g = self.inner.lock();
            if g.buckets.last().map(|(b, _, _)| *b) != Some(bucket) {
                g.buckets.push((bucket, 0, 0));
            }
            let last = g.buckets.last_mut().unwrap();
            last.1 += 1;
            last.2 += *captured_len as u64;
        }
    }
}

impl StatsCommand for IoStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "===================================================================")?;
        writeln!(out, "| IO Statistics ({}s buckets)                                     |", self.interval_secs)?;
        writeln!(out, "|----------------------------------------------------------------|")?;
        writeln!(out, "| {:>16} | {:>10} | {:>14} |", "Bucket (s)", "Packets", "Bytes")?;
        for (b, p, by) in &self.inner.lock().buckets {
            writeln!(out, "| {:>16.3} | {:>10} | {:>14} |", b, p, by)?;
        }
        writeln!(out, "===================================================================")?;
        Ok(())
    }
}
