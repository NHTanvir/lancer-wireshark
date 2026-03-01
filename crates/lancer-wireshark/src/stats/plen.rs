//! `-z plen,tree` — packet length histogram.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};
use parking_lot::Mutex;

pub struct PlenStat { buckets: Mutex<[u64; 11]> }
impl PlenStat { pub fn new() -> Self { Self { buckets: Mutex::new([0; 11]) } } }
impl Tap for PlenStat {
    fn name(&self) -> &'static str { "plen,tree" }
    fn on_event(&self, ev: &TapEvent) {
        if let TapEvent::Frame { original_len, .. } = ev {
            let bucket = match original_len {
                0..=19 => 0, 20..=39 => 1, 40..=79 => 2, 80..=159 => 3, 160..=319 => 4,
                320..=639 => 5, 640..=1279 => 6, 1280..=2559 => 7, 2560..=5119 => 8,
                5120..=10239 => 9, _ => 10,
            };
            self.buckets.lock()[bucket] += 1;
        }
    }
}
impl StatsCommand for PlenStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let labels = ["0-19","20-39","40-79","80-159","160-319","320-639","640-1279","1280-2559","2560-5119","5120-10239","10240+"];
        for (i, b) in self.buckets.lock().iter().enumerate() {
            writeln!(out, "{:>10}: {b}", labels[i])?;
        }
        Ok(())
    }
}
