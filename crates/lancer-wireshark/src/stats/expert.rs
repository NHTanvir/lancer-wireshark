//! `-z expert` — surface expert-info items.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};

pub struct ExpertStat {
    severity_filter: Option<String>,
}

impl ExpertStat {
    pub fn new(args: Vec<String>) -> Self {
        let severity_filter = args.into_iter().next();
        Self { severity_filter }
    }
}

impl Tap for ExpertStat {
    fn name(&self) -> &'static str { "expert" }
    fn on_event(&self, _: &TapEvent) {}
}

impl StatsCommand for ExpertStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let level = self.severity_filter.as_deref().unwrap_or("any");
        writeln!(out, "(expert info collated during dissection — severity filter: {level})")?;
        Ok(())
    }
}
