//! `-z follow,<proto>,<mode>,<filter>` plumbing — actual reconstruction
//! is delegated to [`epan::follow::FollowStream`].

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};

pub struct FollowStat { args: Vec<String> }
impl FollowStat { pub fn new(args: Vec<String>) -> Self { Self { args } } }
impl Tap for FollowStat {
    fn name(&self) -> &'static str { "follow" }
    fn on_event(&self, _: &TapEvent) {}
}
impl StatsCommand for FollowStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "follow,{}", self.args.join(","))?;
        Ok(())
    }
}
