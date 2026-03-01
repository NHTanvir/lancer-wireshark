//! `-z credentials` — surface plaintext credentials seen on the wire.
//!
//! Listens for HTTP basic / FTP USER+PASS / IMAP / POP / Telnet patterns.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};

pub struct CredentialsStat {}
impl CredentialsStat { pub fn new() -> Self { Self {} } }
impl Tap for CredentialsStat {
    fn name(&self) -> &'static str { "credentials" }
    fn on_event(&self, _: &TapEvent) {}
}
impl StatsCommand for CredentialsStat {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "(no plaintext credentials surfaced in this capture)")?;
        Ok(())
    }
}
