//! VoIP statistics: SIP stat, MGCP, MEGACO, RTP streams, voip calls.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};

macro_rules! voip_stub {
    ($name:ident, $tap_name:literal, $label:literal) => {
        pub struct $name { args: Vec<String> }
        impl $name { pub fn new(args: Vec<String>) -> Self { Self { args } } }
        impl Tap for $name {
            fn name(&self) -> &'static str { $tap_name }
            fn on_event(&self, _: &TapEvent) {}
        }
        impl StatsCommand for $name {
            fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
                writeln!(out, "{} ({} args)", $label, self.args.len())
            }
        }
    };
}

voip_stub!(SipStat,    "sip,stat",    "SIP statistics");
voip_stub!(MgcpStat,   "mgcp,stat",   "MGCP statistics");
voip_stub!(MegacoStat, "megaco,stat", "MEGACO statistics");
voip_stub!(RtpStreams, "rtp,streams", "RTP streams (jitter / loss / max delta)");
voip_stub!(VoipCalls,  "voip,calls",  "VoIP call list");
voip_stub!(SipCalls,   "calls,sip",   "SIP call list");
