//! Misc `-z` commands: bootp/dhcp stat, hpfeeds, gquic, wlan, dests, flow,
//! http2 frame tree, quic handshake, stat,tree, conv/endpoints,dnp3.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};

macro_rules! misc_stub {
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

misc_stub!(BootpStat,      "bootp,stat",       "BOOTP/DHCP statistics");
misc_stub!(DhcpStat,       "dhcp,stat",        "DHCP message-type statistics");
misc_stub!(HpfeedsTree,    "hpfeeds,tree",     "HPFEEDS tree");
misc_stub!(GquicTree,      "gquic,tree",       "GQUIC fallback statistics");
misc_stub!(WlanStat,       "wlan,stat",        "802.11 stations");
misc_stub!(DestsTree,      "dests,tree",       "Destinations tree");
misc_stub!(FlowFilter,     "flow",             "Flow graph");
misc_stub!(Http2Tree,      "http2,tree",       "HTTP/2 frame/stream counts");
misc_stub!(QuicHandshake,  "quic,handshake",   "QUIC handshake statistics");
misc_stub!(StatTree,       "stat,tree",        "Generic stat tree builder");
misc_stub!(ConvDnp3,       "conv,dnp3",        "DNP3 conversations");
misc_stub!(EndpointsDnp3,  "endpoints,dnp3",   "DNP3 endpoints");
misc_stub!(HttpSeq,        "http_seq",         "HTTP request sequence");
