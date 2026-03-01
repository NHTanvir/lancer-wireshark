//! Telco / cellular statistics — LTE / 3GPP / GSM / ANSI.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};

macro_rules! telco_stub {
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

telco_stub!(MacLteStat,    "mac-lte,stat",    "MAC-LTE statistics");
telco_stub!(RlcLteStat,    "rlc-lte,stat",    "RLC-LTE statistics");
telco_stub!(PdcpLteStat,   "pdcp-lte,stat",   "PDCP-LTE statistics");
telco_stub!(Mac3gppStat,   "mac-3gpp,stat",   "MAC-3GPP statistics");
telco_stub!(Rlc3gppStat,   "rlc-3gpp,stat",   "RLC-3GPP statistics");
telco_stub!(F5TmmDistTree, "f5_tmm_dist,tree","F5 TMM distribution");
telco_stub!(AnsiABsmap,    "ansi_a,bsmap",    "ANSI-A BSMAP");
telco_stub!(AnsiADtap,     "ansi_a,dtap",     "ANSI-A DTAP");
telco_stub!(AnsiMap,       "ansi_map",        "ANSI-MAP");
telco_stub!(GsmABssmap,    "gsm_a,bssmap",    "GSM-A BSSMAP");
