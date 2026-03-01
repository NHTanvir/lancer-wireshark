//! Service Response Time (SRT) collectors for RPC / SMB / SMB2 / LDAP / NFS / ICMP.
//!
//! Each is a registered name so `-z smb,srt` etc. are recognised; per-call
//! timing collection is a follow-up.

use super::StatsCommand;
use epan::tap::{Tap, TapEvent};

macro_rules! srt_stub {
    ($struct_name:ident, $tap_name:literal, $label:literal) => {
        pub struct $struct_name {
            args: Vec<String>,
        }
        impl $struct_name {
            pub fn new(args: Vec<String>) -> Self {
                Self { args }
            }
        }
        impl Tap for $struct_name {
            fn name(&self) -> &'static str { $tap_name }
            fn on_event(&self, _: &TapEvent) {}
        }
        impl StatsCommand for $struct_name {
            fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
                writeln!(out, "{} SRT ({} args)", $label, self.args.len())
            }
        }
    };
}

srt_stub!(RpcSrtStat, "rpc,srt", "Sun RPC");
srt_stub!(RpcProgramsStat, "rpc,programs", "Sun RPC programs");
srt_stub!(SmbSrtStat, "smb,srt", "SMB");
srt_stub!(Smb2SrtStat, "smb2,srt", "SMB2");
srt_stub!(LdapSrtStat, "ldap,srt", "LDAP");
srt_stub!(NfsSrtStat, "nfs,srt", "NFS");
srt_stub!(IcmpSrtStat, "icmp,srt", "ICMP");
srt_stub!(Icmpv6SrtStat, "icmpv6,srt", "ICMPv6");
