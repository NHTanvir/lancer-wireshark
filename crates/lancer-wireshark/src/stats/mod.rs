//! `-z` statistics framework. Each command subscribes to the engine's tap
//! bus and accumulates state; the `finalize` call prints results.

pub mod io_stat;
pub mod conv;
pub mod endpoints;
pub mod hosts;
pub mod http;
pub mod dns;
pub mod expert;
pub mod follow;
pub mod credentials;
pub mod ja3;
pub mod plen;
pub mod ptype;
pub mod srt;
pub mod voip;
pub mod telco;
pub mod misc;

use anyhow::Result;
use epan::tap::{Tap, TapBus};
use std::sync::Arc;

pub trait StatsCommand: Tap {
    fn finalize(&self, out: &mut dyn std::io::Write) -> std::io::Result<()>;
}

#[derive(Debug, Clone)]
pub struct StatsSpec {
    pub kind: String,
    pub args: Vec<String>,
}

impl StatsSpec {
    pub fn parse(s: &str) -> Self {
        let mut it = s.split(',');
        let kind = it.next().unwrap_or("").to_string();
        let args = it.map(|s| s.to_string()).collect();
        StatsSpec { kind, args }
    }
}

pub fn build(spec: &StatsSpec, bus: &TapBus) -> Result<Arc<dyn StatsCommand>> {
    // Use kind+first arg disambiguation for commands like `smb,srt`,
    // `http2,tree`, `rtp,streams`. We dispatch on a synthetic "kind:sub" form.
    let key = if let Some(sub) = spec.args.first() {
        format!("{}:{}", spec.kind, sub)
    } else {
        spec.kind.clone()
    };

    let cmd: Arc<dyn StatsCommand> = match key.as_str() {
        // Single-word kinds
        k if spec.kind == "io" || k == "io" => Arc::new(io_stat::IoStat::new(spec.args.clone())),
        k if spec.kind == "conv" && spec.args.first().map(|s| s.as_str()) == Some("dnp3") => Arc::new(misc::ConvDnp3::new(spec.args.clone())),
        k if spec.kind == "endpoints" && spec.args.first().map(|s| s.as_str()) == Some("dnp3") => Arc::new(misc::EndpointsDnp3::new(spec.args.clone())),
        k if spec.kind == "conv" || k == "conv" => Arc::new(conv::ConvStat::new(spec.args.clone())),
        k if spec.kind == "endpoints" || k == "endpoints" => Arc::new(endpoints::EndpointsStat::new(spec.args.clone())),
        k if spec.kind == "hosts" || k == "hosts" => Arc::new(hosts::HostsStat::new(spec.args.clone())),
        "http_req" | "http_req:tree" => Arc::new(http::HttpReqStat::new()),
        "http_srv" | "http_srv:tree" => Arc::new(http::HttpSrvStat::new()),
        "http_stat" => Arc::new(http::HttpStatusStat::new()),
        "http_seq" => Arc::new(misc::HttpSeq::new(spec.args.clone())),
        "http:tree" => Arc::new(http::HttpStat::new(spec.args.clone())),
        "http2:tree" => Arc::new(misc::Http2Tree::new(spec.args.clone())),
        "dns" | "dns:tree" => Arc::new(dns::DnsStat::new(spec.args.clone())),
        "expert" | "expert:warn" | "expert:error" | "expert:note" | "expert:chat" => {
            Arc::new(expert::ExpertStat::new(spec.args.clone()))
        }
        "follow" | _ if spec.kind == "follow" => Arc::new(follow::FollowStat::new(spec.args.clone())),
        "credentials" => Arc::new(credentials::CredentialsStat::new()),
        "ja3" | "ja3:tree" => Arc::new(ja3::Ja3Stat::new()),
        "ja4" | "ja4:tree" => Arc::new(ja3::Ja4Stat::new()),
        "plen" | "plen:tree" => Arc::new(plen::PlenStat::new()),
        "ptype" | "ptype:tree" => Arc::new(ptype::PtypeStat::new()),
        // SRT family
        "rpc:srt" => Arc::new(srt::RpcSrtStat::new(spec.args.clone())),
        "rpc:programs" => Arc::new(srt::RpcProgramsStat::new(spec.args.clone())),
        "smb:srt" => Arc::new(srt::SmbSrtStat::new(spec.args.clone())),
        "smb2:srt" => Arc::new(srt::Smb2SrtStat::new(spec.args.clone())),
        "ldap:srt" => Arc::new(srt::LdapSrtStat::new(spec.args.clone())),
        "nfs:srt" => Arc::new(srt::NfsSrtStat::new(spec.args.clone())),
        "icmp:srt" => Arc::new(srt::IcmpSrtStat::new(spec.args.clone())),
        "icmpv6:srt" => Arc::new(srt::Icmpv6SrtStat::new(spec.args.clone())),
        // VoIP
        "sip:stat" => Arc::new(voip::SipStat::new(spec.args.clone())),
        "mgcp:stat" => Arc::new(voip::MgcpStat::new(spec.args.clone())),
        "megaco:stat" => Arc::new(voip::MegacoStat::new(spec.args.clone())),
        "rtp:streams" => Arc::new(voip::RtpStreams::new(spec.args.clone())),
        "voip:calls" => Arc::new(voip::VoipCalls::new(spec.args.clone())),
        "calls:sip" => Arc::new(voip::SipCalls::new(spec.args.clone())),
        // Telco / cellular
        "mac-lte:stat" => Arc::new(telco::MacLteStat::new(spec.args.clone())),
        "rlc-lte:stat" => Arc::new(telco::RlcLteStat::new(spec.args.clone())),
        "pdcp-lte:stat" => Arc::new(telco::PdcpLteStat::new(spec.args.clone())),
        "mac-3gpp:stat" => Arc::new(telco::Mac3gppStat::new(spec.args.clone())),
        "rlc-3gpp:stat" => Arc::new(telco::Rlc3gppStat::new(spec.args.clone())),
        "f5_tmm_dist:tree" => Arc::new(telco::F5TmmDistTree::new(spec.args.clone())),
        "ansi_a:bsmap" => Arc::new(telco::AnsiABsmap::new(spec.args.clone())),
        "ansi_a:dtap" => Arc::new(telco::AnsiADtap::new(spec.args.clone())),
        "ansi_map" => Arc::new(telco::AnsiMap::new(spec.args.clone())),
        "gsm_a:bssmap" => Arc::new(telco::GsmABssmap::new(spec.args.clone())),
        // Misc
        "bootp:stat" => Arc::new(misc::BootpStat::new(spec.args.clone())),
        "dhcp:stat" => Arc::new(misc::DhcpStat::new(spec.args.clone())),
        "hpfeeds:tree" => Arc::new(misc::HpfeedsTree::new(spec.args.clone())),
        "gquic:tree" => Arc::new(misc::GquicTree::new(spec.args.clone())),
        "wlan:stat" => Arc::new(misc::WlanStat::new(spec.args.clone())),
        "dests:tree" => Arc::new(misc::DestsTree::new(spec.args.clone())),
        "flow" => Arc::new(misc::FlowFilter::new(spec.args.clone())),
        "quic:handshake" => Arc::new(misc::QuicHandshake::new(spec.args.clone())),
        "stat:tree" => Arc::new(misc::StatTree::new(spec.args.clone())),
        // Plain `http` with no sub falls back to http,tree default
        k if spec.kind == "http" => Arc::new(http::HttpStat::new(spec.args.clone())),
        other => anyhow::bail!("unsupported -z command: {other}"),
    };
    bus.subscribe(arc_to_dyn(cmd.clone()));
    Ok(cmd)
}

fn arc_to_dyn(c: Arc<dyn StatsCommand>) -> Arc<dyn Tap> {
    struct Adapter(Arc<dyn StatsCommand>);
    impl Tap for Adapter {
        fn name(&self) -> &'static str { self.0.name() }
        fn on_event(&self, ev: &epan::tap::TapEvent) { self.0.on_event(ev) }
    }
    Arc::new(Adapter(c))
}
