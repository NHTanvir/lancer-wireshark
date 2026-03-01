//! Per-protocol dissectors. One module per protocol — see plan.md
//! "## Granular feature catalog" for the MVP list of ~50 protocols.

pub mod ethernet;
pub mod arp;
pub mod vlan;
pub mod lldp;
pub mod cdp;
pub mod stp;
pub mod pppoe;
pub mod llc;
pub mod snap;

pub mod ipv4;
pub mod ipv6;
pub mod icmpv4;
pub mod icmpv6;
pub mod igmp;
pub mod gre;
pub mod ipsec;

pub mod tcp;
pub mod udp;
pub mod sctp;
pub mod dccp;

pub mod tls;
pub mod dtls;
pub mod quic;
pub mod wireguard;

pub mod http;
pub mod http2;
pub mod http3;
pub mod dns;
pub mod dhcp;
pub mod dhcpv6;
pub mod ftp;
pub mod ssh;
pub mod smtp;
pub mod imap;
pub mod pop3;
pub mod ntp;
pub mod snmp;
pub mod mdns;
pub mod llmnr;
pub mod netbios;
pub mod smb;
pub mod kerberos;
pub mod ldap;
pub mod telnet;
pub mod radius;
pub mod syslog;
pub mod bgp;
pub mod ospf;
pub mod mqtt;
pub mod amqp;
pub mod kafka;
pub mod redis;
pub mod mysql;
pub mod postgres;
pub mod mongodb;
pub mod stun;
pub mod sip;
pub mod sdp;
pub mod rtp;
pub mod rtcp;
pub mod modbus;
pub mod coap;
pub mod gtp;
pub mod mld;
pub mod ipsec_ah;
pub mod udp_lite;
pub mod grpc;
pub mod websocket;
pub mod rip;
pub mod isis;
pub mod turn;
pub mod dnp3;
pub mod s1ap;
pub mod x2ap;
pub mod nas_eps;
pub mod nas_5gs;
pub mod diameter;
pub mod ja3;
pub mod frame;

pub use frame::FrameDissector;

use crate::register::Registry;
use std::sync::Arc;

/// Register every built-in dissector with the engine registry.
pub fn register_builtin(reg: &mut Registry) {
    let dissectors: Vec<Arc<dyn crate::dissector::Dissector>> = vec![
        Arc::new(frame::FrameDissector::default()),
        Arc::new(ethernet::EthernetDissector::default()),
        Arc::new(arp::ArpDissector::default()),
        Arc::new(vlan::VlanDissector::default()),
        Arc::new(lldp::LldpDissector::default()),
        Arc::new(cdp::CdpDissector::default()),
        Arc::new(stp::StpDissector::default()),
        Arc::new(pppoe::PppoeDissector::default()),
        Arc::new(llc::LlcDissector::default()),
        Arc::new(snap::SnapDissector::default()),
        Arc::new(ipv4::Ipv4Dissector::default()),
        Arc::new(ipv6::Ipv6Dissector::default()),
        Arc::new(icmpv4::Icmpv4Dissector::default()),
        Arc::new(icmpv6::Icmpv6Dissector::default()),
        Arc::new(igmp::IgmpDissector::default()),
        Arc::new(gre::GreDissector::default()),
        Arc::new(ipsec::IpsecDissector::default()),
        Arc::new(tcp::TcpDissector::default()),
        Arc::new(udp::UdpDissector::default()),
        Arc::new(sctp::SctpDissector::default()),
        Arc::new(dccp::DccpDissector::default()),
        Arc::new(tls::TlsDissector::default()),
        Arc::new(dtls::DtlsDissector::default()),
        Arc::new(quic::QuicDissector::default()),
        Arc::new(wireguard::WireguardDissector::default()),
        Arc::new(http::HttpDissector::default()),
        Arc::new(http2::Http2Dissector::default()),
        Arc::new(http3::Http3Dissector::default()),
        Arc::new(dns::DnsDissector::default()),
        Arc::new(dhcp::DhcpDissector::default()),
        Arc::new(dhcpv6::Dhcpv6Dissector::default()),
        Arc::new(ftp::FtpDissector::default()),
        Arc::new(ssh::SshDissector::default()),
        Arc::new(smtp::SmtpDissector::default()),
        Arc::new(imap::ImapDissector::default()),
        Arc::new(pop3::Pop3Dissector::default()),
        Arc::new(ntp::NtpDissector::default()),
        Arc::new(snmp::SnmpDissector::default()),
        Arc::new(mdns::MdnsDissector::default()),
        Arc::new(llmnr::LlmnrDissector::default()),
        Arc::new(netbios::NetbiosDissector::default()),
        Arc::new(smb::SmbDissector::default()),
        Arc::new(kerberos::KerberosDissector::default()),
        Arc::new(ldap::LdapDissector::default()),
        Arc::new(telnet::TelnetDissector::default()),
        Arc::new(radius::RadiusDissector::default()),
        Arc::new(syslog::SyslogDissector::default()),
        Arc::new(bgp::BgpDissector::default()),
        Arc::new(ospf::OspfDissector::default()),
        Arc::new(mqtt::MqttDissector::default()),
        Arc::new(amqp::AmqpDissector::default()),
        Arc::new(kafka::KafkaDissector::default()),
        Arc::new(redis::RedisDissector::default()),
        Arc::new(mysql::MysqlDissector::default()),
        Arc::new(postgres::PostgresDissector::default()),
        Arc::new(mongodb::MongoDissector::default()),
        Arc::new(stun::StunDissector::default()),
        Arc::new(sip::SipDissector::default()),
        Arc::new(sdp::SdpDissector::default()),
        Arc::new(rtp::RtpDissector::default()),
        Arc::new(rtcp::RtcpDissector::default()),
        Arc::new(modbus::ModbusDissector::default()),
        Arc::new(coap::CoapDissector::default()),
        Arc::new(gtp::GtpDissector::default()),
        Arc::new(diameter::DiameterDissector::default()),
        Arc::new(mld::MldDissector::default()),
        Arc::new(ipsec_ah::IpsecAhDissector::default()),
        Arc::new(udp_lite::UdpLiteDissector::default()),
        Arc::new(grpc::GrpcDissector::default()),
        Arc::new(websocket::WebsocketDissector::default()),
        Arc::new(rip::RipDissector::default()),
        Arc::new(isis::IsisDissector::default()),
        Arc::new(turn::TurnDissector::default()),
        Arc::new(dnp3::Dnp3Dissector::default()),
        Arc::new(s1ap::S1apDissector::default()),
        Arc::new(x2ap::X2apDissector::default()),
        Arc::new(nas_eps::NasEpsDissector::default()),
        Arc::new(nas_5gs::Nas5gsDissector::default()),
    ];
    for d in dissectors {
        d.register(reg);
        reg.register_dissector(d.name(), d.clone());
    }

    // Wire up standard dispatch table defaults.
    wire_tables(reg);
}

fn wire_tables(reg: &Registry) {
    // Ethertype → next dissector
    let eth = reg.table("ethertype");
    if let Some(d) = reg.dissector("ip") {
        eth.add_uint(0x0800, d);
    }
    if let Some(d) = reg.dissector("ipv6") {
        eth.add_uint(0x86DD, d);
    }
    if let Some(d) = reg.dissector("arp") {
        eth.add_uint(0x0806, d);
    }
    if let Some(d) = reg.dissector("vlan") {
        eth.add_uint(0x8100, d.clone());
        eth.add_uint(0x88A8, d);
    }
    if let Some(d) = reg.dissector("lldp") {
        eth.add_uint(0x88CC, d);
    }
    if let Some(d) = reg.dissector("pppoe") {
        eth.add_uint(0x8863, d.clone());
        eth.add_uint(0x8864, d);
    }

    // IP protocol → L4
    let ipproto = reg.table("ip.proto");
    if let Some(d) = reg.dissector("icmp") {
        ipproto.add_uint(1, d);
    }
    if let Some(d) = reg.dissector("igmp") {
        ipproto.add_uint(2, d);
    }
    if let Some(d) = reg.dissector("tcp") {
        ipproto.add_uint(6, d);
    }
    if let Some(d) = reg.dissector("udp") {
        ipproto.add_uint(17, d);
    }
    if let Some(d) = reg.dissector("gre") {
        ipproto.add_uint(47, d);
    }
    if let Some(d) = reg.dissector("ipsec.esp") {
        ipproto.add_uint(50, d);
    }
    if let Some(d) = reg.dissector("ipsec.ah") {
        ipproto.add_uint(51, d);
    }
    if let Some(d) = reg.dissector("udplite") {
        ipproto.add_uint(136, d);
    }
    if let Some(d) = reg.dissector("icmpv6") {
        ipproto.add_uint(58, d);
    }
    if let Some(d) = reg.dissector("sctp") {
        ipproto.add_uint(132, d);
    }
    if let Some(d) = reg.dissector("dccp") {
        ipproto.add_uint(33, d);
    }

    // TCP port → app
    let tcp = reg.table("tcp.port");
    static TCP_MAP: &[(u32, &str)] = &[
        (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
        (53, "dns"), (80, "http"), (110, "pop3"), (143, "imap"),
        (179, "bgp"), (389, "ldap"), (443, "tls"), (465, "tls"),
        (587, "smtp"), (636, "tls"), (873, "rsync"),
        (993, "tls"), (995, "tls"), (1883, "mqtt"), (3306, "mysql"),
        (3389, "rdp"), (5432, "postgres"), (5672, "amqp"),
        (5683, "coap"), (5900, "vnc"), (6379, "redis"),
        (8080, "http"), (8443, "tls"), (8883, "tls"),
        (9042, "cassandra"), (9092, "kafka"), (9200, "http"),
        (11211, "memcached"), (27017, "mongodb"),
    ];
    for (port, name) in TCP_MAP {
        if let Some(d) = reg.dissector(name) {
            tcp.add_uint(*port, d);
        }
    }

    // UDP port → app
    let udp = reg.table("udp.port");
    static UDP_MAP: &[(u32, &str)] = &[
        (53, "dns"), (67, "dhcp"), (68, "dhcp"), (69, "tftp"),
        (88, "kerberos"), (123, "ntp"), (137, "netbios"),
        (138, "netbios"), (161, "snmp"), (162, "snmp"),
        (500, "isakmp"), (514, "syslog"), (520, "rip"),
        (546, "dhcpv6"), (547, "dhcpv6"), (1900, "ssdp"),
        (4500, "ipsec.nat-t"), (4789, "vxlan"),
        (3478, "stun"), (5060, "sip"), (5353, "mdns"),
        (5355, "llmnr"), (5683, "coap"), (51820, "wireguard"),
    ];
    for (port, name) in UDP_MAP {
        if let Some(d) = reg.dissector(name) {
            udp.add_uint(*port, d);
        }
    }

    // Modbus dispatch (any TCP traffic on 502)
    if let Some(d) = reg.dissector("modbus") {
        tcp.add_uint(502, d);
    }

    // SCTP payload PPID → app (Diameter, S1AP, ...)
    let sctp = reg.table("sctp.ppid");
    if let Some(d) = reg.dissector("diameter") {
        sctp.add_uint(46, d);
    }

    // PPID 18 = S1AP / 47 = X2AP (we don't ship dedicated dissectors yet)
}
