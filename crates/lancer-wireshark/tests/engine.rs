//! Engine wiring smoke tests.

use epan::{Dfilter, Engine};

#[test]
fn engine_registers_all_protocols() {
    let e = Engine::new();
    let names: Vec<_> = e.registry.protocols_iter().into_iter().map(|(_, s, _)| s).collect();
    for must_have in [
        "frame", "eth", "ip", "ipv6", "icmp", "icmpv6", "tcp", "udp",
        "tls", "dtls", "quic", "http", "http2", "http3", "dns", "bootp",
        "dhcpv6", "ftp", "ssh", "smtp", "imap", "pop", "ntp", "snmp",
        "mdns", "llmnr", "netbios", "smb", "kerberos", "ldap", "telnet",
        "radius", "syslog", "bgp", "ospf", "mqtt", "amqp", "kafka",
        "redis", "mysql", "pgsql", "mongo", "stun", "sip", "sdp", "rtp",
        "rtcp", "modbus", "coap", "gtp", "diameter", "wg", "vlan",
        "lldp", "cdp", "stp", "pppoe", "llc", "snap", "arp", "igmp",
        "gre", "esp", "sctp", "dccp",
    ] {
        assert!(names.iter().any(|n| n == must_have), "missing protocol {must_have} from registry: {names:?}");
    }
}

#[test]
fn dfilter_basics_compile() {
    let e = Engine::new();
    for f in [
        "ip.addr == 10.0.0.1",
        "tcp.port == 443",
        "tcp.flags.syn == 1",
        "http.request.method == \"GET\"",
        "dns.qry.name contains \"example\"",
        "tcp.dstport in {80, 443, 8080..8088}",
    ] {
        Dfilter::compile(f, &e.registry).unwrap_or_else(|e| panic!("compile {f:?}: {e}"));
    }
}
