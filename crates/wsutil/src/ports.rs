//! IANA TCP/UDP port → service-name lookup.

use once_cell::sync::Lazy;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
    Sctp,
}

static PORTS_TCP: Lazy<HashMap<u16, &'static str>> = Lazy::new(|| build(PORT_TABLE_TCP));
static PORTS_UDP: Lazy<HashMap<u16, &'static str>> = Lazy::new(|| build(PORT_TABLE_UDP));

fn build(rows: &[(u16, &'static str)]) -> HashMap<u16, &'static str> {
    let mut m = HashMap::with_capacity(rows.len());
    for (p, n) in rows {
        m.insert(*p, *n);
    }
    m
}

pub fn lookup(port: u16, proto: L4Proto) -> Option<&'static str> {
    match proto {
        L4Proto::Tcp => PORTS_TCP.get(&port).copied(),
        L4Proto::Udp => PORTS_UDP.get(&port).copied(),
        L4Proto::Sctp => None,
    }
}

pub static PORT_TABLE_TCP: &[(u16, &str)] = &[
    (20, "ftp-data"), (21, "ftp"), (22, "ssh"), (23, "telnet"),
    (25, "smtp"), (43, "whois"), (53, "dns"), (67, "bootps"),
    (68, "bootpc"), (69, "tftp"), (80, "http"), (88, "kerberos"),
    (110, "pop3"), (111, "sunrpc"), (113, "ident"), (119, "nntp"),
    (123, "ntp"), (135, "msrpc"), (137, "netbios-ns"), (138, "netbios-dgm"),
    (139, "netbios-ssn"), (143, "imap"), (161, "snmp"), (162, "snmptrap"),
    (179, "bgp"), (194, "irc"), (220, "imap3"), (389, "ldap"),
    (443, "https"), (445, "microsoft-ds"), (465, "smtps"), (500, "isakmp"),
    (514, "syslog"), (515, "printer"), (520, "rip"), (521, "ripng"),
    (546, "dhcpv6-client"), (547, "dhcpv6-server"), (554, "rtsp"),
    (587, "smtp-submission"), (631, "ipp"), (636, "ldaps"), (873, "rsync"),
    (989, "ftps-data"), (990, "ftps"), (993, "imaps"), (995, "pop3s"),
    (1080, "socks"), (1194, "openvpn"), (1433, "mssql"), (1434, "ms-sql-m"),
    (1521, "oracle"), (1701, "l2tp"), (1812, "radius"), (1813, "radius-acct"),
    (1883, "mqtt"), (2049, "nfs"), (2181, "zookeeper"), (3128, "squid"),
    (3306, "mysql"), (3389, "rdp"), (3478, "stun"), (4369, "epmd"),
    (4433, "tls-test"), (4789, "vxlan"), (5060, "sip"), (5061, "sips"),
    (5432, "postgres"), (5601, "kibana"), (5672, "amqp"), (5683, "coap"),
    (5900, "vnc"), (6379, "redis"), (6443, "kubernetes-api"), (6514, "syslog-tls"),
    (6660, "irc"), (6667, "irc"), (7000, "afs3-fileserver"), (7001, "afs3-callback"),
    (7100, "font-service"), (8000, "http-alt"), (8009, "ajp13"), (8080, "http-proxy"),
    (8081, "http-alt"), (8086, "influxdb"), (8088, "radan-http"), (8443, "https-alt"),
    (8883, "mqtts"), (9000, "cslistener"), (9042, "cassandra"), (9092, "kafka"),
    (9100, "jetdirect"), (9200, "elasticsearch"), (9300, "elasticsearch-cluster"),
    (9418, "git"), (10000, "snet-sensor-mgmt"), (11211, "memcached"),
    (15672, "rabbitmq-mgmt"), (27017, "mongodb"), (50000, "ibm-db2"),
];

pub static PORT_TABLE_UDP: &[(u16, &str)] = &[
    (53, "dns"), (67, "bootps"), (68, "bootpc"), (69, "tftp"),
    (88, "kerberos"), (111, "sunrpc"), (123, "ntp"), (137, "netbios-ns"),
    (138, "netbios-dgm"), (161, "snmp"), (162, "snmptrap"), (177, "xdmcp"),
    (500, "isakmp"), (514, "syslog"), (520, "rip"), (521, "ripng"),
    (546, "dhcpv6-client"), (547, "dhcpv6-server"), (623, "ipmi-rmcp"),
    (1194, "openvpn"), (1900, "ssdp"), (3702, "ws-discovery"),
    (4500, "ipsec-nat-t"), (4789, "vxlan"), (5060, "sip"), (5353, "mdns"),
    (5355, "llmnr"), (6343, "sflow"), (51820, "wireguard"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_https() {
        assert_eq!(lookup(443, L4Proto::Tcp), Some("https"));
    }

    #[test]
    fn lookup_dns_udp() {
        assert_eq!(lookup(53, L4Proto::Udp), Some("dns"));
    }
}
