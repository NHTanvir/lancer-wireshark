//! IANA Private Enterprise Number → name (SNMP, RADIUS vendor attributes, etc.).

use once_cell::sync::Lazy;
use std::collections::HashMap;

static TABLE: Lazy<HashMap<u32, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for (k, v) in DATA {
        m.insert(*k, *v);
    }
    m
});

pub fn lookup(pen: u32) -> Option<&'static str> {
    TABLE.get(&pen).copied()
}

static DATA: &[(u32, &str)] = &[
    (9, "Cisco"),
    (11, "HP"),
    (43, "3Com"),
    (74, "Synoptics"),
    (76, "BBN"),
    (133, "AT&T"),
    (157, "Sun Microsystems"),
    (171, "D-Link"),
    (193, "Ericsson"),
    (232, "Compaq"),
    (244, "Lantronix"),
    (311, "Microsoft"),
    (388, "Motorola"),
    (529, "Ascend Communications"),
    (664, "Aruba"),
    (737, "Symantec"),
    (1206, "WatchGuard"),
    (1742, "Mitel"),
    (1991, "Foundry Networks"),
    (2076, "Polycom"),
    (2434, "VeriSign"),
    (2636, "Juniper Networks"),
    (3076, "Altiga (Cisco VPN)"),
    (3375, "F5 Networks"),
    (4203, "Avaya"),
    (4329, "Apple"),
    (4413, "Broadcom"),
    (4515, "DSLForum"),
    (4874, "Redback Networks"),
    (4901, "Brocade Communications"),
    (5263, "GitHub"),
    (5535, "Asterisk PBX"),
    (5651, "Force10 Networks"),
    (5771, "Cisco Systems VPN3000"),
    (6066, "MikroTik"),
    (6307, "Aruba Wireless"),
    (6527, "Alcatel-Lucent"),
    (6876, "VMware"),
    (8030, "Edgewater Networks"),
    (9148, "Citrix"),
    (10415, "3GPP"),
    (10591, "TippingPoint"),
    (10923, "WireSpring"),
    (11129, "Google"),
    (11591, "FreeRADIUS"),
    (12356, "Fortinet"),
    (14179, "Cisco Aironet"),
    (14525, "Trapeze Networks"),
    (15497, "Ubiquiti"),
    (16591, "Apple AirPort"),
    (16924, "GoodGuy LLC"),
    (17648, "Linksys"),
    (18681, "Mojo Networks"),
    (21091, "Riverbed Technology"),
    (22418, "EnGenius"),
    (25506, "H3C"),
    (28458, "PaloAlto Networks"),
    (32473, "Example Enterprises"),
    (36807, "Cloudflare"),
    (39577, "Hetzner"),
    (40824, "DigitalOcean"),
    (50545, "Anthropic (test)"),
];
