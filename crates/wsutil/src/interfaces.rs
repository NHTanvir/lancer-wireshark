//! Capture-interface enumeration shared between `lancer-wireshark` and `dumpcap`.
//!
//! The actual live discovery is performed by the `pcap` crate; this module
//! defines the record types and provides helpers for `-D` listing format.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub description: Option<String>,
    pub is_loopback: bool,
    pub is_up: bool,
    pub is_running: bool,
    pub addresses: Vec<String>,
    pub link_types: Vec<LinkType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkType {
    Ethernet,
    Wifi,
    Loopback,
    Raw,
    Ppp,
    Sll,
    Sll2,
    Null,
    Other(u32),
}

impl LinkType {
    pub fn from_dlt(dlt: u32) -> Self {
        match dlt {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            7 => LinkType::Other(7), // SLIP_BSDOS
            9 => LinkType::Ppp,
            101 => LinkType::Raw,
            105 => LinkType::Wifi,
            113 => LinkType::Sll,
            127 => LinkType::Wifi, // radiotap
            228 => LinkType::Other(228), // IPV4
            276 => LinkType::Sll2,
            other => LinkType::Other(other),
        }
    }

    pub fn dlt(&self) -> u32 {
        match self {
            LinkType::Null => 0,
            LinkType::Ethernet => 1,
            LinkType::Ppp => 9,
            LinkType::Raw => 101,
            LinkType::Loopback => 0,
            LinkType::Wifi => 105,
            LinkType::Sll => 113,
            LinkType::Sll2 => 276,
            LinkType::Other(v) => *v,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LinkType::Null => "NULL",
            LinkType::Ethernet => "EN10MB (Ethernet)",
            LinkType::Wifi => "IEEE802_11",
            LinkType::Loopback => "LOOPBACK",
            LinkType::Raw => "RAW",
            LinkType::Ppp => "PPP",
            LinkType::Sll => "Linux cooked v1",
            LinkType::Sll2 => "Linux cooked v2",
            LinkType::Other(_) => "OTHER",
        }
    }
}

/// Format `-D` style: `N. <name> (<desc>)`.
pub fn format_d(interfaces: &[Interface]) -> String {
    let mut out = String::new();
    for it in interfaces {
        out.push_str(&format!("{}. {}", it.index, it.name));
        if let Some(d) = &it.description {
            out.push_str(&format!(" ({d})"));
        }
        out.push('\n');
    }
    out
}

/// Format `-L` style for one interface (link-layer types).
pub fn format_l(interface: &Interface) -> String {
    let mut out = format!("Data link types of interface {} (use option -y to set):\n", interface.name);
    for lt in &interface.link_types {
        out.push_str(&format!("  {} ({})\n", lt.dlt(), lt.as_str()));
    }
    out
}
