//! Per-packet metadata threaded through the dissection pipeline.

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct PInfo {
    pub frame_number: u64,
    pub timestamp_secs: i64,
    pub timestamp_nanos: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub interface_id: u32,
    pub link_type: u32,
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub vlan_id: Option<u16>,
    pub l4_proto: Option<u8>,
    /// "info column" — short human summary, set by leaf dissectors.
    pub info: String,
    pub current_proto: String,
    /// 1-pass / 2-pass distinction (Wireshark's `-2`).
    pub second_pass: bool,
    /// Frame-relative timestamp (delta to first packet).
    pub rel_ts_secs: i64,
    pub rel_ts_nanos: u32,
    /// Bytes consumed by ancestors before the current dissector started.
    pub layer_consumed: usize,
    /// Conversation handle (interned key).
    pub conv_id: Option<u64>,
    /// True if the engine is currently building a `frame.*` field set.
    pub include_frame_fields: bool,
}

impl PInfo {
    pub fn new(frame_number: u64, ts: (i64, u32), captured: u32, original: u32) -> Self {
        Self {
            frame_number,
            timestamp_secs: ts.0,
            timestamp_nanos: ts.1,
            captured_len: captured,
            original_len: original,
            interface_id: 0,
            link_type: 1,
            src_addr: None,
            dst_addr: None,
            src_mac: None,
            dst_mac: None,
            src_port: None,
            dst_port: None,
            vlan_id: None,
            l4_proto: None,
            info: String::new(),
            current_proto: String::new(),
            second_pass: false,
            rel_ts_secs: 0,
            rel_ts_nanos: 0,
            layer_consumed: 0,
            conv_id: None,
            include_frame_fields: true,
        }
    }
    pub fn append_info(&mut self, s: &str) {
        if !self.info.is_empty() {
            self.info.push(' ');
        }
        self.info.push_str(s);
    }
    pub fn set_info(&mut self, s: String) {
        self.info = s;
    }
}
