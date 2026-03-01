//! Follow-stream extraction (`-z follow,<proto>,<mode>,<filter>`).
//!
//! For TCP / UDP / TLS / HTTP / HTTP/2 / QUIC, walk a conversation's
//! accumulated `FollowChunk` log and emit it in the requested encoding
//! (ascii / raw / hex / yaml / json).

use crate::conversation::{Conversation, Direction, FollowChunk};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowMode {
    Ascii,
    Raw,
    Hex,
    Yaml,
    Json,
}

impl FollowMode {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "ascii" => FollowMode::Ascii,
            "raw" => FollowMode::Raw,
            "hex" | "hexdump" => FollowMode::Hex,
            "yaml" => FollowMode::Yaml,
            "json" => FollowMode::Json,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowProto {
    Tcp,
    Udp,
    Tls,
    Http,
    Http2,
    Http3,
    Dccp,
    Quic,
    Mpeg2ts,
    Pes,
}

impl FollowProto {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "tcp" => FollowProto::Tcp,
            "udp" => FollowProto::Udp,
            "tls" | "ssl" => FollowProto::Tls,
            "http" => FollowProto::Http,
            "http2" => FollowProto::Http2,
            "http3" => FollowProto::Http3,
            "dccp" => FollowProto::Dccp,
            "quic" => FollowProto::Quic,
            "mpeg2ts" => FollowProto::Mpeg2ts,
            "pes" => FollowProto::Pes,
            _ => return None,
        })
    }
}

pub struct FollowStream {
    pub proto: FollowProto,
    pub conv: Arc<Conversation>,
}

impl FollowStream {
    pub fn new(proto: FollowProto, conv: Arc<Conversation>) -> Self {
        Self { proto, conv }
    }

    pub fn chunks(&self) -> Vec<FollowChunk> {
        self.conv.state.lock().follow_payload.clone()
    }

    pub fn render(&self, mode: FollowMode) -> String {
        let chunks = self.chunks();
        match mode {
            FollowMode::Ascii => render_ascii(&chunks),
            FollowMode::Raw => render_raw(&chunks),
            FollowMode::Hex => render_hex(&chunks),
            FollowMode::Yaml => render_yaml(&chunks),
            FollowMode::Json => render_json(&chunks),
        }
    }
}

fn dir_marker(d: Direction) -> &'static str {
    match d {
        Direction::AtoB => "=>",
        Direction::BtoA => "<=",
    }
}

fn render_ascii(chunks: &[FollowChunk]) -> String {
    let mut out = String::new();
    for c in chunks {
        out.push_str(&format!("--- {} {} bytes (frame {}) ---\n", dir_marker(c.direction), c.bytes.len(), c.frame_number));
        let mut printable = String::with_capacity(c.bytes.len());
        for &b in &c.bytes {
            if (32u8..127).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
                printable.push(b as char);
            } else {
                printable.push('.');
            }
        }
        out.push_str(&printable);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn render_raw(chunks: &[FollowChunk]) -> String {
    let mut out = String::new();
    for c in chunks {
        out.push_str(&hex::encode(&c.bytes));
        out.push('\n');
    }
    out
}

fn render_hex(chunks: &[FollowChunk]) -> String {
    let mut out = String::new();
    for c in chunks {
        out.push_str(&format!("--- {} frame {} ---\n", dir_marker(c.direction), c.frame_number));
        out.push_str(&wsutil::format_hexdump(&c.bytes));
    }
    out
}

fn render_yaml(chunks: &[FollowChunk]) -> String {
    let mut out = String::from("packets:\n");
    for c in chunks {
        out.push_str(&format!(
            "  - direction: {}\n    frame: {}\n    bytes_hex: {}\n",
            match c.direction { Direction::AtoB => "client_to_server", Direction::BtoA => "server_to_client" },
            c.frame_number,
            hex::encode(&c.bytes)
        ));
    }
    out
}

fn render_json(chunks: &[FollowChunk]) -> String {
    let mut arr = Vec::with_capacity(chunks.len());
    for c in chunks {
        arr.push(serde_json::json!({
            "direction": match c.direction { Direction::AtoB => "client_to_server", Direction::BtoA => "server_to_client" },
            "frame": c.frame_number,
            "ts": format!("{}.{:09}", c.timestamp_secs, c.timestamp_nanos),
            "len": c.bytes.len(),
            "data_hex": hex::encode(&c.bytes),
        }));
    }
    serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
}

/// Trait implemented by per-protocol follow extractors that need to peel
/// a transport encapsulation off before emitting the inner payload.
pub trait FollowExtractor: Send + Sync {
    fn proto(&self) -> FollowProto;
    fn extract(&self, conv: &Conversation) -> Vec<FollowChunk>;
}
