//! Local IPC for piping captured / dissected packets between processes
//! (capture daemon → main process → GUI). MVP: newline-delimited JSON.

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketLine {
    pub frame_number: u64,
    pub ts_secs: i64,
    pub ts_nanos: u32,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub protocol: String,
    pub info: String,
    pub bytes_hex: String,
}

pub fn encode(p: &PacketLine) -> Result<String> {
    Ok(serde_json::to_string(p)?)
}

pub fn decode(line: &str) -> Result<PacketLine> {
    Ok(serde_json::from_str(line)?)
}
