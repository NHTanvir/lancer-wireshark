//! Elastic newline-delimited JSON (`-T ek`).

use super::OutputOptions;
use anyhow::Result;
use epan::register::Registry;
use epan::{PInfo, ProtoTree};
use serde_json::json;
use std::io::Write;

pub fn write<W: Write>(w: &mut W, _: &OutputOptions, pinfo: &PInfo, tree: &ProtoTree, _: &Registry) -> Result<()> {
    let index = json!({ "index": { "_index": format!("packets-{}", pinfo.timestamp_secs), "_type": "doc" } });
    writeln!(w, "{}", serde_json::to_string(&index)?)?;
    let body = json!({
        "timestamp": format!("{}.{:09}", pinfo.timestamp_secs, pinfo.timestamp_nanos),
        "layers": {
            "frame": {
                "frame_frame_number": pinfo.frame_number,
                "frame_frame_len": pinfo.original_len,
                "frame_frame_protocols": tree.proto_stack.join(":"),
            }
        }
    });
    writeln!(w, "{}", serde_json::to_string(&body)?)?;
    Ok(())
}
