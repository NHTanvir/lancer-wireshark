//! JSON output (top-level array of packet objects).

use super::OutputOptions;
use anyhow::Result;
use epan::proto::ProtoItem;
use epan::register::Registry;
use epan::{PInfo, ProtoTree};
use serde_json::{json, Map, Value};
use std::io::Write;

pub fn write<W: Write>(
    w: &mut W,
    opts: &OutputOptions,
    pinfo: &PInfo,
    tree: &ProtoTree,
    reg: &Registry,
    raw: &[u8],
    first: &mut bool,
    raw_form: bool,
) -> Result<()> {
    let mut packet = Map::new();
    packet.insert(
        "_index".into(),
        json!(format!("packets-{}", pinfo.timestamp_secs)),
    );
    packet.insert("_type".into(), json!("doc"));
    packet.insert("_score".into(), json!(null));
    let mut source = Map::new();
    let mut layers: Map<String, Value> = Map::new();
    layers.insert(
        "frame".into(),
        json!({
            "frame.number": pinfo.frame_number,
            "frame.cap_len": pinfo.captured_len,
            "frame.len": pinfo.original_len,
            "frame.time_epoch": format!("{}.{:09}", pinfo.timestamp_secs, pinfo.timestamp_nanos),
            "frame.interface_id": pinfo.interface_id,
            "frame.protocols": tree.proto_stack.join("/"),
        }),
    );
    for item in &tree.items {
        merge_into(&mut layers, item, reg, raw_form, opts.no_duplicate_keys, raw);
    }
    source.insert("layers".into(), Value::Object(layers));
    packet.insert("_source".into(), Value::Object(source));

    if !*first {
        write!(w, ",\n")?;
    }
    *first = false;
    let s = serde_json::to_string_pretty(&Value::Object(packet))?;
    write!(w, "  {s}")?;
    Ok(())
}

fn merge_into(layers: &mut Map<String, Value>, item: &ProtoItem, reg: &Registry, raw_form: bool, _no_dup: bool, raw: &[u8]) {
    let abbr = reg.field(item.field).map(|f| f.abbr.to_string()).unwrap_or_default();
    if abbr.is_empty() {
        for c in &item.children {
            merge_into(layers, c, reg, raw_form, _no_dup, raw);
        }
        return;
    }
    let proto_key = abbr.split('.').next().unwrap_or(&abbr).to_string();
    let entry = layers.entry(proto_key).or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(map) = entry {
        let display = reg.field(item.field).map(|f| f.display).unwrap_or(epan::proto::FieldDisplay::BaseNone);
        let vals = reg.field(item.field).and_then(|f| f.vals);
        let value_str = item.value.display(display, vals);
        let prev = map.remove(&abbr);
        let new_val = if raw_form {
            let mut obj = Map::new();
            obj.insert("value".into(), Value::String(value_str.clone()));
            obj.insert(
                "raw".into(),
                Value::String(hex::encode(raw.get(item.abs_offset..item.abs_offset + item.length).unwrap_or(&[]))),
            );
            Value::Object(obj)
        } else {
            Value::String(value_str)
        };
        let merged = match prev {
            Some(Value::Array(mut arr)) => {
                arr.push(new_val);
                Value::Array(arr)
            }
            Some(other) => Value::Array(vec![other, new_val]),
            None => new_val,
        };
        map.insert(abbr.clone(), merged);
    }
    for c in &item.children {
        merge_into(layers, c, reg, raw_form, _no_dup, raw);
    }
}
