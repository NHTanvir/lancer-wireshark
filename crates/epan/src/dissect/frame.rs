//! Synthetic "Frame" dissector — sets up the `frame.*` field tree used by
//! every output format and most display filters (`frame.number`,
//! `frame.time`, `frame.len`, `frame.interface_id`, `frame.protocols`).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static FRAME: OnceCell<FrameFields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct FrameFields {
    number: FieldId,
    time: FieldId,
    time_epoch: FieldId,
    time_delta: FieldId,
    time_relative: FieldId,
    cap_len: FieldId,
    len: FieldId,
    interface_id: FieldId,
    protocols: FieldId,
}

#[derive(Default)]
pub struct FrameDissector;

impl Dissector for FrameDissector {
    fn name(&self) -> &'static str {
        "frame"
    }

    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Frame", "frame", "frame");
        let f = FrameFields {
            number: reg.register_field(ProtoField::simple("frame.number", "Frame number", FieldType::U64, FieldDisplay::BaseDec)),
            time: reg.register_field(ProtoField::simple("frame.time", "Arrival Time", FieldType::AbsoluteTime, FieldDisplay::BaseNone)),
            time_epoch: reg.register_field(ProtoField::simple("frame.time_epoch", "Epoch Time", FieldType::AbsoluteTime, FieldDisplay::BaseNone)),
            time_delta: reg.register_field(ProtoField::simple("frame.time_delta", "Time delta from previous packet", FieldType::RelativeTime, FieldDisplay::BaseNone)),
            time_relative: reg.register_field(ProtoField::simple("frame.time_relative", "Time since reference or first frame", FieldType::RelativeTime, FieldDisplay::BaseNone)),
            cap_len: reg.register_field(ProtoField::simple("frame.cap_len", "Captured Length", FieldType::U32, FieldDisplay::BaseDec)),
            len: reg.register_field(ProtoField::simple("frame.len", "Frame Length", FieldType::U32, FieldDisplay::BaseDec)),
            interface_id: reg.register_field(ProtoField::simple("frame.interface_id", "Interface id", FieldType::U32, FieldDisplay::BaseDec)),
            protocols: reg.register_field(ProtoField::simple("frame.protocols", "Protocols in frame", FieldType::String, FieldDisplay::StrAscii)),
        };
        let _ = FRAME.set(f);
    }

    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let f = FRAME.get().expect("frame fields not registered");
        if pinfo.include_frame_fields {
            tree.append_proto("frame");
            let mut root = ProtoItem::subtree(f.number, format!("Frame {}", pinfo.frame_number), 0, tvb.len());
            root.push(ProtoItem::new(f.number, FieldValue::U64(pinfo.frame_number), 0, 0));
            root.push(ProtoItem::new(
                f.time,
                FieldValue::Time { secs: pinfo.timestamp_secs, nanos: pinfo.timestamp_nanos },
                0,
                0,
            ));
            root.push(ProtoItem::new(
                f.time_epoch,
                FieldValue::Time { secs: pinfo.timestamp_secs, nanos: pinfo.timestamp_nanos },
                0,
                0,
            ));
            root.push(ProtoItem::new(
                f.time_relative,
                FieldValue::Time { secs: pinfo.rel_ts_secs, nanos: pinfo.rel_ts_nanos },
                0,
                0,
            ));
            root.push(ProtoItem::new(f.cap_len, FieldValue::U64(pinfo.captured_len as u64), 0, 0));
            root.push(ProtoItem::new(f.len, FieldValue::U64(pinfo.original_len as u64), 0, 0));
            root.push(ProtoItem::new(f.interface_id, FieldValue::U64(pinfo.interface_id as u64), 0, 0));
            tree.push(root);
        }
        let _ = f;
        DissectResult::Ok(tvb.len())
    }
}
