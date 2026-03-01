//! HTTP/2 — frame header walker.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { len: FieldId, ty: FieldId, flags: FieldId, stream_id: FieldId }

#[derive(Default)] pub struct Http2Dissector;
impl Dissector for Http2Dissector {
    fn name(&self) -> &'static str { "http2" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("HyperText Transfer Protocol 2", "http2", "http2");
        let f = Fields {
            len: reg.register_field(ProtoField::simple("http2.length", "Length", FieldType::U32, FieldDisplay::BaseDec)),
            ty: reg.register_field(ProtoField::simple("http2.type", "Type", FieldType::U8, FieldDisplay::BaseDec)),
            flags: reg.register_field(ProtoField::simple("http2.flags", "Flags", FieldType::U8, FieldDisplay::BaseHex)),
            stream_id: reg.register_field(ProtoField::simple("http2.streamid", "Stream ID", FieldType::U32, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 9 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "http2".into();
        tree.append_proto("http2");
        let mut off = 0usize;
        while off + 9 <= tvb.len() {
            let len = tvb.u24_be(off).unwrap_or(0) as usize;
            let ty = tvb.u8(off + 3).unwrap_or(0);
            let flags = tvb.u8(off + 4).unwrap_or(0);
            let sid = tvb.u32_be(off + 5).unwrap_or(0) & 0x7FFF_FFFF;
            if off + 9 + len > tvb.len() { break; }
            let mut frame = ProtoItem::subtree(f.ty, format!("HTTP/2 frame type={ty} stream={sid} len={len}"), off, 9 + len);
            frame.push(ProtoItem::new(f.len, FieldValue::U64(len as u64), off, 3));
            frame.push(ProtoItem::new(f.ty, FieldValue::U64(ty as u64), off + 3, 1));
            frame.push(ProtoItem::new(f.flags, FieldValue::U64(flags as u64), off + 4, 1));
            frame.push(ProtoItem::new(f.stream_id, FieldValue::U64(sid as u64), off + 5, 4));
            tree.push(frame);
            off += 9 + len;
        }
        DissectResult::Ok(off)
    }
}
