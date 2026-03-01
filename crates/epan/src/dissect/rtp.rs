//! RTP — fixed 12-byte header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { version: FieldId, payload_type: FieldId, seq: FieldId, timestamp: FieldId, ssrc: FieldId }

#[derive(Default)] pub struct RtpDissector;
impl Dissector for RtpDissector {
    fn name(&self) -> &'static str { "rtp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Real-Time Transport Protocol", "rtp", "rtp");
        let f = Fields {
            version: reg.register_field(ProtoField::simple("rtp.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            payload_type: reg.register_field(ProtoField::simple("rtp.p_type", "Payload Type", FieldType::U8, FieldDisplay::BaseDec)),
            seq: reg.register_field(ProtoField::simple("rtp.seq", "Sequence", FieldType::U16, FieldDisplay::BaseDec)),
            timestamp: reg.register_field(ProtoField::simple("rtp.timestamp", "Timestamp", FieldType::U32, FieldDisplay::BaseDec)),
            ssrc: reg.register_field(ProtoField::simple("rtp.ssrc", "SSRC", FieldType::U32, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 12 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "rtp".into();
        tree.append_proto("rtp");
        let first = tvb.u8(0).unwrap_or(0);
        let ver = first >> 6;
        let pt = tvb.u8(1).unwrap_or(0) & 0x7F;
        let mut root = ProtoItem::subtree(f.version, "RTP".into(), 0, 12);
        root.push(ProtoItem::new(f.version, FieldValue::U64(ver as u64), 0, 1));
        root.push(ProtoItem::new(f.payload_type, FieldValue::U64(pt as u64), 1, 1));
        root.push(ProtoItem::new(f.seq, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.timestamp, FieldValue::U64(tvb.u32_be(4).unwrap_or(0) as u64), 4, 4));
        root.push(ProtoItem::new(f.ssrc, FieldValue::U64(tvb.u32_be(8).unwrap_or(0) as u64), 8, 4));
        tree.push(root);
        DissectResult::Ok(12)
    }
}
