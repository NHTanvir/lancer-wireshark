//! DTLS — TLS over UDP. We reuse the TLS dissector for record dispatch with
//! a small wrapper that strips the DTLS sequence-number prefix.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ct: FieldId, ver: FieldId, epoch: FieldId, seq: FieldId, len: FieldId }

#[derive(Default)] pub struct DtlsDissector;
impl Dissector for DtlsDissector {
    fn name(&self) -> &'static str { "dtls" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Datagram TLS", "dtls", "dtls");
        let f = Fields {
            ct: reg.register_field(ProtoField::simple("dtls.record.content_type", "Content Type", FieldType::U8, FieldDisplay::BaseDec)),
            ver: reg.register_field(ProtoField::simple("dtls.record.version", "Version", FieldType::U16, FieldDisplay::BaseHex)),
            epoch: reg.register_field(ProtoField::simple("dtls.record.epoch", "Epoch", FieldType::U16, FieldDisplay::BaseDec)),
            seq: reg.register_field(ProtoField::simple("dtls.record.sequence_number", "Sequence number", FieldType::U64, FieldDisplay::BaseDec)),
            len: reg.register_field(ProtoField::simple("dtls.record.length", "Length", FieldType::U16, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 13 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "dtls".into();
        tree.append_proto("dtls");
        let mut root = ProtoItem::subtree(f.ct, "DTLS record".into(), 0, 13);
        root.push(ProtoItem::new(f.ct, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.ver, FieldValue::U64(tvb.u16_be(1).unwrap_or(0) as u64), 1, 2));
        root.push(ProtoItem::new(f.epoch, FieldValue::U64(tvb.u16_be(3).unwrap_or(0) as u64), 3, 2));
        let seq = tvb.bytes(5, 6).unwrap_or(&[]);
        let mut sv: u64 = 0;
        for b in seq { sv = (sv << 8) | *b as u64; }
        root.push(ProtoItem::new(f.seq, FieldValue::U64(sv), 5, 6));
        root.push(ProtoItem::new(f.len, FieldValue::U64(tvb.u16_be(11).unwrap_or(0) as u64), 11, 2));
        tree.push(root);
        DissectResult::Ok(13)
    }
}
