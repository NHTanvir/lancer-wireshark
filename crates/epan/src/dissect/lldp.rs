//! LLDP (Link Layer Discovery Protocol) dissector — TLV walker only.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct Fields {
    tlv_type: FieldId,
    tlv_len: FieldId,
    tlv_payload: FieldId,
}

#[derive(Default)]
pub struct LldpDissector;

impl Dissector for LldpDissector {
    fn name(&self) -> &'static str { "lldp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Link Layer Discovery Protocol", "lldp", "lldp");
        let f = Fields {
            tlv_type: reg.register_field(ProtoField::simple("lldp.tlv.type", "TLV Type", FieldType::U8, FieldDisplay::BaseDec)),
            tlv_len: reg.register_field(ProtoField::simple("lldp.tlv.len", "TLV Length", FieldType::U16, FieldDisplay::BaseDec)),
            tlv_payload: reg.register_field(ProtoField::simple("lldp.tlv.payload", "TLV Payload", FieldType::Bytes, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let f = F.get().unwrap();
        pinfo.current_proto = "lldp".into();
        tree.append_proto("lldp");
        let mut root = ProtoItem::subtree(f.tlv_type, "Link Layer Discovery Protocol".into(), 0, tvb.len());
        let mut off = 0;
        while off + 2 <= tvb.len() {
            let hdr = tvb.u16_be(off).unwrap_or(0);
            let ty = (hdr >> 9) as u8 & 0x7F;
            let len = hdr & 0x1FF;
            if ty == 0 || (off + 2 + len as usize) > tvb.len() {
                break;
            }
            root.push(ProtoItem::new(f.tlv_type, FieldValue::U64(ty as u64), off, 1));
            root.push(ProtoItem::new(f.tlv_len, FieldValue::U64(len as u64), off, 2));
            let payload = tvb.bytes(off + 2, len as usize).unwrap_or(&[]);
            root.push(ProtoItem::new(f.tlv_payload, FieldValue::Bytes(payload.to_vec()), off + 2, len as usize));
            off += 2 + len as usize;
        }
        tree.push(root);
        DissectResult::Ok(off)
    }
}
