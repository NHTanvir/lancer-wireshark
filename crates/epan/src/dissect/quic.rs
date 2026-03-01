//! QUIC — header dissection only (no payload decryption without a keylog).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { first: FieldId, version: FieldId, dcid_len: FieldId, dcid: FieldId, scid_len: FieldId, scid: FieldId }

#[derive(Default)] pub struct QuicDissector;
impl Dissector for QuicDissector {
    fn name(&self) -> &'static str { "quic" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("QUIC IETF", "quic", "quic");
        let f = Fields {
            first: reg.register_field(ProtoField::simple("quic.first_byte", "First Byte", FieldType::U8, FieldDisplay::BaseHex)),
            version: reg.register_field(ProtoField::simple("quic.version", "Version", FieldType::U32, FieldDisplay::BaseHex)),
            dcid_len: reg.register_field(ProtoField::simple("quic.dcid_len", "Destination CID length", FieldType::U8, FieldDisplay::BaseDec)),
            dcid: reg.register_field(ProtoField::simple("quic.dcid", "Destination Connection ID", FieldType::Bytes, FieldDisplay::SepColon)),
            scid_len: reg.register_field(ProtoField::simple("quic.scid_len", "Source CID length", FieldType::U8, FieldDisplay::BaseDec)),
            scid: reg.register_field(ProtoField::simple("quic.scid", "Source Connection ID", FieldType::Bytes, FieldDisplay::SepColon)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 7 { return DissectResult::NeedMoreData; }
        let first = tvb.u8(0).unwrap_or(0);
        let long = first & 0x80 != 0;
        let f = F.get().unwrap();
        pinfo.current_proto = "quic".into();
        tree.append_proto("quic");
        let mut root = ProtoItem::subtree(f.first, "QUIC".into(), 0, tvb.len());
        root.push(ProtoItem::new(f.first, FieldValue::U64(first as u64), 0, 1));
        if long {
            let version = tvb.u32_be(1).unwrap_or(0);
            root.push(ProtoItem::new(f.version, FieldValue::U64(version as u64), 1, 4));
            let dcil = tvb.u8(5).unwrap_or(0) as usize;
            if 6 + dcil > tvb.len() { return DissectResult::NeedMoreData; }
            root.push(ProtoItem::new(f.dcid_len, FieldValue::U64(dcil as u64), 5, 1));
            root.push(ProtoItem::new(f.dcid, FieldValue::Bytes(tvb.bytes(6, dcil).unwrap_or(&[]).to_vec()), 6, dcil));
            let scil = tvb.u8(6 + dcil).unwrap_or(0) as usize;
            if 7 + dcil + scil > tvb.len() { return DissectResult::NeedMoreData; }
            root.push(ProtoItem::new(f.scid_len, FieldValue::U64(scil as u64), 6 + dcil, 1));
            root.push(ProtoItem::new(f.scid, FieldValue::Bytes(tvb.bytes(7 + dcil, scil).unwrap_or(&[]).to_vec()), 7 + dcil, scil));
            pinfo.set_info(format!("QUIC long-header v=0x{version:x}"));
        } else {
            pinfo.set_info("QUIC short-header (1-RTT)".into());
        }
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
