//! SCTP header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { srcport: FieldId, dstport: FieldId, vtag: FieldId, csum: FieldId }

#[derive(Default)] pub struct SctpDissector;
impl Dissector for SctpDissector {
    fn name(&self) -> &'static str { "sctp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Stream Control Transmission Protocol", "sctp", "sctp");
        let f = Fields {
            srcport: reg.register_field(ProtoField::simple("sctp.srcport", "Source Port", FieldType::U16, FieldDisplay::BaseDec)),
            dstport: reg.register_field(ProtoField::simple("sctp.dstport", "Destination Port", FieldType::U16, FieldDisplay::BaseDec)),
            vtag: reg.register_field(ProtoField::simple("sctp.verification_tag", "Verification tag", FieldType::U32, FieldDisplay::BaseHex)),
            csum: reg.register_field(ProtoField::simple("sctp.checksum", "Checksum", FieldType::U32, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 12 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "sctp".into();
        tree.append_proto("sctp");
        let mut root = ProtoItem::subtree(f.srcport, "Stream Control Transmission Protocol".into(), 0, 12);
        root.push(ProtoItem::new(f.srcport, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.dstport, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.vtag, FieldValue::U64(tvb.u32_be(4).unwrap_or(0) as u64), 4, 4));
        root.push(ProtoItem::new(f.csum, FieldValue::U64(tvb.u32_be(8).unwrap_or(0) as u64), 8, 4));
        tree.push(root);
        DissectResult::Ok(12)
    }
}
