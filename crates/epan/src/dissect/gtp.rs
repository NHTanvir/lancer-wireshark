//! GTP v1/v2 — header decode.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { flags: FieldId, mtype: FieldId, length: FieldId, teid: FieldId }

#[derive(Default)] pub struct GtpDissector;
impl Dissector for GtpDissector {
    fn name(&self) -> &'static str { "gtp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("GPRS Tunneling Protocol", "gtp", "gtp");
        let f = Fields {
            flags: reg.register_field(ProtoField::simple("gtp.flags", "Flags", FieldType::U8, FieldDisplay::BaseHex)),
            mtype: reg.register_field(ProtoField::simple("gtp.message_type", "Message Type", FieldType::U8, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("gtp.length", "Length", FieldType::U16, FieldDisplay::BaseDec)),
            teid: reg.register_field(ProtoField::simple("gtp.teid", "TEID", FieldType::U32, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "gtp".into();
        tree.append_proto("gtp");
        let mut root = ProtoItem::subtree(f.flags, "GTP".into(), 0, 8);
        root.push(ProtoItem::new(f.flags, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.mtype, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.teid, FieldValue::U64(tvb.u32_be(4).unwrap_or(0) as u64), 4, 4));
        tree.push(root);
        DissectResult::Ok(8)
    }
}
