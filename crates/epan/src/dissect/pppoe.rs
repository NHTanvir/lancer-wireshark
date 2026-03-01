//! PPPoE — Discovery + Session.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { vt: FieldId, code: FieldId, sid: FieldId, len: FieldId }

#[derive(Default)] pub struct PppoeDissector;
impl Dissector for PppoeDissector {
    fn name(&self) -> &'static str { "pppoe" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("PPP over Ethernet", "pppoe", "pppoe");
        let f = Fields {
            vt: reg.register_field(ProtoField::simple("pppoe.version_type", "Version+Type", FieldType::U8, FieldDisplay::BaseHex)),
            code: reg.register_field(ProtoField::simple("pppoe.code", "Code", FieldType::U8, FieldDisplay::BaseHex)),
            sid: reg.register_field(ProtoField::simple("pppoe.session_id", "Session ID", FieldType::U16, FieldDisplay::BaseHex)),
            len: reg.register_field(ProtoField::simple("pppoe.payload_length", "Payload Length", FieldType::U16, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 6 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "pppoe".into();
        tree.append_proto("pppoe");
        let mut root = ProtoItem::subtree(f.code, "PPPoE".into(), 0, 6);
        root.push(ProtoItem::new(f.vt, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.code, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.sid, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.len, FieldValue::U64(tvb.u16_be(4).unwrap_or(0) as u64), 4, 2));
        tree.push(root);
        DissectResult::Ok(6)
    }
}
