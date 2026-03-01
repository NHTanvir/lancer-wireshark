//! RADIUS — code + identifier + length + authenticator.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { code: FieldId, id: FieldId, length: FieldId }

#[derive(Default)] pub struct RadiusDissector;
impl Dissector for RadiusDissector {
    fn name(&self) -> &'static str { "radius" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("RADIUS", "radius", "radius");
        let f = Fields {
            code: reg.register_field(ProtoField::simple("radius.code", "Code", FieldType::U8, FieldDisplay::BaseDec)),
            id: reg.register_field(ProtoField::simple("radius.id", "Identifier", FieldType::U8, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("radius.length", "Length", FieldType::U16, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 20 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "radius".into();
        tree.append_proto("radius");
        let mut root = ProtoItem::subtree(f.code, "RADIUS".into(), 0, 20);
        root.push(ProtoItem::new(f.code, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.id, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        tree.push(root);
        DissectResult::Ok(20)
    }
}
