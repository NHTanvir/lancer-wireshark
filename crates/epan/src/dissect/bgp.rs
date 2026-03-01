//! BGP — common header (marker + length + type).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, length: FieldId }

#[derive(Default)] pub struct BgpDissector;
impl Dissector for BgpDissector {
    fn name(&self) -> &'static str { "bgp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Border Gateway Protocol", "bgp", "bgp");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("bgp.type", "Type", FieldType::U8, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("bgp.length", "Length", FieldType::U16, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 19 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "bgp".into();
        tree.append_proto("bgp");
        let mut root = ProtoItem::subtree(f.ty, "BGP".into(), 0, 19);
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u16_be(16).unwrap_or(0) as u64), 16, 2));
        root.push(ProtoItem::new(f.ty, FieldValue::U64(tvb.u8(18).unwrap_or(0) as u64), 18, 1));
        tree.push(root);
        DissectResult::Ok(19)
    }
}
