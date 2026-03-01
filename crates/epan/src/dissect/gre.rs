//! GRE — Generic Routing Encapsulation.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { flags: FieldId, proto: FieldId }

#[derive(Default)] pub struct GreDissector;
impl Dissector for GreDissector {
    fn name(&self) -> &'static str { "gre" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Generic Routing Encapsulation", "gre", "gre");
        let f = Fields {
            flags: reg.register_field(ProtoField::simple("gre.flags", "Flags+Version", FieldType::U16, FieldDisplay::BaseHex)),
            proto: reg.register_field(ProtoField::simple("gre.proto", "Protocol Type", FieldType::U16, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "gre".into();
        tree.append_proto("gre");
        let mut root = ProtoItem::subtree(f.proto, "GRE".into(), 0, 4);
        root.push(ProtoItem::new(f.flags, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.proto, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        tree.push(root);
        DissectResult::Ok(4)
    }
}
