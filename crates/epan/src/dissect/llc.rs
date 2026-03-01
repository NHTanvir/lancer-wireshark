//! IEEE 802.2 LLC header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { dsap: FieldId, ssap: FieldId, ctrl: FieldId }

#[derive(Default)] pub struct LlcDissector;
impl Dissector for LlcDissector {
    fn name(&self) -> &'static str { "llc" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Logical-Link Control", "llc", "llc");
        let f = Fields {
            dsap: reg.register_field(ProtoField::simple("llc.dsap", "DSAP", FieldType::U8, FieldDisplay::BaseHex)),
            ssap: reg.register_field(ProtoField::simple("llc.ssap", "SSAP", FieldType::U8, FieldDisplay::BaseHex)),
            ctrl: reg.register_field(ProtoField::simple("llc.control", "Control", FieldType::U8, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 3 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "llc".into();
        tree.append_proto("llc");
        let mut root = ProtoItem::subtree(f.dsap, "LLC".into(), 0, 3);
        root.push(ProtoItem::new(f.dsap, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.ssap, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.ctrl, FieldValue::U64(tvb.u8(2).unwrap_or(0) as u64), 2, 1));
        tree.push(root);
        DissectResult::Ok(3)
    }
}
