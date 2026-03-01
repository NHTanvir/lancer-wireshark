//! RIP v1/v2 — command + version.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { command: FieldId, version: FieldId }

#[derive(Default)] pub struct RipDissector;
impl Dissector for RipDissector {
    fn name(&self) -> &'static str { "rip" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Routing Information Protocol", "rip", "rip");
        let f = Fields {
            command: reg.register_field(ProtoField::simple("rip.command", "Command", FieldType::U8, FieldDisplay::BaseDec)),
            version: reg.register_field(ProtoField::simple("rip.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "rip".into();
        tree.append_proto("rip");
        let mut root = ProtoItem::subtree(f.command, "RIP".into(), 0, 4);
        root.push(ProtoItem::new(f.command, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.version, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        tree.push(root);
        DissectResult::Ok(4)
    }
}
