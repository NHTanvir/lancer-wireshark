//! PostgreSQL — message type + length.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { msgtype: FieldId, length: FieldId }

#[derive(Default)] pub struct PostgresDissector;
impl Dissector for PostgresDissector {
    fn name(&self) -> &'static str { "postgres" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("PostgreSQL", "pgsql", "pgsql");
        let f = Fields {
            msgtype: reg.register_field(ProtoField::simple("pgsql.type", "Message Type", FieldType::U8, FieldDisplay::BaseHex)),
            length: reg.register_field(ProtoField::simple("pgsql.length", "Length", FieldType::U32, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 5 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "pgsql".into();
        tree.append_proto("pgsql");
        let mut root = ProtoItem::subtree(f.msgtype, "PostgreSQL".into(), 0, 5);
        root.push(ProtoItem::new(f.msgtype, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u32_be(1).unwrap_or(0) as u64), 1, 4));
        tree.push(root);
        DissectResult::Ok(5)
    }
}
