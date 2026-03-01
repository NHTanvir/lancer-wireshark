//! MySQL — packet length (3) + sequence (1).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { length: FieldId, seq: FieldId }

#[derive(Default)] pub struct MysqlDissector;
impl Dissector for MysqlDissector {
    fn name(&self) -> &'static str { "mysql" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("MySQL", "mysql", "mysql");
        let f = Fields {
            length: reg.register_field(ProtoField::simple("mysql.packet_length", "Packet Length", FieldType::U32, FieldDisplay::BaseDec)),
            seq: reg.register_field(ProtoField::simple("mysql.packet_number", "Packet Number", FieldType::U8, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "mysql".into();
        tree.append_proto("mysql");
        let length = (tvb.u8(0).unwrap_or(0) as u32)
            | ((tvb.u8(1).unwrap_or(0) as u32) << 8)
            | ((tvb.u8(2).unwrap_or(0) as u32) << 16);
        let seq = tvb.u8(3).unwrap_or(0);
        let mut root = ProtoItem::subtree(f.length, "MySQL".into(), 0, 4);
        root.push(ProtoItem::new(f.length, FieldValue::U64(length as u64), 0, 3));
        root.push(ProtoItem::new(f.seq, FieldValue::U64(seq as u64), 3, 1));
        tree.push(root);
        DissectResult::Ok(4)
    }
}
