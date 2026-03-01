//! Modbus/TCP — MBAP header + function code.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { trans: FieldId, proto: FieldId, length: FieldId, unit: FieldId, function: FieldId }

#[derive(Default)] pub struct ModbusDissector;
impl Dissector for ModbusDissector {
    fn name(&self) -> &'static str { "modbus" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Modbus", "modbus", "modbus");
        let f = Fields {
            trans: reg.register_field(ProtoField::simple("modbus.trans_id", "Transaction Identifier", FieldType::U16, FieldDisplay::BaseDec)),
            proto: reg.register_field(ProtoField::simple("modbus.prot_id", "Protocol Identifier", FieldType::U16, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("modbus.len", "Length", FieldType::U16, FieldDisplay::BaseDec)),
            unit: reg.register_field(ProtoField::simple("modbus.unit_id", "Unit Identifier", FieldType::U8, FieldDisplay::BaseDec)),
            function: reg.register_field(ProtoField::simple("modbus.func_code", "Function Code", FieldType::U8, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "modbus".into();
        tree.append_proto("modbus");
        let mut root = ProtoItem::subtree(f.trans, "Modbus".into(), 0, 8);
        root.push(ProtoItem::new(f.trans, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.proto, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u16_be(4).unwrap_or(0) as u64), 4, 2));
        root.push(ProtoItem::new(f.unit, FieldValue::U64(tvb.u8(6).unwrap_or(0) as u64), 6, 1));
        root.push(ProtoItem::new(f.function, FieldValue::U64(tvb.u8(7).unwrap_or(0) as u64), 7, 1));
        tree.push(root);
        DissectResult::Ok(8)
    }
}
