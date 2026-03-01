//! IEEE 802.1Q VLAN tag dissector.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct Fields {
    pri: FieldId,
    dei: FieldId,
    id: FieldId,
    typ: FieldId,
}

#[derive(Default)]
pub struct VlanDissector;

impl Dissector for VlanDissector {
    fn name(&self) -> &'static str {
        "vlan"
    }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("802.1Q VLAN", "vlan", "vlan");
        let f = Fields {
            pri: reg.register_field(ProtoField::simple("vlan.priority", "Priority", FieldType::U8, FieldDisplay::BaseDec)),
            dei: reg.register_field(ProtoField::simple("vlan.dei", "DEI", FieldType::Boolean, FieldDisplay::BaseNone)),
            id: reg.register_field(ProtoField::simple("vlan.id", "ID", FieldType::U16, FieldDisplay::BaseDec)),
            typ: reg.register_field(ProtoField::simple("vlan.etype", "Type", FieldType::U16, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 {
            return DissectResult::NeedMoreData;
        }
        let f = F.get().unwrap();
        let tci = tvb.u16_be(0).unwrap_or(0);
        let pri = (tci >> 13) as u8;
        let dei = (tci >> 12) & 1 != 0;
        let id = tci & 0x0FFF;
        let etype = tvb.u16_be(2).unwrap_or(0);
        pinfo.vlan_id = Some(id);
        tree.append_proto("vlan");
        let mut root = ProtoItem::subtree(f.id, format!("802.1Q VLAN (id {id})"), 0, 4);
        root.push(ProtoItem::new(f.pri, FieldValue::U64(pri as u64), 0, 1));
        root.push(ProtoItem::new(f.dei, FieldValue::Bool(dei), 0, 1));
        root.push(ProtoItem::new(f.id, FieldValue::U64(id as u64), 0, 2));
        root.push(ProtoItem::new(f.typ, FieldValue::U64(etype as u64), 2, 2));
        tree.push(root);
        DissectResult::Ok(4)
    }
}
