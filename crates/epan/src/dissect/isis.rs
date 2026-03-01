//! IS-IS — surface common header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { irpd: FieldId, header_len: FieldId, type_field: FieldId, version: FieldId }

#[derive(Default)] pub struct IsisDissector;
impl Dissector for IsisDissector {
    fn name(&self) -> &'static str { "isis" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("ISO 10589 IS-IS", "isis", "isis");
        let f = Fields {
            irpd: reg.register_field(ProtoField::simple("isis.irpd", "Intra-domain Routing Protocol Disc.", FieldType::U8, FieldDisplay::BaseHex)),
            header_len: reg.register_field(ProtoField::simple("isis.header_length", "PDU Header Length", FieldType::U8, FieldDisplay::BaseDec)),
            type_field: reg.register_field(ProtoField::simple("isis.type", "PDU Type", FieldType::U8, FieldDisplay::BaseDec)),
            version: reg.register_field(ProtoField::simple("isis.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "isis".into();
        tree.append_proto("isis");
        let mut root = ProtoItem::subtree(f.irpd, "IS-IS".into(), 0, 8);
        root.push(ProtoItem::new(f.irpd, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.header_len, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.version, FieldValue::U64(tvb.u8(2).unwrap_or(0) as u64), 2, 1));
        root.push(ProtoItem::new(f.type_field, FieldValue::U64(tvb.u8(4).unwrap_or(0) as u64), 4, 1));
        tree.push(root);
        DissectResult::Ok(8)
    }
}
