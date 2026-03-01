//! Kafka wire — request/response size + API key/version.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { length: FieldId, api_key: FieldId, api_version: FieldId, correlation_id: FieldId }

#[derive(Default)] pub struct KafkaDissector;
impl Dissector for KafkaDissector {
    fn name(&self) -> &'static str { "kafka" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Apache Kafka", "kafka", "kafka");
        let f = Fields {
            length: reg.register_field(ProtoField::simple("kafka.len", "Length", FieldType::U32, FieldDisplay::BaseDec)),
            api_key: reg.register_field(ProtoField::simple("kafka.api_key", "API key", FieldType::U16, FieldDisplay::BaseDec)),
            api_version: reg.register_field(ProtoField::simple("kafka.api_version", "API version", FieldType::U16, FieldDisplay::BaseDec)),
            correlation_id: reg.register_field(ProtoField::simple("kafka.correlation_id", "Correlation ID", FieldType::U32, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 12 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "kafka".into();
        tree.append_proto("kafka");
        let mut root = ProtoItem::subtree(f.length, "Kafka".into(), 0, 12);
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u32_be(0).unwrap_or(0) as u64), 0, 4));
        root.push(ProtoItem::new(f.api_key, FieldValue::U64(tvb.u16_be(4).unwrap_or(0) as u64), 4, 2));
        root.push(ProtoItem::new(f.api_version, FieldValue::U64(tvb.u16_be(6).unwrap_or(0) as u64), 6, 2));
        root.push(ProtoItem::new(f.correlation_id, FieldValue::U64(tvb.u32_be(8).unwrap_or(0) as u64), 8, 4));
        tree.push(root);
        DissectResult::Ok(12)
    }
}
