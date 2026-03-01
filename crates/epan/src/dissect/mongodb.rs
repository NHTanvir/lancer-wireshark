//! MongoDB wire — header: messageLength, requestID, responseTo, opCode.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { length: FieldId, req_id: FieldId, resp_to: FieldId, op: FieldId }

#[derive(Default)] pub struct MongoDissector;
impl Dissector for MongoDissector {
    fn name(&self) -> &'static str { "mongo" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("MongoDB Wire", "mongo", "mongo");
        let f = Fields {
            length: reg.register_field(ProtoField::simple("mongo.length", "Message Length", FieldType::U32, FieldDisplay::BaseDec)),
            req_id: reg.register_field(ProtoField::simple("mongo.request_id", "Request ID", FieldType::U32, FieldDisplay::BaseDec)),
            resp_to: reg.register_field(ProtoField::simple("mongo.response_to", "Response To", FieldType::U32, FieldDisplay::BaseDec)),
            op: reg.register_field(ProtoField::simple("mongo.opcode", "Op Code", FieldType::U32, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 16 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "mongodb".into();
        tree.append_proto("mongo");
        let mut root = ProtoItem::subtree(f.length, "MongoDB".into(), 0, 16);
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u32_le(0).unwrap_or(0) as u64), 0, 4));
        root.push(ProtoItem::new(f.req_id, FieldValue::U64(tvb.u32_le(4).unwrap_or(0) as u64), 4, 4));
        root.push(ProtoItem::new(f.resp_to, FieldValue::U64(tvb.u32_le(8).unwrap_or(0) as u64), 8, 4));
        root.push(ProtoItem::new(f.op, FieldValue::U64(tvb.u32_le(12).unwrap_or(0) as u64), 12, 4));
        tree.push(root);
        DissectResult::Ok(16)
    }
}
