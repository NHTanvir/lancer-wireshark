//! STUN — RFC 5389 header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, length: FieldId, cookie: FieldId, tid: FieldId }

#[derive(Default)] pub struct StunDissector;
impl Dissector for StunDissector {
    fn name(&self) -> &'static str { "stun" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Session Traversal Utilities for NAT", "stun", "stun");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("stun.type", "Message Type", FieldType::U16, FieldDisplay::BaseHex)),
            length: reg.register_field(ProtoField::simple("stun.length", "Message Length", FieldType::U16, FieldDisplay::BaseDec)),
            cookie: reg.register_field(ProtoField::simple("stun.cookie", "Magic Cookie", FieldType::U32, FieldDisplay::BaseHex)),
            tid: reg.register_field(ProtoField::simple("stun.id", "Transaction ID", FieldType::Bytes, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 20 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "stun".into();
        tree.append_proto("stun");
        let mut root = ProtoItem::subtree(f.ty, "STUN".into(), 0, 20);
        root.push(ProtoItem::new(f.ty, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.cookie, FieldValue::U64(tvb.u32_be(4).unwrap_or(0) as u64), 4, 4));
        root.push(ProtoItem::new(f.tid, FieldValue::Bytes(tvb.bytes(8, 12).unwrap_or(&[]).to_vec()), 8, 12));
        tree.push(root);
        DissectResult::Ok(20)
    }
}
