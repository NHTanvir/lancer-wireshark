//! TURN (RFC 5766) — surfaces TURN message classes.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { msg_type: FieldId, msg_length: FieldId, msg_cookie: FieldId, msg_id: FieldId }

#[derive(Default)] pub struct TurnDissector;
impl Dissector for TurnDissector {
    fn name(&self) -> &'static str { "turn" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Traversal Using Relays around NAT", "turn", "turn");
        let f = Fields {
            msg_type: reg.register_field(ProtoField::simple("turn.type", "Message Type", FieldType::U16, FieldDisplay::BaseHex)),
            msg_length: reg.register_field(ProtoField::simple("turn.length", "Message Length", FieldType::U16, FieldDisplay::BaseDec)),
            msg_cookie: reg.register_field(ProtoField::simple("turn.cookie", "Cookie", FieldType::U32, FieldDisplay::BaseHex)),
            msg_id: reg.register_field(ProtoField::simple("turn.id", "Transaction ID", FieldType::Bytes, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 20 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "turn".into();
        tree.append_proto("turn");
        let mut root = ProtoItem::subtree(f.msg_type, "TURN".into(), 0, 20);
        root.push(ProtoItem::new(f.msg_type, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.msg_length, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.msg_cookie, FieldValue::U64(tvb.u32_be(4).unwrap_or(0) as u64), 4, 4));
        root.push(ProtoItem::new(f.msg_id, FieldValue::Bytes(tvb.bytes(8, 12).unwrap_or(&[]).to_vec()), 8, 12));
        tree.push(root);
        DissectResult::Ok(20)
    }
}
