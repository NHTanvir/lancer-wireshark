//! LDAP — ASN.1 BER, surface only message id + protocol op type.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { messageid: FieldId, protocol_op: FieldId }

#[derive(Default)] pub struct LdapDissector;
impl Dissector for LdapDissector {
    fn name(&self) -> &'static str { "ldap" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Lightweight Directory Access Protocol", "ldap", "ldap");
        let f = Fields {
            messageid: reg.register_field(ProtoField::simple("ldap.messageID", "MessageID", FieldType::U32, FieldDisplay::BaseDec)),
            protocol_op: reg.register_field(ProtoField::simple("ldap.protocolOp", "protocolOp", FieldType::U8, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "ldap".into();
        tree.append_proto("ldap");
        let mut root = ProtoItem::subtree(f.messageid, "LDAP".into(), 0, tvb.len());
        root.push(ProtoItem::new(f.messageid, FieldValue::U64(tvb.u8(3).unwrap_or(0) as u64), 0, 4));
        root.push(ProtoItem::new(f.protocol_op, FieldValue::U64(tvb.u8(tvb.len().saturating_sub(1)).unwrap_or(0) as u64), 0, 1));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
