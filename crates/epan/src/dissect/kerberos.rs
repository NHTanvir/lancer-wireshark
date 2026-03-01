//! Kerberos — surface application tag and message type only.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<FieldId> = OnceCell::new();

#[derive(Default)] pub struct KerberosDissector;
impl Dissector for KerberosDissector {
    fn name(&self) -> &'static str { "kerberos" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Kerberos", "kerberos", "kerberos");
        let _ = F.set(reg.register_field(ProtoField::simple("kerberos.msg_type", "Message Type", FieldType::U8, FieldDisplay::BaseDec)));
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 2 { return DissectResult::NeedMoreData; }
        let fid = *F.get().unwrap();
        pinfo.current_proto = "kerberos".into();
        tree.append_proto("kerberos");
        let app_tag = tvb.u8(0).unwrap_or(0);
        let mut root = ProtoItem::subtree(fid, "Kerberos".into(), 0, tvb.len());
        root.push(ProtoItem::new(fid, FieldValue::U64(app_tag as u64), 0, 1));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
