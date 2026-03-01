//! X2AP (LTE X2 Application Protocol) — placeholder.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<FieldId> = OnceCell::new();

#[derive(Default)] pub struct X2apDissector;
impl Dissector for X2apDissector {
    fn name(&self) -> &'static str { "x2ap" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("X2AP", "x2ap", "x2ap");
        let _ = F.set(reg.register_field(ProtoField::simple("x2ap.procedureCode", "procedureCode", FieldType::U8, FieldDisplay::BaseDec)));
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 2 { return DissectResult::NeedMoreData; }
        let fid = *F.get().unwrap();
        pinfo.current_proto = "x2ap".into();
        tree.append_proto("x2ap");
        let mut root = ProtoItem::subtree(fid, "X2AP".into(), 0, 2);
        root.push(ProtoItem::new(fid, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
