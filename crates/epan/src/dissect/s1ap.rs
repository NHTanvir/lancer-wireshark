//! S1AP (LTE S1 Application Protocol) — placeholder header surface.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<FieldId> = OnceCell::new();

#[derive(Default)] pub struct S1apDissector;
impl Dissector for S1apDissector {
    fn name(&self) -> &'static str { "s1ap" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("S1 Application Protocol", "s1ap", "s1ap");
        let _ = F.set(reg.register_field(ProtoField::simple("s1ap.procedureCode", "procedureCode", FieldType::U8, FieldDisplay::BaseDec)));
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 2 { return DissectResult::NeedMoreData; }
        let fid = *F.get().unwrap();
        pinfo.current_proto = "s1ap".into();
        tree.append_proto("s1ap");
        let mut root = ProtoItem::subtree(fid, "S1AP".into(), 0, 2);
        root.push(ProtoItem::new(fid, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
