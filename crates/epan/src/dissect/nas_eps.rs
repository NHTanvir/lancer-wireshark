//! NAS-EPS (Non-Access Stratum for LTE).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<FieldId> = OnceCell::new();

#[derive(Default)] pub struct NasEpsDissector;
impl Dissector for NasEpsDissector {
    fn name(&self) -> &'static str { "nas_eps" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("NAS-EPS", "nas-eps", "nas-eps");
        let _ = F.set(reg.register_field(ProtoField::simple("nas_eps.msg_type", "Message Type", FieldType::U8, FieldDisplay::BaseHex)));
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 2 { return DissectResult::NeedMoreData; }
        let fid = *F.get().unwrap();
        pinfo.current_proto = "nas_eps".into();
        tree.append_proto("nas-eps");
        let mut root = ProtoItem::subtree(fid, "NAS-EPS".into(), 0, 2);
        root.push(ProtoItem::new(fid, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
