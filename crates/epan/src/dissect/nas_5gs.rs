//! NAS-5GS (Non-Access Stratum for 5G).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<FieldId> = OnceCell::new();

#[derive(Default)] pub struct Nas5gsDissector;
impl Dissector for Nas5gsDissector {
    fn name(&self) -> &'static str { "nas_5gs" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("NAS-5GS", "nas-5gs", "nas-5gs");
        let _ = F.set(reg.register_field(ProtoField::simple("nas_5gs.msg_type", "Message Type", FieldType::U8, FieldDisplay::BaseHex)));
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 2 { return DissectResult::NeedMoreData; }
        let fid = *F.get().unwrap();
        pinfo.current_proto = "nas_5gs".into();
        tree.append_proto("nas-5gs");
        let mut root = ProtoItem::subtree(fid, "NAS-5GS".into(), 0, 2);
        root.push(ProtoItem::new(fid, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
