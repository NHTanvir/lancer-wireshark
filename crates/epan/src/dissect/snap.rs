//! SNAP encapsulation header (5 bytes: OUI 3 + PID 2).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { oui: FieldId, pid: FieldId }

#[derive(Default)] pub struct SnapDissector;
impl Dissector for SnapDissector {
    fn name(&self) -> &'static str { "snap" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("SNAP", "snap", "snap");
        let f = Fields {
            oui: reg.register_field(ProtoField::simple("snap.oui", "OUI", FieldType::Bytes, FieldDisplay::SepColon)),
            pid: reg.register_field(ProtoField::simple("snap.pid", "PID", FieldType::U16, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 5 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "snap".into();
        tree.append_proto("snap");
        let oui = tvb.bytes(0, 3).unwrap_or(&[]);
        let pid = tvb.u16_be(3).unwrap_or(0);
        let mut root = ProtoItem::subtree(f.oui, "SNAP".into(), 0, 5);
        root.push(ProtoItem::new(f.oui, FieldValue::Bytes(oui.to_vec()), 0, 3));
        root.push(ProtoItem::new(f.pid, FieldValue::U64(pid as u64), 3, 2));
        tree.push(root);
        DissectResult::Ok(5)
    }
}
