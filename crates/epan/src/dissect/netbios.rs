//! NetBIOS Name Service — header surface.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { tid: FieldId, flags: FieldId }

#[derive(Default)] pub struct NetbiosDissector;
impl Dissector for NetbiosDissector {
    fn name(&self) -> &'static str { "netbios" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("NetBIOS", "netbios", "netbios");
        let f = Fields {
            tid: reg.register_field(ProtoField::simple("netbios.id", "Transaction ID", FieldType::U16, FieldDisplay::BaseHex)),
            flags: reg.register_field(ProtoField::simple("netbios.flags", "Flags", FieldType::U16, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "netbios".into();
        tree.append_proto("netbios");
        let mut root = ProtoItem::subtree(f.tid, "NetBIOS Name Service".into(), 0, 4);
        root.push(ProtoItem::new(f.tid, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.flags, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        tree.push(root);
        DissectResult::Ok(4)
    }
}
