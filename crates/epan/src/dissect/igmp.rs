//! IGMP header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, group: FieldId }

#[derive(Default)] pub struct IgmpDissector;
impl Dissector for IgmpDissector {
    fn name(&self) -> &'static str { "igmp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Internet Group Management Protocol", "igmp", "igmp");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("igmp.type", "Type", FieldType::U8, FieldDisplay::BaseHex)),
            group: reg.register_field(ProtoField::simple("igmp.maddr", "Multicast Address", FieldType::Ipv4, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "igmp".into();
        tree.append_proto("igmp");
        let mut root = ProtoItem::subtree(f.ty, "IGMP".into(), 0, 8);
        root.push(ProtoItem::new(f.ty, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.group, FieldValue::Ipv4(tvb.ipv4(4).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)), 4, 4));
        tree.push(root);
        DissectResult::Ok(8)
    }
}
