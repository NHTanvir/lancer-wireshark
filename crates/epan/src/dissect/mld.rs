//! MLD (Multicast Listener Discovery) — IPv6 group management.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, code: FieldId, max_resp: FieldId, mcast_addr: FieldId }

#[derive(Default)] pub struct MldDissector;
impl Dissector for MldDissector {
    fn name(&self) -> &'static str { "mld" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Multicast Listener Discovery", "mld", "mld");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("mld.type", "Type", FieldType::U8, FieldDisplay::BaseHex)),
            code: reg.register_field(ProtoField::simple("mld.code", "Code", FieldType::U8, FieldDisplay::BaseHex)),
            max_resp: reg.register_field(ProtoField::simple("mld.maximum_response_delay", "Maximum Response Delay", FieldType::U16, FieldDisplay::BaseDec)),
            mcast_addr: reg.register_field(ProtoField::simple("mld.multicast_address", "Multicast Address", FieldType::Ipv6, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 24 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "mld".into();
        tree.append_proto("mld");
        let mut root = ProtoItem::subtree(f.ty, "MLD".into(), 0, 24);
        root.push(ProtoItem::new(f.ty, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.code, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.max_resp, FieldValue::U64(tvb.u16_be(4).unwrap_or(0) as u64), 4, 2));
        root.push(ProtoItem::new(f.mcast_addr, FieldValue::Ipv6(tvb.ipv6(8).unwrap_or(std::net::Ipv6Addr::UNSPECIFIED)), 8, 16));
        tree.push(root);
        DissectResult::Ok(24)
    }
}
