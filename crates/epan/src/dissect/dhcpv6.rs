//! DHCPv6 — message-type + transaction-id surface.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { msgtype: FieldId, xid: FieldId }

#[derive(Default)] pub struct Dhcpv6Dissector;
impl Dissector for Dhcpv6Dissector {
    fn name(&self) -> &'static str { "dhcpv6" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("DHCPv6", "dhcpv6", "dhcpv6");
        let f = Fields {
            msgtype: reg.register_field(ProtoField::simple("dhcpv6.msgtype", "Message type", FieldType::U8, FieldDisplay::BaseDec)),
            xid: reg.register_field(ProtoField::simple("dhcpv6.xid", "Transaction ID", FieldType::U32, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "dhcpv6".into();
        tree.append_proto("dhcpv6");
        let mt = tvb.u8(0).unwrap_or(0);
        let xid = tvb.u24_be(1).unwrap_or(0);
        let mut root = ProtoItem::subtree(f.msgtype, "DHCPv6".into(), 0, 4);
        root.push(ProtoItem::new(f.msgtype, FieldValue::U64(mt as u64), 0, 1));
        root.push(ProtoItem::new(f.xid, FieldValue::U64(xid as u64), 1, 3));
        tree.push(root);
        DissectResult::Ok(4)
    }
}
