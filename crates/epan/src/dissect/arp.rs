//! ARP dissector.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct Fields {
    htype: FieldId,
    ptype: FieldId,
    hlen: FieldId,
    plen: FieldId,
    opcode: FieldId,
    src_hw: FieldId,
    src_proto: FieldId,
    dst_hw: FieldId,
    dst_proto: FieldId,
}

#[derive(Default)]
pub struct ArpDissector;

impl Dissector for ArpDissector {
    fn name(&self) -> &'static str {
        "arp"
    }

    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Address Resolution Protocol", "arp", "arp");
        let f = Fields {
            htype: reg.register_field(ProtoField::simple("arp.hw.type", "Hardware type", FieldType::U16, FieldDisplay::BaseDec)),
            ptype: reg.register_field(ProtoField::simple("arp.proto.type", "Protocol type", FieldType::U16, FieldDisplay::BaseHex)),
            hlen: reg.register_field(ProtoField::simple("arp.hw.size", "Hardware size", FieldType::U8, FieldDisplay::BaseDec)),
            plen: reg.register_field(ProtoField::simple("arp.proto.size", "Protocol size", FieldType::U8, FieldDisplay::BaseDec)),
            opcode: reg.register_field(ProtoField::simple("arp.opcode", "Opcode", FieldType::U16, FieldDisplay::BaseDec)),
            src_hw: reg.register_field(ProtoField::simple("arp.src.hw_mac", "Sender MAC address", FieldType::Ether, FieldDisplay::SepColon)),
            src_proto: reg.register_field(ProtoField::simple("arp.src.proto_ipv4", "Sender IP address", FieldType::Ipv4, FieldDisplay::BaseNone)),
            dst_hw: reg.register_field(ProtoField::simple("arp.dst.hw_mac", "Target MAC address", FieldType::Ether, FieldDisplay::SepColon)),
            dst_proto: reg.register_field(ProtoField::simple("arp.dst.proto_ipv4", "Target IP address", FieldType::Ipv4, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }

    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 28 {
            return DissectResult::NeedMoreData;
        }
        let f = F.get().unwrap();
        let htype = tvb.u16_be(0).unwrap_or(0);
        let ptype = tvb.u16_be(2).unwrap_or(0);
        let hlen = tvb.u8(4).unwrap_or(0);
        let plen = tvb.u8(5).unwrap_or(0);
        let op = tvb.u16_be(6).unwrap_or(0);
        let sha = tvb.mac(8).unwrap_or([0; 6]);
        let spa = tvb.ipv4(14).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        let tha = tvb.mac(18).unwrap_or([0; 6]);
        let tpa = tvb.ipv4(24).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

        let op_str = match op {
            1 => "request",
            2 => "reply",
            3 => "RARP request",
            4 => "RARP reply",
            _ => "?",
        };
        pinfo.set_info(format!("{op_str}: {spa} → {tpa}"));
        pinfo.current_proto = "arp".into();
        tree.append_proto("arp");

        let mut root = ProtoItem::subtree(f.opcode, format!("Address Resolution Protocol ({op_str})"), 0, 28);
        root.push(ProtoItem::new(f.htype, FieldValue::U64(htype as u64), 0, 2));
        root.push(ProtoItem::new(f.ptype, FieldValue::U64(ptype as u64), 2, 2));
        root.push(ProtoItem::new(f.hlen, FieldValue::U64(hlen as u64), 4, 1));
        root.push(ProtoItem::new(f.plen, FieldValue::U64(plen as u64), 5, 1));
        root.push(ProtoItem::new(f.opcode, FieldValue::U64(op as u64), 6, 2));
        root.push(ProtoItem::new(f.src_hw, FieldValue::Ether(sha), 8, 6));
        root.push(ProtoItem::new(f.src_proto, FieldValue::Ipv4(spa), 14, 4));
        root.push(ProtoItem::new(f.dst_hw, FieldValue::Ether(tha), 18, 6));
        root.push(ProtoItem::new(f.dst_proto, FieldValue::Ipv4(tpa), 24, 4));
        tree.push(root);
        DissectResult::Ok(28)
    }
}
