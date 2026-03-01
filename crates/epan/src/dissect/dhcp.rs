//! DHCPv4 / BOOTP — fixed header plus option-tag walker.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { op: FieldId, htype: FieldId, hops: FieldId, xid: FieldId, ciaddr: FieldId, yiaddr: FieldId, siaddr: FieldId, giaddr: FieldId, chaddr: FieldId, opt_type: FieldId, opt_len: FieldId, opt_value: FieldId }

#[derive(Default)] pub struct DhcpDissector;
impl Dissector for DhcpDissector {
    fn name(&self) -> &'static str { "dhcp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Dynamic Host Configuration Protocol", "bootp", "bootp");
        let f = Fields {
            op: reg.register_field(ProtoField::simple("bootp.op", "Op", FieldType::U8, FieldDisplay::BaseDec)),
            htype: reg.register_field(ProtoField::simple("bootp.htype", "Hardware type", FieldType::U8, FieldDisplay::BaseDec)),
            hops: reg.register_field(ProtoField::simple("bootp.hops", "Hops", FieldType::U8, FieldDisplay::BaseDec)),
            xid: reg.register_field(ProtoField::simple("bootp.xid", "Transaction ID", FieldType::U32, FieldDisplay::BaseHex)),
            ciaddr: reg.register_field(ProtoField::simple("bootp.ip.client", "Client IP", FieldType::Ipv4, FieldDisplay::BaseNone)),
            yiaddr: reg.register_field(ProtoField::simple("bootp.ip.your", "Your IP", FieldType::Ipv4, FieldDisplay::BaseNone)),
            siaddr: reg.register_field(ProtoField::simple("bootp.ip.server", "Server IP", FieldType::Ipv4, FieldDisplay::BaseNone)),
            giaddr: reg.register_field(ProtoField::simple("bootp.ip.relay", "Relay IP", FieldType::Ipv4, FieldDisplay::BaseNone)),
            chaddr: reg.register_field(ProtoField::simple("bootp.hw.mac_addr", "Client MAC", FieldType::Ether, FieldDisplay::SepColon)),
            opt_type: reg.register_field(ProtoField::simple("bootp.option.type", "Option Tag", FieldType::U8, FieldDisplay::BaseDec)),
            opt_len: reg.register_field(ProtoField::simple("bootp.option.length", "Option Length", FieldType::U8, FieldDisplay::BaseDec)),
            opt_value: reg.register_field(ProtoField::simple("bootp.option.value", "Option Value", FieldType::Bytes, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 240 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "dhcp".into();
        tree.append_proto("bootp");
        let mut root = ProtoItem::subtree(f.op, "Dynamic Host Configuration Protocol".into(), 0, tvb.len());
        root.push(ProtoItem::new(f.op, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.htype, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.hops, FieldValue::U64(tvb.u8(3).unwrap_or(0) as u64), 3, 1));
        root.push(ProtoItem::new(f.xid, FieldValue::U64(tvb.u32_be(4).unwrap_or(0) as u64), 4, 4));
        root.push(ProtoItem::new(f.ciaddr, FieldValue::Ipv4(tvb.ipv4(12).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)), 12, 4));
        root.push(ProtoItem::new(f.yiaddr, FieldValue::Ipv4(tvb.ipv4(16).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)), 16, 4));
        root.push(ProtoItem::new(f.siaddr, FieldValue::Ipv4(tvb.ipv4(20).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)), 20, 4));
        root.push(ProtoItem::new(f.giaddr, FieldValue::Ipv4(tvb.ipv4(24).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)), 24, 4));
        root.push(ProtoItem::new(f.chaddr, FieldValue::Ether(tvb.mac(28).unwrap_or([0; 6])), 28, 6));
        // options
        let mut p = 240usize;
        if tvb.u32_be(236).unwrap_or(0) == 0x63825363 {
            while p + 1 <= tvb.len() {
                let tag = tvb.u8(p).unwrap_or(0);
                if tag == 0xFF { break; }
                if tag == 0 { p += 1; continue; }
                let len = tvb.u8(p + 1).unwrap_or(0) as usize;
                if p + 2 + len > tvb.len() { break; }
                let value = tvb.bytes(p + 2, len).unwrap_or(&[]);
                let mut o = ProtoItem::subtree(f.opt_type, format!("Option {tag}"), p, 2 + len);
                o.push(ProtoItem::new(f.opt_type, FieldValue::U64(tag as u64), p, 1));
                o.push(ProtoItem::new(f.opt_len, FieldValue::U64(len as u64), p + 1, 1));
                o.push(ProtoItem::new(f.opt_value, FieldValue::Bytes(value.to_vec()), p + 2, len));
                root.push(o);
                p += 2 + len;
            }
        }
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
