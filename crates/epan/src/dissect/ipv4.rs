//! IPv4 dissector.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;
use std::net::IpAddr;

static F: OnceCell<Ipv4Fields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct Ipv4Fields {
    version: FieldId,
    ihl: FieldId,
    dscp: FieldId,
    total_len: FieldId,
    id: FieldId,
    flags: FieldId,
    frag_off: FieldId,
    ttl: FieldId,
    proto: FieldId,
    csum: FieldId,
    src: FieldId,
    dst: FieldId,
    addr: FieldId,
}

#[derive(Default)]
pub struct Ipv4Dissector;

impl Dissector for Ipv4Dissector {
    fn name(&self) -> &'static str {
        "ip"
    }

    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Internet Protocol Version 4", "ip", "ip");
        let f = Ipv4Fields {
            version: reg.register_field(ProtoField::simple("ip.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            ihl: reg.register_field(ProtoField::simple("ip.hdr_len", "Header Length", FieldType::U8, FieldDisplay::BaseDec)),
            dscp: reg.register_field(ProtoField::simple("ip.dsfield", "Differentiated Services Field", FieldType::U8, FieldDisplay::BaseHex)),
            total_len: reg.register_field(ProtoField::simple("ip.len", "Total Length", FieldType::U16, FieldDisplay::BaseDec)),
            id: reg.register_field(ProtoField::simple("ip.id", "Identification", FieldType::U16, FieldDisplay::BaseHexDec)),
            flags: reg.register_field(ProtoField::simple("ip.flags", "Flags", FieldType::U8, FieldDisplay::BaseHex)),
            frag_off: reg.register_field(ProtoField::simple("ip.frag_offset", "Fragment Offset", FieldType::U16, FieldDisplay::BaseDec)),
            ttl: reg.register_field(ProtoField::simple("ip.ttl", "Time to live", FieldType::U8, FieldDisplay::BaseDec)),
            proto: reg.register_field(ProtoField::simple("ip.proto", "Protocol", FieldType::U8, FieldDisplay::BaseDec)),
            csum: reg.register_field(ProtoField::simple("ip.checksum", "Header Checksum", FieldType::U16, FieldDisplay::BaseHex)),
            src: reg.register_field(ProtoField::simple("ip.src", "Source Address", FieldType::Ipv4, FieldDisplay::BaseNone)),
            dst: reg.register_field(ProtoField::simple("ip.dst", "Destination Address", FieldType::Ipv4, FieldDisplay::BaseNone)),
            addr: reg.register_field(ProtoField::simple("ip.addr", "Source or Destination Address", FieldType::Ipv4, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }

    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 20 {
            return DissectResult::NeedMoreData;
        }
        let v_ihl = tvb.u8(0).unwrap_or(0);
        let version = v_ihl >> 4;
        if version != 4 {
            return DissectResult::NotForUs;
        }
        let ihl = (v_ihl & 0x0F) as usize * 4;
        if ihl < 20 || tvb.len() < ihl {
            return DissectResult::NeedMoreData;
        }
        let f = F.get().expect("ipv4 fields not registered");
        let dscp = tvb.u8(1).unwrap_or(0);
        let total = tvb.u16_be(2).unwrap_or(0);
        let id = tvb.u16_be(4).unwrap_or(0);
        let flag_frag = tvb.u16_be(6).unwrap_or(0);
        let flags = (flag_frag >> 13) as u8;
        let frag_off = flag_frag & 0x1FFF;
        let ttl = tvb.u8(8).unwrap_or(0);
        let proto = tvb.u8(9).unwrap_or(0);
        let csum = tvb.u16_be(10).unwrap_or(0);
        let src = tvb.ipv4(12).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        let dst = tvb.ipv4(16).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

        pinfo.src_addr = Some(IpAddr::V4(src));
        pinfo.dst_addr = Some(IpAddr::V4(dst));
        pinfo.l4_proto = Some(proto);
        pinfo.current_proto = "ip".into();
        tree.append_proto("ip");

        let mut root = ProtoItem::subtree(f.src, format!("Internet Protocol Version 4, Src: {src}, Dst: {dst}"), 0, ihl);
        root.push(ProtoItem::new(f.version, FieldValue::U64(version as u64), 0, 1));
        root.push(ProtoItem::new(f.ihl, FieldValue::U64(ihl as u64), 0, 1));
        root.push(ProtoItem::new(f.dscp, FieldValue::U64(dscp as u64), 1, 1));
        root.push(ProtoItem::new(f.total_len, FieldValue::U64(total as u64), 2, 2));
        root.push(ProtoItem::new(f.id, FieldValue::U64(id as u64), 4, 2));
        root.push(ProtoItem::new(f.flags, FieldValue::U64(flags as u64), 6, 1));
        root.push(ProtoItem::new(f.frag_off, FieldValue::U64(frag_off as u64), 6, 2));
        root.push(ProtoItem::new(f.ttl, FieldValue::U64(ttl as u64), 8, 1));
        root.push(ProtoItem::new(f.proto, FieldValue::U64(proto as u64), 9, 1));
        root.push(ProtoItem::new(f.csum, FieldValue::U64(csum as u64), 10, 2));
        root.push(ProtoItem::new(f.src, FieldValue::Ipv4(src), 12, 4));
        root.push(ProtoItem::new(f.dst, FieldValue::Ipv4(dst), 16, 4));
        root.push(ProtoItem::new(f.addr, FieldValue::Ipv4(src), 12, 4));
        root.push(ProtoItem::new(f.addr, FieldValue::Ipv4(dst), 16, 4));
        tree.push(root);

        let _ = total;
        DissectResult::Ok(ihl)
    }
}
