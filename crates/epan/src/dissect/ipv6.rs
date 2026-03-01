//! IPv6 dissector (no extension-header chain traversal in v1 — we surface
//! the next header value and hand off to the L4 dispatcher).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;
use std::net::IpAddr;

static F: OnceCell<Fields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct Fields {
    version: FieldId,
    tc: FieldId,
    flow: FieldId,
    plen: FieldId,
    next: FieldId,
    hlim: FieldId,
    src: FieldId,
    dst: FieldId,
    addr: FieldId,
}

#[derive(Default)]
pub struct Ipv6Dissector;

impl Dissector for Ipv6Dissector {
    fn name(&self) -> &'static str {
        "ipv6"
    }

    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Internet Protocol Version 6", "ipv6", "ipv6");
        let f = Fields {
            version: reg.register_field(ProtoField::simple("ipv6.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            tc: reg.register_field(ProtoField::simple("ipv6.tclass", "Traffic class", FieldType::U8, FieldDisplay::BaseHex)),
            flow: reg.register_field(ProtoField::simple("ipv6.flow", "Flow label", FieldType::U32, FieldDisplay::BaseHex)),
            plen: reg.register_field(ProtoField::simple("ipv6.plen", "Payload length", FieldType::U16, FieldDisplay::BaseDec)),
            next: reg.register_field(ProtoField::simple("ipv6.nxt", "Next header", FieldType::U8, FieldDisplay::BaseDec)),
            hlim: reg.register_field(ProtoField::simple("ipv6.hlim", "Hop limit", FieldType::U8, FieldDisplay::BaseDec)),
            src: reg.register_field(ProtoField::simple("ipv6.src", "Source", FieldType::Ipv6, FieldDisplay::BaseNone)),
            dst: reg.register_field(ProtoField::simple("ipv6.dst", "Destination", FieldType::Ipv6, FieldDisplay::BaseNone)),
            addr: reg.register_field(ProtoField::simple("ipv6.addr", "Source or Destination", FieldType::Ipv6, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }

    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 40 {
            return DissectResult::NeedMoreData;
        }
        let f = F.get().unwrap();
        let first = tvb.u32_be(0).unwrap_or(0);
        let version = (first >> 28) as u8;
        if version != 6 {
            return DissectResult::NotForUs;
        }
        let tc = ((first >> 20) & 0xFF) as u8;
        let flow = first & 0xFFFFF;
        let plen = tvb.u16_be(4).unwrap_or(0);
        let next = tvb.u8(6).unwrap_or(0);
        let hlim = tvb.u8(7).unwrap_or(0);
        let src = tvb.ipv6(8).unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);
        let dst = tvb.ipv6(24).unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);

        pinfo.src_addr = Some(IpAddr::V6(src));
        pinfo.dst_addr = Some(IpAddr::V6(dst));
        pinfo.l4_proto = Some(next);
        pinfo.current_proto = "ipv6".into();
        tree.append_proto("ipv6");

        let mut root = ProtoItem::subtree(f.src, format!("Internet Protocol Version 6, Src: {src}, Dst: {dst}"), 0, 40);
        root.push(ProtoItem::new(f.version, FieldValue::U64(version as u64), 0, 1));
        root.push(ProtoItem::new(f.tc, FieldValue::U64(tc as u64), 0, 2));
        root.push(ProtoItem::new(f.flow, FieldValue::U64(flow as u64), 1, 3));
        root.push(ProtoItem::new(f.plen, FieldValue::U64(plen as u64), 4, 2));
        root.push(ProtoItem::new(f.next, FieldValue::U64(next as u64), 6, 1));
        root.push(ProtoItem::new(f.hlim, FieldValue::U64(hlim as u64), 7, 1));
        root.push(ProtoItem::new(f.src, FieldValue::Ipv6(src), 8, 16));
        root.push(ProtoItem::new(f.dst, FieldValue::Ipv6(dst), 24, 16));
        root.push(ProtoItem::new(f.addr, FieldValue::Ipv6(src), 8, 16));
        root.push(ProtoItem::new(f.addr, FieldValue::Ipv6(dst), 24, 16));
        tree.push(root);
        DissectResult::Ok(40)
    }
}
