//! DNS dissector — RFC 1035 header + Q/A walker (no name compression to
//! arbitrary depth; we walk pointers once and recover).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct Fields {
    id: FieldId,
    flags: FieldId,
    qd: FieldId,
    an: FieldId,
    ns: FieldId,
    ar: FieldId,
    qry_name: FieldId,
    qry_type: FieldId,
    qry_class: FieldId,
    resp_name: FieldId,
    resp_type: FieldId,
    resp_a: FieldId,
    resp_aaaa: FieldId,
    response_code: FieldId,
    qr: FieldId,
}

#[derive(Default)] pub struct DnsDissector;

impl Dissector for DnsDissector {
    fn name(&self) -> &'static str { "dns" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Domain Name System", "dns", "dns");
        let f = Fields {
            id: reg.register_field(ProtoField::simple("dns.id", "Transaction ID", FieldType::U16, FieldDisplay::BaseHex)),
            flags: reg.register_field(ProtoField::simple("dns.flags", "Flags", FieldType::U16, FieldDisplay::BaseHex)),
            qd: reg.register_field(ProtoField::simple("dns.count.queries", "Questions", FieldType::U16, FieldDisplay::BaseDec)),
            an: reg.register_field(ProtoField::simple("dns.count.answers", "Answer RRs", FieldType::U16, FieldDisplay::BaseDec)),
            ns: reg.register_field(ProtoField::simple("dns.count.auth_rr", "Authority RRs", FieldType::U16, FieldDisplay::BaseDec)),
            ar: reg.register_field(ProtoField::simple("dns.count.add_rr", "Additional RRs", FieldType::U16, FieldDisplay::BaseDec)),
            qry_name: reg.register_field(ProtoField::simple("dns.qry.name", "Name", FieldType::String, FieldDisplay::StrAscii)),
            qry_type: reg.register_field(ProtoField::simple("dns.qry.type", "Type", FieldType::U16, FieldDisplay::BaseDec)),
            qry_class: reg.register_field(ProtoField::simple("dns.qry.class", "Class", FieldType::U16, FieldDisplay::BaseHex)),
            resp_name: reg.register_field(ProtoField::simple("dns.resp.name", "Name", FieldType::String, FieldDisplay::StrAscii)),
            resp_type: reg.register_field(ProtoField::simple("dns.resp.type", "Type", FieldType::U16, FieldDisplay::BaseDec)),
            resp_a: reg.register_field(ProtoField::simple("dns.a", "A", FieldType::Ipv4, FieldDisplay::BaseNone)),
            resp_aaaa: reg.register_field(ProtoField::simple("dns.aaaa", "AAAA", FieldType::Ipv6, FieldDisplay::BaseNone)),
            response_code: reg.register_field(ProtoField::simple("dns.flags.rcode", "Response Code", FieldType::U8, FieldDisplay::BaseDec)),
            qr: reg.register_field(ProtoField::simple("dns.flags.response", "Response", FieldType::Boolean, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 12 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "dns".into();
        tree.append_proto("dns");
        let id = tvb.u16_be(0).unwrap_or(0);
        let flags = tvb.u16_be(2).unwrap_or(0);
        let qd = tvb.u16_be(4).unwrap_or(0);
        let an = tvb.u16_be(6).unwrap_or(0);
        let ns = tvb.u16_be(8).unwrap_or(0);
        let ar = tvb.u16_be(10).unwrap_or(0);
        let is_response = flags & 0x8000 != 0;
        let rcode = (flags & 0x000F) as u8;

        let mut root = ProtoItem::subtree(f.id, format!("Domain Name System ({})", if is_response { "response" } else { "query" }), 0, tvb.len());
        root.push(ProtoItem::new(f.id, FieldValue::U64(id as u64), 0, 2));
        root.push(ProtoItem::new(f.flags, FieldValue::U64(flags as u64), 2, 2));
        root.push(ProtoItem::new(f.qr, FieldValue::Bool(is_response), 2, 1));
        root.push(ProtoItem::new(f.response_code, FieldValue::U64(rcode as u64), 3, 1));
        root.push(ProtoItem::new(f.qd, FieldValue::U64(qd as u64), 4, 2));
        root.push(ProtoItem::new(f.an, FieldValue::U64(an as u64), 6, 2));
        root.push(ProtoItem::new(f.ns, FieldValue::U64(ns as u64), 8, 2));
        root.push(ProtoItem::new(f.ar, FieldValue::U64(ar as u64), 10, 2));

        let mut off = 12usize;
        let mut first_qry: Option<String> = None;
        for _ in 0..qd {
            let (name, n_used) = read_name(tvb.as_slice(), off);
            off += n_used;
            if off + 4 > tvb.len() { break; }
            let qtype = tvb.u16_be(off).unwrap_or(0);
            let qclass = tvb.u16_be(off + 2).unwrap_or(0);
            off += 4;
            if first_qry.is_none() {
                first_qry = Some(name.clone());
            }
            let mut q = ProtoItem::subtree(f.qry_name, format!("Query: {name}"), off, 4);
            q.push(ProtoItem::new(f.qry_name, FieldValue::Str(name), 0, 0));
            q.push(ProtoItem::new(f.qry_type, FieldValue::U64(qtype as u64), 0, 2));
            q.push(ProtoItem::new(f.qry_class, FieldValue::U64(qclass as u64), 0, 2));
            root.push(q);
        }
        for _ in 0..(an + ns + ar) {
            let (name, n_used) = read_name(tvb.as_slice(), off);
            off += n_used;
            if off + 10 > tvb.len() { break; }
            let rtype = tvb.u16_be(off).unwrap_or(0);
            let _rclass = tvb.u16_be(off + 2).unwrap_or(0);
            let _ttl = tvb.u32_be(off + 4).unwrap_or(0);
            let rdlen = tvb.u16_be(off + 8).unwrap_or(0) as usize;
            off += 10;
            if off + rdlen > tvb.len() { break; }
            let mut a = ProtoItem::subtree(f.resp_name, format!("{rtype} record for {name}"), off, rdlen);
            a.push(ProtoItem::new(f.resp_name, FieldValue::Str(name), 0, 0));
            a.push(ProtoItem::new(f.resp_type, FieldValue::U64(rtype as u64), 0, 2));
            if rtype == 1 && rdlen == 4 {
                let ip = tvb.ipv4(off).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
                a.push(ProtoItem::new(f.resp_a, FieldValue::Ipv4(ip), off, 4));
            } else if rtype == 28 && rdlen == 16 {
                let ip = tvb.ipv6(off).unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);
                a.push(ProtoItem::new(f.resp_aaaa, FieldValue::Ipv6(ip), off, 16));
            }
            root.push(a);
            off += rdlen;
        }

        if let Some(q) = first_qry {
            pinfo.set_info(if is_response { format!("Standard query response 0x{id:04x} {q}") } else { format!("Standard query 0x{id:04x} {q}") });
        }
        tree.push(root);
        DissectResult::Ok(off.min(tvb.len()))
    }
}

fn read_name(buf: &[u8], mut off: usize) -> (String, usize) {
    let mut name = String::new();
    let mut bytes_used_outside_pointer = 0;
    let mut followed_pointer = false;
    let mut guard = 0;
    loop {
        if off >= buf.len() || guard > 128 {
            break;
        }
        guard += 1;
        let len = buf[off];
        if len == 0 {
            if !followed_pointer {
                bytes_used_outside_pointer += 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if off + 1 >= buf.len() { break; }
            let ptr = ((len & 0x3F) as usize) << 8 | buf[off + 1] as usize;
            if !followed_pointer {
                bytes_used_outside_pointer += 2;
            }
            off = ptr;
            followed_pointer = true;
            continue;
        }
        let l = len as usize;
        if off + 1 + l > buf.len() { break; }
        if !name.is_empty() { name.push('.'); }
        name.push_str(std::str::from_utf8(&buf[off + 1..off + 1 + l]).unwrap_or(""));
        if !followed_pointer {
            bytes_used_outside_pointer += 1 + l;
        }
        off += 1 + l;
    }
    (name, bytes_used_outside_pointer.max(1))
}
