//! SNMP v1/v2c — version + community + PDU header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { version: FieldId, community: FieldId }

#[derive(Default)] pub struct SnmpDissector;
impl Dissector for SnmpDissector {
    fn name(&self) -> &'static str { "snmp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Simple Network Management Protocol", "snmp", "snmp");
        let f = Fields {
            version: reg.register_field(ProtoField::simple("snmp.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            community: reg.register_field(ProtoField::simple("snmp.community", "Community", FieldType::String, FieldDisplay::StrAscii)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "snmp".into();
        tree.append_proto("snmp");
        let mut root = ProtoItem::subtree(f.version, "SNMP".into(), 0, tvb.len());
        // Light ASN.1 parse: SEQUENCE { INTEGER version, OCTET STRING community, ... }
        let mut off = 0usize;
        if tvb.u8(0).unwrap_or(0) == 0x30 {
            off += 1;
            let (_len, used) = ber_len(tvb.as_slice(), off);
            off += used;
            if tvb.get_byte(off) == Some(0x02) {
                let (vlen, vused) = ber_len(tvb.as_slice(), off + 1);
                let value_off = off + 1 + vused;
                let mut v: u64 = 0;
                for i in 0..vlen {
                    v = (v << 8) | tvb.u8(value_off + i).unwrap_or(0) as u64;
                }
                root.push(ProtoItem::new(f.version, FieldValue::U64(v), off, 1 + vused + vlen));
                off = value_off + vlen;
            }
            if tvb.get_byte(off) == Some(0x04) {
                let (slen, sused) = ber_len(tvb.as_slice(), off + 1);
                let s = tvb.string_ascii(off + 1 + sused, slen).unwrap_or("").to_string();
                root.push(ProtoItem::new(f.community, FieldValue::Str(s), off + 1 + sused, slen));
            }
        }
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}

trait GetByte { fn get_byte(&self, off: usize) -> Option<u8>; }
impl<'a> GetByte for Tvb<'a> {
    fn get_byte(&self, off: usize) -> Option<u8> { self.u8(off).ok() }
}

fn ber_len(b: &[u8], off: usize) -> (usize, usize) {
    if off >= b.len() { return (0, 0); }
    let first = b[off];
    if first & 0x80 == 0 { return (first as usize, 1); }
    let n = (first & 0x7F) as usize;
    if off + 1 + n > b.len() { return (0, 1); }
    let mut v: usize = 0;
    for i in 0..n { v = (v << 8) | b[off + 1 + i] as usize; }
    (v, 1 + n)
}
