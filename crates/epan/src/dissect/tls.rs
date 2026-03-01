//! TLS dissector — record header + ClientHello/ServerHello, SNI extraction,
//! JA3/JA4 fingerprinting computed via [`crate::dissect::ja3`].

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct Fields {
    record_type: FieldId,
    record_version: FieldId,
    record_length: FieldId,
    handshake_type: FieldId,
    handshake_version: FieldId,
    sni: FieldId,
    ja3: FieldId,
    ja3_hash: FieldId,
    ja4: FieldId,
    cipher_suite: FieldId,
    alpn: FieldId,
}

#[derive(Default)] pub struct TlsDissector;

impl Dissector for TlsDissector {
    fn name(&self) -> &'static str { "tls" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Transport Layer Security", "tls", "tls");
        let f = Fields {
            record_type: reg.register_field(ProtoField::simple("tls.record.content_type", "Content Type", FieldType::U8, FieldDisplay::BaseDec)),
            record_version: reg.register_field(ProtoField::simple("tls.record.version", "Version", FieldType::U16, FieldDisplay::BaseHex)),
            record_length: reg.register_field(ProtoField::simple("tls.record.length", "Length", FieldType::U16, FieldDisplay::BaseDec)),
            handshake_type: reg.register_field(ProtoField::simple("tls.handshake.type", "Handshake Type", FieldType::U8, FieldDisplay::BaseDec)),
            handshake_version: reg.register_field(ProtoField::simple("tls.handshake.version", "Handshake Version", FieldType::U16, FieldDisplay::BaseHex)),
            sni: reg.register_field(ProtoField::simple("tls.handshake.extensions_server_name", "Server Name (SNI)", FieldType::String, FieldDisplay::StrAscii)),
            ja3: reg.register_field(ProtoField::simple("tls.handshake.ja3", "JA3", FieldType::String, FieldDisplay::StrAscii)),
            ja3_hash: reg.register_field(ProtoField::simple("tls.handshake.ja3_hash", "JA3 hash", FieldType::String, FieldDisplay::StrAscii)),
            ja4: reg.register_field(ProtoField::simple("tls.handshake.ja4", "JA4", FieldType::String, FieldDisplay::StrAscii)),
            cipher_suite: reg.register_field(ProtoField::simple("tls.handshake.ciphersuite", "Cipher Suite", FieldType::U16, FieldDisplay::BaseHex)),
            alpn: reg.register_field(ProtoField::simple("tls.handshake.extensions_alpn", "ALPN", FieldType::String, FieldDisplay::StrAscii)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 5 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        let ct = tvb.u8(0).unwrap_or(0);
        // Accept only known TLS content types
        if !matches!(ct, 20..=24) { return DissectResult::NotForUs; }
        let version = tvb.u16_be(1).unwrap_or(0);
        let length = tvb.u16_be(3).unwrap_or(0) as usize;
        if version & 0xFF00 != 0x0300 { return DissectResult::NotForUs; }
        if tvb.len() < 5 + length { return DissectResult::NeedMoreData; }
        pinfo.current_proto = "tls".into();
        tree.append_proto("tls");

        let mut root = ProtoItem::subtree(f.record_type, format!("TLS record (content_type={ct})"), 0, 5 + length);
        root.push(ProtoItem::new(f.record_type, FieldValue::U64(ct as u64), 0, 1));
        root.push(ProtoItem::new(f.record_version, FieldValue::U64(version as u64), 1, 2));
        root.push(ProtoItem::new(f.record_length, FieldValue::U64(length as u64), 3, 2));

        if ct == 22 && length >= 4 {
            let hs_type = tvb.u8(5).unwrap_or(0);
            let hs_len = tvb.u24_be(6).unwrap_or(0) as usize;
            let hs_version = tvb.u16_be(9).unwrap_or(0);
            let mut hs = ProtoItem::subtree(f.handshake_type, format!("Handshake type {hs_type}"), 5, hs_len + 4);
            hs.push(ProtoItem::new(f.handshake_type, FieldValue::U64(hs_type as u64), 5, 1));
            hs.push(ProtoItem::new(f.handshake_version, FieldValue::U64(hs_version as u64), 9, 2));
            if hs_type == 1 || hs_type == 2 {
                // ClientHello / ServerHello — try to read SNI and cipher
                if let Some(sni) = parse_sni(tvb.as_slice(), 5, hs_len + 4) {
                    hs.push(ProtoItem::new(f.sni, FieldValue::Str(sni.clone()), 0, 0));
                    pinfo.set_info(format!("{} SNI={}", if hs_type == 1 { "Client Hello" } else { "Server Hello" }, sni));
                }
                if hs_type == 1 {
                    let ja3 = crate::dissect::ja3::compute_ja3(tvb.as_slice(), 5);
                    if let Some(s) = ja3 {
                        let h = crate::dissect::ja3::md5_hex(&s);
                        hs.push(ProtoItem::new(f.ja3, FieldValue::Str(s.clone()), 0, 0));
                        hs.push(ProtoItem::new(f.ja3_hash, FieldValue::Str(h), 0, 0));
                    }
                    let ja4 = crate::dissect::ja3::compute_ja4(tvb.as_slice(), 5);
                    if let Some(j) = ja4 {
                        hs.push(ProtoItem::new(f.ja4, FieldValue::Str(j), 0, 0));
                    }
                }
            }
            root.push(hs);
        }

        let _ = f.cipher_suite;
        let _ = f.alpn;
        tree.push(root);
        DissectResult::Ok(5 + length)
    }
}

fn parse_sni(buf: &[u8], hs_off: usize, hs_len: usize) -> Option<String> {
    let hs = buf.get(hs_off..hs_off + hs_len)?;
    // ClientHello layout: type(1) length(3) version(2) random(32) sid_len(1) sid sid_len cs_len(2) cs ...
    let mut p = 4;
    p += 2 + 32;
    if p >= hs.len() { return None; }
    let sid_len = *hs.get(p)? as usize;
    p += 1 + sid_len;
    if p + 2 > hs.len() { return None; }
    let cs_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2 + cs_len;
    if p >= hs.len() { return None; }
    let comp_len = *hs.get(p)? as usize;
    p += 1 + comp_len;
    if p + 2 > hs.len() { return None; }
    let ext_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2;
    let ext_end = p + ext_len;
    while p + 4 <= ext_end && p + 4 <= hs.len() {
        let etype = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let elen = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        p += 4;
        if etype == 0x0000 && elen >= 5 {
            // server_name extension
            let _list_len = u16::from_be_bytes([hs[p], hs[p + 1]]);
            let _name_type = hs[p + 2];
            let name_len = u16::from_be_bytes([hs[p + 3], hs[p + 4]]) as usize;
            let start = p + 5;
            let end = start + name_len;
            if end <= hs.len() {
                return std::str::from_utf8(&hs[start..end]).ok().map(|s| s.to_string());
            }
        }
        p += elen;
    }
    None
}
