//! SSH — read banner / packet length + cipher type field, no decryption.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { protocol: FieldId, packet_length: FieldId, padding_length: FieldId, msg_code: FieldId }

#[derive(Default)] pub struct SshDissector;
impl Dissector for SshDissector {
    fn name(&self) -> &'static str { "ssh" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Secure Shell Protocol", "ssh", "ssh");
        let f = Fields {
            protocol: reg.register_field(ProtoField::simple("ssh.protocol", "Banner", FieldType::String, FieldDisplay::StrAscii)),
            packet_length: reg.register_field(ProtoField::simple("ssh.packet_length", "Packet Length", FieldType::U32, FieldDisplay::BaseDec)),
            padding_length: reg.register_field(ProtoField::simple("ssh.padding_length", "Padding Length", FieldType::U8, FieldDisplay::BaseDec)),
            msg_code: reg.register_field(ProtoField::simple("ssh.message_code", "Message Code", FieldType::U8, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let f = F.get().unwrap();
        pinfo.current_proto = "ssh".into();
        tree.append_proto("ssh");
        if tvb.as_slice().starts_with(b"SSH-") {
            let line = tvb.as_slice().split(|&b| b == b'\n').next().unwrap_or(&[]);
            let banner = std::str::from_utf8(line).unwrap_or("").trim_end_matches('\r').to_string();
            pinfo.set_info(banner.clone());
            let mut root = ProtoItem::subtree(f.protocol, format!("SSH banner: {banner}"), 0, banner.len());
            root.push(ProtoItem::new(f.protocol, FieldValue::Str(banner.clone()), 0, banner.len()));
            tree.push(root);
            return DissectResult::Ok(tvb.len());
        }
        if tvb.len() < 6 { return DissectResult::NeedMoreData; }
        let plen = tvb.u32_be(0).unwrap_or(0);
        let pad = tvb.u8(4).unwrap_or(0);
        let code = tvb.u8(5).unwrap_or(0);
        let mut root = ProtoItem::subtree(f.packet_length, "SSH (encrypted)".into(), 0, tvb.len());
        root.push(ProtoItem::new(f.packet_length, FieldValue::U64(plen as u64), 0, 4));
        root.push(ProtoItem::new(f.padding_length, FieldValue::U64(pad as u64), 4, 1));
        root.push(ProtoItem::new(f.msg_code, FieldValue::U64(code as u64), 5, 1));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
