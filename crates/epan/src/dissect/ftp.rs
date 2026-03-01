//! FTP — single line of ASCII per packet.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { command: FieldId, response_code: FieldId, response_arg: FieldId, request_arg: FieldId }

#[derive(Default)] pub struct FtpDissector;
impl Dissector for FtpDissector {
    fn name(&self) -> &'static str { "ftp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("File Transfer Protocol", "ftp", "ftp");
        let f = Fields {
            command: reg.register_field(ProtoField::simple("ftp.request.command", "Request command", FieldType::String, FieldDisplay::StrAscii)),
            response_code: reg.register_field(ProtoField::simple("ftp.response.code", "Response code", FieldType::U16, FieldDisplay::BaseDec)),
            response_arg: reg.register_field(ProtoField::simple("ftp.response.arg", "Response arg", FieldType::String, FieldDisplay::StrAscii)),
            request_arg: reg.register_field(ProtoField::simple("ftp.request.arg", "Request arg", FieldType::String, FieldDisplay::StrAscii)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let s = std::str::from_utf8(tvb.as_slice()).unwrap_or("");
        let first_line = s.lines().next().unwrap_or("").trim_end();
        let f = F.get().unwrap();
        pinfo.current_proto = "ftp".into();
        tree.append_proto("ftp");
        pinfo.set_info(first_line.into());
        let mut root = ProtoItem::subtree(f.command, format!("FTP: {first_line}"), 0, first_line.len());
        if let Some((code_s, arg)) = first_line.split_once(' ') {
            if let Ok(code) = code_s.parse::<u16>() {
                root.push(ProtoItem::new(f.response_code, FieldValue::U64(code as u64), 0, code_s.len()));
                root.push(ProtoItem::new(f.response_arg, FieldValue::Str(arg.into()), 0, arg.len()));
            } else {
                root.push(ProtoItem::new(f.command, FieldValue::Str(code_s.into()), 0, code_s.len()));
                root.push(ProtoItem::new(f.request_arg, FieldValue::Str(arg.into()), 0, arg.len()));
            }
        } else if !first_line.is_empty() {
            root.push(ProtoItem::new(f.command, FieldValue::Str(first_line.into()), 0, first_line.len()));
        }
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
