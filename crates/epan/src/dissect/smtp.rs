//! SMTP — text-line walker.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { command: FieldId, response_code: FieldId, line: FieldId }

#[derive(Default)] pub struct SmtpDissector;
impl Dissector for SmtpDissector {
    fn name(&self) -> &'static str { "smtp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Simple Mail Transfer Protocol", "smtp", "smtp");
        let f = Fields {
            command: reg.register_field(ProtoField::simple("smtp.req.command", "Command", FieldType::String, FieldDisplay::StrAscii)),
            response_code: reg.register_field(ProtoField::simple("smtp.response.code", "Response Code", FieldType::U16, FieldDisplay::BaseDec)),
            line: reg.register_field(ProtoField::simple("smtp.line", "Line", FieldType::String, FieldDisplay::StrAscii)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let s = std::str::from_utf8(tvb.as_slice()).unwrap_or("");
        let line = s.lines().next().unwrap_or("").trim_end();
        let f = F.get().unwrap();
        pinfo.current_proto = "smtp".into();
        tree.append_proto("smtp");
        pinfo.set_info(line.into());
        let mut root = ProtoItem::subtree(f.line, format!("SMTP: {line}"), 0, line.len());
        if let Some((code_s, _)) = line.split_once(' ') {
            if let Ok(code) = code_s.parse::<u16>() {
                root.push(ProtoItem::new(f.response_code, FieldValue::U64(code as u64), 0, code_s.len()));
            } else {
                root.push(ProtoItem::new(f.command, FieldValue::Str(code_s.into()), 0, code_s.len()));
            }
        }
        root.push(ProtoItem::new(f.line, FieldValue::Str(line.into()), 0, line.len()));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
