//! IMAP — text-line dissector.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<FieldId> = OnceCell::new();

#[derive(Default)] pub struct ImapDissector;
impl Dissector for ImapDissector {
    fn name(&self) -> &'static str { "imap" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Internet Message Access Protocol", "imap", "imap");
        let _ = F.set(reg.register_field(ProtoField::simple("imap.line", "Line", FieldType::String, FieldDisplay::StrAscii)));
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let line = std::str::from_utf8(tvb.as_slice()).unwrap_or("").lines().next().unwrap_or("").trim_end();
        pinfo.current_proto = "imap".into();
        tree.append_proto("imap");
        pinfo.set_info(line.into());
        let fid = *F.get().unwrap();
        let mut root = ProtoItem::subtree(fid, format!("IMAP: {line}"), 0, line.len());
        root.push(ProtoItem::new(fid, FieldValue::Str(line.into()), 0, line.len()));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
