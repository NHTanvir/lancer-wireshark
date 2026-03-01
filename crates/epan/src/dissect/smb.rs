//! SMB / SMB2 — header surface.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { magic: FieldId, command: FieldId }

#[derive(Default)] pub struct SmbDissector;
impl Dissector for SmbDissector {
    fn name(&self) -> &'static str { "smb" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("SMB / SMB2", "smb", "smb");
        let f = Fields {
            magic: reg.register_field(ProtoField::simple("smb.magic", "Magic", FieldType::U32, FieldDisplay::BaseHex)),
            command: reg.register_field(ProtoField::simple("smb.cmd", "Command", FieldType::U16, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "smb".into();
        tree.append_proto("smb");
        let mut root = ProtoItem::subtree(f.magic, "SMB".into(), 0, 8);
        root.push(ProtoItem::new(f.magic, FieldValue::U64(tvb.u32_be(0).unwrap_or(0) as u64), 0, 4));
        root.push(ProtoItem::new(f.command, FieldValue::U64(tvb.u16_le(12.min(tvb.len() - 2)).unwrap_or(0) as u64), 4, 2));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
