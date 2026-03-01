//! SDP — text body inside SIP.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<FieldId> = OnceCell::new();

#[derive(Default)] pub struct SdpDissector;
impl Dissector for SdpDissector {
    fn name(&self) -> &'static str { "sdp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Session Description Protocol", "sdp", "sdp");
        let _ = F.set(reg.register_field(ProtoField::simple("sdp.text", "Body", FieldType::String, FieldDisplay::StrAscii)));
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        pinfo.current_proto = "sdp".into();
        tree.append_proto("sdp");
        let fid = *F.get().unwrap();
        let text = String::from_utf8_lossy(tvb.as_slice()).into_owned();
        let mut root = ProtoItem::subtree(fid, "SDP".into(), 0, tvb.len());
        root.push(ProtoItem::new(fid, FieldValue::Str(text), 0, tvb.len()));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
