//! RTCP — header decode (version, packet type, length).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { version: FieldId, pt: FieldId, length: FieldId }

#[derive(Default)] pub struct RtcpDissector;
impl Dissector for RtcpDissector {
    fn name(&self) -> &'static str { "rtcp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("RTP Control Protocol", "rtcp", "rtcp");
        let f = Fields {
            version: reg.register_field(ProtoField::simple("rtcp.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            pt: reg.register_field(ProtoField::simple("rtcp.pt", "Packet Type", FieldType::U8, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("rtcp.length", "Length", FieldType::U16, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "rtcp".into();
        tree.append_proto("rtcp");
        let mut root = ProtoItem::subtree(f.version, "RTCP".into(), 0, 4);
        root.push(ProtoItem::new(f.version, FieldValue::U64((tvb.u8(0).unwrap_or(0) >> 6) as u64), 0, 1));
        root.push(ProtoItem::new(f.pt, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        tree.push(root);
        DissectResult::Ok(4)
    }
}
