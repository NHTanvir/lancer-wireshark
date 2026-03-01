//! UDP-Lite (RFC 3828) — like UDP but the length field is a coverage value.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { sport: FieldId, dport: FieldId, coverage: FieldId, csum: FieldId }

#[derive(Default)] pub struct UdpLiteDissector;
impl Dissector for UdpLiteDissector {
    fn name(&self) -> &'static str { "udplite" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("UDP-Lite", "udplite", "udplite");
        let f = Fields {
            sport: reg.register_field(ProtoField::simple("udplite.srcport", "Source Port", FieldType::U16, FieldDisplay::BaseDec)),
            dport: reg.register_field(ProtoField::simple("udplite.dstport", "Destination Port", FieldType::U16, FieldDisplay::BaseDec)),
            coverage: reg.register_field(ProtoField::simple("udplite.checksum_coverage", "Checksum Coverage", FieldType::U16, FieldDisplay::BaseDec)),
            csum: reg.register_field(ProtoField::simple("udplite.checksum", "Checksum", FieldType::U16, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "udplite".into();
        tree.append_proto("udplite");
        let mut root = ProtoItem::subtree(f.sport, "UDP-Lite".into(), 0, 8);
        root.push(ProtoItem::new(f.sport, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.dport, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.coverage, FieldValue::U64(tvb.u16_be(4).unwrap_or(0) as u64), 4, 2));
        root.push(ProtoItem::new(f.csum, FieldValue::U64(tvb.u16_be(6).unwrap_or(0) as u64), 6, 2));
        tree.push(root);
        DissectResult::Ok(8)
    }
}
