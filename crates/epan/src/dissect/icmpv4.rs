//! ICMPv4 — type + code + checksum + remaining payload.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, code: FieldId, csum: FieldId, payload: FieldId }

#[derive(Default)] pub struct Icmpv4Dissector;
impl Dissector for Icmpv4Dissector {
    fn name(&self) -> &'static str { "icmp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Internet Control Message Protocol", "icmp", "icmp");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("icmp.type", "Type", FieldType::U8, FieldDisplay::BaseDec)),
            code: reg.register_field(ProtoField::simple("icmp.code", "Code", FieldType::U8, FieldDisplay::BaseDec)),
            csum: reg.register_field(ProtoField::simple("icmp.checksum", "Checksum", FieldType::U16, FieldDisplay::BaseHex)),
            payload: reg.register_field(ProtoField::simple("icmp.payload", "Payload", FieldType::Bytes, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "icmp".into();
        tree.append_proto("icmp");
        let ty = tvb.u8(0).unwrap_or(0);
        let code = tvb.u8(1).unwrap_or(0);
        let label = match ty {
            0 => "Echo (ping) reply",
            3 => "Destination unreachable",
            5 => "Redirect",
            8 => "Echo (ping) request",
            11 => "Time-to-live exceeded",
            _ => "ICMP",
        };
        pinfo.set_info(format!("{label} (code {code})"));
        let mut root = ProtoItem::subtree(f.ty, label.into(), 0, tvb.len());
        root.push(ProtoItem::new(f.ty, FieldValue::U64(ty as u64), 0, 1));
        root.push(ProtoItem::new(f.code, FieldValue::U64(code as u64), 1, 1));
        root.push(ProtoItem::new(f.csum, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        if tvb.len() > 4 {
            root.push(ProtoItem::new(f.payload, FieldValue::Bytes(tvb.bytes(4, tvb.len() - 4).unwrap_or(&[]).to_vec()), 4, tvb.len() - 4));
        }
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
