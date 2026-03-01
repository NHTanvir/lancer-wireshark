//! UDP dissector.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<UdpFields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct UdpFields {
    srcport: FieldId,
    dstport: FieldId,
    port: FieldId,
    length: FieldId,
    csum: FieldId,
    payload: FieldId,
}

#[derive(Default)]
pub struct UdpDissector;

impl Dissector for UdpDissector {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("User Datagram Protocol", "udp", "udp");
        let f = UdpFields {
            srcport: reg.register_field(ProtoField::simple("udp.srcport", "Source Port", FieldType::U16, FieldDisplay::BaseDec)),
            dstport: reg.register_field(ProtoField::simple("udp.dstport", "Destination Port", FieldType::U16, FieldDisplay::BaseDec)),
            port: reg.register_field(ProtoField::simple("udp.port", "Source or Destination Port", FieldType::U16, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("udp.length", "Length", FieldType::U16, FieldDisplay::BaseDec)),
            csum: reg.register_field(ProtoField::simple("udp.checksum", "Checksum", FieldType::U16, FieldDisplay::BaseHex)),
            payload: reg.register_field(ProtoField::simple("udp.payload", "Payload", FieldType::Bytes, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }

    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 {
            return DissectResult::NeedMoreData;
        }
        let f = F.get().unwrap();
        let sport = tvb.u16_be(0).unwrap_or(0);
        let dport = tvb.u16_be(2).unwrap_or(0);
        let len = tvb.u16_be(4).unwrap_or(0);
        let csum = tvb.u16_be(6).unwrap_or(0);

        pinfo.src_port = Some(sport);
        pinfo.dst_port = Some(dport);
        pinfo.current_proto = "udp".into();
        tree.append_proto("udp");

        let payload_len = (len as usize).saturating_sub(8).min(tvb.len().saturating_sub(8));
        let mut root = ProtoItem::subtree(f.srcport, format!("User Datagram Protocol, Src Port: {sport}, Dst Port: {dport}"), 0, 8);
        root.push(ProtoItem::new(f.srcport, FieldValue::U64(sport as u64), 0, 2));
        root.push(ProtoItem::new(f.dstport, FieldValue::U64(dport as u64), 2, 2));
        root.push(ProtoItem::new(f.port, FieldValue::U64(sport as u64), 0, 2));
        root.push(ProtoItem::new(f.port, FieldValue::U64(dport as u64), 2, 2));
        root.push(ProtoItem::new(f.length, FieldValue::U64(len as u64), 4, 2));
        root.push(ProtoItem::new(f.csum, FieldValue::U64(csum as u64), 6, 2));
        if payload_len > 0 {
            let p = tvb.bytes(8, payload_len).unwrap_or(&[]);
            root.push(ProtoItem::new(f.payload, FieldValue::Bytes(p.to_vec()), 8, payload_len));
        }
        pinfo.set_info(format!("{sport} → {dport}  Len={payload_len}"));
        tree.push(root);
        DissectResult::Ok(8)
    }
}
