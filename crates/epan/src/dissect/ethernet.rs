//! Ethernet II dissector.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<EthFields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct EthFields {
    src: FieldId,
    dst: FieldId,
    typ: FieldId,
    addr: FieldId,
    len: FieldId,
}

#[derive(Default)]
pub struct EthernetDissector;

impl Dissector for EthernetDissector {
    fn name(&self) -> &'static str {
        "eth"
    }

    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Ethernet II", "eth", "eth");
        let f = EthFields {
            src: reg.register_field(ProtoField::simple("eth.src", "Source", FieldType::Ether, FieldDisplay::SepColon)),
            dst: reg.register_field(ProtoField::simple("eth.dst", "Destination", FieldType::Ether, FieldDisplay::SepColon)),
            typ: reg.register_field(ProtoField::simple("eth.type", "Type", FieldType::U16, FieldDisplay::BaseHex)),
            addr: reg.register_field(ProtoField::simple("eth.addr", "Address", FieldType::Ether, FieldDisplay::SepColon)),
            len: reg.register_field(ProtoField::simple("eth.len", "Length", FieldType::U16, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }

    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 14 {
            return DissectResult::NeedMoreData;
        }
        let f = F.get().expect("eth fields not registered");
        let dst = tvb.mac(0).unwrap_or([0; 6]);
        let src = tvb.mac(6).unwrap_or([0; 6]);
        let etype = tvb.u16_be(12).unwrap_or(0);

        pinfo.src_mac = Some(src);
        pinfo.dst_mac = Some(dst);
        pinfo.current_proto = "eth".into();
        tree.append_proto("eth");

        let mut root = ProtoItem::subtree(
            f.dst,
            format!(
                "Ethernet II, Src: {}, Dst: {}",
                wsutil::mac::format_mac(src),
                wsutil::mac::format_mac(dst)
            ),
            0,
            14,
        );
        root.push(ProtoItem::new(f.dst, FieldValue::Ether(dst), 0, 6));
        root.push(ProtoItem::new(f.src, FieldValue::Ether(src), 6, 6));
        root.push(ProtoItem::new(f.addr, FieldValue::Ether(dst), 0, 6));
        root.push(ProtoItem::new(f.addr, FieldValue::Ether(src), 6, 6));
        if etype <= 0x05DC {
            root.push(ProtoItem::new(f.len, FieldValue::U64(etype as u64), 12, 2));
        } else {
            root.push(ProtoItem::new(f.typ, FieldValue::U64(etype as u64), 12, 2));
        }
        tree.push(root);

        DissectResult::Ok(14)
    }
}
