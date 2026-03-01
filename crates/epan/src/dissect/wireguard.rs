//! WireGuard — surface the message-type byte + reserved padding.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, reserved: FieldId, sender: FieldId, receiver: FieldId }

#[derive(Default)] pub struct WireguardDissector;
impl Dissector for WireguardDissector {
    fn name(&self) -> &'static str { "wireguard" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("WireGuard", "wg", "wg");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("wg.type", "Type", FieldType::U8, FieldDisplay::BaseDec)),
            reserved: reg.register_field(ProtoField::simple("wg.reserved", "Reserved", FieldType::Bytes, FieldDisplay::BaseNone)),
            sender: reg.register_field(ProtoField::simple("wg.sender", "Sender", FieldType::U32, FieldDisplay::BaseHex)),
            receiver: reg.register_field(ProtoField::simple("wg.receiver", "Receiver", FieldType::U32, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "wg".into();
        tree.append_proto("wg");
        let ty = tvb.u8(0).unwrap_or(0);
        let mut root = ProtoItem::subtree(f.ty, format!("WireGuard type {ty}"), 0, tvb.len());
        root.push(ProtoItem::new(f.ty, FieldValue::U64(ty as u64), 0, 1));
        root.push(ProtoItem::new(f.reserved, FieldValue::Bytes(tvb.bytes(1, 3).unwrap_or(&[]).to_vec()), 1, 3));
        root.push(ProtoItem::new(f.sender, FieldValue::U64(tvb.u32_le(4).unwrap_or(0) as u64), 4, 4));
        if ty == 2 && tvb.len() >= 12 {
            root.push(ProtoItem::new(f.receiver, FieldValue::U64(tvb.u32_le(8).unwrap_or(0) as u64), 8, 4));
        }
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
