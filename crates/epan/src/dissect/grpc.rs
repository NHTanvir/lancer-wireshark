//! gRPC — surfaces the gRPC framing inside an HTTP/2 DATA frame.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { compressed: FieldId, length: FieldId, message: FieldId }

#[derive(Default)] pub struct GrpcDissector;
impl Dissector for GrpcDissector {
    fn name(&self) -> &'static str { "grpc" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("gRPC", "grpc", "grpc");
        let f = Fields {
            compressed: reg.register_field(ProtoField::simple("grpc.compressed", "Compressed Flag", FieldType::U8, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("grpc.length", "Length", FieldType::U32, FieldDisplay::BaseDec)),
            message: reg.register_field(ProtoField::simple("grpc.message", "Message", FieldType::Bytes, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 5 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "grpc".into();
        tree.append_proto("grpc");
        let compressed = tvb.u8(0).unwrap_or(0);
        let length = tvb.u32_be(1).unwrap_or(0) as usize;
        let mut root = ProtoItem::subtree(f.length, format!("gRPC message (len {length})"), 0, 5 + length);
        root.push(ProtoItem::new(f.compressed, FieldValue::U64(compressed as u64), 0, 1));
        root.push(ProtoItem::new(f.length, FieldValue::U64(length as u64), 1, 4));
        if 5 + length <= tvb.len() {
            let msg = tvb.bytes(5, length).unwrap_or(&[]);
            root.push(ProtoItem::new(f.message, FieldValue::Bytes(msg.to_vec()), 5, length));
        }
        tree.push(root);
        DissectResult::Ok(5 + length.min(tvb.len() - 5))
    }
}
