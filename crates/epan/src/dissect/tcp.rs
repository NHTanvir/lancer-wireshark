//! TCP dissector + per-flow conversation tracking.

use crate::conversation::{ConvKey, Direction, FollowChunk};
use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<TcpFields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct TcpFields {
    srcport: FieldId,
    dstport: FieldId,
    port: FieldId,
    seq: FieldId,
    seq_raw: FieldId,
    ack: FieldId,
    hdr_len: FieldId,
    flags: FieldId,
    fsyn: FieldId,
    fack: FieldId,
    ffin: FieldId,
    frst: FieldId,
    fpsh: FieldId,
    furg: FieldId,
    fecn: FieldId,
    fcwr: FieldId,
    window: FieldId,
    csum: FieldId,
    urg_ptr: FieldId,
    len: FieldId,
    payload: FieldId,
    stream: FieldId,
}

#[derive(Default)]
pub struct TcpDissector;

impl Dissector for TcpDissector {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Transmission Control Protocol", "tcp", "tcp");
        let f = TcpFields {
            srcport: reg.register_field(ProtoField::simple("tcp.srcport", "Source Port", FieldType::U16, FieldDisplay::BaseDec)),
            dstport: reg.register_field(ProtoField::simple("tcp.dstport", "Destination Port", FieldType::U16, FieldDisplay::BaseDec)),
            port: reg.register_field(ProtoField::simple("tcp.port", "Source or Destination Port", FieldType::U16, FieldDisplay::BaseDec)),
            seq: reg.register_field(ProtoField::simple("tcp.seq", "Sequence Number", FieldType::U32, FieldDisplay::BaseDec)),
            seq_raw: reg.register_field(ProtoField::simple("tcp.seq_raw", "Sequence Number (raw)", FieldType::U32, FieldDisplay::BaseDec)),
            ack: reg.register_field(ProtoField::simple("tcp.ack", "Acknowledgment Number", FieldType::U32, FieldDisplay::BaseDec)),
            hdr_len: reg.register_field(ProtoField::simple("tcp.hdr_len", "Header Length", FieldType::U8, FieldDisplay::BaseDec)),
            flags: reg.register_field(ProtoField::simple("tcp.flags", "Flags", FieldType::U16, FieldDisplay::BaseHex)),
            fsyn: reg.register_field(ProtoField::simple("tcp.flags.syn", "SYN", FieldType::Boolean, FieldDisplay::BaseNone)),
            fack: reg.register_field(ProtoField::simple("tcp.flags.ack", "ACK", FieldType::Boolean, FieldDisplay::BaseNone)),
            ffin: reg.register_field(ProtoField::simple("tcp.flags.fin", "FIN", FieldType::Boolean, FieldDisplay::BaseNone)),
            frst: reg.register_field(ProtoField::simple("tcp.flags.reset", "Reset", FieldType::Boolean, FieldDisplay::BaseNone)),
            fpsh: reg.register_field(ProtoField::simple("tcp.flags.push", "Push", FieldType::Boolean, FieldDisplay::BaseNone)),
            furg: reg.register_field(ProtoField::simple("tcp.flags.urg", "Urgent", FieldType::Boolean, FieldDisplay::BaseNone)),
            fecn: reg.register_field(ProtoField::simple("tcp.flags.ecn", "ECN-Echo", FieldType::Boolean, FieldDisplay::BaseNone)),
            fcwr: reg.register_field(ProtoField::simple("tcp.flags.cwr", "Congestion Window Reduced", FieldType::Boolean, FieldDisplay::BaseNone)),
            window: reg.register_field(ProtoField::simple("tcp.window_size_value", "Window", FieldType::U16, FieldDisplay::BaseDec)),
            csum: reg.register_field(ProtoField::simple("tcp.checksum", "Checksum", FieldType::U16, FieldDisplay::BaseHex)),
            urg_ptr: reg.register_field(ProtoField::simple("tcp.urgent_pointer", "Urgent pointer", FieldType::U16, FieldDisplay::BaseDec)),
            len: reg.register_field(ProtoField::simple("tcp.len", "Segment Length", FieldType::U32, FieldDisplay::BaseDec)),
            payload: reg.register_field(ProtoField::simple("tcp.payload", "Payload", FieldType::Bytes, FieldDisplay::BaseNone)),
            stream: reg.register_field(ProtoField::simple("tcp.stream", "Stream index", FieldType::U32, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }

    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 20 {
            return DissectResult::NeedMoreData;
        }
        let f = F.get().unwrap();
        let sport = tvb.u16_be(0).unwrap_or(0);
        let dport = tvb.u16_be(2).unwrap_or(0);
        let seq = tvb.u32_be(4).unwrap_or(0);
        let ack = tvb.u32_be(8).unwrap_or(0);
        let off_flags = tvb.u16_be(12).unwrap_or(0);
        let data_off = ((off_flags >> 12) & 0x0F) as usize * 4;
        let flags = off_flags & 0x01FF;
        let window = tvb.u16_be(14).unwrap_or(0);
        let csum = tvb.u16_be(16).unwrap_or(0);
        let urg = tvb.u16_be(18).unwrap_or(0);
        if data_off < 20 || tvb.len() < data_off {
            return DissectResult::NeedMoreData;
        }

        pinfo.src_port = Some(sport);
        pinfo.dst_port = Some(dport);
        pinfo.current_proto = "tcp".into();
        tree.append_proto("tcp");

        let payload_len = tvb.len().saturating_sub(data_off);
        let mut root = ProtoItem::subtree(
            f.srcport,
            format!("Transmission Control Protocol, Src Port: {sport}, Dst Port: {dport}, Seq: {seq}, Ack: {ack}, Len: {payload_len}"),
            0,
            data_off,
        );
        root.push(ProtoItem::new(f.srcport, FieldValue::U64(sport as u64), 0, 2));
        root.push(ProtoItem::new(f.dstport, FieldValue::U64(dport as u64), 2, 2));
        root.push(ProtoItem::new(f.port, FieldValue::U64(sport as u64), 0, 2));
        root.push(ProtoItem::new(f.port, FieldValue::U64(dport as u64), 2, 2));
        root.push(ProtoItem::new(f.seq, FieldValue::U64(seq as u64), 4, 4));
        root.push(ProtoItem::new(f.seq_raw, FieldValue::U64(seq as u64), 4, 4));
        root.push(ProtoItem::new(f.ack, FieldValue::U64(ack as u64), 8, 4));
        root.push(ProtoItem::new(f.hdr_len, FieldValue::U64(data_off as u64), 12, 1));
        root.push(ProtoItem::new(f.flags, FieldValue::U64(flags as u64), 12, 2));
        root.push(ProtoItem::new(f.fsyn, FieldValue::Bool(flags & 0x02 != 0), 13, 1));
        root.push(ProtoItem::new(f.fack, FieldValue::Bool(flags & 0x10 != 0), 13, 1));
        root.push(ProtoItem::new(f.ffin, FieldValue::Bool(flags & 0x01 != 0), 13, 1));
        root.push(ProtoItem::new(f.frst, FieldValue::Bool(flags & 0x04 != 0), 13, 1));
        root.push(ProtoItem::new(f.fpsh, FieldValue::Bool(flags & 0x08 != 0), 13, 1));
        root.push(ProtoItem::new(f.furg, FieldValue::Bool(flags & 0x20 != 0), 13, 1));
        root.push(ProtoItem::new(f.fecn, FieldValue::Bool(flags & 0x40 != 0), 13, 1));
        root.push(ProtoItem::new(f.fcwr, FieldValue::Bool(flags & 0x80 != 0), 13, 1));
        root.push(ProtoItem::new(f.window, FieldValue::U64(window as u64), 14, 2));
        root.push(ProtoItem::new(f.csum, FieldValue::U64(csum as u64), 16, 2));
        root.push(ProtoItem::new(f.urg_ptr, FieldValue::U64(urg as u64), 18, 2));
        root.push(ProtoItem::new(f.len, FieldValue::U64(payload_len as u64), 0, 0));

        if payload_len > 0 {
            let payload = tvb.bytes(data_off, payload_len).unwrap_or(&[]);
            root.push(ProtoItem::new(f.payload, FieldValue::Bytes(payload.to_vec()), data_off, payload_len));
        }

        // Build a brief info string
        let mut flagstr = String::new();
        if flags & 0x02 != 0 { flagstr.push_str("SYN, "); }
        if flags & 0x10 != 0 { flagstr.push_str("ACK, "); }
        if flags & 0x01 != 0 { flagstr.push_str("FIN, "); }
        if flags & 0x04 != 0 { flagstr.push_str("RST, "); }
        if flags & 0x08 != 0 { flagstr.push_str("PSH, "); }
        if flags & 0x20 != 0 { flagstr.push_str("URG, "); }
        let flagstr = flagstr.trim_end_matches(", ");
        pinfo.set_info(format!("{sport} → {dport} [{flagstr}] Seq={seq} Ack={ack} Win={window} Len={payload_len}"));

        tree.push(root);
        DissectResult::Ok(data_off)
    }
}

/// Record a TCP payload chunk into the conversation's follow-stream log.
/// Called by `lancer-wireshark`'s capture pipeline once it has both src/dst
/// IPs (from the IP layer) — we don't have IP context inside this dissector.
pub fn record_follow(conv: &crate::conversation::Conversation, direction: Direction, payload: &[u8], pinfo: &PInfo) {
    let mut state = conv.state.lock();
    state.follow_payload.push(FollowChunk {
        direction,
        bytes: payload.to_vec(),
        frame_number: pinfo.frame_number,
        timestamp_secs: pinfo.timestamp_secs,
        timestamp_nanos: pinfo.timestamp_nanos,
    });
}

#[allow(dead_code)]
pub fn key_from_pinfo(pinfo: &PInfo) -> Option<ConvKey> {
    Some(ConvKey::canonical(
        pinfo.src_addr,
        pinfo.src_port?,
        pinfo.dst_addr,
        pinfo.dst_port?,
        6,
        pinfo.vlan_id,
    ))
}
