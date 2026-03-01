//! mDNS — RFC 6762 (DNS over multicast). Wire format mirrors DNS, so we
//! identify and rebrand only.

use crate::dissect::dns::DnsDissector;
use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::ProtoTree;
use crate::register::Registry;
use crate::tvb::Tvb;

#[derive(Default)] pub struct MdnsDissector;
impl Dissector for MdnsDissector {
    fn name(&self) -> &'static str { "mdns" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Multicast DNS", "mdns", "mdns");
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        pinfo.current_proto = "mdns".into();
        tree.append_proto("mdns");
        DnsDissector::default().dissect(tvb, pinfo, tree)
    }
}
