//! Custom-dissector scaffolding helper.

use super::{ChatMessage, Provider};
use anyhow::Result;

pub fn generate_lua_skeleton(provider: &dyn Provider, description: &str) -> Result<String> {
    let system = ChatMessage {
        role: "system".into(),
        content: "Generate a Wireshark/lancer-wireshark Lua dissector skeleton \
                  matching the user's description. Include a ProtoField for each \
                  named field and a basic `dissector(tvb, pinfo, tree)` body.".into(),
    };
    let user = ChatMessage { role: "user".into(), content: description.into() };
    provider.complete(&[system, user])
}
