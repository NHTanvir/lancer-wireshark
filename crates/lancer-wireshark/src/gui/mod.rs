//! Native GUI launcher — delegates to the `lancer-wireshark-ui` crate.

use anyhow::Result;

pub fn launch() -> Result<()> {
    lancer_wireshark_ui::launch()
}
