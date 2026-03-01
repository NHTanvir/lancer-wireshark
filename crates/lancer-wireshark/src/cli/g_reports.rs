//! `-G <report>` info reports.

use anyhow::Result;
use epan::Engine;

pub fn print(engine: &Engine, report: &str) -> Result<()> {
    let r = match report {
        "fields" => engine.registry.report_fields(),
        "protocols" => engine.registry.report_protocols(),
        "values" => "values report not supported in MVP".into(),
        "decodes" => engine.decode_as.entries().iter().map(|e| format!("{}\t{:?}\t{}", e.table, e.key, e.dissector_name)).collect::<Vec<_>>().join("\n"),
        "defaultprefs" => default_prefs(),
        "currentprefs" => default_prefs(),
        "dissector-tables" => engine.registry.report_tables(),
        "heuristic-decodes" => engine.registry.heuristic_tables().join("\n"),
        "folders" => folders(),
        "ftypes" => ftypes_report(),
        "plugins" => "(no plugins loaded)".into(),
        "manuf" => manuf_report(),
        "enterprises" => "(use wsutil::enterprise::lookup at runtime)".into(),
        "services" => services_report(),
        "elastic-mapping" => "{\"properties\":{}}".into(),
        other => format!("unknown -G report: {other}"),
    };
    println!("{r}");
    Ok(())
}

fn default_prefs() -> String {
    "# lancer-wireshark default preferences\n\
     # (preference editing via the GUI lives in lancer-wireshark-ui)\n".into()
}

fn folders() -> String {
    let cfg = directories::ProjectDirs::from("io", "Lancer", "lancer-wireshark");
    let cfg = cfg.as_ref().map(|d| d.config_dir().display().to_string()).unwrap_or_else(|| "<none>".into());
    format!("Personal configuration: {cfg}\n")
}

fn manuf_report() -> String {
    let mut out = String::new();
    for (prefix, name) in wsutil::oui::OUI_DATA {
        out.push_str(&format!("{prefix:02x?}\t{name}\n"));
    }
    out
}

fn services_report() -> String {
    let mut out = String::new();
    for (port, name) in wsutil::ports::PORT_TABLE_TCP {
        out.push_str(&format!("{name}\t{port}/tcp\n"));
    }
    for (port, name) in wsutil::ports::PORT_TABLE_UDP {
        out.push_str(&format!("{name}\t{port}/udp\n"));
    }
    out
}

fn ftypes_report() -> String {
    "FT_NONE\nFT_BOOLEAN\nFT_UINT8\nFT_UINT16\nFT_UINT32\nFT_UINT64\nFT_INT8\nFT_INT16\nFT_INT32\nFT_INT64\nFT_FLOAT\nFT_DOUBLE\nFT_STRING\nFT_BYTES\nFT_IPv4\nFT_IPv6\nFT_ETHER\nFT_ABSOLUTE_TIME\nFT_RELATIVE_TIME\nFT_GUID\nFT_OID\n".into()
}
