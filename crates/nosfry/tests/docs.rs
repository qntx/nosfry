//! Documentation consistency tests: README's supported-NIP table
//! against the NIP-11 the relay advertises, the configuration
//! reference against `nosfry.example.toml`, and every TOML block in
//! the guides against `Config::load`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::shadow_unrelated,
    unused_crate_dependencies,
    reason = "tests may panic on failure paths; deps cover every test binary"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use common::Relay;
use nosfry::config::Config;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The repository root (`crates/nosfry`'s grandparent).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_owned()
}

/// One row of README's `## Supported NIPs` table: the NIP number and
/// the exact condition string from the Advertised column.
fn readme_nip_table() -> Vec<(u16, String)> {
    let text = std::fs::read_to_string(repo_root().join("README.md")).unwrap();
    let mut inside = false;
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.starts_with("## ") {
            inside = line == "## Supported NIPs";
            continue;
        }
        if !inside || !line.starts_with("| [") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let nip: u16 = cells[1]
            .strip_prefix('[')
            .and_then(|c| c.split(']').next())
            .unwrap()
            .parse()
            .unwrap();
        rows.push((nip, cells[3].to_owned()));
    }
    assert!(
        !rows.is_empty(),
        "README's Supported NIPs table parsed to no rows"
    );
    rows
}

/// The TOML lines (`section`, `key = value`) that satisfy one
/// Advertised condition, on top of a config where every optional NIP
/// is off. An unknown condition string panics so a renamed or new
/// condition is noticed.
fn enabling(condition: &str, admin_hex: &str) -> Vec<(&'static str, String)> {
    match condition {
        "always" => Vec::new(),
        "when `relay.service_url` is set" => {
            vec![("relay", "service_url = \"ws://127.0.0.1:7777\"".to_owned())]
        }
        "when `relay.service_url` is set and `relay.access` gates kind 1059 reads" => {
            vec![
                ("relay", "service_url = \"ws://127.0.0.1:7777\"".to_owned()),
                ("[[relay.access.rules]]", "kinds = [1059]".to_owned()),
                (
                    "[[relay.access.rules]]",
                    "read = [\"author\", \"recipient\"]".to_owned(),
                ),
            ]
        }
        "when `max_filter_limit_count` is not 0" => {
            vec![("relay.limits", "max_filter_limit_count = 1".to_owned())]
        }
        "when `max_sync_events` is not 0" => {
            vec![("relay.limits", "max_sync_events = 1".to_owned())]
        }
        "when `relay.management.admins` is set" => {
            vec![("relay.management", format!("admins = [\"{admin_hex}\"]"))]
        }
        other => panic!("README's supported-nip condition is unknown to this test: {other:?}"),
    }
}

/// Render `(section, key = value)` lines into TOML text, grouped by
/// section with the last line winning a repeated key.
fn render(lines: &[(&'static str, String)]) -> String {
    let mut order: Vec<&'static str> = Vec::new();
    let mut sections: BTreeMap<&'static str, BTreeMap<String, &String>> = BTreeMap::new();
    for (section, line) in lines {
        if !sections.contains_key(section) {
            order.push(section);
        }
        let key = line.split('=').next().unwrap().trim().to_owned();
        sections.entry(*section).or_default().insert(key, line);
    }
    let mut out = String::new();
    for section in order {
        if section.starts_with('[') {
            out.push_str(section);
        } else {
            out.push('[');
            out.push_str(section);
            out.push(']');
        }
        out.push('\n');
        for line in sections[&section].values() {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The config with every optional NIP off: no `service_url`, no
/// admins, no access rules, COUNT and sync disabled.
fn off_lines() -> Vec<(&'static str, String)> {
    vec![
        ("relay.limits", "max_filter_limit_count = 0".to_owned()),
        ("relay.limits", "max_sync_events = 0".to_owned()),
        ("relay.access", "rules = []".to_owned()),
    ]
}

/// Drop the off-state `rules = []` scalar — it cannot render beside
/// a `[[relay.access.rules]]` table in one document.
fn drop_scalar_access_rules(lines: &mut Vec<(&'static str, String)>) {
    lines.retain(|(section, line)| !(*section == "relay.access" && line.starts_with("rules")));
}

/// Parse `text` as a configuration file through `Config::load`, the
/// path the binary itself takes.
fn config_from(text: &str) -> Config {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), text).unwrap();
    Config::load(file.path()).unwrap()
}

/// The NIP-11 document of a running relay.
async fn nip11(addr: std::net::SocketAddr) -> Value {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let (_, body) = text.split_once("\r\n\r\n").expect("http head/body split");
    serde_json::from_str(body).expect("nip11 json")
}

/// `supported_nips` the relay advertises under `lines`.
async fn advertised(lines: &[(&'static str, String)]) -> BTreeSet<u16> {
    let relay = Relay::start_with(config_from(&render(lines))).await;
    let doc = nip11(relay.addr).await;
    relay.stop().await;
    doc["supported_nips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|nip| u16::try_from(nip.as_u64().unwrap()).unwrap())
        .collect()
}

#[tokio::test]
async fn readme_nip_table_matches_the_relay() {
    let admin_hex = faster_hex::hex_string(&common::key(1).x_only_public_key().0.to_byte_array());
    let rows = readme_nip_table();
    let always: BTreeSet<u16> = rows
        .iter()
        .filter(|(_, condition)| condition == "always")
        .map(|(nip, _)| *nip)
        .collect();
    assert!(
        !always.is_empty(),
        "the table must have at least one always-advertised NIP"
    );

    // Everything off: exactly the "always" rows.
    assert_eq!(
        advertised(&off_lines()).await,
        always,
        "with every feature off the NIP-11 list must be the \"always\" rows"
    );

    // Everything off plus one condition: always plus every row whose
    // enabling lines the applied config covers — a condition that
    // implies another row's (a stricter `service_url` rule still
    // advertises NIP-42) pulls that row in too.
    for (nip, condition) in &rows {
        if condition == "always" {
            continue;
        }
        let mut lines = off_lines();
        let add = enabling(condition, &admin_hex);
        // An array-of-tables rule replaces the off-state `rules = []`
        // — both cannot render in one document.
        if add.iter().any(|(section, _)| section.starts_with('[')) {
            drop_scalar_access_rules(&mut lines);
        }
        lines.extend(add);
        let mut want = always.clone();
        want.extend(
            rows.iter()
                .filter(|(_, implied_condition)| implied_condition != "always")
                .filter(|(_, implied_condition)| {
                    enabling(implied_condition, &admin_hex)
                        .iter()
                        .all(|line| lines.contains(line))
                })
                .map(|(implied, _)| *implied),
        );
        assert_eq!(
            advertised(&lines).await,
            want,
            "condition {condition:?} must advertise NIP-{nip} plus every implied row"
        );
    }

    // Everything on: every row. A second run restores the stock
    // `relay.access` default — the NIP-59 row must exist for the
    // sets to stay equal, so a dropped row fails here instead of
    // silently shrinking both sides.
    let mut lines = off_lines();
    let mut want = always;
    for (nip, condition) in &rows {
        if condition == "always" {
            continue;
        }
        let add = enabling(condition, &admin_hex);
        if add.iter().any(|(section, _)| section.starts_with('[')) {
            drop_scalar_access_rules(&mut lines);
        }
        lines.extend(add);
        want.insert(*nip);
    }
    assert_eq!(
        advertised(&lines).await,
        want,
        "with every feature on the NIP-11 list must be the whole table"
    );
    // `rules = []` from `off_lines` cannot coexist with the stock
    // rule table — rebuild the set without it.
    let mut stock: Vec<(&'static str, String)> = lines
        .iter()
        .filter(|(section, line)| !(*section == "relay.access" && line.starts_with("rules")))
        .cloned()
        .collect();
    stock.extend([
        (
            "[[relay.access.rules]]",
            "kinds = [4, 1059, 21059]".to_owned(),
        ),
        (
            "[[relay.access.rules]]",
            "read = [\"author\", \"recipient\"]".to_owned(),
        ),
    ]);
    assert_eq!(
        advertised(&stock).await,
        want,
        "with every feature on and stock restricted kinds the NIP-11 list must be the whole table"
    );
}

/// `nosfry.example.toml` flattened to `dotted.key` -> value (arrays
/// are leaves).
fn example_keys() -> BTreeMap<String, toml::Value> {
    let text = std::fs::read_to_string(repo_root().join("nosfry.example.toml")).unwrap();
    let root: toml::Table = toml::from_str(&text).unwrap();
    let mut out = BTreeMap::new();
    flatten(&root, "", &mut out);
    out
}

/// Flatten `table` into `out` under the dotted `prefix`.
fn flatten(table: &toml::Table, prefix: &str, out: &mut BTreeMap<String, toml::Value>) {
    for (key, value) in table {
        let dotted = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            toml::Value::Table(inner) => flatten(inner, &dotted, out),
            _ => {
                out.insert(dotted, value.clone());
            }
        }
    }
}

/// The `## Reference` tables of `guides/configuration.md` as
/// `dotted.key` -> (default as a TOML value, reload kind).
fn reference_rows() -> BTreeMap<String, (toml::Value, String)> {
    let text = std::fs::read_to_string(repo_root().join("guides/configuration.md")).unwrap();
    let mut inside = false;
    let mut rows = BTreeMap::new();
    for line in text.lines() {
        if line.starts_with("## ") {
            inside = line == "## Reference";
            continue;
        }
        if !inside || !line.starts_with("| `") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let key = cells[1].trim_matches('`').to_owned();
        let default = cells[2].trim_matches('`');
        let reload = cells[3];
        assert!(
            ["restart", "new", "live"].contains(&reload),
            "{key}: Reload cell {reload:?} is not restart/new/live"
        );
        let parsed: toml::Table = format!("v = {default}")
            .parse()
            .unwrap_or_else(|e| panic!("{key}: default cell {default:?} is not TOML: {e}"));
        rows.insert(key, (parsed["v"].clone(), reload.to_owned()));
    }
    assert!(!rows.is_empty(), "the Reference section parsed to no rows");
    rows
}

#[test]
fn configuration_reference_matches_the_example() {
    let example = example_keys();
    let documented = reference_rows();
    let missing: Vec<&String> = example
        .keys()
        .filter(|key| !documented.contains_key(*key))
        .collect();
    let extra: Vec<&String> = documented
        .keys()
        .filter(|key| !example.contains_key(*key))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "configuration.md and nosfry.example.toml disagree on keys: \
         missing from the guide {missing:?}, unknown keys in the guide {extra:?}"
    );
    for (key, value) in &example {
        assert_eq!(
            &documented[key].0, value,
            "configuration.md shows a different default for `{key}`"
        );
    }
}

/// Every fenced `toml` code block of `path`.
fn toml_blocks(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut blocks = Vec::new();
    let mut block: Option<String> = None;
    for line in text.lines() {
        match &mut block {
            Some(content) if line.trim_start().starts_with("```") => {
                blocks.push(std::mem::take(content));
                block = None;
            }
            Some(content) => {
                content.push_str(line);
                content.push('\n');
            }
            None if line.trim_start() == "```toml" => block = Some(String::new()),
            None => {}
        }
    }
    blocks
}

#[test]
fn guide_toml_blocks_load() {
    let root = repo_root();
    let mut files = vec![root.join("README.md")];
    for entry in std::fs::read_dir(root.join("guides")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "md")
            && path.file_name().unwrap() != "workers.md"
        {
            files.push(path);
        }
    }
    let mut count = 0;
    for file in &files {
        for (index, block) in toml_blocks(file).iter().enumerate() {
            count += 1;
            let tmp = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(tmp.path(), block).unwrap();
            if let Err(error) = Config::load(tmp.path()) {
                panic!(
                    "{}: toml block {index} fails Config::load: {error}",
                    file.display()
                );
            }
        }
    }
    assert!(
        count >= 3,
        "expected at least the three guide TOML blocks, found {count}"
    );
}
