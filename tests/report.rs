//! Output-surface rendering: the human table, `--plain`, and `--json`
//! (FR-OUT-1, FR-OUT-2, FR-OUT-3, FR-OUT-5).
//!
//! `render_string` is the pure core behind `report::render`, so each surface is
//! asserted as a string without capturing stdout. All three surfaces emit the
//! same three sections -- keys, the WEP-BSSID summary, then the stats -- so the
//! tests check that every surface carries the same information and that `--quiet`
//! reduces each to keys only.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation, reason = "integration test fixtures")]

use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;

use std::collections::BTreeMap;
use std::time::Duration;

use wepwolf::attack::CrackResult;
use wepwolf::model::{BssidWep, IvSample, Mac, WepKey};
use wepwolf::report::{Format, render_string};
use wepwolf::scan::ScanResult;
use wepwolf::stats::Stats;

const BSSID: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

/// A WEP-classified BSSID (Privacy bit + WEP data, no RSN) with seven distinct
/// IVs, so the unique-IV count the surfaces report is a non-trivial 7.
fn wep_bssid(essid: &[u8]) -> BssidWep {
    BssidWep {
        bssid: Mac::from_bytes(BSSID),
        essid: Some(essid.to_vec()),
        saw_privacy: true,
        saw_wep_data: true,
        ivs: (0..7u32).map(|c| IvSample::new([c as u8, 0, 0], &[0u8; 8])).collect(),
        ..Default::default()
    }
}

/// A one-BSSID scan result with a single recovered key in the accounting and the
/// timing fields stamped, so the banner's wallclock/sweep rows render.
fn result_with(essid: &[u8]) -> ScanResult {
    let mut bssids = BTreeMap::new();
    bssids.insert(Mac::from_bytes(BSSID), wep_bssid(essid));
    let stats = Stats {
        captures_read: 1,
        packets_total: 42,
        bssids_total: 1,
        wep_bssids: 1,
        cracked: 1,
        wallclock: Duration::from_millis(150),
        sweep: Duration::from_millis(150),
        ..Default::default()
    };
    ScanResult { bssids, stats }
}

/// A recovered-key record for the fixture BSSID, cracked 0.42 s into the sweep.
fn crack(key: &[u8], essid: &[u8]) -> CrackResult {
    CrackResult {
        bssid: Mac::from_bytes(BSSID),
        essid: Some(essid.to_vec()),
        key: WepKey::new(key).unwrap(),
        attack: "ptw",
        key_id: 0,
        elapsed: Duration::from_millis(420),
    }
}

#[test]
fn table_surface_shows_keys_summary_and_banner() {
    // FR-OUT-1 (table surface) and FR-OUT-2 (per-key fields): the keys block, the
    // WEP-BSSID summary, then the stats banner with the timing rows and a footer.
    let out = render_string(&result_with(b"netname"), &[crack(b"mykey", b"netname")], Format::Table, false);
    // Keys section.
    assert!(out.contains("KEYS RECOVERED"));
    assert!(out.contains("00:11:22:33:44:55"), "bssid present");
    assert!(out.contains("6d:79:6b:65:79"), "key hex present");
    assert!(out.contains("mykey"), "ascii key appended to the key cell");
    assert!(out.contains("ptw"), "attack present");
    assert!(out.contains("netname"), "essid present");
    assert!(out.contains("0.42s"), "per-key crack time present");
    // Summary section.
    assert!(out.contains("WEP BSSIDs (most IVs first):"), "bssid summary present");
    // Stats section.
    assert!(out.contains("=== WEPWolf"), "banner present when not quiet");
    assert!(out.contains("wallclock"), "timing row present");
    assert!(out.lines().any(|l| l.starts_with("wepwolf ")), "version footer present");
}

#[test]
fn quiet_keeps_keys_only_on_the_table() {
    // FR-OUT-1: --quiet reduces the table to the recovered keys -- no summary, no banner.
    let out = render_string(&result_with(b"netname"), &[crack(b"mykey", b"netname")], Format::Table, true);
    assert!(out.contains("KEYS RECOVERED"), "keys still shown");
    assert!(!out.contains("WEP BSSIDs (most IVs first):"), "summary suppressed under quiet");
    assert!(!out.contains("=== WEPWolf"), "banner suppressed under quiet");
}

#[test]
fn plain_surface_is_tagged_records() {
    // FR-OUT-1/2: tab-separated records tagged key / wep / stat, the full per-key
    // record on the key line, and the same summary + stats as the other surfaces.
    let out = render_string(&result_with(b"netname"), &[crack(b"mykey", b"netname")], Format::Plain, false);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "key\t00:11:22:33:44:55\tnetname\t6d:79:6b:65:79\tmykey\t40\t0\tptw\t7\t0.420");
    assert!(lines.contains(&"wep\t00:11:22:33:44:55\tnetname\t7\tptw"), "wep summary line");
    assert!(lines.contains(&"stat\tcracked\t1"), "stat line");
    assert!(lines.iter().any(|l| l.starts_with("stat\twallclock_s\t")), "timing stat line");
}

#[test]
fn plain_quiet_is_keys_only() {
    // FR-OUT-1: --quiet drops the summary and stat lines from --plain too.
    let out = render_string(&result_with(b"netname"), &[crack(b"mykey", b"netname")], Format::Plain, true);
    assert!(!out.is_empty());
    assert!(out.lines().all(|l| l.starts_with("key\t")), "only key records under quiet");
}

#[test]
fn json_surface_is_typed_ndjson() {
    // FR-OUT-1: one typed object per line -- key objects, bssid objects, then a
    // single stats object carrying the full breakdown.
    let out = render_string(&result_with(b"netname"), &[crack(b"mykey", b"netname")], Format::Json, false);
    let lines: Vec<&str> = out.lines().collect();
    for line in &lines {
        assert!(line.starts_with('{') && line.ends_with('}'), "each NDJSON line is an object: {line}");
    }
    let key = lines[0];
    assert!(key.contains("\"type\":\"key\""));
    assert!(key.contains("\"bssid\":\"00:11:22:33:44:55\""));
    assert!(key.contains("\"key_hex\":\"6d:79:6b:65:79\""));
    assert!(key.contains("\"key_ascii\":\"mykey\""));
    assert!(key.contains("\"key_bits\":40"));
    assert!(key.contains("\"key_id\":0"));
    assert!(key.contains("\"attack\":\"ptw\""));
    assert!(key.contains("\"ivs\":7"));
    assert!(key.contains("\"seconds\":0.420"));
    assert!(lines.iter().any(|l| l.contains("\"type\":\"bssid\"") && l.contains("\"via\":\"ptw\"")), "bssid object");
    let stats = lines.last().unwrap();
    assert!(stats.contains("\"type\":\"stats\""));
    assert!(stats.contains("\"cracked\":1"));
    assert!(stats.contains("\"timing\":{\"wallclock_s\":"));
}

#[test]
fn non_printable_key_has_no_ascii_per_surface() {
    // FR-OUT-3: the ASCII form is present only when every octet is printable --
    // null in JSON, an empty field in --plain.
    let key = [0x00u8, 0x01, 0x02, 0x03, 0x04];
    let json = render_string(&result_with(b"netname"), &[crack(&key, b"netname")], Format::Json, false);
    assert!(json.contains("\"key_ascii\":null"), "non-printable key is null in JSON");
    let plain = render_string(&result_with(b"netname"), &[crack(&key, b"netname")], Format::Plain, false);
    let key_line = plain.lines().next().unwrap();
    // hex then an empty ASCII field: ...00:01:02:03:04 \t \t 40...
    assert!(key_line.contains("00:01:02:03:04\t\t40"), "empty ascii field for a non-printable key: {key_line}");
}

#[test]
fn banner_reports_uncracked_reason() {
    // FR-OUT-5: uncracked WEP BSSIDs are reported with a thin/infeasible reason.
    let mut result = result_with(b"netname");
    result.stats.cracked = 0;
    result.stats.uncracked_thin = 1;
    let out = render_string(&result, &[], Format::Table, false);
    assert!(out.contains("capture too thin"), "uncracked reason row present");
}
