//! Differential validation against aircrack-ng (FR-TEST-1, C5) and the FR-audit
//! self-check (FR-TEST-2).
//!
//! The aircrack differential runs only when the binary and the (git-ignored)
//! reference capture are both present; it skips cleanly otherwise so the suite
//! never depends on local test data.
#![allow(clippy::unwrap_used, reason = "integration test")]

use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;
use wepwolf as _;

use std::path::Path;
use std::process::Command;

#[test]
fn matches_aircrack_ng_on_known_capture() {
    // FR-TEST-1 (C5): wepwolf's recovered key is identical to aircrack-ng's on
    // the same capture -- aircrack-ng is the ground truth.
    let cap = Path::new("ref/test-vectors/wep/wep_64_ptw.cap");
    let have_aircrack = Command::new("aircrack-ng").arg("--help").output().is_ok();
    if !cap.exists() || !have_aircrack {
        eprintln!("FR-TEST-1: aircrack-ng or reference capture absent -- skipping differential");
        return;
    }

    let ww = Command::new(env!("CARGO_BIN_EXE_wepwolf")).arg(cap).arg("--plain").output().unwrap();
    let ww_stdout = String::from_utf8_lossy(&ww.stdout);
    // --plain `key` line: key \t bssid \t essid \t key_hex \t key_ascii \t bits \t id \t attack \t ivs \t seconds.
    let key_line = ww_stdout.lines().find(|l| l.starts_with("key\t")).unwrap_or_default();
    let fields: Vec<&str> = key_line.split('\t').collect();
    let ww_bssid = fields.get(1).copied().unwrap_or_default().trim().to_owned();
    let ww_key = fields.get(3).copied().unwrap_or_default().trim().to_lowercase();
    assert!(!ww_key.is_empty(), "wepwolf must recover a key: {ww_stdout}");

    // aircrack-ng wants the BSSID named; reuse the one wepwolf reported.
    let ac = Command::new("aircrack-ng").arg("-q").arg("-b").arg(&ww_bssid).arg(cap).output().unwrap();
    let ac_stdout = String::from_utf8_lossy(&ac.stdout);
    // aircrack prints `KEY FOUND! [ 1F:1F:1F:1F:1F ]`.
    let ac_key = ac_stdout
        .split_once("KEY FOUND! [ ")
        .and_then(|(_, rest)| rest.split_once(" ]"))
        .map(|(key, _)| key.trim().to_lowercase())
        .unwrap_or_default();
    assert!(!ac_key.is_empty(), "aircrack-ng must recover a key: {ac_stdout}");

    assert_eq!(ww_key, ac_key, "wepwolf key must match aircrack-ng ground truth");
}

#[test]
fn audit_maps_every_fr_to_a_test() {
    // FR-TEST-2: scripts/audit_fr.sh fails on any FR referenced in src without a
    // test (and on a second key-acceptance path); run it and require success.
    // The audit scripts are a local / `make` asset (git-ignored, not shipped), so
    // skip cleanly when absent -- the way the aircrack differential above skips
    // without its binary -- and the suite never depends on them. `make audit`
    // runs this gate locally.
    if !Path::new("scripts/audit_fr.sh").exists() {
        eprintln!("FR-TEST-2: scripts/audit_fr.sh absent -- skipping the FR audit");
        return;
    }
    let status = Command::new("bash").arg("scripts/audit_fr.sh").status().unwrap();
    assert!(status.success(), "the FR-to-test audit must pass");
}
