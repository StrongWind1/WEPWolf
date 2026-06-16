//! CLI parsing, exit codes, progress suppression, and `--debug` diagnostics
//! (FR-CLI-1, FR-CLI-2, FR-OUT-4, FR-UI-4, FR-DEBUG-2, FR-DEBUG-3).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    reason = "integration test fixtures"
)]

use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;

use clap::Parser as _;
use wepwolf::cli::Cli;
use wepwolf::progress::Progress;

#[test]
fn requires_a_capture_path() {
    // FR-CLI-1: the positional capture path is required; bare invocation errors.
    assert!(Cli::try_parse_from(["wepwolf"]).is_err(), "missing path must be an error");
}

#[test]
fn accepts_the_documented_flags() {
    // FR-CLI-2: every optional flag parses into the expected field.
    let cli = Cli::try_parse_from([
        "wepwolf",
        "--json",
        "--quiet",
        "--keylen",
        "104",
        "--threads",
        "4",
        "--bssid",
        "00:11:22:33:44:55",
        "--brute",
        "-w",
        "list.txt",
        "cap.pcap",
    ])
    .expect("documented flags parse");
    assert!(cli.json && cli.quiet && cli.brute);
    assert_eq!(cli.keylen.as_deref(), Some("104"));
    assert_eq!(cli.threads, Some(4));
    assert_eq!(cli.bssid.as_deref(), Some("00:11:22:33:44:55"));
    assert_eq!(cli.wordlist.as_deref(), Some(std::path::Path::new("list.txt")));
    assert_eq!(cli.paths, vec![std::path::PathBuf::from("cap.pcap")]);
}

#[test]
fn short_flags_alias_long_flags() {
    // FR-CLI-2: the aircrack/sibling-style short options parse to the same fields
    // as their long forms -- -n/--keylen, -b/--bssid, -f/--fudge, -d/--debug, -l/--log.
    let cli = Cli::try_parse_from([
        "wepwolf",
        "-b",
        "00:11:22:33:44:55",
        "-f",
        "8",
        "-n",
        "104",
        "-d",
        "-l",
        "run.log",
        "cap.pcap",
    ])
    .expect("short flags parse");
    assert_eq!(cli.bssid.as_deref(), Some("00:11:22:33:44:55"));
    assert_eq!(cli.keylen.as_deref(), Some("104"));
    assert!(cli.debug);
    assert_eq!(cli.log.as_deref(), Some(std::path::Path::new("run.log")));
    assert!(cli.fudge.is_some_and(|f| (f - 8.0).abs() < 1e-6), "-f parses the fudge factor");
}

#[test]
fn progress_is_suppressed_off_tty() {
    // FR-UI-1 (ingest spinner), FR-UI-2 (sweep bar + streamed rows), FR-UI-3
    // (brute keyspace bar), FR-UI-4: every surface of a disabled factory is a
    // safe no-op -- the path taken under --json / --plain / --quiet and off-TTY.
    let p = Progress::new(false);
    assert!(!p.enabled(), "disabled when not shown");
    let spinner = p.ingest_spinner();
    spinner.set_message("scanning".to_owned());
    spinner.finish();
    let sweep = p.sweep_bar(3);
    sweep.inc(1);
    sweep.println("cracked row");
    sweep.finish();
    p.brute_bar(1 << 40, "scalar").finish();
}

#[test]
fn exits_nonzero_without_a_key() {
    // FR-OUT-4: the process exits non-zero when no key is recovered. FR-IN-4:
    // it runs fully non-interactively, so this spawned process completes (never
    // blocks on stdin). An empty but valid pcap yields no BSSIDs, so nothing cracks.
    let path = std::env::temp_dir().join(format!("wepwolf_cli_empty_{}.pcap", std::process::id()));
    // 24-byte pcap global header (LE microsecond, DLT 105 = raw 802.11), no records.
    let mut hdr = Vec::new();
    hdr.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    hdr.extend_from_slice(&2u16.to_le_bytes());
    hdr.extend_from_slice(&4u16.to_le_bytes());
    hdr.extend_from_slice(&0i32.to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes());
    hdr.extend_from_slice(&65_535u32.to_le_bytes());
    hdr.extend_from_slice(&105u32.to_le_bytes());
    std::fs::write(&path, &hdr).unwrap();

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_wepwolf"))
        .arg(&path)
        .arg("--quiet")
        .status()
        .expect("run wepwolf");
    std::fs::remove_file(&path).ok();
    assert_eq!(status.code(), Some(1), "no key recovered must exit 1");
}

/// A pcap containing one WEP beacon (Privacy bit, no RSN) for `bssid`, no data.
fn wep_beacon_pcap(bssid: [u8; 6]) -> Vec<u8> {
    let mut frame = vec![0x80u8, 0x00, 0x00, 0x00]; // FC: beacon, duration
    frame.extend_from_slice(&[0xff; 6]); // addr1 broadcast
    frame.extend_from_slice(&bssid); // addr2
    frame.extend_from_slice(&bssid); // addr3 (BSSID)
    frame.extend_from_slice(&[0x00, 0x00]); // sequence
    frame.extend_from_slice(&[0u8; 8]); // timestamp
    frame.extend_from_slice(&[0x64, 0x00]); // beacon interval
    frame.extend_from_slice(&[0x10, 0x00]); // capability: Privacy (bit 4)
    frame.extend_from_slice(&[0x00, 0x04, b'w', b'e', b'p', b'1']); // SSID IE "wep1"
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65_535u32.to_le_bytes());
    pcap.extend_from_slice(&105u32.to_le_bytes()); // DLT 105 = raw 802.11
    let len = frame.len() as u32;
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&len.to_le_bytes());
    pcap.extend_from_slice(&len.to_le_bytes());
    pcap.extend_from_slice(&frame);
    pcap
}

#[test]
fn debug_reports_material_and_uncracked_reason() {
    // FR-DEBUG-2 (per-BSSID material dump) and FR-DEBUG-3 (why each WEP BSSID
    // went uncracked) both land on stderr under --debug.
    let path = std::env::temp_dir().join(format!("wepwolf_dbg_{}.pcap", std::process::id()));
    std::fs::write(&path, wep_beacon_pcap([0x10, 0x22, 0x33, 0x44, 0x55, 0x66])).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wepwolf"))
        .arg(&path)
        .arg("--debug")
        .arg("--quiet")
        .output()
        .expect("run wepwolf");
    std::fs::remove_file(&path).ok();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("bssid 10:22:33:44:55:66 wep"), "FR-DEBUG-2 material dump: {stderr}");
    assert!(stderr.contains("attack 10:22:33:44:55:66: uncracked -- thin"), "FR-DEBUG-3 reason: {stderr}");
}
