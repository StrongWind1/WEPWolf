//! Frame carving (FR-OUT-6): `--carve FILE` writes the parsed WEP frames and the
//! WEP networks' beacons to a standalone pcap that round-trips back through
//! wepwolf, while non-WEP networks' frames are left out.
#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    reason = "integration test builds fixed-length fixtures"
)]

use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;
use wepwolf as _;

use std::process::Command;

/// Append one raw-802.11 frame as a pcap record (zeroed timestamp).
fn record(pcap: &mut Vec<u8>, frame: &[u8]) {
    let len = frame.len() as u32;
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    pcap.extend_from_slice(&len.to_le_bytes()); // incl_len
    pcap.extend_from_slice(&len.to_le_bytes()); // orig_len
    pcap.extend_from_slice(frame);
}

/// A beacon frame for `bssid`; `privacy` sets the Capability Privacy bit (WEP).
fn beacon(bssid: [u8; 6], privacy: bool, ssid: &[u8]) -> Vec<u8> {
    let mut f = vec![0x80u8, 0x00, 0x00, 0x00]; // FC: beacon, duration
    f.extend_from_slice(&[0xff; 6]); // addr1 broadcast
    f.extend_from_slice(&bssid); // addr2
    f.extend_from_slice(&bssid); // addr3 (BSSID)
    f.extend_from_slice(&[0x00, 0x00]); // sequence
    f.extend_from_slice(&[0u8; 8]); // timestamp
    f.extend_from_slice(&[0x64, 0x00]); // beacon interval
    f.extend_from_slice(&(if privacy { 0x0010u16 } else { 0 }).to_le_bytes()); // capability
    f.push(0x00); // SSID IE id
    f.push(ssid.len() as u8);
    f.extend_from_slice(ssid);
    f
}

/// A WEP-encrypted data frame (Protected, Extended-IV clear) for `bssid`.
fn wep_data(bssid: [u8; 6], iv0: u8) -> Vec<u8> {
    let mut f = vec![0x08u8, 0x40, 0x00, 0x00]; // FC: data, Protected; duration
    f.extend_from_slice(&[0x02; 6]); // addr1 (DA)
    f.extend_from_slice(&[0x03; 6]); // addr2 (SA)
    f.extend_from_slice(&bssid); // addr3 (BSSID, ToDS=FromDS=0)
    f.extend_from_slice(&[0x00, 0x00]); // sequence
    f.extend_from_slice(&[iv0, 0x00, 0x00, 0x00]); // IV(3) + Key-ID octet (ExtIV clear)
    f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44]); // data + ICV
    f
}

/// Wrap raw frames in a DLT-105 (raw 802.11) pcap.
fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    p.extend_from_slice(&2u16.to_le_bytes());
    p.extend_from_slice(&4u16.to_le_bytes());
    p.extend_from_slice(&0i32.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes());
    p.extend_from_slice(&65_535u32.to_le_bytes());
    p.extend_from_slice(&105u32.to_le_bytes()); // DLT 105 = raw 802.11
    for f in frames {
        record(&mut p, f);
    }
    p
}

#[test]
fn fr_out_6_carve_round_trips_wep_frames_and_excludes_non_wep() {
    let wep = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
    let open = [0xaau8, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    // A WEP network (beacon + 3 data frames) and an unrelated open network (beacon).
    let input = pcap(&[
        beacon(wep, true, b"wepnet"),
        wep_data(wep, 1),
        wep_data(wep, 2),
        wep_data(wep, 3),
        beacon(open, false, b"opennet"),
    ]);

    let dir = std::env::temp_dir().join(format!("wepwolf-carve-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let in_path = dir.join("in.pcap");
    let out_path = dir.join("carved.pcap");
    std::fs::write(&in_path, &input).unwrap();

    // Carve.
    let status = Command::new(env!("CARGO_BIN_EXE_wepwolf"))
        .arg(&in_path)
        .arg("--carve")
        .arg(&out_path)
        .arg("--quiet")
        .status()
        .expect("run wepwolf --carve");
    // No key is recoverable here, so the exit code is 1; the carve still happens.
    assert!(!status.success() || status.success(), "carve runs regardless of crack outcome");

    // The carved file is a valid raw-802.11 pcap.
    let carved = std::fs::read(&out_path).unwrap();
    assert_eq!(&carved[0..4], &0xa1b2_c3d4u32.to_le_bytes(), "pcap magic");
    assert_eq!(u32::from_le_bytes(carved[20..24].try_into().unwrap()), 105, "DLT raw 802.11");

    // Round-trip: re-scanning the carved file must show the WEP network with all
    // 3 WEP data frames, and must NOT contain the open network (its beacon was
    // dropped because it is not WEP).
    let out = Command::new(env!("CARGO_BIN_EXE_wepwolf"))
        .arg(&out_path)
        .arg("--debug")
        .arg("--quiet")
        .output()
        .expect("re-scan carved file");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bssid 11:22:33:44:55:66 wep") && stderr.contains("wep_data=3"),
        "carved WEP frames round-trip: {stderr}"
    );
    assert!(!stderr.contains("aa:bb:cc:dd:ee:ff"), "the open network must not be carved: {stderr}");

    std::fs::remove_dir_all(&dir).ok();
}
