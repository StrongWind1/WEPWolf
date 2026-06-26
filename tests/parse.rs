//! Capture ingest, frame accounting, and classification on synthetic pcaps
//! (FR-IN-1, FR-PARSE-4, FR-CLASSIFY-1).
//!
//! The fixtures are built in-memory and written to a temp file, so the test is
//! self-contained -- it does not depend on the (git-ignored) `ref/` test data.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "integration test fixtures"
)]

use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;

use std::sync::atomic::{AtomicU32, Ordering};

use wepwolf::crypto::{Rc4, crc32};
use wepwolf::diag::{DebugPrinter, Logger, MemMonitor};
use wepwolf::model::Mac;
use wepwolf::model::WepKey;
use wepwolf::model::{BssidWep, Encryption};
use wepwolf::scan::{self, ScanResult};
use wepwolf::wep::Verifier;

/// Raw IEEE 802.11 link type (no radio header).
const DLT_IEEE802_11: u32 = 105;

/// Build a little-endian microsecond pcap with the given DLT and raw frames.
fn build_pcap(dlt: u32, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes()); // magic
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&dlt.to_le_bytes()); // network / DLT
    for f in frames {
        let len = u32::try_from(f.len()).unwrap();
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        out.extend_from_slice(&len.to_le_bytes()); // incl_len
        out.extend_from_slice(&len.to_le_bytes()); // orig_len
        out.extend_from_slice(f);
    }
    out
}

/// Build a Beacon management frame for `bssid`/`ssid`, optionally with the
/// Privacy capability bit and an RSN information element.
fn beacon(bssid: [u8; 6], ssid: &[u8], privacy: bool, rsn: bool) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x80, 0x00]); // FC: type=mgmt(0), subtype=beacon(8)
    f.extend_from_slice(&[0x00, 0x00]); // duration
    f.extend_from_slice(&[0xff; 6]); // addr1 (broadcast)
    f.extend_from_slice(&bssid); // addr2
    f.extend_from_slice(&bssid); // addr3 (BSSID)
    f.extend_from_slice(&[0x00, 0x00]); // sequence control
    f.extend_from_slice(&[0u8; 8]); // timestamp
    f.extend_from_slice(&[0x64, 0x00]); // beacon interval
    f.extend_from_slice(&[u8::from(privacy) << 4, 0x00]); // capability (Privacy = bit 4)
    f.push(0); // SSID IE id
    f.push(u8::try_from(ssid.len()).unwrap());
    f.extend_from_slice(ssid);
    if rsn {
        f.extend_from_slice(&[48, 2, 0x01, 0x00]); // minimal RSN IE
    }
    f
}

/// Write a pcap blob to a unique temp file and scan it.
fn scan_bytes(pcap: &[u8], tag: &str) -> ScanResult {
    static N: AtomicU32 = AtomicU32::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("wepwolf_{tag}_{}_{id}.pcap", std::process::id()));
    std::fs::write(&path, pcap).unwrap();
    let debug = DebugPrinter::new(false);
    let mut logger = Logger::new(None).unwrap();
    let mut mem = MemMonitor::new();
    let progress = wepwolf::progress::Progress::new(false);
    let result = scan::scan(std::slice::from_ref(&path), &debug, &mut logger, &mut mem, &progress, None).unwrap();
    std::fs::remove_file(&path).ok();
    result
}

#[test]
fn reads_pcap_and_classifies_wep() {
    // FR-IN-1 (read a pcap), FR-CLASSIFY-1 (Privacy bit, no RSN -> WEP).
    let pcap = build_pcap(DLT_IEEE802_11, &[beacon([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], b"wepnet", true, false)]);
    let result = scan_bytes(&pcap, "wep");
    assert_eq!(result.stats.captures_read, 1);
    let obs = result.bssids.get(&Mac::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])).expect("bssid present");
    assert_eq!(obs.encryption(), Encryption::Wep);
    assert_eq!(obs.essid.as_deref(), Some(b"wepnet".as_slice()));
}

#[test]
fn classifies_wpa_from_rsn() {
    // FR-CLASSIFY-1: an RSN IE marks WPA even with the Privacy bit set.
    let pcap = build_pcap(DLT_IEEE802_11, &[beacon([0xaa; 6], b"wpanet", true, true)]);
    let result = scan_bytes(&pcap, "wpa");
    assert_eq!(result.bssids.get(&Mac::from_bytes([0xaa; 6])).map(BssidWep::encryption), Some(Encryption::Wpa));
}

#[test]
fn packet_accounting_identity_holds() {
    // FR-PARSE-2 (malformed/control frames counted and skipped, never fatal) and
    // FR-PARSE-4: every read packet lands in exactly one accounting bucket.
    let frames = vec![
        beacon([0x01; 6], b"a", true, false),
        beacon([0x02; 6], b"b", false, false),
        vec![0xd4, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], // 10-byte ACK (control)
    ];
    let s = scan_bytes(&build_pcap(DLT_IEEE802_11, &frames), "acct").stats;
    let dropped = s.packets_unknown_link + s.link_errors + s.malformed_mac + s.truncated;
    let accounted = s.data_frames + s.mgmt_frames + s.ctrl_frames + s.extension_frames + dropped;
    assert_eq!(s.packets_total, 3);
    assert_eq!(accounted, s.packets_total, "packet-accounting identity must reconcile");
    assert_eq!(s.ctrl_frames, 1, "the ACK is a control frame");
}

/// Build a WEP-encrypted data frame for `bssid` under `key`, IV `iv`, MSDU `plaintext`.
fn wep_data_frame(bssid: [u8; 6], key: &[u8], iv: [u8; 3], plaintext: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x08, 0x40]); // FC: type=data(2), Protected bit set
    f.extend_from_slice(&[0x00, 0x00]); // duration
    f.extend_from_slice(&[0xff; 6]); // addr1
    f.extend_from_slice(&[0x10; 6]); // addr2 (STA)
    f.extend_from_slice(&bssid); // addr3 (BSSID; ToDS=FromDS=0 -> ap=addr3)
    f.extend_from_slice(&[0x00, 0x00]); // sequence control
    f.extend_from_slice(&iv); // WEP IV
    f.push(0x00); // Key-ID octet: key_id 0, Extended-IV clear
    let mut payload = plaintext.to_vec();
    payload.extend_from_slice(&crc32(plaintext).to_le_bytes());
    let mut seed = iv.to_vec();
    seed.extend_from_slice(key);
    Rc4::new(&seed).apply_keystream(&mut payload);
    f.extend_from_slice(&payload);
    f
}

/// A WEP data frame addressed to a specific cleartext destination MAC (addr1, with
/// ToDS=FromDS=0 so the L2 destination is addr1), for protocol-recognition tests.
fn wep_data_frame_to(bssid: [u8; 6], dst: [u8; 6], key: &[u8], iv: [u8; 3], plaintext: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x08, 0x40]); // FC: type=data(2), Protected bit set
    f.extend_from_slice(&[0x00, 0x00]); // duration
    f.extend_from_slice(&dst); // addr1 = L2 destination
    f.extend_from_slice(&[0x10; 6]); // addr2 (STA)
    f.extend_from_slice(&bssid); // addr3 (BSSID)
    f.extend_from_slice(&[0x00, 0x00]); // sequence control
    f.extend_from_slice(&iv);
    f.push(0x00); // Key-ID octet
    let mut payload = plaintext.to_vec();
    payload.extend_from_slice(&crc32(plaintext).to_le_bytes());
    let mut seed = iv.to_vec();
    seed.extend_from_slice(key);
    Rc4::new(&seed).apply_keystream(&mut payload);
    f.extend_from_slice(&payload);
    f
}

#[test]
fn ipv6_nd_known_plaintext_harvested() {
    // FR-WEP-6: a WEP data frame to an IPv6 multicast DA (33:33:..) is mined with
    // the IPv6 Neighbor-Discovery known plaintext (EtherType 86DD, next-header
    // ICMPv6, hop-limit 255) end-to-end through the scanner -- where the IPv4-shaped
    // guess would mis-key it. The recovered keystream matches the true RC4 stream.
    let bssid = [0x2a; 6];
    let key: &[u8] = &[1, 2, 3, 4, 5];
    let iv = [9u8, 9, 9];
    let mut plaintext =
        vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD, 0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3A, 0xFF];
    plaintext.resize(56, 0); // MSDU 56 -> IPv6 payload length 8, matching octets 12..14
    let dst = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]; // ff02::1 all-nodes
    let frame = wep_data_frame_to(bssid, dst, key, iv, &plaintext);
    let result = scan_bytes(&build_pcap(DLT_IEEE802_11, &[frame]), "ipv6nd");
    let rec = result.bssids.get(&Mac::from_bytes(bssid)).expect("bssid present");
    let ipv6 = rec.arp_keystreams().iter().find(|s| s.df_index.is_none()).expect("an IPv6 ND sample was harvested");
    let mut seed = iv.to_vec();
    seed.extend_from_slice(key);
    let mut ks = [0u8; 16];
    Rc4::new(&seed).keystream(&mut ks);
    assert_eq!(&ipv6.keystream()[..16], &ks, "IPv6 ND known plaintext applied over 16 octets");
}

/// Build an 802.11 Authentication management frame (subtype 11) with raw addresses.
fn auth_frame(addr1: [u8; 6], addr2: [u8; 6], addr3: [u8; 6], protected: bool, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0xB0, if protected { 0x40 } else { 0x00 }]); // FC: mgmt(0) auth(11), Protected?
    f.extend_from_slice(&[0x00, 0x00]); // duration
    f.extend_from_slice(&addr1);
    f.extend_from_slice(&addr2);
    f.extend_from_slice(&addr3);
    f.extend_from_slice(&[0x00, 0x00]); // sequence control
    f.extend_from_slice(body);
    f
}

#[test]
fn harvested_wep_verifies_with_known_key() {
    // FR-WEP-1, FR-WEP-2, FR-WEP-3, FR-WEP-5: identify WEP data, extract IV/Key-ID, accumulate IV samples + key id.
    // FR-CORRECT-1/2: the harvested frames verify with the right key, reject the wrong one.
    let key = [0x11, 0x22, 0x33, 0x44, 0x55];
    let bssid = [0x0a; 6];
    let frames = vec![
        wep_data_frame(bssid, &key, [1, 2, 3], b"\xaa\xaa\x03\x00\x00\x00 first wep frame body"),
        wep_data_frame(bssid, &key, [4, 5, 6], b"\xaa\xaa\x03\x00\x00\x00 second wep frame body!"),
        wep_data_frame(bssid, &key, [7, 8, 9], &[0u8; 36]), // 36-octet MSDU -> ARP keystream
    ];
    let result = scan_bytes(&build_pcap(DLT_IEEE802_11, &frames), "verify");
    let r = result.bssids.get(&Mac::from_bytes(bssid)).expect("bssid present");
    assert_eq!(r.encryption(), Encryption::Wep);
    assert_eq!(r.wep_data_frames, 3);
    assert_eq!(r.ivs().len(), 3, "one IV sample per WEP data frame");
    // Every long-enough frame yields a PTW keystream: the 36-octet MSDU as ARP,
    // and the two ordinary frames via the reconstructed IPv4 header (FR-ATK-PTW-1).
    assert_eq!(r.arp_keystreams().len(), 3, "long known-plaintext keystreams: 2 IP-reconstructed + 1 ARP");
    assert_eq!(r.key_ids_seen, 0b0001, "key id 0 observed");

    let verifier = Verifier::new(r.enc_frames().to_vec());
    assert!(verifier.accept(&WepKey::new(&key).unwrap()), "the correct key must be accepted");
    assert!(!verifier.accept(&WepKey::new(&[0x11, 0x22, 0x33, 0x44, 0x56]).unwrap()), "a wrong key must be rejected");
}

#[test]
fn shared_key_auth_recovers_keystream() {
    // FR-WEP-4: cleartext challenge (frame 2) + WEP-encrypted frame 3 -> keystream,
    // and the BSSID classifies WEP from the auth exchange alone (no beacon).
    let bssid = [0x0b; 6];
    let sta = [0x20; 6];
    let challenge: Vec<u8> = (0..16u8).collect();
    let keystream: Vec<u8> = (0..40u8).map(|b| b.wrapping_mul(7).wrapping_add(1)).collect();

    // Frame 2 (AP->STA, cleartext): addr1=STA, addr2=BSSID, addr3=BSSID.
    let mut f2body = vec![0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 16, challenge.len() as u8];
    f2body.extend_from_slice(&challenge);
    let f2 = auth_frame(sta, bssid, bssid, false, &f2body);

    // Frame 3 (STA->AP, WEP): addr1=BSSID, addr2=STA, addr3=BSSID.
    let mut plaintext = vec![0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 16, challenge.len() as u8];
    plaintext.extend_from_slice(&challenge);
    plaintext.extend_from_slice(&[0u8; 4]); // ICV placeholder
    let cipher: Vec<u8> = plaintext.iter().zip(keystream.iter().cycle()).map(|(p, k)| p ^ k).collect();
    let mut f3body = vec![0x09, 0x09, 0x09, 0x00]; // IV + Key-ID octet
    f3body.extend_from_slice(&cipher);
    let f3 = auth_frame(bssid, sta, bssid, true, &f3body);

    let result = scan_bytes(&build_pcap(DLT_IEEE802_11, &[f2, f3]), "ska");
    let r = result.bssids.get(&Mac::from_bytes(bssid)).expect("bssid present");
    assert_eq!(r.encryption(), Encryption::Wep);
    assert_eq!(r.wep_auth_frames, 1);
    let ks = r.ska_keystream().expect("ska keystream recovered");
    let known_len = 8 + challenge.len();
    let expected: Vec<u8> = keystream.iter().cycle().take(known_len).copied().collect();
    assert_eq!(&ks[..known_len], &expected[..], "recovered keystream matches the known plaintext XOR");
    // FR-ATK-SKA-1: the SKA keystream is also handed to the statistical attacks
    // as an IV sample, so an auth-only capture can still bootstrap a crack.
    assert_eq!(r.arp_keystreams().len(), 1, "SKA keystream feeds the attack sample pool");
    assert_eq!(r.arp_keystreams()[0].iv, [0x09, 0x09, 0x09], "the sample carries the frame-3 IV");
}

#[test]
fn dictionary_attack_recovers_key() {
    // FR-ATK-1, FR-ATK-DICT-1: a wordlist containing the key cracks the BSSID end-to-end.
    use wepwolf::attack::{self, Attack, dict::DictAttack};
    let key = *b"mykey"; // 5-octet ASCII WEP-40 key
    let bssid = [0x0c; 6];
    let frames = vec![
        wep_data_frame(bssid, &key, [1, 2, 3], b"\xaa\xaa\x03\x00\x00\x00 first body for the crack"),
        wep_data_frame(bssid, &key, [4, 5, 6], b"\xaa\xaa\x03\x00\x00\x00 second body for the crack"),
    ];
    let result = scan_bytes(&build_pcap(DLT_IEEE802_11, &frames), "crack");
    let attacks: Vec<Box<dyn Attack>> =
        vec![Box::new(DictAttack::from_words(vec![b"wrongkey".to_vec(), b"mykey".to_vec()]))];
    let cracks = attack::crack_all(
        &result.bssids,
        &attacks,
        &wepwolf::model::KeyLen::all(),
        None,
        None,
        None,
        &[],
        &wepwolf::progress::Progress::new(false),
        &DebugPrinter::new(false),
    )
    .cracks;
    assert_eq!(cracks.len(), 1, "exactly one key recovered");
    assert_eq!(cracks[0].key.as_slice(), b"mykey");
    assert_eq!(cracks[0].attack, "dictionary");
}

#[test]
fn reads_gzip_compressed_capture() {
    // FR-IN-2: a gzip-compressed pcap is read transparently (detected by magic).
    use std::io::Write as _;
    let pcap = build_pcap(DLT_IEEE802_11, &[beacon([0x0e; 6], b"gznet", true, false)]);
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&pcap).unwrap();
    let gz = enc.finish().unwrap();
    let result = scan_bytes(&gz, "gz");
    assert_eq!(result.stats.captures_read, 1);
    assert_eq!(result.bssids.get(&Mac::from_bytes([0x0e; 6])).map(BssidWep::encryption), Some(Encryption::Wep));
}

#[test]
fn merges_bssid_across_inputs() {
    // FR-IN-3: the same BSSID seen in two separate inputs merges into one record.
    let bssid = [0x0f; 6];
    let f1 = build_pcap(DLT_IEEE802_11, &[beacon(bssid, b"merge", true, false)]);
    let f2 = build_pcap(
        DLT_IEEE802_11,
        &[
            wep_data_frame(bssid, &[1, 2, 3, 4, 5], [1, 2, 3], b"\xaa\xaa\x03\x00\x00\x00 first body for merge"),
            wep_data_frame(bssid, &[1, 2, 3, 4, 5], [4, 5, 6], b"\xaa\xaa\x03\x00\x00\x00 second body for merge"),
        ],
    );
    let dir = std::env::temp_dir();
    let p1 = dir.join(format!("wepwolf_merge1_{}.pcap", std::process::id()));
    let p2 = dir.join(format!("wepwolf_merge2_{}.pcap", std::process::id()));
    std::fs::write(&p1, &f1).unwrap();
    std::fs::write(&p2, &f2).unwrap();
    let debug = DebugPrinter::new(false);
    let mut logger = Logger::new(None).unwrap();
    let mut mem = MemMonitor::new();
    let progress = wepwolf::progress::Progress::new(false);
    let result = scan::scan(&[p1.clone(), p2.clone()], &debug, &mut logger, &mut mem, &progress, None).unwrap();
    std::fs::remove_file(&p1).ok();
    std::fs::remove_file(&p2).ok();
    let rec = result.bssids.get(&Mac::from_bytes(bssid)).expect("merged bssid present");
    assert_eq!(rec.essid.as_deref(), Some(b"merge".as_slice()), "essid carried from file 1");
    assert_eq!(rec.wep_data_frames, 2, "wep data frames counted from file 2");
    assert_eq!(result.stats.captures_read, 2);
}

#[test]
fn parallel_ingest_is_deterministic() {
    // FR-IN-6: the input files are ingested in parallel, but their per-BSSID
    // material is folded in input-file order, so the merged result is independent
    // of thread scheduling. Three files carry the same BSSID with disjoint,
    // identifiable IVs (file k uses [k*10,..] and [k*10+1,..]); a single WEP/SNAP
    // data frame contributes exactly one IV sample in frame order, so the merged
    // record's IV sequence must follow path order -- and re-scanning the same
    // paths must reproduce it exactly.
    let bssid = [0x1a; 6];
    let key: &[u8] = &[1, 2, 3, 4, 5];
    let body: &[u8] = b"\xaa\xaa\x03\x00\x00\x00 deterministic merge body";
    let make = |k: u8| {
        build_pcap(
            DLT_IEEE802_11,
            &[wep_data_frame(bssid, key, [k * 10, 0, 0], body), wep_data_frame(bssid, key, [k * 10 + 1, 0, 0], body)],
        )
    };
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let paths: Vec<std::path::PathBuf> = (1u8..=3)
        .map(|k| {
            let p = dir.join(format!("wepwolf_det{k}_{pid}.pcap"));
            std::fs::write(&p, make(k)).unwrap();
            p
        })
        .collect();

    let debug = DebugPrinter::new(false);
    let progress = wepwolf::progress::Progress::new(false);
    let iv_order = || {
        let mut logger = Logger::new(None).unwrap();
        let mut mem = MemMonitor::new();
        let result = scan::scan(&paths, &debug, &mut logger, &mut mem, &progress, None).unwrap();
        let rec = result.bssids.get(&Mac::from_bytes(bssid)).expect("merged bssid present");
        assert_eq!(result.stats.captures_read, 3, "all three files counted");
        rec.ivs().iter().map(|s| s.iv[0]).collect::<Vec<u8>>()
    };

    let first = iv_order();
    let second = iv_order();
    for p in &paths {
        std::fs::remove_file(p).ok();
    }
    assert_eq!(first, vec![10, 11, 20, 21, 30, 31], "IV samples follow input-file order, not thread order");
    assert_eq!(first, second, "the parallel ingest is deterministic across runs");
}

#[test]
fn strips_radiotap_link_header() {
    // FR-PARSE-1 (Radiotap link header stripped) and FR-PARSE-3 (the FCS resolver
    // runs on the stripped payload) before the 802.11 MAC header is parsed
    // (DLT 127 = LINKTYPE_IEEE802_11_RADIOTAP).
    const DLT_RADIOTAP: u32 = 127;
    // Minimal radiotap: version 0, pad 0, len 8 (LE), present bitmap 0 (no fields).
    let mut framed = vec![0x00u8, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
    framed.extend_from_slice(&beacon([0x0b; 6], b"rtnet", true, false));
    let result = scan_bytes(&build_pcap(DLT_RADIOTAP, &[framed]), "rt");
    assert_eq!(result.bssids.get(&Mac::from_bytes([0x0b; 6])).map(BssidWep::encryption), Some(Encryption::Wep));
}

#[test]
fn streams_large_capture_with_bounded_memory() {
    // FR-IN-5: a large capture is streamed packet-by-packet -- every packet is
    // processed while only the (bounded) per-BSSID records are retained, so peak
    // RSS does not scale with the packet count.
    let frames: Vec<Vec<u8>> = (0..60_000).map(|_| beacon([0x77; 6], b"big", true, false)).collect();
    let pcap = build_pcap(DLT_IEEE802_11, &frames);
    let path = std::env::temp_dir().join(format!("wepwolf_big_{}.pcap", std::process::id()));
    std::fs::write(&path, &pcap).unwrap();
    let debug = DebugPrinter::new(false);
    let mut logger = Logger::new(None).unwrap();
    let mut mem = MemMonitor::new();
    let progress = wepwolf::progress::Progress::new(false);
    let result = scan::scan(std::slice::from_ref(&path), &debug, &mut logger, &mut mem, &progress, None).unwrap();
    std::fs::remove_file(&path).ok();
    assert_eq!(result.stats.packets_total, 60_000, "every packet was streamed");
    assert_eq!(result.bssids.len(), 1, "one BSSID retained regardless of frame count");
    assert!(mem.peak_rss_bytes() < 256 * 1024 * 1024, "peak RSS stays bounded");
}
