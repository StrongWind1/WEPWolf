//! Statistical attack recovery on synthetic material (FR-ATK-1, FR-ATK-PTW-1, FR-ATK-KOREK-1).
//!
//! Material is generated directly (no pcap) for a known key; each attack must
//! recover that key through the public API and the Verifier gate.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation, reason = "integration test fixtures")]

use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use sysinfo as _;

use wepwolf::attack::Attack;
use wepwolf::attack::bias::BiasAttack;
use wepwolf::attack::fms::FmsAttack;
use wepwolf::attack::ptw::PtwAttack;
use wepwolf::crypto::{Rc4, crc32};
use wepwolf::model::{BssidWep, EncFrame, IvSample, KeyLen, WepKey, WepMaterial};
use wepwolf::wep::Verifier;

/// Two frames the Verifier can confirm a candidate against.
fn verifier_for(key: &[u8]) -> Verifier {
    let frames = [[1u8, 2, 3], [4, 5, 6]]
        .iter()
        .map(|iv| {
            let plain = b"\xaa\xaa\x03\x00\x00\x00 integration verifier frame";
            let mut data = plain.to_vec();
            data.extend_from_slice(&crc32(plain).to_le_bytes());
            let mut seed = iv.to_vec();
            seed.extend_from_slice(key);
            Rc4::new(&seed).apply_keystream(&mut data);
            EncFrame { iv: *iv, data, key_id: 0 }
        })
        .collect();
    Verifier::new(frames)
}

/// The true RC4 keystream for `iv || key`, as the harvest would recover it.
fn keystream(iv: [u8; 3], key: &[u8], n: usize) -> IvSample {
    let mut seed = iv.to_vec();
    seed.extend_from_slice(key);
    let mut ks = vec![0u8; n];
    Rc4::new(&seed).keystream(&mut ks);
    IvSample::new(iv, &ks)
}

#[test]
fn ptw_recovers_wep40_key() {
    // FR-ATK-PTW-1: PTW cracks a WEP-40 key from ordinary (ARP-length) traffic.
    let key = [0x2bu8, 0x7e, 0x15, 0x16, 0x28];
    let arp = (0..80_000u32).map(|c| keystream([c as u8, (c >> 8) as u8, (c >> 16) as u8], &key, 16)).collect();
    let bssid = BssidWep::with_material(WepMaterial { arp_keystreams: arp, ..Default::default() });
    let recovered = PtwAttack::default().run(&bssid, KeyLen::Wep40, &verifier_for(&key));
    assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
}

#[test]
fn bias_recovers_wep40_key() {
    // FR-ATK-1: the Klein RC4-bias attack recovers a WEP-40 key from ordinary traffic.
    let key = [0x9fu8, 0x42, 0x0d, 0xb1, 0x77];
    let arp = (0..80_000u32).map(|c| keystream([c as u8, (c >> 8) as u8, (c >> 16) as u8], &key, 16)).collect();
    let bssid = BssidWep::with_material(WepMaterial { arp_keystreams: arp, ..Default::default() });
    let recovered = BiasAttack::default().run(&bssid, KeyLen::Wep40, &verifier_for(&key));
    assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
}

#[test]
fn cross_bssid_key_reuse() {
    // FR-PERF-1 (parallel sweep across BSSIDs) and FR-PERF-2 (a key cracked on
    // one BSSID unlocks a same-key BSSID too thin to crack on its own).
    use std::collections::BTreeMap;
    use wepwolf::attack::{self, Attack};
    use wepwolf::model::Mac;

    let key = [0x2bu8, 0x7e, 0x15, 0x16, 0x28];
    let enc: Vec<EncFrame> = [[9u8, 9, 9], [8, 8, 8]]
        .iter()
        .map(|iv| {
            let plain = b"\xaa\xaa\x03\x00\x00\x00 reuse frame body";
            let mut data = plain.to_vec();
            data.extend_from_slice(&crc32(plain).to_le_bytes());
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            Rc4::new(&seed).apply_keystream(&mut data);
            EncFrame { iv: *iv, data, key_id: 0 }
        })
        .collect();

    // A: enough PTW material to crack outright.
    let arp = (0..80_000u32).map(|c| keystream([c as u8, (c >> 8) as u8, (c >> 16) as u8], &key, 16)).collect();
    let a = BssidWep {
        bssid: Mac::from_bytes([0x0a; 6]),
        saw_wep_data: true,
        ..BssidWep::with_material(WepMaterial { arp_keystreams: arp, enc_frames: enc.clone(), ..Default::default() })
    };
    // B: same key, only verifier frames -- no samples to attack, so it relies on reuse.
    let b = BssidWep {
        bssid: Mac::from_bytes([0x0b; 6]),
        saw_wep_data: true,
        ..BssidWep::with_material(WepMaterial { enc_frames: enc, ..Default::default() })
    };

    let mut map = BTreeMap::new();
    map.insert(a.bssid, a);
    map.insert(b.bssid, b);

    let attacks: Vec<Box<dyn Attack>> = vec![Box::new(PtwAttack::default())];
    let cracks = attack::crack_all(
        &map,
        &attacks,
        &[KeyLen::Wep40],
        None,
        None,
        None,
        &[],
        &wepwolf::progress::Progress::new(false),
        &wepwolf::diag::DebugPrinter::new(false),
    )
    .cracks;
    assert_eq!(cracks.len(), 2, "both BSSIDs end up cracked");
    assert!(cracks.iter().any(|c| c.attack == "reuse"), "the thin BSSID is cracked via reuse");
}

#[test]
fn ska_handshake_network_is_credited_to_ska() {
    // FR-ATK-SKA-1: a network where a shared-key handshake was captured is cracked
    // via the SKA bootstrap (the handshake keystream seeds the shared sigma search)
    // and attributed to "ska", not "ptw" -- so keys_by_ska is meaningful. The same
    // traffic without a handshake falls straight through to PTW.
    use std::collections::{BTreeMap, HashMap};
    use wepwolf::attack::{self, ska::SkaAttack};
    use wepwolf::model::Mac;

    let key = [0x2bu8, 0x7e, 0x15, 0x16, 0x28];
    let enc: Vec<EncFrame> = [[9u8, 9, 9], [8, 8, 8]]
        .iter()
        .map(|iv| {
            let plain = b"\xaa\xaa\x03\x00\x00\x00 ska attribution frame";
            let mut data = plain.to_vec();
            data.extend_from_slice(&crc32(plain).to_le_bytes());
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            Rc4::new(&seed).apply_keystream(&mut data);
            EncFrame { iv: *iv, data, key_id: 0 }
        })
        .collect();
    let arp: Vec<IvSample> =
        (0..80_000u32).map(|c| keystream([c as u8, (c >> 8) as u8, (c >> 16) as u8], &key, 16)).collect();

    // Same traffic on both; only the first carries a captured handshake.
    let with_ska = BssidWep {
        bssid: Mac::from_bytes([0x0e; 6]),
        saw_wep_data: true,
        ..BssidWep::with_material(WepMaterial {
            arp_keystreams: arp.clone(),
            enc_frames: enc.clone(),
            ska_keystream: Some(vec![0u8; 40]),
            ..Default::default()
        })
    };
    let no_ska = BssidWep {
        bssid: Mac::from_bytes([0x0f; 6]),
        saw_wep_data: true,
        ..BssidWep::with_material(WepMaterial { arp_keystreams: arp, enc_frames: enc, ..Default::default() })
    };

    let mut map = BTreeMap::new();
    map.insert(with_ska.bssid, with_ska);
    map.insert(no_ska.bssid, no_ska);
    let attacks: Vec<Box<dyn Attack>> = vec![Box::new(SkaAttack::default()), Box::new(PtwAttack::default())];
    let cracks = attack::crack_all(
        &map,
        &attacks,
        &[KeyLen::Wep40],
        None,
        None,
        None,
        &[],
        &wepwolf::progress::Progress::new(false),
        &wepwolf::diag::DebugPrinter::new(false),
    )
    .cracks;
    let via: HashMap<Mac, &str> = cracks.iter().map(|c| (c.bssid, c.attack)).collect();
    assert_eq!(via.get(&Mac::from_bytes([0x0e; 6])).copied(), Some("ska"), "handshake network is credited to SKA");
    assert_eq!(via.get(&Mac::from_bytes([0x0f; 6])).copied(), Some("ptw"), "no-handshake network falls through to PTW");
}

#[test]
fn rejects_16_byte_key() {
    // FR-CLASSIFY-2: only the real WEP sizes (5 / 13 / 29 octets) make a key; the
    // 16-octet "152-bit" vendor extension is rejected (C6).
    assert!(WepKey::new(&[0u8; 16]).is_none(), "16-byte key must be rejected");
    for n in [5usize, 13, 29] {
        assert!(WepKey::new(&vec![0u8; n]).is_some(), "{n}-byte key must be accepted");
    }
}

#[test]
fn per_bssid_time_max_bounds_the_brute_force() {
    // FR-PERF-3: a zero per-BSSID budget stops the brute before it can find even a
    // low-index key; with no budget the same key is recovered via the brute force.
    use std::collections::BTreeMap;
    use std::time::Duration;
    use wepwolf::attack::{self, brute::BruteAttack};
    use wepwolf::model::Mac;
    use wepwolf::progress::Progress;

    let key = [0x03u8, 0, 0, 0, 0]; // low index -> quick to brute
    let enc: Vec<EncFrame> = [[2u8, 4, 6], [1, 3, 5]]
        .iter()
        .map(|iv| {
            let plain = b"\xaa\xaa\x03\x00\x00\x00 grind frame body";
            let mut data = plain.to_vec();
            data.extend_from_slice(&crc32(plain).to_le_bytes());
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            Rc4::new(&seed).apply_keystream(&mut data);
            EncFrame { iv: *iv, data, key_id: 0 }
        })
        .collect();
    let b = BssidWep {
        bssid: Mac::from_bytes([0x0c; 6]),
        saw_wep_data: true,
        ..BssidWep::with_material(WepMaterial { enc_frames: enc, ..Default::default() })
    };
    let mut map = BTreeMap::new();
    map.insert(b.bssid, b);
    let attacks: Vec<Box<dyn Attack>> = vec![Box::new(BruteAttack)];
    let prog = Progress::new(false);

    let cracked = attack::crack_all(
        &map,
        &attacks,
        &[KeyLen::Wep40],
        None,
        None,
        None,
        &[],
        &prog,
        &wepwolf::diag::DebugPrinter::new(false),
    )
    .cracks;
    assert!(cracked.iter().any(|c| c.attack == "brute"), "no budget -> brute finds the low key");

    let bounded = attack::crack_all(
        &map,
        &attacks,
        &[KeyLen::Wep40],
        Some(Duration::ZERO),
        None,
        None,
        &[],
        &prog,
        &wepwolf::diag::DebugPrinter::new(false),
    )
    .cracks;
    assert!(bounded.is_empty(), "zero budget -> brute force bails before finding it");
}

#[test]
fn total_brute_time_max_bounds_the_whole_brute_force() {
    // FR-PERF-3: a global --total-brute-time-max stops the brute-force phase across
    // BSSIDs. Even with an unbounded per-BSSID budget, a zero TOTAL brute budget bails
    // before the phase brute-forces a low-index key an unbounded run recovers.
    use std::collections::BTreeMap;
    use std::time::Duration;
    use wepwolf::attack::{self, brute::BruteAttack};
    use wepwolf::model::Mac;
    use wepwolf::progress::Progress;

    let key = [0x03u8, 0, 0, 0, 0]; // low index -> quick to brute when allowed
    let enc: Vec<EncFrame> = [[2u8, 4, 6], [1, 3, 5]]
        .iter()
        .map(|iv| {
            let plain = b"\xaa\xaa\x03\x00\x00\x00 grind frame body";
            let mut data = plain.to_vec();
            data.extend_from_slice(&crc32(plain).to_le_bytes());
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            Rc4::new(&seed).apply_keystream(&mut data);
            EncFrame { iv: *iv, data, key_id: 0 }
        })
        .collect();
    let b = BssidWep {
        bssid: Mac::from_bytes([0x0c; 6]),
        saw_wep_data: true,
        ..BssidWep::with_material(WepMaterial { enc_frames: enc, ..Default::default() })
    };
    let mut map = BTreeMap::new();
    map.insert(b.bssid, b);
    let attacks: Vec<Box<dyn Attack>> = vec![Box::new(BruteAttack)];
    let prog = Progress::new(false);

    // No global cap (and no per-BSSID cap): the brute force recovers the low-index key.
    let found = attack::crack_all(
        &map,
        &attacks,
        &[KeyLen::Wep40],
        None,
        None,
        None,
        &[],
        &prog,
        &wepwolf::diag::DebugPrinter::new(false),
    )
    .cracks;
    assert!(found.iter().any(|c| c.attack == "brute"), "no brute budget -> brute finds the low key");

    // A zero TOTAL brute budget stops the phase before brute-forcing anything, even
    // though the per-BSSID budget is unbounded.
    let bounded = attack::crack_all(
        &map,
        &attacks,
        &[KeyLen::Wep40],
        None,
        None,
        Some(Duration::ZERO),
        &[],
        &prog,
        &wepwolf::diag::DebugPrinter::new(false),
    )
    .cracks;
    assert!(bounded.is_empty(), "zero global brute budget -> brute-force phase bails");
}

#[test]
fn fms_recovers_wep40_key() {
    // FR-ATK-KOREK-1: FMS cracks a WEP-40 key from weak IVs.
    let key = [0xca_u8, 0xfe, 0xba, 0xbe, 0x42];
    let mut ivs = Vec::new();
    for b in 0..5u8 {
        for x in 0..256u16 {
            ivs.push(keystream([3 + b, 0xFF, x as u8], &key, 1));
        }
    }
    let bssid = BssidWep::with_material(WepMaterial { ivs, ..Default::default() });
    let recovered = FmsAttack.run(&bssid, KeyLen::Wep40, &verifier_for(&key));
    assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
}

#[test]
fn keygen_recovers_neesus_wep40_key() {
    // FR-ATK-KEYGEN-1: the Neesus-Datacom generator derives the key from a passphrase.
    use wepwolf::attack::keygen::{KeygenAttack, neesus_keys};
    let passphrase = b"linksys";
    let key = neesus_keys(passphrase)[0];
    let attack = KeygenAttack::from_words(vec![passphrase.to_vec()]);
    let recovered = attack.run(&BssidWep::default(), KeyLen::Wep40, &verifier_for(&key));
    assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
}

#[test]
fn brute_recovers_low_wep40_key() {
    // FR-BRUTE-1, FR-SIMD-3: the exhaustive search runs behind the BruteBackend
    // trait and finds a low-index WEP-40 key.
    use wepwolf::attack::brute::CpuBrute;
    use wepwolf::attack::{BruteBackend, KeyRange};
    let key = [0x07u8, 0, 0, 0, 0];
    let found = CpuBrute.search40(&verifier_for(&key), KeyRange { start: 0, end: 4096 });
    assert_eq!(found.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
}

#[test]
fn cracks_each_key_slot_independently() {
    // FR-ATK-SLOT-1: an AP running two WEP keys (Key ID 0 and 1), whose frames are
    // pooled in one record, is cracked per slot -- recovering BOTH keys, where a
    // single vote table keyed only by BSSID (aircrack-ng's model) would mix the two
    // key schedules and report at most one.
    use std::collections::{BTreeMap, HashMap};
    use wepwolf::attack::{self, Attack};
    use wepwolf::model::Mac;

    let key0 = [0x2bu8, 0x7e, 0x15, 0x16, 0x28];
    let key1 = [0x9fu8, 0x42, 0x0d, 0xb1, 0x77];

    // Per-slot samples + verifier frames, each tagged with its Key ID and mixed
    // into one record (as the harvester sees interleaved slot-0/slot-1 traffic).
    let mut arp = Vec::new();
    let mut enc = Vec::new();
    for (slot, key) in [(0u8, &key0), (1u8, &key1)] {
        for c in 0..50_000u32 {
            arp.push(keystream([c as u8, (c >> 8) as u8, slot], key, 16).with_key_id(slot));
        }
        for iv in [[slot, 1, 1], [slot, 2, 2]] {
            let plain = b"\xaa\xaa\x03\x00\x00\x00 slot verifier frame";
            let mut data = plain.to_vec();
            data.extend_from_slice(&crc32(plain).to_le_bytes());
            let mut seed = iv.to_vec();
            seed.extend_from_slice(key);
            Rc4::new(&seed).apply_keystream(&mut data);
            enc.push(EncFrame { iv, data, key_id: slot });
        }
    }
    let b = BssidWep {
        bssid: Mac::from_bytes([0x0d; 6]),
        key_ids_seen: 0b11,
        saw_wep_data: true,
        ..BssidWep::with_material(WepMaterial { arp_keystreams: arp, enc_frames: enc, ..Default::default() })
    };
    let mut map = BTreeMap::new();
    map.insert(b.bssid, b);

    let attacks: Vec<Box<dyn Attack>> = vec![Box::new(PtwAttack::default())];
    let cracks = attack::crack_all(
        &map,
        &attacks,
        &[KeyLen::Wep40],
        None,
        None,
        None,
        &[],
        &wepwolf::progress::Progress::new(false),
        &wepwolf::diag::DebugPrinter::new(false),
    )
    .cracks;
    let recovered: HashMap<u8, Vec<u8>> = cracks.iter().map(|c| (c.key_id, c.key.as_slice().to_vec())).collect();
    assert_eq!(recovered.get(&0).map(Vec::as_slice), Some(key0.as_slice()), "slot 0 key recovered");
    assert_eq!(recovered.get(&1).map(Vec::as_slice), Some(key1.as_slice()), "slot 1 key recovered");
}

/// A record with `n` distinct IVs (and nothing else), for the feasibility tests.
fn record_with_unique_ivs(n: u32) -> BssidWep {
    BssidWep::with_material(WepMaterial {
        ivs: (0..n).map(|c| IvSample::new([c as u8, (c >> 8) as u8, (c >> 16) as u8], &[0u8; 8])).collect(),
        ..Default::default()
    })
}

#[test]
fn feasibility_gates_on_unique_ivs_not_raw_frames() {
    // FR-OUT-5: distinct IVs, not raw frames, decide whether the statistical attacks
    // run. A capture replaying one packet is frame-rich but has a single IV; a thin
    // capture has too few to converge; only at the floor for a key length is that
    // length attempted. (The measured basis for the floor: `iv_floor_study`.)
    let replayed = BssidWep::with_material(WepMaterial {
        ivs: (0..1500u32).map(|_| IvSample::new([1, 2, 3], &[0u8; 8])).collect(),
        ..Default::default()
    });
    assert!(!PtwAttack::default().applicable(&replayed, KeyLen::Wep40), "1500 frames of one IV are one IV");
    let thin = record_with_unique_ivs(999);
    assert!(!PtwAttack::default().applicable(&thin, KeyLen::Wep40), "below the WEP-40 floor: not attempted");
    let floor = record_with_unique_ivs(1000);
    assert!(PtwAttack::default().applicable(&floor, KeyLen::Wep40), "at the WEP-40 floor: attempted");
    assert!(!PtwAttack::default().applicable(&floor, KeyLen::Wep104), "WEP-104 has its own, higher floor");
    assert!(PtwAttack::default().applicable(&record_with_unique_ivs(5000), KeyLen::Wep104), "and is attempted at it");
}

#[test]
fn every_statistical_attack_shares_the_convergence_floor() {
    // FR-OUT-5, FR-PERF-3: one rule for PTW, KoreK, FMS, bias, and the SKA bootstrap
    // -- none runs on a capture below the floor, where its search could only spend
    // its budget -- while the dictionary, which needs no IVs, applies to every
    // network, so a weak or default key on a thin capture is still found.
    use wepwolf::attack::dict::{COMMON_KEYS, DictAttack};
    use wepwolf::attack::korek::KorekAttack;
    use wepwolf::attack::ska::SkaAttack;
    let with_handshake = |n: u32| {
        let mut record = record_with_unique_ivs(n);
        record.material_mut().ska_keystream = Some(vec![0u8; 24]);
        record
    };
    let (thin, rich) = (with_handshake(200), with_handshake(1000));
    let statistical: [(&str, Box<dyn Attack>); 5] = [
        ("ptw", Box::new(PtwAttack::default())),
        ("korek", Box::new(KorekAttack::default())),
        ("fms", Box::new(FmsAttack)),
        ("bias", Box::new(BiasAttack::default())),
        ("ska", Box::new(SkaAttack::default())),
    ];
    for (name, attack) in &statistical {
        assert!(!attack.applicable(&thin, KeyLen::Wep40), "{name} must not run below the floor");
        assert!(attack.applicable(&rich, KeyLen::Wep40), "{name} runs at the floor");
    }
    let dict = DictAttack::from_words(COMMON_KEYS.iter().map(|k| k.as_bytes().to_vec()).collect());
    assert!(dict.applicable(&thin, KeyLen::Wep40), "the dictionary tries every network");
    assert!(dict.applicable(&BssidWep::default(), KeyLen::Wep104), "even one with no IVs at all");
}

#[test]
fn thin_network_with_a_default_key_still_cracks() {
    // FR-OUT-5, FR-ATK-DICT-1: sparing a thin network the statistical searches must
    // not spare it the attempt. Through the whole engine, with every attack
    // registered, a 40-IV network using a common default key is recovered -- by
    // the dictionary -- and one with an unlisted key is simply reported uncracked.
    use std::collections::BTreeMap;
    use wepwolf::attack::dict::{COMMON_KEYS, DictAttack};
    use wepwolf::attack::korek::KorekAttack;
    use wepwolf::attack::{self};
    use wepwolf::model::Mac;
    use wepwolf::progress::Progress;

    let net = |id: u8, key: &[u8; 5]| {
        let frames =
            |n: u32, len: usize| -> Vec<IvSample> { (0..n).map(|c| keystream([c as u8, id, 7], key, len)).collect() };
        let enc_frames = [[id, 1, 1], [id, 2, 2]]
            .iter()
            .map(|iv| {
                let plain = b"\xaa\xaa\x03\x00\x00\x00 thin network frame";
                let mut data = plain.to_vec();
                data.extend_from_slice(&crc32(plain).to_le_bytes());
                let mut seed = iv.to_vec();
                seed.extend_from_slice(key);
                Rc4::new(&seed).apply_keystream(&mut data);
                EncFrame { iv: *iv, data, key_id: 0 }
            })
            .collect();
        BssidWep {
            bssid: Mac::from_bytes([id; 6]),
            saw_wep_data: true,
            key_ids_seen: 1,
            ..BssidWep::with_material(WepMaterial {
                ivs: frames(40, 7),
                arp_keystreams: frames(40, 16),
                enc_frames,
                ..Default::default()
            })
        }
    };
    let default_key = [0x12u8, 0x34, 0x56, 0x78, 0x90];
    let mut map = BTreeMap::new();
    for record in [net(1, &default_key), net(2, &[0x9b, 0x1d, 0xe7, 0x42, 0x60])] {
        map.insert(record.bssid, record);
    }
    let attacks: Vec<Box<dyn Attack>> = vec![
        Box::new(PtwAttack::default()),
        Box::new(KorekAttack::default()),
        Box::new(FmsAttack),
        Box::new(BiasAttack::default()),
        Box::new(DictAttack::from_words(COMMON_KEYS.iter().map(|k| k.as_bytes().to_vec()).collect())),
    ];
    let cracks = attack::crack_all(
        &map,
        &attacks,
        &KeyLen::all(),
        Some(std::time::Duration::from_mins(5)),
        None,
        None,
        &[],
        &Progress::new(false),
        &wepwolf::diag::DebugPrinter::new(false),
    )
    .cracks;
    assert_eq!(cracks.len(), 1, "only the default-key network has a recoverable key");
    assert_eq!(cracks[0].bssid, Mac::from_bytes([1; 6]));
    assert_eq!(cracks[0].attack, "dictionary");
    assert_eq!(cracks[0].key.as_slice(), default_key);
}

/// A statistical attack with its convergence floor lifted, so the study can
/// measure what it would recover on a capture the engine no longer runs it on.
struct Ungated(Box<dyn Attack>);

impl Attack for Ungated {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn applicable(&self, _bssid: &BssidWep, _len: KeyLen) -> bool {
        true
    }
    fn single_pass(&self) -> bool {
        self.0.single_pass()
    }
    fn run(&self, bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey> {
        self.0.run(bssid, len, verifier)
    }
}

/// One trial of the IV-floor study: whether the statistical attacks, run through
/// the engine with their floor lifted, recover a random WEP-40 key from `n`
/// distinct IVs that each carry a fully known 16-octet keystream (the attacker's
/// best case), within the engine's IV-scaled share of the default time cap.
fn iv_floor_trial(n: usize, seed: u64) -> bool {
    use wepwolf::attack::korek::KorekAttack;
    use wepwolf::attack::{self, Tuning};
    let mut state = seed;
    let mut next = move || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let key: [u8; 5] = core::array::from_fn(|_| next() as u8);
    let mut distinct = std::collections::HashSet::new();
    let (mut ivs, mut arp) = (Vec::with_capacity(n), Vec::with_capacity(n));
    while ivs.len() < n {
        let r = next();
        let iv = [r as u8, (r >> 8) as u8, (r >> 16) as u8];
        if distinct.insert(iv) {
            ivs.push(keystream(iv, &key, 7));
            arp.push(keystream(iv, &key, 16));
        }
    }
    let bssid = BssidWep {
        saw_wep_data: true,
        key_ids_seen: 1,
        ..BssidWep::with_material(WepMaterial { ivs, arp_keystreams: arp, ..Default::default() })
    };
    let tuning = Tuning { ffact: None, brute_tail: 2, alnum: false }; // the CLI defaults
    let attacks: Vec<Box<dyn Attack>> = vec![
        Box::new(Ungated(Box::new(PtwAttack { tuning }))),
        Box::new(Ungated(Box::new(KorekAttack { tuning }))),
        Box::new(Ungated(Box::new(FmsAttack))),
        Box::new(Ungated(Box::new(BiasAttack { tuning }))),
    ];
    // The engine's share of the default 300 s cap: cap * n / 20,000.
    let budget = std::time::Duration::from_millis(15) * u32::try_from(n.min(20_000)).unwrap();
    attack::crack(&bssid, &verifier_for(&key), &attacks, &[KeyLen::Wep40], Some(budget))
        .is_some_and(|c| c.key.as_slice() == key)
}

#[test]
#[ignore = "measurement: statistical success rate by distinct-IV count (backs attack::min_samples)"]
fn iv_floor_study() {
    // FR-OUT-5: the convergence floor is a measured number, not a guess. For each
    // distinct-IV count, random WEP-40 keys are attacked in the attacker's best
    // case with the floor lifted, and the share recovered is printed. The floor is
    // sound while it sits well below the first count at which anything cracks.
    // Run with `cargo test --release --test attacks iv_floor_study -- --ignored
    // --nocapture` on an otherwise idle machine (the budgets are wall-clock); the
    // whole table takes about eight minutes on sixteen threads.
    use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
    const POINTS: [(usize, u64); 14] = [
        (8, 400),
        (16, 400),
        (32, 400),
        (64, 400),
        (128, 400),
        (256, 400),
        (512, 400),
        (1000, 160),
        (2000, 48),
        (3000, 48),
        (5000, 32),
        (8000, 32),
        (20000, 32),
        (40000, 32),
    ];
    println!("{:>7} {:>12} {:>8}", "IVs", "recovered", "rate");
    for (n, trials) in POINTS {
        let ok = (0..trials).into_par_iter().filter(|t| iv_floor_trial(n, 0xC0_FFEE ^ ((n as u64) << 20) ^ t)).count();
        // The rate in hundredths of a percent, in integers.
        let rate = u64::try_from(ok).unwrap() * 10_000 / trials;
        println!("{n:>7} {ok:>7}/{trials:<4} {:>4}.{:02}%", rate / 100, rate % 100);
    }
}

#[test]
fn built_in_common_keys_crack_a_default_key_with_no_wordlist() {
    // FR-ATK-DICT-1: the shipped common/weak-key list is tried as a dictionary even
    // without --wordlist, so a default-key network (here the hex 12:34:56:78:90 that
    // dominates real captures) cracks for free -- the path that lets a thin net with a
    // default key crack now that every network is attempted.
    use wepwolf::attack::dict::{COMMON_KEYS, DictAttack};
    let key = [0x12u8, 0x34, 0x56, 0x78, 0x90]; // "1234567890" hex-typed default
    let words: Vec<Vec<u8>> = COMMON_KEYS.iter().map(|k| k.as_bytes().to_vec()).collect();
    let dict = DictAttack::from_words(words);
    let recovered = dict.run(&BssidWep::default(), KeyLen::Wep40, &verifier_for(&key));
    assert_eq!(
        recovered.as_ref().map(WepKey::as_slice),
        Some(key.as_slice()),
        "the built-in list recovers the common default key with no wordlist"
    );
}

#[test]
fn total_recovery_time_max_bounds_the_recovery_phase() {
    // FR-PERF-3: a global --total-recovery-time-max caps the parallel sweep across BSSIDs. A
    // zero budget skips the sweep entirely (no fresh statistical cracking), even for a
    // network PTW would otherwise recover; an unbounded budget recovers it.
    use std::collections::BTreeMap;
    use std::time::Duration;
    use wepwolf::attack::{self, ptw::PtwAttack};
    use wepwolf::model::Mac;
    use wepwolf::progress::Progress;

    let key = [0x2bu8, 0x7e, 0x15, 0x16, 0x28];
    let arp = (0..80_000u32).map(|c| keystream([c as u8, (c >> 8) as u8, (c >> 16) as u8], &key, 16)).collect();
    let enc: Vec<EncFrame> = [[9u8, 9, 9], [8, 8, 8]]
        .iter()
        .map(|iv| {
            let plain = b"\xaa\xaa\x03\x00\x00\x00 recovery budget frame";
            let mut data = plain.to_vec();
            data.extend_from_slice(&crc32(plain).to_le_bytes());
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            Rc4::new(&seed).apply_keystream(&mut data);
            EncFrame { iv: *iv, data, key_id: 0 }
        })
        .collect();
    let b = BssidWep {
        bssid: Mac::from_bytes([0x0a; 6]),
        saw_wep_data: true,
        ..BssidWep::with_material(WepMaterial { arp_keystreams: arp, enc_frames: enc, ..Default::default() })
    };
    let mut map = BTreeMap::new();
    map.insert(b.bssid, b);
    let attacks: Vec<Box<dyn Attack>> = vec![Box::new(PtwAttack::default())];
    let prog = Progress::new(false);
    let dbg = wepwolf::diag::DebugPrinter::new(false);

    let found = attack::crack_all(&map, &attacks, &[KeyLen::Wep40], None, None, None, &[], &prog, &dbg).cracks;
    assert!(found.iter().any(|c| c.attack == "ptw"), "no recovery budget -> PTW recovers the key");

    let bounded =
        attack::crack_all(&map, &attacks, &[KeyLen::Wep40], None, Some(Duration::ZERO), None, &[], &prog, &dbg).cracks;
    assert!(bounded.is_empty(), "zero recovery budget -> the sweep is skipped, nothing recovered");
}

#[test]
fn simd_brute_matches_scalar_brute() {
    // FR-SIMD-2, FR-SIMD-3, FR-BRUTE-1: the SIMD-batched backend (a known-plaintext
    // prefilter feeding the sole Verifier accept path, C4) recovers the same WEP-40
    // key as the scalar backend, and its prefilter produces no false positive --
    // a range that excludes the key still recovers nothing.
    use wepwolf::attack::brute::{CpuBrute, SimdBrute};
    use wepwolf::attack::{BruteBackend, KeyRange};
    let key = [0x09u8, 0, 0, 0, 0];
    let verifier = verifier_for(&key);
    let range = KeyRange { start: 0, end: 4096 };
    let scalar = CpuBrute.search40(&verifier, range);
    let simd = SimdBrute::new().search40(&verifier, range);
    assert_eq!(simd.as_ref().map(WepKey::as_slice), Some(key.as_slice()), "simd backend finds the key");
    assert_eq!(scalar.as_ref().map(WepKey::as_slice), simd.as_ref().map(WepKey::as_slice), "simd == scalar backend");
    // [0, 9) excludes index 9: prefilter survivors must still pass the Verifier.
    let excluded = SimdBrute::new().search40(&verifier, KeyRange { start: 0, end: 9 });
    assert_eq!(excluded, None, "no false positive when the key is out of range");
}

#[test]
fn brute_is_wep40_only() {
    // FR-BRUTE-2: the exhaustive search applies only to WEP-40; 104/232-bit keys
    // are recovered by dictionary/keygen, never brute-forced (2^104 is infeasible).
    use wepwolf::attack::brute::BruteAttack;
    assert!(BruteAttack.applicable(&BssidWep::default(), KeyLen::Wep40));
    assert!(!BruteAttack.applicable(&BssidWep::default(), KeyLen::Wep104));
    assert!(!BruteAttack.applicable(&BssidWep::default(), KeyLen::Wep232));
}

/// A parsed-header stand-in for one frame of `ap`'s traffic, as the scanner hands
/// it to the harvester.
const fn harvest_hdr(
    ap: wepwolf::model::Mac,
    frame_type: u8,
    subtype: u8,
    fragment_number: u8,
) -> wepwolf::ieee80211::frame::MacHeader {
    use wepwolf::ieee80211::frame::{FrameDirection, MacHeader};
    use wepwolf::model::Mac;
    MacHeader {
        ap,
        sta: Mac::from_bytes([0x02; 6]),
        dst: Mac::from_bytes([0x02; 6]),
        frame_type,
        subtype,
        protected: true,
        body_offset: 24,
        direction: FrameDirection::FromSta,
        more_fragments: false,
        sequence_number: 0,
        fragment_number,
        is_amsdu: false,
        mesh_control_present: false,
    }
}

/// A WEP MPDU body as it sits on the air: `IV(3) || Key-ID octet || RC4(plain || ICV)`.
fn wep_body(iv: [u8; 3], key: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut data = plain.to_vec();
    data.extend_from_slice(&crc32(plain).to_le_bytes());
    let mut seed = iv.to_vec();
    seed.extend_from_slice(key);
    Rc4::new(&seed).apply_keystream(&mut data);
    let mut body = vec![iv[0], iv[1], iv[2], 0x00];
    body.extend_from_slice(&data);
    body
}

/// Harvest `frames` (header, body) for one BSSID through the real classifier and
/// brute-force the result, bounded so a regression fails fast instead of grinding.
fn brute_after_harvest(
    frames: &[(wepwolf::ieee80211::frame::MacHeader, Vec<u8>)],
) -> Vec<wepwolf::attack::CrackResult> {
    use std::collections::BTreeMap;
    use std::time::Duration;
    use wepwolf::attack::{self, brute::BruteAttack};
    use wepwolf::classify::{self, ChallengeCache};
    use wepwolf::progress::Progress;

    let mut map = BTreeMap::new();
    let mut challenges = ChallengeCache::new();
    for (hdr, body) in frames {
        classify::observe(&mut map, &mut challenges, hdr, body, false);
    }
    let attacks: Vec<Box<dyn Attack>> = vec![Box::new(BruteAttack)];
    attack::crack_all(
        &map,
        &attacks,
        &[KeyLen::Wep40],
        Some(Duration::from_secs(5)),
        None,
        None,
        &[],
        &Progress::new(false),
        &wepwolf::diag::DebugPrinter::new(false),
    )
    .cracks
}

#[test]
fn brute_prefilter_survives_a_leading_shared_key_auth_frame() {
    // FR-BRUTE-1, FR-SIMD-2: the brute's known-plaintext prefilter must be built
    // from a frame whose leading plaintext really is known. A Shared-Key auth frame
    // 3 is retained for the verifier like any WEP frame, but its body starts with
    // the auth fields (01 00 03 00), not LLC/SNAP -- when it is the first frame
    // captured for a network, a prefilter that assumes SNAP rejects the true key
    // and the whole 2^40 sweep comes back empty.
    use wepwolf::ieee80211::frame::{TYPE_DATA, TYPE_MANAGEMENT};
    use wepwolf::model::Mac;
    let ap = Mac::from_bytes([0x0a; 6]);
    let key = [0x03u8, 0, 0, 0, 0]; // low index -> found at once when the prefilter is sound
    // Auth frame 3: alg = Shared Key (1), seq = 3, status = 0, Challenge IE.
    let mut auth_plain = vec![0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 16, 8];
    auth_plain.extend_from_slice(b"chalenge");
    let data_plain = b"\xaa\xaa\x03\x00\x00\x00\x08\x00 an ordinary data frame";
    let found = brute_after_harvest(&[
        (harvest_hdr(ap, TYPE_MANAGEMENT, 11, 0), wep_body([9, 9, 9], &key, &auth_plain)),
        (harvest_hdr(ap, TYPE_DATA, 0, 0), wep_body([1, 2, 3], &key, data_plain)),
        (harvest_hdr(ap, TYPE_DATA, 0, 0), wep_body([4, 5, 6], &key, data_plain)),
    ]);
    assert!(found.iter().any(|c| c.attack == "brute" && c.key.as_slice() == key), "brute must find the key");
}

#[test]
fn brute_prefilter_survives_a_leading_non_first_fragment() {
    // FR-BRUTE-1, FR-SIMD-2: only the first fragment of an MSDU carries the LLC/SNAP
    // header; a later fragment is a WEP MPDU in its own right (its own IV and ICV,
    // so it still verifies) but its plaintext is mid-packet. It must not seed the
    // prefilter either.
    use wepwolf::ieee80211::frame::TYPE_DATA;
    use wepwolf::model::Mac;
    let ap = Mac::from_bytes([0x0b; 6]);
    let key = [0x04u8, 0, 0, 0, 0];
    let data_plain = b"\xaa\xaa\x03\x00\x00\x00\x08\x00 the first fragment of a packet";
    let found = brute_after_harvest(&[
        (harvest_hdr(ap, TYPE_DATA, 0, 1), wep_body([7, 7, 7], &key, b"...the tail end of some earlier packet")),
        (harvest_hdr(ap, TYPE_DATA, 0, 0), wep_body([1, 2, 3], &key, data_plain)),
        (harvest_hdr(ap, TYPE_DATA, 0, 0), wep_body([4, 5, 6], &key, data_plain)),
    ]);
    assert!(found.iter().any(|c| c.attack == "brute" && c.key.as_slice() == key), "brute must find the key");
}
