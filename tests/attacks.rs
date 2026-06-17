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
use rayon as _;
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
    let cracks =
        attack::crack_all(&map, &attacks, &[KeyLen::Wep40], None, &[], &wepwolf::progress::Progress::new(false)).cracks;
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
    let cracks =
        attack::crack_all(&map, &attacks, &[KeyLen::Wep40], None, &[], &wepwolf::progress::Progress::new(false)).cracks;
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
fn time_budget_bounds_the_grind() {
    // FR-PERF-3: a zero budget stops the brute before it can find even a
    // low-index key; with no budget the same key is recovered via the grind.
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

    let cracked = attack::crack_all(&map, &attacks, &[KeyLen::Wep40], None, &[], &prog).cracks;
    assert!(cracked.iter().any(|c| c.attack == "brute"), "no budget -> brute finds the low key");

    let bounded = attack::crack_all(&map, &attacks, &[KeyLen::Wep40], Some(Duration::ZERO), &[], &prog).cracks;
    assert!(bounded.is_empty(), "zero budget -> grind bails before finding it");
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
    let cracks =
        attack::crack_all(&map, &attacks, &[KeyLen::Wep40], None, &[], &wepwolf::progress::Progress::new(false)).cracks;
    let recovered: HashMap<u8, Vec<u8>> = cracks.iter().map(|c| (c.key_id, c.key.as_slice().to_vec())).collect();
    assert_eq!(recovered.get(&0).map(Vec::as_slice), Some(key0.as_slice()), "slot 0 key recovered");
    assert_eq!(recovered.get(&1).map(Vec::as_slice), Some(key1.as_slice()), "slot 1 key recovered");
}

#[test]
fn feasibility_gates_on_unique_ivs_not_raw_frames() {
    // FR-OUT-5: the feasibility gate counts distinct IVs, not raw frames -- a
    // capture that replays one packet is frame-rich but IV-poor and cannot converge,
    // so attacking it only burns the per-BSSID budget.
    let count = 1500u32; // above min_samples(Wep40) = 1000
    // Many frames, one IV: too little unique material -> attack not applicable.
    let replayed = BssidWep::with_material(WepMaterial {
        ivs: (0..count).map(|_| IvSample::new([1, 2, 3], &[0u8; 8])).collect(),
        ..Default::default()
    });
    assert!(!PtwAttack::default().applicable(&replayed, KeyLen::Wep40), "one IV replayed many times is not feasible");
    // Same frame count, distinct IVs: feasible.
    let varied = BssidWep::with_material(WepMaterial {
        ivs: (0..count).map(|c| IvSample::new([c as u8, (c >> 8) as u8, 0], &[0u8; 8])).collect(),
        ..Default::default()
    });
    assert!(PtwAttack::default().applicable(&varied, KeyLen::Wep40), "enough distinct IVs is feasible");
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
