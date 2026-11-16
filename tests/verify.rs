//! The single key-acceptance path on hand-built WEP frames (FR-CORRECT-1, FR-CORRECT-2).
//!
//! A frame is built exactly as 802.11 WEP specifies: CRC-32 ICV appended to the
//! plaintext, then the whole thing RC4-encrypted under `IV || secret`. The
//! verifier must accept the right key and reject wrong keys and thin material.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation, reason = "integration test fixtures")]

// lib-only deps; silence the per-target unused-crate-dependencies lint.
use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;

use wepwolf::crypto::{Rc4, crc32};
use wepwolf::model::WepKey;
use wepwolf::wep::{EncFrame, Verifier};

/// Encrypt one WEP MPDU body: `plaintext || CRC32(plaintext)_le`, RC4'd under `IV || secret`.
fn make_frame(iv: [u8; 3], secret: &[u8], plaintext: &[u8]) -> EncFrame {
    let mut data = plaintext.to_vec();
    data.extend_from_slice(&crc32(plaintext).to_le_bytes());
    let mut seed = iv.to_vec();
    seed.extend_from_slice(secret);
    Rc4::new(&seed).apply_keystream(&mut data);
    EncFrame { iv, data, key_id: 0 }
}

#[test]
fn accepts_correct_rejects_wrong() {
    // FR-CORRECT-1 (accept the real key) and FR-CORRECT-2 (reject wrong keys).
    let secret = [0x11, 0x22, 0x33, 0x44, 0x55]; // WEP-40
    let verifier = Verifier::new(vec![
        make_frame([0x01, 0x02, 0x03], &secret, b"\xaa\xaa\x03\x00\x00\x00 first frame payload"),
        make_frame([0xfe, 0xed, 0x42], &secret, b"a different second frame for the icv check"),
    ]);

    let right = WepKey::new(&secret).unwrap();
    assert!(verifier.accept(&right), "the correct key must be accepted");

    let wrong = WepKey::new(&[0x11, 0x22, 0x33, 0x44, 0x56]).unwrap();
    assert!(!verifier.accept(&wrong), "a one-byte-off key must be rejected");
}

#[test]
fn single_frame_never_accepts() {
    // FR-CORRECT-2: two independent CRC agreements are required, so one frame
    // can never be enough -- the conservative stance against a fluke match.
    let secret = [9u8; 13]; // WEP-104
    let verifier = Verifier::new(vec![make_frame([7, 7, 7], &secret, b"only one frame present")]);
    let right = WepKey::new(&secret).unwrap();
    assert!(!verifier.accept(&right), "a single frame cannot reach two agreements");
}

/// The plain reading of the acceptance rule, kept deliberately naive: decrypt each
/// frame whole with the scalar RC4, split off the ICV, compare it to the scalar
/// CRC-32 of the body, and count. The verifier must agree with this on every input.
fn reference_accept(frames: &[EncFrame], secret: &[u8]) -> bool {
    let mut agreements = 0;
    for frame in frames {
        if frame.data.len() < 4 {
            continue;
        }
        let mut seed = frame.iv.to_vec();
        seed.extend_from_slice(secret);
        let mut dec = frame.data.clone();
        Rc4::new(&seed).apply_keystream(&mut dec);
        let (body, icv) = dec.split_at(dec.len() - 4);
        if crc32(body).to_le_bytes() == icv {
            agreements += 1;
        }
    }
    agreements >= 2
}

/// A deterministic body of `len` octets (no rng in tests).
fn body(len: usize, salt: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31).wrapping_add(salt.wrapping_mul(7)) & 0xff) as u8).collect()
}

/// A frame per entry of `lens` (the encrypted `Data || ICV` length), all under
/// `secret`; frames listed in `corrupt` get one flipped bit, and a length under
/// four is a runt that cannot hold an ICV at all.
fn frames_of(secret: &[u8], lens: &[usize], corrupt: &[usize]) -> Vec<EncFrame> {
    lens.iter()
        .enumerate()
        .map(|(n, &len)| {
            let iv = [(n as u8).wrapping_mul(17).wrapping_add(1), (n as u8).wrapping_mul(5), (n as u8).wrapping_add(3)];
            if len < 4 {
                return EncFrame { iv, data: vec![0xab; len], key_id: 0 };
            }
            let mut frame = make_frame(iv, secret, &body(len - 4, n));
            if corrupt.contains(&n) {
                let mid = frame.data.len() / 2;
                if let Some(octet) = frame.data.get_mut(mid) {
                    *octet ^= 0x10;
                }
            }
            frame
        })
        .collect()
}

#[test]
fn agrees_with_the_naive_reference_on_every_shape() {
    // FR-CORRECT-1, FR-CORRECT-2: the verifier decrypts a candidate's frames side by
    // side and stops as soon as the outcome is settled, but the answer must be
    // exactly "at least two retained frames agree" -- for every key length, every
    // mix of frame lengths (including the 256-octet block edges), runts, more
    // frames than one batch holds, and every placement of corrupt frames.
    let secrets: [&[u8]; 3] = [&[1, 2, 3, 4, 5], b"thirteen-byte", &[0x7e; 29]];
    let shapes: [&[usize]; 11] = [
        &[40; 8],
        &[40, 40, 62, 90, 132, 300, 700, 1500],
        &[1500, 700, 300, 132, 90, 62, 40, 40],
        &[5, 4, 6, 300],
        &[40],
        &[40, 41],
        &[3, 40, 2, 50, 0],
        &[40, 44, 256, 257, 512, 511, 255, 4, 100, 100, 100, 1024, 33],
        &[260; 9],
        &[300; 20],
        &[],
    ];
    let mut checked = 0u32;
    for secret in secrets {
        let mut wrong = secret.to_vec();
        wrong[0] ^= 1;
        for shape in shapes {
            let n = shape.len();
            let all: Vec<usize> = (0..n).collect();
            let corruptions: [Vec<usize>; 9] = [
                vec![],
                vec![0],
                vec![n.saturating_sub(1)],
                all.iter().copied().skip(2).collect(), // only the first two intact
                all.iter().copied().take(n.saturating_sub(2)).collect(), // only the last two intact
                all.iter().copied().take(n.saturating_sub(1)).collect(), // only the last intact
                all.iter().copied().filter(|i| i % 2 == 0).collect(),
                all.iter().copied().filter(|&i| i != 0 && i + 1 != n).collect(), // first and last intact
                all.clone(),
            ];
            for corrupt in &corruptions {
                let frames = frames_of(secret, shape, corrupt);
                let verifier = Verifier::new(frames.clone());
                for candidate in [secret, wrong.as_slice()] {
                    let key = WepKey::new(candidate).unwrap();
                    assert_eq!(
                        verifier.accept(&key),
                        reference_accept(&frames, candidate),
                        "verifier != reference: secret len {}, shape {shape:?}, corrupt {corrupt:?}, right key {}",
                        secret.len(),
                        candidate == secret
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 500, "the matrix must actually run ({checked} cases)");
}

#[test]
fn two_intact_frames_anywhere_are_enough() {
    // FR-CORRECT-1: the early stop must never skip a frame that could still settle
    // the outcome. Twenty frames span three batches; with only two intact, the key
    // is accepted wherever those two sit, and rejected once one of them goes.
    let secret = [0xc0, 0xff, 0xee, 0x15, 0x90];
    let key = WepKey::new(&secret).unwrap();
    let lens = [64usize; 20];
    for (a, b) in [(0, 1), (0, 19), (18, 19), (7, 8), (8, 16), (3, 12)] {
        let corrupt: Vec<usize> = (0..20).filter(|&i| i != a && i != b).collect();
        assert!(Verifier::new(frames_of(&secret, &lens, &corrupt)).accept(&key), "intact frames {a} and {b}");
        let one_left: Vec<usize> = (0..20).filter(|&i| i != a).collect();
        assert!(!Verifier::new(frames_of(&secret, &lens, &one_left)).accept(&key), "only frame {a} intact");
    }
}

#[test]
fn pushed_frames_count_like_constructed_ones() {
    // FR-CORRECT-1: frames added one at a time verify the same as a prebuilt set.
    let secret = [5u8, 4, 3, 2, 1];
    let key = WepKey::new(&secret).unwrap();
    let mut verifier = Verifier::default();
    assert!(!verifier.accept(&key), "no frames, no agreement");
    verifier.push(make_frame([1, 1, 1], &secret, &body(100, 1)));
    assert!(!verifier.accept(&key), "one frame is not enough");
    verifier.push(make_frame([2, 2, 2], &secret, &body(900, 2)));
    assert!(verifier.accept(&key), "the second agreeing frame settles it");
}
