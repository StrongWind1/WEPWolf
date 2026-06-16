//! The single key-acceptance path on hand-built WEP frames (FR-CORRECT-1, FR-CORRECT-2).
//!
//! A frame is built exactly as 802.11 WEP specifies: CRC-32 ICV appended to the
//! plaintext, then the whole thing RC4-encrypted under `IV || secret`. The
//! verifier must accept the right key and reject wrong keys and thin material.

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
