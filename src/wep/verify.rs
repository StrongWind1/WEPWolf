//! The single key-acceptance path (C4, FR-CORRECT-1, FR-CORRECT-2); every key it
//! accepts is differentially validated against aircrack-ng (C5, FR-TEST-1).
//!
//! No statistical attack declares victory on its own: every candidate key is
//! routed through [`Verifier::accept`], which RC4-decrypts retained frames and
//! checks the CRC-32 ICV. Requiring two independent CRC agreements bounds a
//! false accept at roughly 2^-64, the same standard aircrack-ng applies.
#![allow(
    clippy::indexing_slicing,
    reason = "fixed 32-octet seed buffer and 4-octet ICV tail are guarded by explicit length checks"
)]

use crate::crypto::Rc4;
use crate::model::{EncFrame, WepKey};
use crate::simd;

/// The leading WEP MSDU plaintext is the LLC/SNAP header (RFC 1042), so the first
/// octets every WEP frame decrypts to are known: `0xAA 0xAA 0x03 0x00`. Per
/// [IEEE 802.11-2007] section 8.2.1. Four octets pin the true key's keystream
/// strongly enough that a wrong candidate clears the prefilter with probability
/// 2^-32. The length is the width of [`KnownPrefix::keystream`].
const SNAP_KNOWN: [u8; 4] = [0xAA, 0xAA, 0x03, 0x00];

/// A known-plaintext prefilter for the brute (`crate::attack::brute`).
///
/// The IV of a retained frame and the keystream the true key must produce over the
/// known LLC/SNAP prefix. It rejects candidate keys cheaply *before*
/// [`Verifier::accept`], which stays the sole acceptance path (C4) -- a survivor is
/// still verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownPrefix {
    /// The IV of the source frame (the RC4 seed prefix `IV || secret`).
    pub iv: [u8; 3],
    /// The keystream the true key yields over the prefix: `ciphertext XOR SNAP`.
    pub keystream: [u8; 4],
}

/// The only component permitted to declare a candidate key correct.
#[derive(Debug, Default, Clone)]
pub struct Verifier {
    /// Frames decrypted to confirm a candidate.
    pub frames: Vec<EncFrame>,
}

impl Verifier {
    /// Build a verifier over a set of retained encrypted frames.
    #[must_use]
    pub const fn new(frames: Vec<EncFrame>) -> Self {
        Self { frames }
    }

    /// Retain one more frame.
    pub fn push(&mut self, frame: EncFrame) {
        self.frames.push(frame);
    }

    /// A known-plaintext prefilter from the first long-enough retained frame, or
    /// `None` if none qualifies.
    ///
    /// The leading WEP plaintext is the LLC/SNAP header (`SNAP_KNOWN`), so the true
    /// key's keystream over those octets is `ciphertext XOR SNAP`. The brute uses
    /// this to reject the overwhelming majority of candidate keys with a few RC4
    /// octets instead of a full frame decrypt -- the same known-plaintext shortcut
    /// aircrack-ng applies (C5). It is a filter, never an acceptance: a survivor
    /// still passes through [`Verifier::accept`] (C4).
    #[must_use]
    pub fn prefilter(&self) -> Option<KnownPrefix> {
        let frame = self.frames.iter().find(|f| f.data.len() >= SNAP_KNOWN.len())?;
        let mut keystream = [0u8; 4];
        for (slot, (&cipher, &snap)) in keystream.iter_mut().zip(frame.data.iter().zip(&SNAP_KNOWN)) {
            *slot = cipher ^ snap;
        }
        Some(KnownPrefix { iv: frame.iv, keystream })
    }

    /// True iff `key` RC4-decrypts at least two retained frames to a plaintext
    /// whose CRC-32 matches the transmitted ICV (little-endian, as aircrack-ng
    /// checks). A wrong key matches with probability ~2^-32 per frame, so two
    /// agreements make a false accept negligible.
    #[must_use]
    pub fn accept(&self, key: &WepKey) -> bool {
        let secret = key.as_slice();
        // seed = IV(3) || secret; the secret tail is constant across frames, so
        // fill it once and overwrite only the IV prefix per frame.
        let mut seed = [0u8; 32];
        let seed_len = 3 + secret.len();
        seed[3..seed_len].copy_from_slice(secret);

        // Fold the ICV on the best available SIMD tier (PCLMULQDQ via crc32fast).
        let tier = simd::best();
        let mut agreements = 0usize;
        // One scratch buffer reused across frames: `accept` is the hot path of the
        // statistical search (millions of candidate keys), so a per-frame heap
        // allocation would dominate the reject path.
        let mut dec: Vec<u8> = Vec::with_capacity(self.frames.first().map_or(0, |f| f.data.len()));
        for frame in &self.frames {
            if frame.data.len() < 4 {
                continue;
            }
            seed[..3].copy_from_slice(&frame.iv);
            dec.clear();
            dec.extend_from_slice(&frame.data);
            Rc4::new(&seed[..seed_len]).apply_keystream(&mut dec);
            let split = dec.len() - 4;
            let (plain, icv) = dec.split_at(split);
            let received = u32::from_le_bytes([icv[0], icv[1], icv[2], icv[3]]);
            if simd::crc32(tier, plain) == received {
                agreements += 1;
                if agreements >= 2 {
                    return true;
                }
            }
        }
        false
    }
}
