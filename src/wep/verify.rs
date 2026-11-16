//! The single key-acceptance path (C4, FR-CORRECT-1, FR-CORRECT-2); every key it
//! accepts is differentially validated against aircrack-ng (C5, FR-TEST-1).
//!
//! No statistical attack declares victory on its own: every candidate key is
//! routed through [`Verifier::accept`], which RC4-decrypts retained frames and
//! checks the CRC-32 ICV. Requiring two independent CRC agreements bounds a
//! false accept at roughly 2^-64, the same standard aircrack-ng applies.
#![allow(
    clippy::indexing_slicing,
    reason = "fixed-size lane arrays indexed below the lane count, and frame slices bounded by the frame length the loop is driven by"
)]

use crate::crypto::crc32::RESIDUE;
use crate::crypto::rc4::Rc4Lanes;
pub use crate::model::KnownPrefix;
use crate::model::{EncFrame, WepKey};
use crate::simd::Crc32Fold;

/// Frames decrypted side by side per candidate key (the RC4 lane count).
const LANES: usize = 8;

/// Keystream octets produced per lane per round. Large enough that the CRC fold
/// gets blocks its wide kernels can use, small enough to live on the stack.
const BLOCK: usize = 256;

/// The shortest body that can hold an ICV: the 4-octet ICV itself.
const ICV_LEN: usize = 4;

/// The agreements a key needs: two independent frames (FR-CORRECT-1).
const REQUIRED: usize = 2;

/// One frame queued for a lane: its IV and its encrypted `Data || ICV`.
#[derive(Clone, Copy)]
struct Lane<'a> {
    /// The frame's IV (the RC4 seed prefix).
    iv: [u8; 3],
    /// The encrypted body, ICV included.
    data: &'a [u8],
}

/// The leading WEP MSDU plaintext is the LLC/SNAP header (RFC 1042), so the first
/// octets every WEP frame decrypts to are known: `0xAA 0xAA 0x03 0x00`. Per
/// [IEEE 802.11-2007] section 8.2.1. Four octets pin the true key's keystream
/// strongly enough that a wrong candidate clears the prefilter with probability
/// 2^-32. The length is the width of [`KnownPrefix::keystream`].
pub(crate) const SNAP_KNOWN: [u8; 4] = [0xAA, 0xAA, 0x03, 0x00];

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
    /// `None` if none qualifies -- on the assumption that the frame is the first
    /// fragment of a data MSDU.
    ///
    /// Such a frame starts with the LLC/SNAP header (`SNAP_KNOWN`), so the true
    /// key's keystream over those octets is `ciphertext XOR SNAP`. The brute uses
    /// this to reject the overwhelming majority of candidate keys with a few RC4
    /// octets instead of a full frame decrypt -- the same known-plaintext shortcut
    /// aircrack-ng applies (C5). It is a filter, never an acceptance: a survivor
    /// still passes through [`Verifier::accept`] (C4).
    ///
    /// The verifier holds only encrypted bodies, so it cannot check the assumption:
    /// a Shared-Key auth frame or a later fragment retained first would yield an
    /// anchor that rejects the true key. A caller with the harvested record uses
    /// `crate::model::BssidWep::known_prefix` instead, which is recorded only from
    /// a frame whose leading plaintext is known; this is for a caller that built
    /// the frames itself.
    #[must_use]
    pub fn prefilter(&self) -> Option<KnownPrefix> {
        self.frames.iter().find_map(|f| KnownPrefix::from_known_plaintext(f.iv, &f.data, SNAP_KNOWN))
    }

    /// True iff `key` RC4-decrypts at least two retained frames to a plaintext
    /// whose CRC-32 matches the transmitted ICV (little-endian, as aircrack-ng
    /// checks). A wrong key matches with probability ~2^-32 per frame, so two
    /// agreements make a false accept negligible.
    ///
    /// This is the hot path of every search -- nearly every call is a wrong key, and
    /// rejecting it means failing all but one of the frames -- so the frames are
    /// decrypted side by side on [`Rc4Lanes`] rather than one after another, and
    /// the call stops as soon as the outcome is settled: at the second agreement,
    /// or once too few frames are left to reach it. Which frames are tried, and in
    /// what order, never changes the answer: it is "at least two retained frames
    /// agree", exactly.
    #[must_use]
    pub fn accept(&self, key: &WepKey) -> bool {
        let secret = key.as_slice();
        // Only a frame long enough to hold an ICV can ever agree.
        let mut pending = self.frames.iter().filter(|f| f.data.len() >= ICV_LEN);
        let mut remaining = pending.clone().count();
        let mut agreements = 0usize;
        while agreements < REQUIRED {
            let need = REQUIRED - agreements;
            if remaining < need {
                return false;
            }
            // Leave `need - 1` frames out of this batch: if none of the frames in it
            // agrees, those cannot rescue the key, so they are never decrypted. For
            // the usual wrong key that is one frame's work saved per call.
            let take = LANES.min(remaining - need + 1);
            let mut batch = [Lane { iv: [0; 3], data: &[] }; LANES];
            let mut queued = 0usize;
            for (slot, frame) in batch.iter_mut().zip(pending.by_ref().take(take)) {
                *slot = Lane { iv: frame.iv, data: &frame.data };
                queued += 1;
            }
            // Shortest first, so the lanes still running are always a suffix.
            let batch = &mut batch[..queued];
            batch.sort_unstable_by_key(|lane| lane.data.len());
            agreements += icv_agreements(secret, batch);
            remaining -= queued;
        }
        true
    }
}

/// How many of `batch`'s frames decrypt under `secret` to a body whose CRC-32
/// matches its ICV.
///
/// `batch` holds at most [`LANES`] frames, each at least [`ICV_LEN`] octets,
/// shortest first. Every frame gets its own RC4 lane (`seed = IV || secret`); the
/// lanes are key-scheduled together and then run a block at a time, each block
/// XOR-ed against the ciphertext and folded straight into that frame's CRC. A
/// frame retires when its body ends, and its ICV is settled by the CRC residue
/// (`crate::crypto::crc32::RESIDUE`) -- the whole `Data || ICV` folds to it exactly
/// when the ICV is the CRC of the data, so the tail is never split off.
fn icv_agreements(secret: &[u8], batch: &[Lane<'_>]) -> usize {
    let lanes = batch.len().min(LANES);
    // seed = IV(3) || secret: 8, 16, or 32 octets for WEP-40 / 104 / 232.
    let seed_len = 3 + secret.len();
    let mut seeds = [[0u8; 32]; LANES];
    for (seed, lane) in seeds.iter_mut().zip(batch) {
        seed[..3].copy_from_slice(&lane.iv);
        seed[3..seed_len].copy_from_slice(secret);
    }
    let mut rc4 = Rc4Lanes::<LANES>::schedule(&seeds, seed_len, lanes);
    let mut folds: [Crc32Fold; LANES] = core::array::from_fn(|_| Crc32Fold::default());
    let mut keystream = [[0u8; BLOCK]; LANES];
    let mut plain = [0u8; BLOCK];

    let mut agreements = 0usize;
    // `first` is the shortest frame still running; everything before it is done.
    let mut first = 0usize;
    let mut offset = 0usize;
    while first < lanes {
        let end = batch[first].data.len();
        while offset < end {
            let len = (end - offset).min(BLOCK);
            rc4.keystream(first..lanes, &mut keystream, len);
            for lane in first..lanes {
                let cipher = &batch[lane].data[offset..offset + len];
                for ((p, c), k) in plain.iter_mut().zip(cipher).zip(&keystream[lane]) {
                    *p = c ^ k;
                }
                folds[lane].update(&plain[..len]);
            }
            offset += len;
        }
        // Retire every frame that ends here (equal lengths end together).
        while first < lanes && batch[first].data.len() == end {
            if core::mem::take(&mut folds[first]).finish() == RESIDUE {
                agreements += 1;
            }
            first += 1;
        }
    }
    agreements
}
