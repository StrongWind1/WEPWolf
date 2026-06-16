//! 40-bit exhaustive search (FR-BRUTE-1).
//!
//! The scalar `CpuBrute` walks the 2^40 WEP-40 key space, confirming each candidate through the Verifier. It is the last-resort fallback when the statistical attacks have no material; SIMD batching and the rayon sweep/grind scheduler (M7) make a full sweep practical, and it is gated behind `--brute` so it never runs by accident. WEP-40 only -- longer raw keys are infeasible (FR-BRUTE-1).
#![allow(clippy::cast_possible_truncation, reason = "extracting the 5 key octets from the 40-bit index")]

use super::{Attack, BruteBackend, KeyRange};
use crate::model::{BssidWep, KeyLen, WepKey};
use crate::simd::{self, SimdTier};
use crate::wep::{KnownPrefix, Verifier};

/// One past the last index of the 40-bit WEP-40 key space.
const SPACE_40: u64 = 1 << 40;

/// Independent RC4 lanes the prefilter batches at once. Enough to overlap each
/// lane's data-dependent S-box latency (cross-lane ILP); the `LANES` S-boxes
/// (`LANES` * 256 octets) stay comfortably within L1.
pub(crate) const LANES: usize = 16;

/// Known-plaintext octets compared per candidate (the LLC/SNAP prefix). Four
/// octets reject a wrong key with probability `1 - 2^-32`, so over the 2^40 space
/// only ~2^8 candidates ever reach the full `Verifier` (C4). Must equal the width
/// of [`KnownPrefix::keystream`].
const PREFIX: usize = 4;

/// The WEP-40 key at little-endian 40-bit `index`, or `None` past the space.
/// Shared by the simple `search40` and the engine's cancellable grind loop.
#[must_use]
pub(crate) fn key_at(index: u64) -> Option<WepKey> {
    WepKey::new(&[index as u8, (index >> 8) as u8, (index >> 16) as u8, (index >> 24) as u8, (index >> 32) as u8])
}

/// Scalar CPU backend for the 40-bit search.
#[derive(Debug, Clone, Copy)]
pub struct CpuBrute;

impl BruteBackend for CpuBrute {
    fn label(&self) -> &'static str {
        "cpu-scalar"
    }

    fn search40(&self, verifier: &Verifier, range: KeyRange) -> Option<WepKey> {
        for idx in range.start..range.end {
            if let Some(key) = key_at(idx)
                && verifier.accept(&key)
            {
                return Some(key);
            }
        }
        None
    }
}

/// SIMD-batched backend for the 40-bit search (FR-SIMD-2, FR-SIMD-3).
///
/// A known-plaintext prefilter -- batched RC4 over a candidate-key batch -- rejects
/// almost every key on its leading keystream octets, so the expensive full-frame
/// decrypt and CRC of [`Verifier::accept`] (the sole acceptance path, C4) run only
/// for the ~2^8 survivors of the 2^40 space.
#[derive(Debug, Clone, Copy)]
pub struct SimdBrute {
    /// The detected SIMD tier, used to label the backend.
    tier: SimdTier,
}

impl SimdBrute {
    /// Build the backend on the best detected SIMD tier (FR-SIMD-1).
    #[must_use]
    pub fn new() -> Self {
        Self { tier: simd::best() }
    }
}

impl Default for SimdBrute {
    fn default() -> Self {
        Self::new()
    }
}

impl BruteBackend for SimdBrute {
    fn label(&self) -> &'static str {
        self.tier.label()
    }

    fn search40(&self, verifier: &Verifier, range: KeyRange) -> Option<WepKey> {
        // Without a known-plaintext frame the prefilter cannot be built; fall back
        // to the scalar per-key verify so correctness never rests on the shortcut.
        verifier.prefilter().map_or_else(
            || CpuBrute.search40(verifier, range),
            |filter| search_prefiltered(verifier, filter, self.tier, range.start, range.end),
        )
    }
}

/// Search `[start, end)` with the batched known-plaintext prefilter, returning the
/// first key the `Verifier` accepts (C4) -- only prefilter survivors are verified.
///
/// No cancellation polling: the engine grind wraps this in poll-sized windows so a
/// hit or an expired budget abandons promptly (FR-PERF-3). Shared by [`SimdBrute`]
/// and the grind so the prefilter logic lives in one place.
pub(crate) fn search_prefiltered(
    verifier: &Verifier,
    filter: KnownPrefix,
    tier: SimdTier,
    start: u64,
    end: u64,
) -> Option<WepKey> {
    let mut idx = start;
    while idx < end {
        let lanes = usize::try_from((end - idx).min(LANES as u64)).unwrap_or(LANES);
        // Build a batch of seeds: shared IV prefix, one candidate key per lane.
        let mut seeds = [[0u8; 8]; LANES];
        for (lane, seed) in seeds.iter_mut().enumerate().take(lanes) {
            let k = idx + lane as u64;
            seed[0] = filter.iv[0];
            seed[1] = filter.iv[1];
            seed[2] = filter.iv[2];
            seed[3] = k as u8;
            seed[4] = (k >> 8) as u8;
            seed[5] = (k >> 16) as u8;
            seed[6] = (k >> 24) as u8;
            seed[7] = (k >> 32) as u8;
        }
        let mut out = [[0u8; PREFIX]; LANES];
        simd::rc4_prefix_batch(tier, &seeds, &mut out);
        for (lane, ks) in out.iter().enumerate().take(lanes) {
            // A prefilter survivor: only now pay for the full verify (C4).
            if *ks == filter.keystream
                && let Some(key) = key_at(idx + lane as u64)
                && verifier.accept(&key)
            {
                return Some(key);
            }
        }
        idx += lanes as u64;
    }
    None
}

/// The brute-force attack (WEP-40 only).
#[derive(Debug, Clone, Copy)]
pub struct BruteAttack;

impl Attack for BruteAttack {
    fn name(&self) -> &'static str {
        "brute"
    }

    /// WEP-40 only (FR-BRUTE-2): 104/232-bit keys are recovered by dictionary or
    /// keygen, never by exhaustive search (2^104 is infeasible).
    fn applicable(&self, _bssid: &BssidWep, len: KeyLen) -> bool {
        len == KeyLen::Wep40
    }

    fn run(&self, _bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey> {
        if len != KeyLen::Wep40 {
            return None;
        }
        CpuBrute.search40(verifier, KeyRange { start: 0, end: SPACE_40 })
    }

    /// The brute is the grind: the engine runs it serialised on the full pool.
    fn is_grind(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{CpuBrute, KeyRange};
    use crate::attack::BruteBackend;
    use crate::crypto::{Rc4, crc32};
    use crate::model::{EncFrame, WepKey};
    use crate::wep::Verifier;

    fn verifier_for(key: &[u8]) -> Verifier {
        let frames = [[1u8, 2, 3], [4, 5, 6]]
            .iter()
            .map(|iv| {
                let plain = b"\xaa\xaa\x03\x00\x00\x00 brute verifier frame";
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

    #[test]
    fn brute_finds_a_low_key() {
        // index 5 -> key 05 00 00 00 00; a tiny range proves the search + verify path.
        let key = [0x05u8, 0, 0, 0, 0];
        let found = CpuBrute.search40(&verifier_for(&key), KeyRange { start: 0, end: 4096 });
        assert_eq!(found.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }
}
