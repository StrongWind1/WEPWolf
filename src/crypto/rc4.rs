//! RC4 (ARC4) stream cipher -- the WEP confidentiality primitive.
//!
//! WEP encrypts the MSDU+ICV with RC4 keyed by the 24-bit IV prepended to the
//! shared secret key: `seed = IV(3) || key(5|13|29)` (per [IEEE 802.11-2007]
//! section 8.2.1.2). Encryption and decryption are identical -- XOR with the
//! keystream -- so a recovered key is verified by RC4-decrypting and checking
//! the CRC-32 ICV (`crate::crypto::crc32`, `crate::wep::verify`).
//!
//! This is the straightforward scalar reference. RC4's state is inherently
//! sequential per stream, so SIMD parallelism comes from running *independent*
//! keys/IVs in separate lanes, never from vectorizing one keystream
//! (`crate::simd`). This kernel is the byte-exact oracle for those lanes
//! (FR-CORRECT-1).
#![allow(
    clippy::indexing_slicing,
    reason = "RC4 state is a 256-octet permutation indexed by u8-derived values that are in range by construction"
)]

/// An RC4 keystream generator: the 256-octet permutation state plus the two
/// stream indices `i`, `j`.
#[derive(Debug, Clone)]
pub struct Rc4 {
    /// The key-scheduled permutation of `0..=255`.
    state: [u8; 256],
    /// PRGA output index.
    i: u8,
    /// PRGA swap index.
    j: u8,
}

impl Rc4 {
    /// Key-schedule (KSA) over `key`, returning a generator positioned at the
    /// first keystream byte. For WEP, `key` is the full `IV || secret` seed.
    ///
    /// `key` must be non-empty (a zero-length key is a caller bug; WEP seeds
    /// are always at least 8 octets).
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        debug_assert!(!key.is_empty(), "RC4 key must be non-empty");
        // Identity permutation 0,1,...,255 without a usize->u8 cast.
        let mut state = [0u8; 256];
        for (slot, val) in state.iter_mut().zip(0u8..=255) {
            *slot = val;
        }
        // KSA: scramble the permutation under the key.
        let mut j: u8 = 0;
        for i in 0..256usize {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, usize::from(j));
        }
        Self { state, i: 0, j: 0 }
    }

    /// Produce the next keystream octet (PRGA).
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        let i = usize::from(self.i);
        self.j = self.j.wrapping_add(self.state[i]);
        let j = usize::from(self.j);
        self.state.swap(i, j);
        let sum = self.state[i].wrapping_add(self.state[j]);
        self.state[usize::from(sum)]
    }

    /// XOR the keystream into `buf` in place. WEP encryption and decryption are
    /// the same operation, so this both encrypts plaintext and decrypts
    /// ciphertext.
    ///
    /// The keystream is generated into a stack buffer in chunks and folded in
    /// with the SIMD XOR kernel -- faster than a byte-at-a-time loop on the
    /// full-MTU frames the verifier and brute decrypt (`crate::simd::xor`).
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        let tier = crate::simd::best();
        let mut ks = [0u8; 256];
        for chunk in buf.chunks_mut(ks.len()) {
            let key = &mut ks[..chunk.len()];
            self.keystream(key);
            crate::simd::xor(tier, chunk, key);
        }
    }

    /// Fill `out` with raw keystream octets (used by the keystream-recovery
    /// attacks, e.g. PTW from ARP plaintext).
    pub fn keystream(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.next_byte();
        }
    }
}

/// Batched RC4 keystream prefix for `LANES` independent WEP-40 seeds (FR-SIMD-2).
///
/// Each seed is the 8-octet WEP-40 RC4 seed `IV(3) || secret(5)`. The KSA and the
/// first `PFX` PRGA octets are produced for all `LANES` seeds with the per-lane
/// steps interleaved: lane `n`'s S-box is independent of every other lane's, so
/// the inner loop issues `LANES` independent data-dependent loads/stores that the
/// CPU overlaps, hiding the serial S-box latency that bounds a single scalar
/// stream (cross-lane instruction-level parallelism). The output is byte-identical
/// to `LANES` separate `Rc4::new(seed).keystream(prefix)` calls -- it *is* the
/// same scalar KSA/PRGA, only lane-interleaved -- so the byte-exact gate
/// (FR-SIMD-2) holds on every dispatch tier.
///
/// Only `PFX` octets are produced per lane because this backs the brute's
/// known-plaintext prefilter (`crate::attack::brute`): RC4's 256-step KSA
/// dominates a WEP-40 keystream and almost every candidate key is rejected on the
/// leading octets, so the full frame keystream is never generated for the rejected
/// majority. Vectorising the S-box itself was evaluated and rejected -- the KSA is
/// a data-dependent gather/scatter that x86 `vpgatherdd`/`vpscatterdd` execute one
/// element per micro-op, no faster than the scalar lanes -- so the kernel is one
/// portable form the SIMD tiers share (`crate::simd::rc4_prefix_batch`).
#[allow(
    clippy::needless_range_loop,
    reason = "the PRGA step index drives all lanes together; lane must be the inner loop to keep the streams interleaved for ILP, so the index cannot become an iterator over one output array"
)]
pub fn keystream_prefix_batch<const LANES: usize, const PFX: usize>(
    seeds: &[[u8; 8]; LANES],
    out: &mut [[u8; PFX]; LANES],
) {
    // Identity permutation per lane.
    let mut s = [[0u8; 256]; LANES];
    for lane in &mut s {
        for (slot, val) in lane.iter_mut().zip(0u8..=255) {
            *slot = val;
        }
    }
    // KSA, lanes interleaved so their dependent S-box accesses overlap. The seed
    // length is 8 (WEP-40), so `i % 8` is the cheap `i & 7`.
    let mut j = [0u8; LANES];
    for i in 0..256usize {
        for lane in 0..LANES {
            j[lane] = j[lane].wrapping_add(s[lane][i]).wrapping_add(seeds[lane][i & 7]);
            s[lane].swap(i, usize::from(j[lane]));
        }
    }
    // PRGA, lanes interleaved: the first PFX keystream octets per lane.
    let mut pi = [0u8; LANES];
    let mut pj = [0u8; LANES];
    for k in 0..PFX {
        for lane in 0..LANES {
            pi[lane] = pi[lane].wrapping_add(1);
            let ii = usize::from(pi[lane]);
            pj[lane] = pj[lane].wrapping_add(s[lane][ii]);
            let jj = usize::from(pj[lane]);
            s[lane].swap(ii, jj);
            let sum = s[lane][ii].wrapping_add(s[lane][jj]);
            out[lane][k] = s[lane][usize::from(sum)];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rc4;

    fn keystream_of(key: &[u8], n: usize) -> Vec<u8> {
        let mut ks = vec![0u8; n];
        Rc4::new(key).keystream(&mut ks);
        ks
    }

    // Canonical RC4 keystream vectors (the Wikipedia/cryptanalysis-literature
    // examples). aircrack-ng's RC4 produces the same bytes, so matching these
    // is matching the oracle.
    #[test]
    fn canonical_keystream_vectors() {
        assert_eq!(keystream_of(b"Key", 9), [0xEB, 0x9F, 0x77, 0x81, 0xB7, 0x34, 0xCA, 0x72, 0xA7]);
        assert_eq!(keystream_of(b"Wiki", 5), [0x60, 0x44, 0xDB, 0x6D, 0x41]);
        assert_eq!(keystream_of(b"Secret", 8), [0x04, 0xD4, 0x6B, 0x05, 0x3C, 0xA8, 0x7B, 0x59]);
    }

    // Full encrypt vector: key "Key", plaintext "Plaintext" -> known ciphertext.
    #[test]
    fn encrypt_vector() {
        let mut buf = b"Plaintext".to_vec();
        Rc4::new(b"Key").apply_keystream(&mut buf);
        assert_eq!(buf, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    // Encryption is its own inverse: apply the keystream twice -> identity.
    #[test]
    fn xor_is_involution() {
        let plain = b"the quick brown fox";
        let mut buf = plain.to_vec();
        Rc4::new(b"\x01\x02\x03KEYBYTES").apply_keystream(&mut buf);
        assert_ne!(&buf, plain);
        Rc4::new(b"\x01\x02\x03KEYBYTES").apply_keystream(&mut buf);
        assert_eq!(&buf, plain);
    }
}
