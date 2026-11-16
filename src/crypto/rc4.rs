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
    clippy::cast_possible_truncation,
    reason = "RC4 state is a 256-octet permutation indexed by octet-derived values that are in range by construction; the lane kernel holds those octets in u32 slots, so narrowing one back to u8 is exact"
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
        // KSA: scramble the permutation under the key. The key index wraps with a
        // counter rather than `i % key.len()`, which would cost a division per step.
        let mut j: u8 = 0;
        let mut k = 0usize;
        for i in 0..256usize {
            j = j.wrapping_add(state[i]).wrapping_add(key[k]);
            state.swap(i, usize::from(j));
            k += 1;
            if k == key.len() {
                k = 0;
            }
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

/// `u32` slots per lane: the 256-entry permutation plus padding.
///
/// The padding makes the lane stride 1088 octets, so the same index in two
/// different lanes never shares its low 12 address bits. With an unpadded
/// 1024-octet stride, lane `n` and lane `n + 4` sit exactly 4 KiB apart, and
/// every store to one falsely aliases the next load from the other (the CPU
/// compares only the low address bits before the full address is known),
/// stalling the lanes the interleaving is meant to overlap.
const LANE_STRIDE: usize = 272;

/// The identity permutation `0..=255` in lane layout (the padding stays zero).
const IDENTITY: [u32; LANE_STRIDE] = {
    let mut lane = [0u32; LANE_STRIDE];
    let mut v = 0u32;
    while v < 256 {
        lane[v as usize] = v;
        v += 1;
    }
    lane
};

/// `L` independent RC4 streams advanced in lock-step, lane-interleaved (FR-SIMD-2).
///
/// A single RC4 stream is bound by latency, not throughput: each step's S-box load
/// has to wait on the previous step's data-dependent store. Interleaving the same
/// step across independent lanes lets the CPU overlap those waits (cross-lane
/// instruction-level parallelism), which is where the speed comes from -- the
/// arithmetic is the plain scalar KSA/PRGA, so every lane is byte-identical to its
/// own [`Rc4`] stream on every dispatch tier (the FR-SIMD-2 gate).
///
/// The permutation is held one octet per `u32` slot: byte-wide loads and stores
/// measured markedly slower here than word-wide ones, and the padded stride
/// (`LANE_STRIDE`) keeps lanes from aliasing each other. Vectorising the S-box
/// itself was evaluated and rejected -- the KSA is a data-dependent gather/scatter
/// that x86 `vpgatherdd`/`vpscatterdd` execute one element per micro-op.
///
/// Two callers batch through it: the brute's known-plaintext prefilter (one
/// candidate key per lane, [`keystream_prefix_batch`]) and the verifier (one
/// retained frame per lane under a single candidate key, `crate::wep::verify`).
#[derive(Debug, Clone)]
pub struct Rc4Lanes<const L: usize> {
    /// Each lane's permutation, one octet per `u32` slot.
    s: [[u32; LANE_STRIDE]; L],
    /// Each lane's PRGA swap index.
    j: [u32; L],
    /// The PRGA output index, shared because the lanes advance together.
    i: u32,
}

impl<const L: usize> Rc4Lanes<L> {
    /// Key-schedule the first `lanes` lanes, lane `n` under `seeds[n][..seed_len]`.
    ///
    /// For WEP each seed is `IV(3) || secret`, so `seed_len` is 8, 16, or 32. It
    /// must be in `1..=S`; lanes at or past `lanes` are left unscheduled and must
    /// not be read.
    #[must_use]
    pub fn schedule<const S: usize>(seeds: &[[u8; S]; L], seed_len: usize, lanes: usize) -> Self {
        debug_assert!((1..=S).contains(&seed_len), "RC4 seed length must be in 1..=S");
        let lanes = lanes.min(L);
        let mut s = [IDENTITY; L];
        let mut j = [0u32; L];
        // The seed index wraps with a counter shared by every lane (all seeds have
        // the same length), so no step pays for a division.
        let mut k = 0usize;
        for i in 0..256usize {
            for lane in 0..lanes {
                let si = s[lane][i];
                let jn = j[lane].wrapping_add(si).wrapping_add(u32::from(seeds[lane][k])) & 0xff;
                j[lane] = jn;
                let sj = s[lane][jn as usize];
                s[lane][i] = sj;
                s[lane][jn as usize] = si;
            }
            k += 1;
            if k >= seed_len {
                k = 0;
            }
        }
        Self { s, j: [0u32; L], i: 0 }
    }

    /// Write the next `len` keystream octets of each lane in `lanes` to the front
    /// of that lane's row in `out` (`len` is capped at `B`).
    ///
    /// The lanes share one output index, so every lane still in use must be
    /// advanced by every call. A caller may stop advancing lanes it has finished
    /// with -- the verifier drops each frame as it ends -- but a dropped lane is
    /// then out of step and must not be resumed.
    pub fn keystream<const B: usize>(&mut self, lanes: core::ops::Range<usize>, out: &mut [[u8; B]; L], len: usize) {
        let (first, last) = (lanes.start, lanes.end.min(L));
        let mut i = self.i;
        for b in 0..len.min(B) {
            i = i.wrapping_add(1) & 0xff;
            let ii = i as usize;
            // Lane is the inner loop so the streams stay interleaved.
            for ((s, j), row) in self.s.iter_mut().zip(&mut self.j).zip(out.iter_mut()).take(last).skip(first) {
                let si = s[ii];
                let jn = j.wrapping_add(si) & 0xff;
                *j = jn;
                let sj = s[jn as usize];
                s[ii] = sj;
                s[jn as usize] = si;
                row[b] = s[(si.wrapping_add(sj) & 0xff) as usize] as u8;
            }
        }
        self.i = i;
    }
}

/// Batched RC4 keystream prefix for `LANES` independent WEP-40 seeds (FR-SIMD-2).
///
/// Each seed is the 8-octet WEP-40 RC4 seed `IV(3) || secret(5)`. The KSA and the
/// first `PFX` PRGA octets are produced for all `LANES` seeds on [`Rc4Lanes`], so
/// the output is byte-identical to `LANES` separate `Rc4::new(seed).keystream(prefix)`
/// calls on every dispatch tier (`crate::simd::rc4_prefix_batch`).
///
/// Only `PFX` octets are produced per lane because this backs the brute's
/// known-plaintext prefilter (`crate::attack::brute`): RC4's 256-step KSA
/// dominates a WEP-40 keystream and almost every candidate key is rejected on the
/// leading octets, so the full frame keystream is never generated for the rejected
/// majority.
pub fn keystream_prefix_batch<const LANES: usize, const PFX: usize>(
    seeds: &[[u8; 8]; LANES],
    out: &mut [[u8; PFX]; LANES],
) {
    Rc4Lanes::<LANES>::schedule(seeds, 8, LANES).keystream(0..LANES, out, PFX);
}

#[cfg(test)]
mod tests {
    use super::{Rc4, Rc4Lanes};

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

    // FR-SIMD-2: every lane equals its own scalar stream, for each WEP seed length
    // (8 / 16 / 32 octets) and for a non-power-of-two length, across a block
    // boundary of the 256-step output index.
    #[test]
    fn lanes_match_scalar_streams() {
        for seed_len in [8usize, 16, 32, 11] {
            let mut seeds = [[0u8; 32]; 8];
            for (lane, seed) in seeds.iter_mut().enumerate() {
                for (pos, octet) in seed.iter_mut().enumerate() {
                    *octet = (lane * 37 + pos * 11 + seed_len) as u8;
                }
            }
            let mut lanes = Rc4Lanes::<8>::schedule(&seeds, seed_len, 8);
            let mut got = [[0u8; 300]; 8];
            // Two calls, so the shared output index carries across them and wraps.
            lanes.keystream(0..8, &mut got, 300);
            let mut more = [[0u8; 300]; 8];
            lanes.keystream(0..8, &mut more, 77);
            for (lane, seed) in seeds.iter().enumerate() {
                let want = keystream_of(&seed[..seed_len], 377);
                assert_eq!(got[lane][..], want[..300], "lane {lane} seed_len {seed_len}");
                assert_eq!(more[lane][..77], want[300..], "lane {lane} seed_len {seed_len} (continued)");
            }
        }
    }

    // A caller may schedule fewer lanes than the kernel holds and retire lanes from
    // the front as it goes (the verifier does, frame by frame); the lanes still in
    // use must keep matching their scalar streams.
    #[test]
    fn partial_and_retiring_lanes_match_scalar_streams() {
        let mut seeds = [[0u8; 8]; 8];
        for (lane, seed) in seeds.iter_mut().enumerate() {
            *seed = [1, 2, 3, lane as u8, 0x5a, 0xc3, lane as u8 ^ 0xff, 9];
        }
        let mut lanes = Rc4Lanes::<8>::schedule(&seeds, 8, 5);
        let mut first = [[0u8; 64]; 8];
        lanes.keystream(0..5, &mut first, 40);
        let mut second = [[0u8; 64]; 8];
        lanes.keystream(2..5, &mut second, 64); // lanes 0 and 1 retired
        for (lane, seed) in seeds.iter().enumerate().take(5) {
            let want = keystream_of(seed, 104);
            assert_eq!(first[lane][..40], want[..40], "lane {lane}");
            if lane >= 2 {
                assert_eq!(second[lane][..], want[40..], "lane {lane} after retiring 0 and 1");
            }
        }
    }
}
