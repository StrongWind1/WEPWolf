//! SIMD detection and dispatch (FR-SIMD-1, FR-SIMD-2) plus the canonical
//! primitive vectors (FR-CORRECT-1).
//!
//! Every dispatch tier must agree with the scalar reference byte-for-byte. This
//! is trivial while only the scalar kernel exists, but it is the harness the
//! real SSE2/AVX2/AVX-512 kernels (M7) must pass before they can ship.

// lib-only deps; silence the per-target unused-crate-dependencies lint.
use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;

use wepwolf::crypto::{Rc4, crc32};
use wepwolf::simd::{self, SimdTier};

const TIERS: [SimdTier; 5] =
    [SimdTier::Scalar, SimdTier::Sse2Ssse3, SimdTier::Avx2, SimdTier::Avx512Skx, SimdTier::Avx512Icl];

#[test]
fn detect_reports_a_labeled_tier() {
    // FR-SIMD-1: runtime feature detection yields a usable, labeled tier.
    assert!(!simd::detect().label().is_empty());
}

#[test]
fn every_tier_matches_scalar() {
    // FR-SIMD-2: each dispatch kernel is byte-exact-equal to the scalar oracle.
    let data = b"kernels must equal scalar byte for byte across every tier";
    let key = b"\x01\x02\x03dispatch-seed-bytes";
    for tier in TIERS {
        assert_eq!(simd::crc32(tier, data), crc32(data), "crc32 tier {} != scalar", tier.label());
        let mut from_tier = [0u8; 48];
        let mut from_scalar = [0u8; 48];
        simd::rc4_keystream(tier, key, &mut from_tier);
        Rc4::new(key).keystream(&mut from_scalar);
        assert_eq!(from_tier, from_scalar, "rc4 tier {} != scalar", tier.label());
    }
}

#[test]
fn batched_rc4_prefix_matches_scalar() {
    // FR-SIMD-2: the batched RC4 prefix kernel is byte-exact with LANES separate
    // scalar streams, on every dispatch tier. Seeds are WEP-40 (IV(3)||secret(5)),
    // distinct per lane so each lane exercises a different key schedule.
    const LANES: usize = 16;
    const PFX: usize = 4;
    let mut seeds = [[0u8; 8]; LANES];
    for (seed, n) in seeds.iter_mut().zip(0u8..) {
        // A shared IV with a per-lane secret, mirroring the brute's candidate batch.
        *seed = [0x11, 0x22, 0x33, n, n ^ 0x5a, 0x9c, 0x00, 0xff];
    }
    // Scalar oracle: the first PFX keystream octets of each lane's own stream.
    let mut want = [[0u8; PFX]; LANES];
    for (seed, w) in seeds.iter().zip(want.iter_mut()) {
        Rc4::new(seed).keystream(w);
    }
    for tier in TIERS {
        let mut got = [[0u8; PFX]; LANES];
        simd::rc4_prefix_batch(tier, &seeds, &mut got);
        assert_eq!(got, want, "batched rc4 tier {} != scalar", tier.label());
    }
}

#[test]
fn primitive_known_answers() {
    // FR-CORRECT-1: the scalar primitives match the canonical published vectors.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    let mut ks = [0u8; 3];
    Rc4::new(b"Wiki").keystream(&mut ks);
    assert_eq!(ks, [0x60, 0x44, 0xDB]);
}
