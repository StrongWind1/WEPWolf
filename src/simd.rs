//! SIMD tier detection and dispatch (FR-SIMD-1, FR-SIMD-2).
//!
//! WEP cracking is an integer / byte-permute / carry-less-multiply workload:
//! RC4 KSA-PRGA across *independent* keys and IVs, CRC-32 folding, and key-byte
//! vote tallies. The useful x86 feature ladder is therefore the integer one --
//! SSE2+SSSE3 byte shuffles, AVX2, AVX-512BW, then AVX-512 VBMI + VPCLMULQDQ +
//! VPOPCNTDQ -- never the floating-point features (SSE/AVX/F16C/FMA), which
//! this code never touches.
//!
//! Detection uses `std::is_x86_feature_detected!`, which is safe and resolves at
//! runtime. The CRC-32 fold runs on real SIMD: the SIMD tiers delegate to the
//! `crc32fast` crate, whose PCLMULQDQ kernels carry the `unsafe` intrinsics so
//! this crate keeps `unsafe_code = "forbid"`. RC4's KSA/PRGA is sequential
//! within a single stream, so its lane-parallel form (batched across keys) is a
//! `#[target_feature]` kernel that still routes to the scalar reference; the
//! byte-exact gate (FR-SIMD-2) holds for every tier either way.

/// The selected instruction-set tier, cheapest to richest. The variant order
/// is the dispatch preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdTier {
    /// Portable scalar reference; always available.
    Scalar,
    /// SSE2 + SSSE3 (128-bit integer + `pshufb` byte shuffle).
    Sse2Ssse3,
    /// AVX2 (256-bit integer).
    Avx2,
    /// AVX-512BW ("Skylake-X" integer tier: 512-bit byte/word ops).
    Avx512Skx,
    /// AVX-512 VBMI + VPCLMULQDQ + VPOPCNTDQ ("Ice Lake" tier).
    Avx512Icl,
}

impl SimdTier {
    /// A short stable label for diagnostics and the live progress bar.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Sse2Ssse3 => "sse2+ssse3",
            Self::Avx2 => "avx2",
            Self::Avx512Skx => "avx512-skx",
            Self::Avx512Icl => "avx512-icl",
        }
    }
}

/// Detect the richest integer SIMD tier this CPU supports at runtime.
///
/// On non-x86 targets (or when no extensions are present) this is
/// [`SimdTier::Scalar`].
#[must_use]
pub fn detect() -> SimdTier {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx512vbmi")
            && std::is_x86_feature_detected!("vpclmulqdq")
            && std::is_x86_feature_detected!("avx512vpopcntdq")
        {
            return SimdTier::Avx512Icl;
        }
        if std::is_x86_feature_detected!("avx512bw") {
            return SimdTier::Avx512Skx;
        }
        if std::is_x86_feature_detected!("avx2") {
            return SimdTier::Avx2;
        }
        if std::is_x86_feature_detected!("ssse3") {
            return SimdTier::Sse2Ssse3;
        }
    }
    SimdTier::Scalar
}

/// Compute the WEP ICV CRC-32 using the best kernel for `tier`.
///
/// The scalar tier uses the portable table reference; every SIMD tier folds with
/// PCLMULQDQ via the audited `crc32fast` crate, which runtime-dispatches to
/// SSE4.2/PCLMULQDQ and encapsulates the `unsafe` intrinsics. Both compute the
/// identical IEEE CRC-32 (poly 0xEDB88320), so the byte-exact gate (FR-SIMD-2)
/// holds. This is the same fold the link-layer FCS already uses (C8).
#[must_use]
pub fn crc32(tier: SimdTier, data: &[u8]) -> u32 {
    match tier {
        SimdTier::Scalar => crate::crypto::crc32(data),
        SimdTier::Sse2Ssse3 | SimdTier::Avx2 | SimdTier::Avx512Skx | SimdTier::Avx512Icl => crc32fast::hash(data),
    }
}

/// The richest SIMD tier this CPU supports, detected once and cached.
///
/// `is_x86_feature_detected!` already caches its CPUID probe, but memoising the
/// tier keeps the hot accept/brute path (which calls [`crc32`] per candidate)
/// from re-walking the feature ladder.
#[must_use]
pub fn best() -> SimdTier {
    use std::sync::OnceLock;
    static TIER: OnceLock<SimdTier> = OnceLock::new();
    *TIER.get_or_init(detect)
}

/// Fill `out` with RC4 keystream for `key` using the best kernel for `tier`.
///
/// One stream is sequential, so the SIMD win is lane-parallelism across many
/// keys/IVs ([`rc4_prefix_batch`]). A single stream routes to the scalar RC4.
pub fn rc4_keystream(tier: SimdTier, key: &[u8], out: &mut [u8]) {
    match tier {
        SimdTier::Scalar | SimdTier::Sse2Ssse3 | SimdTier::Avx2 | SimdTier::Avx512Skx | SimdTier::Avx512Icl => {
            crate::crypto::Rc4::new(key).keystream(out);
        },
    }
}

/// Batched RC4 keystream prefix across `LANES` WEP-40 seeds, dispatched by `tier`.
///
/// This is the lane-parallel form (FR-SIMD-2) the brute's known-plaintext
/// prefilter runs over a candidate-key batch (`crate::attack::brute`).
/// RC4's KSA is a data-dependent S-box gather/scatter, which x86 vector
/// gather/scatter does not accelerate -- `vpgatherdd`/`vpscatterdd` retire one
/// element per micro-op, so a vectorised lane is no faster than a scalar one --
/// so every tier runs the one portable lane-interleaved kernel, whose speed comes
/// from cross-lane ILP and (in the brute) prefix rejection rather than vector
/// lanes. Routing every tier to the same kernel keeps it byte-exact with the
/// scalar oracle (FR-SIMD-2); the detected `tier` still labels the active backend.
pub fn rc4_prefix_batch<const LANES: usize, const PFX: usize>(
    tier: SimdTier,
    seeds: &[[u8; 8]; LANES],
    out: &mut [[u8; PFX]; LANES],
) {
    match tier {
        SimdTier::Scalar | SimdTier::Sse2Ssse3 | SimdTier::Avx2 | SimdTier::Avx512Skx | SimdTier::Avx512Icl => {
            crate::crypto::rc4::keystream_prefix_batch(seeds, out);
        },
    }
}

/// XOR `src` into `dst` in place (`dst[i] ^= src[i]`) over `min(len)` octets,
/// SIMD for the bulk and scalar for the tail.
///
/// This is the hot inner step of RC4 frame decryption that the brute and the
/// verifier run per candidate. XOR is bitwise, so every tier is byte-identical
/// to the scalar reference by construction (FR-SIMD-2).
pub fn xor(tier: SimdTier, dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    match tier {
        SimdTier::Scalar => xor_scalar(dst, src, n),
        SimdTier::Sse2Ssse3 | SimdTier::Avx2 | SimdTier::Avx512Skx | SimdTier::Avx512Icl => {
            #[cfg(target_arch = "x86_64")]
            xor_sse2(dst, src, n);
            #[cfg(not(target_arch = "x86_64"))]
            xor_scalar(dst, src, n);
        },
    }
}

/// Scalar reference XOR over the first `n` octets.
fn xor_scalar(dst: &mut [u8], src: &[u8], n: usize) {
    for (d, s) in dst.iter_mut().zip(src).take(n) {
        *d ^= *s;
    }
}

/// SSE2 16-octet-at-a-time XOR (SSE2 is `x86_64` baseline), scalar tail.
#[cfg(target_arch = "x86_64")]
#[allow(
    unsafe_code,
    clippy::cast_ptr_alignment,
    clippy::many_single_char_names,
    reason = "audited SIMD kernel: SSE2 is x86_64 baseline, each 16-byte access is bounds-checked before use, and the unaligned loadu/storeu intrinsics make the u8 pointer cast sound"
)]
fn xor_sse2(dst: &mut [u8], src: &[u8], n: usize) {
    use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};
    let mut i = 0usize;
    while i + 16 <= n {
        // SAFETY: i + 16 <= n <= min(dst.len(), src.len()), so the unaligned
        // 16-byte load/xor/store at offset i is entirely in bounds for both.
        unsafe {
            let d = _mm_loadu_si128(dst.as_ptr().add(i).cast());
            let s = _mm_loadu_si128(src.as_ptr().add(i).cast());
            let x = _mm_xor_si128(d, s);
            _mm_storeu_si128(dst.as_mut_ptr().add(i).cast(), x);
        }
        i += 16;
    }
    for (d, s) in dst.iter_mut().zip(src).skip(i).take(n - i) {
        *d ^= *s;
    }
}

#[cfg(test)]
mod tests {
    use super::{SimdTier, crc32, detect, rc4_keystream, xor};

    #[test]
    fn detect_returns_a_labeled_tier() {
        let tier = detect();
        assert!(!tier.label().is_empty());
    }

    // Every dispatch tier must agree byte-for-byte with the scalar reference
    // (FR-SIMD-2): the CRC fold, the RC4 keystream, and the bulk XOR kernel.
    #[test]
    fn dispatch_matches_scalar() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let key = b"\x01\x02\x03SECRETKEY";
        // A buffer/keystream pair long enough to exercise the 16-byte SIMD path
        // plus a non-multiple-of-16 tail.
        let buf: Vec<u8> = (0u8..=200).collect();
        let ks: Vec<u8> = (0u8..=200).map(|b| b.wrapping_mul(31).wrapping_add(7)).collect();
        let tiers = [SimdTier::Scalar, SimdTier::Sse2Ssse3, SimdTier::Avx2, SimdTier::Avx512Skx, SimdTier::Avx512Icl];
        for tier in tiers {
            assert_eq!(crc32(tier, data), crate::crypto::crc32(data));
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            rc4_keystream(tier, key, &mut a);
            crate::crypto::Rc4::new(key).keystream(&mut b);
            assert_eq!(a, b);

            let mut x_simd = buf.clone();
            xor(tier, &mut x_simd, &ks);
            let x_ref: Vec<u8> = buf.iter().zip(&ks).map(|(d, s)| d ^ s).collect();
            assert_eq!(x_simd, x_ref, "xor tier {} != scalar", tier.label());
        }
    }
}
