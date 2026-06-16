//! IEEE CRC-32 -- the WEP Integrity Check Value (ICV).
//!
//! WEP appends a 4-octet ICV computed over the plaintext MSDU before RC4
//! encryption (per [IEEE 802.11-2007] section 8.2.1.3). That ICV is the
//! **IEEE CRC-32** (the same polynomial used by Ethernet, PNG and zlib):
//! reflected input/output, initial value `0xFFFF_FFFF`, final XOR
//! `0xFFFF_FFFF`, reflected polynomial `0xEDB8_8320`.
//!
//! This is **not** CRC-32C (Castagnoli, poly `0x82F6_3B78`). The SSE4.2
//! `crc32` instruction computes CRC-32C and is therefore the wrong primitive
//! for WEP -- the eventual SIMD fast path must fold with PCLMULQDQ over this
//! polynomial, not use the hardware `crc32` opcode (see `crate::simd`).
//!
//! The implementation here is the bit-at-a-time reference: it allocates no
//! lookup table and indexes nothing, so it is the unambiguous correctness
//! oracle every faster kernel is tested byte-exact against (FR-CORRECT-1).

/// Reflected IEEE CRC-32 polynomial (`0xEDB8_8320`), i.e. `0x04C1_1DB7` bit-reversed.
const POLY: u32 = 0xEDB8_8320;

/// Compute the IEEE CRC-32 of `data` (the WEP ICV polynomial).
///
/// Bit-reflected, init `0xFFFF_FFFF`, final XOR `0xFFFF_FFFF`. Matches zlib
/// `crc32`, so the canonical check value of `b"123456789"` is `0xCBF4_3926`.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            // Branch-free reduction: `mask` is all-ones when the low bit is set,
            // so the polynomial is XORed in exactly on those steps.
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLY & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc32;

    // Canonical IEEE CRC-32 (zlib) known-answer vectors. These are the same
    // values aircrack-ng's CRC computes; matching them is matching the oracle.
    #[test]
    fn known_answer_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    }

    // The defining property that separates IEEE CRC-32 from CRC-32C: the
    // Castagnoli check value of "123456789" is 0xE3069283, which we must NOT
    // produce. Guards against anyone wiring in the SSE4.2 crc32 opcode.
    #[test]
    fn is_not_crc32c() {
        assert_ne!(crc32(b"123456789"), 0xE306_9283);
    }
}
