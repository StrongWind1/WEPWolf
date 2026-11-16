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

/// The value this CRC-32 takes over any message followed by that message's own
/// CRC in little-endian order -- which is exactly how WEP lays out `Data || ICV`.
///
/// It is a constant, independent of the message, and no other four-octet trailer
/// produces it: for a fixed message the final register is a bijection of the
/// trailer. So `crc32(data || icv) == RESIDUE` holds exactly when `icv` is the
/// CRC of `data` -- an equivalence, not an approximation -- which lets the ICV be
/// checked by folding the whole decrypted body in one pass, without first
/// splitting the ICV off its tail (`crate::wep::verify`). The same residue backs
/// the 802.11 FCS check (`crate::link::fcs`).
pub const RESIDUE: u32 = 0x2144_DF1C;

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
    use super::{RESIDUE, crc32};

    // The residue check is exactly the split check: a body followed by its own
    // little-endian CRC folds to RESIDUE, and any other trailer does not.
    #[test]
    fn residue_is_equivalent_to_the_split_icv_check() {
        for len in [0usize, 1, 4, 5, 36, 255, 256, 257, 1500] {
            // A deterministic body: a byte-wide recurrence seeded from the length.
            let mut octet = len.to_le_bytes()[0];
            let body: Vec<u8> = (0..len)
                .map(|_| {
                    octet = octet.wrapping_mul(31).wrapping_add(7);
                    octet
                })
                .collect();
            let icv = crc32(&body).to_le_bytes();
            let mut whole = body.clone();
            whole.extend_from_slice(&icv);
            assert_eq!(crc32(&whole), RESIDUE, "len {len}: correct ICV must fold to the residue");
            for bit in 0..32 {
                let mut bad = whole.clone();
                bad[len + bit / 8] ^= 1 << (bit % 8);
                assert_ne!(crc32(&bad), RESIDUE, "len {len}: a wrong ICV (bit {bit}) must not fold to the residue");
            }
            if len > 0 {
                let mut bad = whole.clone();
                bad[len / 2] ^= 0x80;
                assert_ne!(crc32(&bad), RESIDUE, "len {len}: a corrupted body must not fold to the residue");
            }
        }
    }

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
