//! The Shared-Key-authentication bootstrap attack (FR-ATK-SKA-1).
//!
//! A shared-key auth handshake leaks a run of RC4 keystream for one IV, recovered
//! in `crate::classify::observe_auth` and stored as `BssidWep::ska_keystream` (and
//! also folded into the sample pool). Passively, that single keystream cannot
//! recover the key on its own -- it is one sample, and Klein/PTW need thousands of
//! distinct IVs -- so SKA is a *bootstrap*, not a standalone cipher break: it runs
//! the same Klein/Maitra-Paul sigma vote PTW uses (`crate::attack::ptw::recover`)
//! over the BSSID's pool whenever a handshake was captured, and a key recovered on
//! such a network is attributed to SKA rather than PTW. Every key it returns is
//! still confirmed by the `Verifier` (C4); the handshake keystream is part of the
//! voted pool, so this credits the recovery to the captured handshake.

use super::Attack;
use crate::attack::ptw;
use crate::model::{BssidWep, KeyLen, WepKey};
use crate::wep::Verifier;

/// The Shared-Key-auth bootstrap attack (FR-ATK-SKA-1).
#[derive(Debug, Clone, Copy, Default)]
pub struct SkaAttack {
    /// Last-keybyte bruteforce (`-x`), shared with the PTW search it reuses.
    pub tuning: super::Tuning,
}

impl Attack for SkaAttack {
    fn name(&self) -> &'static str {
        "ska"
    }

    /// Applicable whenever a shared-key handshake was captured: its keystream is
    /// the bootstrap seed, so this fires even on a capture too thin for ordinary
    /// PTW. The search simply returns nothing when the pool cannot converge, so a
    /// handshake-only capture (one sample) is reported uncracked, not falsely.
    fn applicable(&self, bssid: &BssidWep, _len: KeyLen) -> bool {
        bssid.ska_keystream().is_some()
    }

    fn run(&self, bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey> {
        // The harvested SKA keystream is already in the pool; reuse the shared PTW
        // sigma search over it. A key found here is attributed to SKA (FR-ATK-SKA-1).
        ptw::recover(bssid.ivs(), bssid.arp_keystreams(), len.byte_len(), verifier, self.tuning.brute_tail, ptw::W_MP)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation, reason = "test fixtures cast small loop counters to IV octets")]

    use super::SkaAttack;
    use crate::attack::Attack;
    use crate::crypto::{Rc4, crc32};
    use crate::model::{BssidWep, EncFrame, IvSample, KeyLen, WepKey, WepMaterial};
    use crate::wep::Verifier;

    /// The true RC4 keystream for `iv || key`, as the SKA/ARP harvest recovers it.
    fn keystream(iv: [u8; 3], key: &[u8], n: usize) -> IvSample {
        let mut seed = iv.to_vec();
        seed.extend_from_slice(key);
        let mut ks = vec![0u8; n];
        Rc4::new(&seed).keystream(&mut ks);
        IvSample::new(iv, &ks)
    }

    fn verifier_for(key: &[u8]) -> Verifier {
        let frames = [[1u8, 2, 3], [4, 5, 6]]
            .iter()
            .map(|iv| {
                let plain = b"\xaa\xaa\x03\x00\x00\x00 ska verifier frame body";
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
    fn ska_is_applicable_only_with_a_handshake() {
        // FR-ATK-SKA-1: the bootstrap fires only when a shared-key handshake was
        // captured -- a record without one is left to the ordinary statistical path.
        let without = BssidWep::default();
        assert!(!SkaAttack::default().applicable(&without, KeyLen::Wep40), "no handshake -> not applicable");
        let with = BssidWep::with_material(WepMaterial { ska_keystream: Some(vec![0u8; 40]), ..Default::default() });
        assert!(SkaAttack::default().applicable(&with, KeyLen::Wep40), "a captured handshake -> applicable");
    }

    #[test]
    fn ska_bootstraps_a_crack_from_the_pool() {
        // FR-ATK-SKA-1: with a handshake captured, the bootstrap recovers the key
        // from the sample pool (handshake keystream + the harvested traffic) and
        // confirms it through the Verifier (C4).
        let key = [0x2bu8, 0x7e, 0x15, 0x16, 0x28];
        let arp = (0..80_000u32).map(|c| keystream([c as u8, (c >> 8) as u8, (c >> 16) as u8], &key, 16)).collect();
        // A handshake was seen (ska_keystream set), plus enough pool to converge.
        let bssid = BssidWep::with_material(WepMaterial {
            arp_keystreams: arp,
            ska_keystream: Some(vec![0u8; 40]),
            ..Default::default()
        });
        let recovered = SkaAttack::default().run(&bssid, KeyLen::Wep40, &verifier_for(&key));
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }
}
