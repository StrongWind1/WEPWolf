//! Weak-key generators (FR-ATK-KEYGEN-1): derive WEP keys from passphrases.
//!
//! Two de-facto generators turned ASCII passphrases into WEP keys. The Neesus-Datacom 40-bit LCG produces four default keys (the common "64-bit ASCII" form). MD5 of the passphrase repeated to 64 octets, truncated to 13, is the common "128-bit ASCII" form. Candidate passphrases come from `--wordlist`.
#![allow(
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "extracting key octets from a 32-bit RNG word and a 16-octet digest"
)]

use md5::{Digest as _, Md5};

use super::Attack;
use crate::model::{BssidWep, KeyLen, WepKey};
use crate::wep::Verifier;

/// Multiplier of the Neesus-Datacom linear congruential PRNG.
const LCG_MUL: u32 = 0x0003_43FD;
/// Increment of the Neesus-Datacom linear congruential PRNG.
const LCG_ADD: u32 = 0x0026_9EC3;

/// Derives keys from a passphrase wordlist via the weak generators.
#[derive(Debug, Clone)]
pub struct KeygenAttack {
    words: Vec<Vec<u8>>,
}

impl KeygenAttack {
    /// Build from candidate passphrases.
    #[must_use]
    pub const fn from_words(words: Vec<Vec<u8>>) -> Self {
        Self { words }
    }
}

impl Attack for KeygenAttack {
    fn name(&self) -> &'static str {
        "keygen"
    }

    fn applicable(&self, _bssid: &BssidWep, _len: KeyLen) -> bool {
        !self.words.is_empty()
    }

    fn run(&self, _bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey> {
        for word in &self.words {
            match len {
                KeyLen::Wep40 => {
                    for candidate in neesus_keys(word) {
                        if let Some(key) = WepKey::new(&candidate)
                            && verifier.accept(&key)
                        {
                            return Some(key);
                        }
                    }
                },
                KeyLen::Wep104 => {
                    if let Some(key) = WepKey::new(&md5_104(word))
                        && verifier.accept(&key)
                    {
                        return Some(key);
                    }
                },
                KeyLen::Wep232 => {}, // no standard 232-bit passphrase generator
            }
        }
        None
    }
}

/// The four Neesus-Datacom default keys for a 40-bit passphrase.
#[must_use]
pub fn neesus_keys(passphrase: &[u8]) -> [[u8; 5]; 4] {
    let mut seed: u32 = 0;
    for (i, &c) in passphrase.iter().enumerate() {
        seed ^= u32::from(c) << ((i & 3) * 8);
    }
    let mut keys = [[0u8; 5]; 4];
    let mut rng = seed;
    for key in &mut keys {
        for octet in key {
            rng = rng.wrapping_mul(LCG_MUL).wrapping_add(LCG_ADD);
            *octet = (rng >> 16) as u8;
        }
    }
    keys
}

/// The MD5-of-repeated-passphrase 104-bit key (first 13 octets of the digest).
#[must_use]
pub fn md5_104(passphrase: &[u8]) -> [u8; 13] {
    let mut buf = [0u8; 64];
    if !passphrase.is_empty() {
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = passphrase[i % passphrase.len()];
        }
    }
    let digest = Md5::digest(buf);
    let mut key = [0u8; 13];
    key.copy_from_slice(&digest[..13]);
    key
}

#[cfg(test)]
mod tests {
    use super::{md5_104, neesus_keys};

    #[test]
    fn neesus_is_deterministic_and_well_formed() {
        let keys = neesus_keys(b"hello");
        assert_eq!(keys.len(), 4);
        assert_eq!(keys, neesus_keys(b"hello")); // stable
        assert_ne!(keys[0], [0u8; 5]); // a real passphrase yields a non-zero key
    }

    #[test]
    fn md5_104_is_thirteen_octets_and_stable() {
        let key = md5_104(b"password");
        assert_eq!(key.len(), 13);
        assert_eq!(key, md5_104(b"password"));
    }
}
