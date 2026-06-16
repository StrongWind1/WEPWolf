//! Dictionary attack (FR-ATK-DICT-1): try each wordlist entry as a WEP key.
//!
//! Each line is attempted two ways: as raw key octets (when its length is 5, 13,
//! or 29) and as a hex string decoded to octets (colons ignored). The passphrase
//! key generators (Neesus-Datacom, MD5) are a separate attack (`crate::attack::keygen`).

use std::fs::File;
use std::io::{self, BufRead as _, BufReader};
use std::path::Path;

use super::Attack;
use crate::model::{BssidWep, KeyLen, WepKey};
use crate::wep::Verifier;

/// A wordlist-backed key search.
#[derive(Debug, Clone)]
pub struct DictAttack {
    words: Vec<Vec<u8>>,
}

impl DictAttack {
    /// Load a newline-separated wordlist (no default list is shipped, C-budget).
    ///
    /// # Errors
    /// Returns the I/O error if the file cannot be read.
    pub fn from_path(path: &Path) -> io::Result<Self> {
        Ok(Self { words: load_wordlist(path)? })
    }

    /// Build from in-memory words (used by tests).
    #[must_use]
    pub const fn from_words(words: Vec<Vec<u8>>) -> Self {
        Self { words }
    }
}

impl Attack for DictAttack {
    fn name(&self) -> &'static str {
        "dictionary"
    }

    fn applicable(&self, _bssid: &BssidWep, _len: KeyLen) -> bool {
        !self.words.is_empty()
    }

    fn run(&self, _bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey> {
        let want = len.byte_len();
        for word in &self.words {
            if word.len() == want
                && let Some(key) = WepKey::new(word)
                && verifier.accept(&key)
            {
                return Some(key);
            }
            if let Some(bytes) = decode_hex(word)
                && bytes.len() == want
                && let Some(key) = WepKey::new(&bytes)
                && verifier.accept(&key)
            {
                return Some(key);
            }
        }
        None
    }
}

/// Load a newline-separated wordlist into octet vectors (shared by dict + keygen).
///
/// # Errors
/// Returns the I/O error if the file cannot be read.
pub fn load_wordlist(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut words = Vec::new();
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            words.push(trimmed.as_bytes().to_vec());
        }
    }
    Ok(words)
}

/// Decode an ASCII hex string (colons ignored) to octets, or `None` if it is not
/// valid even-length hex.
fn decode_hex(s: &[u8]) -> Option<Vec<u8>> {
    let filtered: Vec<u8> = s.iter().copied().filter(|&c| c != b':').collect();
    if filtered.is_empty() || !filtered.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(filtered.len() / 2);
    for pair in filtered.chunks_exact(2) {
        let hi = hex_val(*pair.first()?)?;
        let lo = hex_val(*pair.get(1)?)?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// One hex digit to its value.
const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn decodes_hex_with_and_without_colons() {
        assert_eq!(decode_hex(b"0102abCD"), Some(vec![0x01, 0x02, 0xAB, 0xCD]));
        assert_eq!(decode_hex(b"01:02:ab:cd"), Some(vec![0x01, 0x02, 0xAB, 0xCD]));
        assert_eq!(decode_hex(b"abcde"), None); // odd length
        assert_eq!(decode_hex(b"xy"), None); // non-hex
    }
}
