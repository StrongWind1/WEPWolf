//! Hashcat-style potfile: an append-only record of recovered WEP keys (FR-OUT).
//!
//! One line per cracked network, `<bssid>:<key_hex>` -- twelve hex digits of
//! BSSID, a colon, then the 5/13/29-octet key as hex, neither field containing a
//! separator. The format is greppable and round-trips: an earlier run's potfile
//! seeds the next, so a network whose key is already known is reported without
//! re-attacking it, exactly as hashcat reuses its pot.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::path::Path;

use crate::model::{Mac, WepKey};

/// Load a potfile into (BSSID, key) pairs, skipping blank/`#`/malformed lines.
/// A missing file is not an error -- it just yields no seeds.
///
/// # Errors
/// Propagates I/O errors other than the file being absent.
pub fn load(path: &Path) -> io::Result<Vec<(Mac, WepKey)>> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        if let Some(pair) = parse_line(&line?) {
            out.push(pair);
        }
    }
    Ok(out)
}

/// Append one recovered key, creating the potfile if it does not exist.
///
/// # Errors
/// Propagates any I/O error from opening or writing the file.
pub fn append(path: &Path, bssid: Mac, key: &WepKey) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", format_line(bssid, key))
}

/// Render one potfile line: `<bssid_hex>:<key_hex>`, both lowercase, no colons.
fn format_line(bssid: Mac, key: &WepKey) -> String {
    let mut line = hex(&bssid.0);
    line.push(':');
    line.push_str(&hex(key.as_slice()));
    line
}

/// Lowercase hex of a byte slice, no separators.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Parse one `<bssid_hex>:<key_hex>` line, or `None` if blank/comment/malformed.
fn parse_line(line: &str) -> Option<(Mac, WepKey)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (bssid_hex, key_hex) = line.split_once(':')?;
    let bssid_bytes = unhex(bssid_hex)?;
    let bssid = <[u8; 6]>::try_from(bssid_bytes.as_slice()).ok().map(Mac::from_bytes)?;
    WepKey::new(&unhex(key_hex)?).map(|key| (bssid, key))
}

/// Decode an even-length hex string to bytes, or `None` on odd length / non-hex.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let &[hi, lo] = pair else { return None };
            let hi = (hi as char).to_digit(16)?;
            let lo = (lo as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{format_line, parse_line};
    use crate::model::{Mac, WepKey};

    #[test]
    fn round_trips_a_key() {
        let bssid = Mac::from_bytes([0x00, 0x12, 0xbf, 0x12, 0x32, 0x29]);
        let key = WepKey::new(&[0x1f; 5]).unwrap();
        let line = format_line(bssid, &key);
        assert_eq!(line, "0012bf123229:1f1f1f1f1f");
        let (b, k) = parse_line(&line).expect("parses");
        assert_eq!(b, bssid);
        assert_eq!(k.as_slice(), key.as_slice());
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("  # a comment").is_none());
        assert!(parse_line("garbage").is_none());
    }
}
