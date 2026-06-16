//! Parser-support types ported from `WPAWolf` (C9): the MAC address, the parse
//! error enum, and small byte helpers.
//!
//! This module sits at the bottom of the dependency DAG -- it imports only from
//! `std`. The capture front-end (`input`, `link`, `ieee80211`) is lifted from
//! `WPAWolf` and depends on exactly these types; the WEP domain layer aliases
//! the address as `crate::model::Mac`.

use std::fmt::Write as _;

// --- MAC addresses ---

/// 6-octet IEEE 802.11 MAC address.
///
/// Stored as a fixed-size byte array for cheap `Copy` semantics and use as a
/// `HashMap` key without heap allocation. `MacAddr::from_bytes` is the canonical
/// constructor; `Display` formats as lowercase colon-separated hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Constructs a `MacAddr` from a raw 6-octet array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Returns a `Display` wrapper formatting the MAC as 12 lowercase hex
    /// characters with no separators (e.g. `aabbccddeeff`), allocation-free.
    #[must_use]
    pub const fn hex_lower(&self) -> MacHexLower<'_> {
        MacHexLower(self)
    }
}

impl std::fmt::Display for MacAddr {
    /// Formats as lowercase colon-separated hex, e.g. `"aa:bb:cc:dd:ee:ff"`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

impl std::fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

/// Display wrapper for the compact, no-separator hex form of a `MacAddr`.
///
/// Formats as 12 lowercase hex characters (e.g. `aabbccddeeff`). Returned by
/// `MacAddr::hex_lower`; never constructed directly outside this module.
#[derive(Clone, Copy, Debug)]
pub struct MacHexLower<'a>(&'a MacAddr);

impl std::fmt::Display for MacHexLower<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0.0;
        write!(f, "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

// --- Errors ---

/// Errors from ingest and parsing. I/O errors abort the run; parse errors are
/// logged and the offending frame is skipped.
#[derive(Debug)]
pub enum Error {
    /// An underlying I/O operation failed.
    Io(std::io::Error),
    /// The file's magic bytes do not match any supported format.
    UnknownFormat(String),
    /// An unknown CLI flag was passed.
    UnknownOption(String),
    /// A CLI flag that requires an argument was supplied without one.
    MissingArgument(String),
    /// A numeric CLI argument could not be parsed.
    InvalidNumber {
        /// The flag name.
        arg: String,
        /// The value that was not numeric.
        value: String,
    },
    /// A buffer was shorter than required to parse a structure.
    Truncated {
        /// Human-readable description of the structure being parsed.
        context: &'static str,
        /// Octets needed.
        needed: usize,
        /// Octets available.
        got: usize,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::UnknownFormat(hex) => write!(f, "unrecognised file format (magic bytes: {hex})"),
            Self::UnknownOption(flag) => write!(f, "unknown option: {flag}"),
            Self::MissingArgument(flag) => write!(f, "{flag} requires an argument"),
            Self::InvalidNumber { arg, value } => write!(f, "{arg}: {value:?} is not a valid number"),
            Self::Truncated { context, needed, got } => write!(f, "{context}: need {needed} bytes, got {got}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Convenience alias so callers can write `Result<T>` instead of `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

// --- Byte helpers ---

/// Lowercase hex with no separators, used for error context and log lines.
#[must_use]
pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Strip trailing NUL padding (e.g. from fixed-width SSID fields).
#[must_use]
pub fn trim_nul_padding(bytes: &[u8]) -> &[u8] {
    let trimmed = bytes.len() - bytes.iter().rev().take_while(|&&b| b == 0).count();
    bytes.get(..trimmed).unwrap_or(bytes)
}
