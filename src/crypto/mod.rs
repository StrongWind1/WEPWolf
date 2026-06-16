//! Cryptographic primitives: RC4 (confidentiality) and IEEE CRC-32 (the ICV).
//!
//! These are the leaf building blocks of WEP. They are deliberately the
//! simplest correct scalar implementations so they can serve as the byte-exact
//! oracle that every SIMD kernel (`crate::simd`) is validated against, and as
//! the single mathematical basis of the one key-acceptance path
//! (`crate::wep::verify`). Per [IEEE 802.11-2007] section 8.2.1.

pub mod crc32;
pub mod rc4;

pub use crc32::crc32;
pub use rc4::Rc4;
