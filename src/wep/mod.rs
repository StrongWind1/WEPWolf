//! The WEP frame model and the single key-acceptance path.
//!
//! WEP MPDU layout per [IEEE 802.11-2007] §8.2.1.2: a 4-octet IV field (24-bit
//! IV + 6-bit Pad + 2-bit Key ID), the RC4-encrypted Data, and the 4-octet
//! encrypted ICV. `frame` parses that body; `verify` is the single accept path.

pub mod frame;
pub mod verify;

pub use crate::model::EncFrame;
pub use frame::{WepView, parse};
pub use verify::{KnownPrefix, Verifier};
