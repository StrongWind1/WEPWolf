//! `WEPWolf` -- offline, one-shot WEP key recovery from 802.11 captures.
//!
//! The library is the pipeline described in `specs/02-architecture.md`: ingest
//! captures, group frames by BSSID, classify encryption, run the cheapest
//! applicable attack first, verify, and report. This module declares that tree;
//! each submodule documents its role and the `FR-*` it implements.
//!
//! Build order is primitives-first (`specs/05-roadmap.md`): `crypto` and `simd`
//! are proven byte-exact against aircrack-ng before any pipeline is wired. The
//! single key-acceptance path lives in `wep::verify` (C4). Every `FR-*` maps to
//! a test, enforced by `scripts/audit_fr.sh` / `make audit` (FR-TEST-2).

// --- Built now (M0/M1): primitives, domain model, the accept path, traits ---
pub mod attack;
pub mod carve;
pub mod classify;
pub mod cli;
pub mod crypto;
pub mod diag;
pub mod ieee80211;
pub mod input;
pub mod link;
pub mod model;
pub mod potfile;
pub mod progress;
pub mod report;
pub mod scan;
pub mod simd;
pub mod stats;
pub mod types;
pub mod wep;
