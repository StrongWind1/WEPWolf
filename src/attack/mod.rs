//! The attack engine: the [`Attack`] trait every recovery method implements and
//! the [`BruteBackend`] trait the 40-bit exhaustive search plugs into.
//!
//! Attacks are tried cheapest-first across all key lengths; only
//! [`crate::wep::Verifier`] may declare a key correct (C4). Active attacks are
//! out of scope by constitution (C2) -- everything here works from already
//! captured traffic.
#![allow(clippy::doc_markdown, reason = "KoreK / PTW / aircrack-ng are attack and tool names, not code identifiers")]

use std::cell::Cell;
use std::time::Instant;

use crate::model::{BssidWep, IvSample, KeyLen, WepKey};
use crate::wep::Verifier;

thread_local! {
    /// Per-BSSID wall-clock deadline for the statistical searches. The engine
    /// sets it before each BSSID's attacks (each rayon worker handles one BSSID
    /// at a time), so a hard network can't starve the rest of the run (FR-PERF-3).
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };

    /// Whether the current attack pass is the *quick* one. The engine sweeps each
    /// BSSID twice: a quick pass that runs only the cheap argmax/top-k search of
    /// every attack across every key length, then a full pass with the expensive
    /// backtracking ladders. This keeps a wrong key-length's heavy search from
    /// eating the whole per-BSSID budget before the true length's cheap crack runs
    /// -- the case that left high-IV WEP-104 captures uncracked (FR-PERF-3).
    static QUICK: Cell<bool> = const { Cell::new(false) };
}

/// Set the calling thread's per-BSSID search deadline.
pub(crate) fn set_deadline(deadline: Option<Instant>) {
    DEADLINE.with(|d| d.set(deadline));
}

/// Whether the current BSSID's deadline has passed -- polled inside the searches
/// so a backtracking attack abandons a hopeless BSSID instead of spinning.
pub(crate) fn deadline_passed() -> bool {
    DEADLINE.with(Cell::get).is_some_and(|d| Instant::now() >= d)
}

/// Set whether the current pass is the quick (cheap-search-only) one.
pub(crate) fn set_quick(quick: bool) {
    QUICK.with(|q| q.set(quick));
}

/// Whether the current pass is quick -- the expensive search phases check this and
/// bail so the cheap search of every length runs before any costly ladder.
pub(crate) fn quick() -> bool {
    QUICK.with(Cell::get)
}

pub mod bias;
pub mod brute;
pub mod dict;
pub mod engine;
pub mod fms;
pub mod keygen;
pub mod korek;
pub mod ptw;
pub mod ska;

pub use engine::{CrackOutcome, CrackResult, crack, crack_all};

/// The unique-IV convergence floor per key length.
///
/// WEP-104/232 are not attempted below it (too few IVs to ever converge), and it is
/// the threshold below which an *uncracked* WEP-40 network is reported "capture too
/// thin" (FR-OUT-5). It is no longer a WEP-40 attack gate -- every network with real
/// IV material is attempted (see `worth_attempting`), so a weak or default key is
/// never pre-skipped; for WEP-40 the floor only labels the result. Not an acceptance
/// threshold: the `Verifier` (C4) remains the only thing that declares a key.
#[must_use]
pub const fn min_samples(len: KeyLen) -> usize {
    match len {
        // WEP-40 PTW typically wants a few thousand IVs; below ~1k is hopeless.
        KeyLen::Wep40 => 1_000,
        // WEP-104 needs tens of thousands; WEP-232 more still.
        KeyLen::Wep104 => 5_000,
        KeyLen::Wep232 => 15_000,
    }
}

/// Distinct IVs across a BSSID's samples -- the real statistical material.
///
/// The attacks tally each IV once (`unique_samples`): a reused IV repeats the same
/// keystream and so the same vote, adding no information. Gating feasibility on the
/// raw frame count would overstate a capture that farms one replayed packet (its
/// IVs barely move), attempting -- and timing out on -- a network that cannot
/// converge. Counting distinct IVs matches how aircrack-ng decides "enough IVs"
/// and how the votes actually accumulate.
pub(crate) fn unique_iv_count(bssid: &BssidWep) -> usize {
    let mut seen: std::collections::HashSet<[u8; 3]> = std::collections::HashSet::with_capacity(bssid.ivs().len());
    for sample in bssid.ivs().iter().chain(bssid.arp_keystreams()) {
        seen.insert(sample.iv);
    }
    seen.len()
}

/// Whether a statistical attack is worth attempting on `bssid` at `len`.
///
/// Every network with real IV material is attempted at WEP-40, so a weak/default key
/// or a lucky low-IV crack is never pre-skipped -- the "thin" label (below the
/// 1000-IV WEP-40 floor) is a *reporting* outcome, not an attack gate (FR-OUT-5). The
/// longer keys keep the higher convergence floor: WEP-104/232 cannot converge from a
/// handful of IVs, so attempting them there only burns the budget. A capture
/// replaying one packet (a single distinct IV) has no statistical material and is
/// skipped at every length -- cross-BSSID reuse and the potfile still try it.
pub(crate) fn worth_attempting(bssid: &BssidWep, len: KeyLen) -> bool {
    // A statistical vote needs at least two distinct IVs to vary at all.
    const MIN_ATTEMPT_IVS: usize = 2;
    let ivs = unique_iv_count(bssid);
    match len {
        KeyLen::Wep40 => ivs >= MIN_ATTEMPT_IVS,
        KeyLen::Wep104 | KeyLen::Wep232 => ivs >= min_samples(len),
    }
}

/// Deduplicate samples by IV, keeping the longest keystream per IV.
///
/// WEP reuses its 24-bit IV heavily, and a reused IV yields the same keystream
/// and so the same vote. Counting it more than once biases the statistical
/// attacks, so -- like aircrack-ng's unique-IV table -- they tally each distinct
/// IV exactly once. This is what lets the KoreK/bias votes converge on real
/// captures where most IVs repeat.
pub(crate) fn unique_samples(ivs: &[IvSample], arp: &[IvSample]) -> Vec<IvSample> {
    let mut best: std::collections::HashMap<[u8; 3], IvSample> = std::collections::HashMap::with_capacity(ivs.len());
    // ARP first so a tie keeps the longer keystream (PTW needs it for WEP-104+).
    for &s in arp.iter().chain(ivs) {
        match best.get(&s.iv) {
            Some(existing) if existing.ks_len >= s.ks_len => {},
            _ => {
                best.insert(s.iv, s);
            },
        }
    }
    best.into_values().collect()
}

/// Candidate-search tuning shared by the KoreK and Klein-bias attacks, mirroring
/// aircrack-ng's `-f` (fudge) / `-x` (last-keybyte bruteforce) / `-c` knobs.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    /// Fudge ratio (aircrack `-f`): a candidate octet is kept while its vote is
    /// at least `top / ffact`. `None` uses the per-length default (5 / 2).
    pub ffact: Option<f32>,
    /// Trailing key octets brute-forced exhaustively (aircrack `-x`, default 1).
    pub brute_tail: usize,
    /// Restrict candidate octets to printable ASCII for a faster, smaller search
    /// when the key is expected to be an ASCII passphrase (aircrack `-c`).
    pub alnum: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Self { ffact: None, brute_tail: 1, alnum: false }
    }
}

impl Tuning {
    /// The fudge ratio for `len`: the override, or aircrack's default -- 5 for
    /// WEP-40, 2 for the longer keys (`do_wep_crack1`, C5).
    #[must_use]
    pub fn ffact_for(self, len: KeyLen) -> f32 {
        // Clamp to >= 1: a fudge factor below 1 would keep nothing.
        self.ffact.unwrap_or(if matches!(len, KeyLen::Wep40) { 5.0 } else { 2.0 }).max(1.0)
    }
}

/// Whether `b` survives the alphanumeric (`-c`) restriction: aircrack keeps NUL
/// and printable ASCII (`0x20..=0x7e`), zeroing the control and high bytes.
fn is_keyspace_byte(b: u8, alnum: bool) -> bool {
    !alnum || b == 0 || (0x20..=0x7e).contains(&b)
}

/// The adaptive ratio-fudge candidates for one key octet: every value whose vote
/// is within a factor `ffact` of the top, highest first (aircrack `-f`). An
/// ambiguous octet yields many candidates, a clear one just the winner.
#[allow(
    clippy::indexing_slicing,
    reason = "votes is a fixed [i32; 256] indexed by u8-derived octet values, always in range"
)]
pub(crate) fn fudge_candidates(votes: &[i32; 256], ffact: f32, alnum: bool) -> Vec<u8> {
    let mut idx: Vec<u8> = (0..=255u8).filter(|&b| is_keyspace_byte(b, alnum)).collect();
    idx.sort_unstable_by(|&a, &b| votes[usize::from(b)].cmp(&votes[usize::from(a)]));
    let Some(&best) = idx.first() else {
        return Vec::new();
    };
    let top = votes[usize::from(best)];
    if top <= 0 {
        return vec![best]; // no usable signal; just the argmax
    }
    let threshold = f64::from(top) / f64::from(ffact);
    idx.into_iter().take_while(|&c| f64::from(votes[usize::from(c)]) >= threshold).collect()
}

/// The octet values a brute-forced tail position iterates: all 256, or the
/// printable-ASCII subset under `-c`.
pub(crate) fn keyspace_bytes(alnum: bool) -> Vec<u8> {
    (0..=255u8).filter(|&b| is_keyspace_byte(b, alnum)).collect()
}

/// The most-voted candidate in a 256-bucket vote table (lowest index wins ties).
/// Shared by the statistical attacks (FMS, PTW, ...).
pub(crate) fn argmax(votes: &[u32; 256]) -> u8 {
    let mut best = 0u8;
    let mut best_votes = 0u32;
    for (candidate, &count) in votes.iter().enumerate() {
        if count > best_votes {
            best_votes = count;
            best = u8::try_from(candidate).unwrap_or(0);
        }
    }
    best
}

/// A WEP key-recovery method (FMS, `KoreK`, PTW, dictionary, keygen, bias, ...).
/// `Send + Sync` so the engine can run attacks across BSSIDs in parallel.
pub trait Attack: Send + Sync {
    /// Short stable name, used for diagnostics and STATS per-attack attribution.
    fn name(&self) -> &'static str;

    /// Whether this attack has enough captured material to run for `bssid` at
    /// the hypothesised key length `len`.
    fn applicable(&self, bssid: &BssidWep, len: KeyLen) -> bool;

    /// Attempt recovery. Any internal candidate must be confirmed through
    /// `verifier` before it is returned, so a `Some` is always a verified key.
    fn run(&self, bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey>;

    /// Whether this is a *grind* attack (the 40-bit brute) the engine runs one
    /// BSSID at a time on the full pool, rather than in the parallel sweep
    /// (FR-PERF-1). Cheap statistical/dictionary attacks leave this `false`.
    fn is_grind(&self) -> bool {
        false
    }

    /// Whether this attack runs an expensive backtracking search that converges only
    /// with enough unique IVs. The engine runs such an attack's deep (full) pass only
    /// at or above [`min_samples`] -- a thin network still gets the cheap quick pass
    /// and the dictionary/common-key checks, but its budget is not burned on a
    /// hopeless ladder (FR-PERF-3). Cheap or material-bootstrapped attacks
    /// (FMS, dictionary, keygen, SKA) leave this `false`.
    fn needs_convergence(&self) -> bool {
        false
    }
}

/// A half-open partition `[start, end)` of the 40-bit key space, handed to a
/// brute backend so the search can be split across workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRange {
    /// First key index in the partition (inclusive).
    pub start: u64,
    /// One past the last key index (exclusive); at most 2^40.
    pub end: u64,
}

/// A backend for the 40-bit exhaustive search -- scalar/SIMD CPU now, GPU-ready
/// later (FR-SIMD-3). WEP-40 is the only length brute-forced; longer keys are
/// recovered statistically or reported infeasible.
pub trait BruteBackend {
    /// Stable label for the live brute bar and diagnostics (e.g. the SIMD tier).
    fn label(&self) -> &'static str;

    /// Search `range`, returning the first key the `verifier` accepts, if any.
    fn search40(&self, verifier: &Verifier, range: KeyRange) -> Option<WepKey>;
}
