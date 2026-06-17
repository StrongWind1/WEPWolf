//! The attack engine: run the registered attacks against a BSSID's material.
//!
//! Attacks run cheapest-first across the key-length hypotheses, and the first key the `Verifier` accepts (C4) wins. The cheap statistical/dictionary attacks run BSSID-parallel (the *sweep*); the gated 40-bit brute runs one BSSID at a time on the full pool (the *grind*), so two brute jobs never compete (FR-PERF-1). The aircrack parity-or-better bar (FR-PERF-4) is measured in `benches/`. Adding an attack is adding a `Box<dyn Attack>`.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rayon::iter::{IntoParallelRefIterator as _, ParallelIterator as _};

use super::Attack;
use super::brute::{key_at, search_prefiltered};
use crate::model::{BssidWep, Encryption, KeyLen, Mac, WepKey};
use crate::progress::Progress;
use crate::wep::Verifier;

/// A recovered key plus the provenance the reporter needs.
#[derive(Debug, Clone)]
pub struct CrackResult {
    /// The BSSID the key belongs to.
    pub bssid: Mac,
    /// The advertised ESSID, if any.
    pub essid: Option<Vec<u8>>,
    /// The recovered secret.
    pub key: WepKey,
    /// The attack that found it.
    pub attack: &'static str,
    /// The default-key slot (0-3) the key was used in.
    pub key_id: u8,
    /// Wall-clock spent cracking this BSSID -- from when its attacks started to
    /// when the key verified (FR-OUT-2 `seconds`), not phase-relative, so a fast
    /// crack reads as fast even when it lands late in the parallel sweep. Stamped
    /// per BSSID for the sweep, per brute for the grind, and the verify time for a
    /// reused or seeded key.
    pub elapsed: Duration,
}

/// The keys recovered plus the phase timings the banner reports (`STATS.md`).
#[derive(Debug, Clone, Default)]
pub struct CrackOutcome {
    /// One `CrackResult` per recovered key (per slot for a multi-key AP).
    pub cracks: Vec<CrackResult>,
    /// Wall-clock in the parallel cheap-attack sweep (seed + sweep + reuse).
    pub sweep: Duration,
    /// Wall-clock in the serialised 40-bit brute grind.
    pub grind: Duration,
}

/// Run the cheap `attacks` (already in cost order) against one BSSID, returning the first verified key (FR-ATK-1).
///
/// The grind attacks (the brute) are skipped here -- [`crack_all`] runs them in a separate, serialised phase. Each attack tries the supplied key-length hypotheses shortest-first; the statistical attacks recover the length implicitly, so no length is favoured (FR-CLASSIFY-2). `--keylen` narrows `lengths` to a single size.
#[must_use]
pub fn crack(
    bssid: &BssidWep,
    verifier: &Verifier,
    attacks: &[Box<dyn Attack>],
    lengths: &[KeyLen],
    budget: Option<Duration>,
) -> Option<CrackResult> {
    // Two passes: a quick pass runs only the cheap argmax/top-k search of every
    // attack across every key length, then a full pass adds the expensive
    // backtracking ladders. This way the true key length's cheap crack is reached
    // before a wrong length's heavy search can burn the budget -- the case that
    // left high-IV WEP-104 captures uncracked (FR-PERF-3). A clean capture cracks
    // in the quick pass and never pays for the ladders.
    //
    // Fair shot (FR-PERF-3): the per-BSSID `budget` is split into an equal slice
    // per statistical attack, set fresh before each one in the full pass, so a slow
    // earlier attack (PTW's deep ladder) cannot starve the ones after it --
    // PTW -> KoreK -> FMS -> bias each get their own turn. The quick pass shares
    // the whole budget because its searches finish near-instantly.
    //
    // The divisor counts only the attacks that will actually run on this BSSID
    // (applicable at some length), so a registered-but-inapplicable attack -- SKA on
    // a no-handshake network, dict/keygen without --wordlist -- does not shrink the
    // slices the runnable ones receive.
    let runnable = u32::try_from(
        attacks.iter().filter(|a| !a.is_grind() && lengths.iter().any(|&l| a.applicable(bssid, l))).count(),
    )
    .unwrap_or(1)
    .max(1);
    let slice = budget.map(|b| b / runnable);
    for quick in [true, false] {
        super::set_quick(quick);
        for attack in attacks {
            if attack.is_grind() {
                continue;
            }
            // Quick pass shares the full budget (cheap searches); the full pass gives
            // each attack its own fresh slice so none is starved.
            let window = if quick { budget } else { slice };
            super::set_deadline(window.and_then(|w| Instant::now().checked_add(w)));
            for &len in lengths {
                if attack.applicable(bssid, len)
                    && let Some(key) = attack.run(bssid, len, verifier)
                {
                    super::set_quick(false);
                    super::set_deadline(None);
                    return Some(result(bssid, key, attack.name()));
                }
            }
        }
    }
    super::set_quick(false);
    super::set_deadline(None);
    None
}

/// Build a `CrackResult` for `bssid` from a recovered `key` and the attack name.
///
/// `elapsed` is stamped by the caller once it knows the phase start; the deep
/// sweep path builds with [`Duration::ZERO`] and `crack_all` overwrites it.
fn result(bssid: &BssidWep, key: WepKey, attack: &'static str) -> CrackResult {
    CrackResult {
        bssid: bssid.bssid,
        essid: bssid.essid.clone(),
        key,
        attack,
        key_id: lowest_key_id(bssid.key_ids_seen),
        elapsed: Duration::ZERO,
    }
}

/// The lowest default-key slot observed (0-3), or 0 when none was seen.
fn lowest_key_id(mask: u8) -> u8 {
    if mask == 0 { 0 } else { u8::try_from(mask.trailing_zeros()).unwrap_or(0) }
}

/// The key slots (0-3) with at least one observed frame, lowest first.
fn active_slots(mask: u8) -> Vec<u8> {
    (0..4u8).filter(|s| mask & (1 << s) != 0).collect()
}

/// A per-slot view of a BSSID: only the samples and verifier frames of one Key ID,
/// so different key schedules never share a vote table (FR-ATK-SLOT-1). The SKA
/// keystream is left intact (it is not slot-specific).
fn slot_view(bssid: &BssidWep, key_id: u8) -> BssidWep {
    let mut view = bssid.clone();
    if let Some(m) = view.material.as_deref_mut() {
        m.ivs.retain(|s| s.key_id == key_id);
        m.arp_keystreams.retain(|s| s.key_id == key_id);
        m.enc_frames.retain(|f| f.key_id == key_id);
    }
    view.key_ids_seen = 1 << key_id;
    view
}

/// Crack a BSSID, separating its WEP key slots (FR-ATK-SLOT-1).
///
/// An AP can run up to four keys at once (Key ID 0-3); their frames use different
/// key schedules, so pooling every slot's votes into one table -- as aircrack-ng
/// does, keying only by BSSID -- lets a busy slot drown the others and reports just
/// one key. The common single-slot capture is attacked as-is; a multi-slot AP is
/// attacked once per slot from only that slot's samples and verifier frames,
/// yielding one verified key per recovered slot.
fn crack_slots(
    bssid: &BssidWep,
    attacks: &[Box<dyn Attack>],
    lengths: &[KeyLen],
    budget: Option<Duration>,
) -> Vec<CrackResult> {
    let slots = active_slots(bssid.key_ids_seen);
    if slots.len() <= 1 {
        let verifier = Verifier::new(bssid.enc_frames().to_vec());
        return crack(bssid, &verifier, attacks, lengths, budget).into_iter().collect();
    }
    // Share the per-BSSID budget across the slots so a multi-slot AP cannot run
    // longer overall than a single-slot one (FR-PERF-3).
    let per_slot = budget.map(|b| b / u32::try_from(slots.len()).unwrap_or(1).max(1));
    slots
        .into_iter()
        .filter_map(|slot| {
            let view = slot_view(bssid, slot);
            let verifier = Verifier::new(view.enc_frames().to_vec());
            crack(&view, &verifier, attacks, lengths, per_slot).map(|mut found| {
                found.key_id = slot;
                found
            })
        })
        .collect()
}

/// A one-line `cracked ...` row, streamed above the sweep bar as a key verifies (FR-UI-2).
fn row(crack: &CrackResult) -> String {
    format!("  cracked {} via {:<6} key {}", crack.bssid, crack.attack, crack.key)
}

/// Recover keys for every WEP BSSID, returning one `CrackResult` per crack.
///
/// Three phases: the parallel cheap-attack *sweep* (FR-PERF-1), cross-BSSID key *reuse* (FR-PERF-2, so co-located same-key APs are cracked once), then the serialised brute *grind* bounded by `budget` per BSSID (FR-PERF-3). Each key streams to the progress surface as it verifies.
#[must_use]
pub fn crack_all(
    bssids: &BTreeMap<Mac, BssidWep>,
    attacks: &[Box<dyn Attack>],
    lengths: &[KeyLen],
    budget: Option<Duration>,
    seed_keys: &[WepKey],
    progress: &Progress,
) -> CrackOutcome {
    let wep: Vec<&BssidWep> = bssids.values().filter(|b| b.encryption() == Encryption::Wep).collect();
    let sweep = progress.sweep_bar(wep.len() as u64);
    let mut cracks: Vec<CrackResult> = Vec::new();
    let mut cracked: HashSet<Mac> = HashSet::new();
    // The clock for every key's reported `seconds`: time from here, the start of
    // the attack phase, to when the key verifies (FR-OUT-2). It also splits the
    // sweep and grind phase totals for the banner (`STATS.md`).
    let phase_start = Instant::now();

    // Phase 0: seed keys (a potfile or prior cracks) -- report a known network
    // without attacking it, the way hashcat reuses its pot.
    if !seed_keys.is_empty() {
        for b in &wep {
            let verifier = Verifier::new(b.enc_frames().to_vec());
            let started = Instant::now();
            if let Some(key) = seed_keys.iter().find(|k| verifier.accept(k)) {
                let mut c = result(b, *key, "potfile");
                c.elapsed = started.elapsed();
                sweep.println(&row(&c));
                sweep.inc(1);
                cracked.insert(b.bssid);
                cracks.push(c);
            }
        }
    }

    // Phase 1: sweep -- each still-uncracked BSSID's cheap attacks run on the
    // pool, bounded by the per-BSSID `budget` (already resolved upstream: the
    // default, an explicit `--time-budget`, or `None` for unlimited) so a hard
    // network cannot starve the rest (FR-PERF-3).
    let swept: Vec<CrackResult> = wep
        .par_iter()
        .filter(|b| !cracked.contains(&b.bssid))
        .flat_map_iter(|b| {
            // Surface the network being worked, so a slow BSSID is visible (FR-UI-1).
            sweep.set_message(format!("attacking {}", b.bssid));
            // Crack each WEP key slot separately (FR-ATK-SLOT-1); crack() splits the
            // per-BSSID budget into a fair slice per attack (FR-PERF-3).
            let started = Instant::now();
            let mut found = crack_slots(b, attacks, lengths, budget);
            // Stamp every slot with the time actually spent cracking this BSSID
            // (FR-OUT-2 `seconds`) -- per-BSSID granularity under the parallel sweep,
            // not phase-relative, so a fast crack reads fast even when it lands late.
            let took = started.elapsed();
            for c in &mut found {
                c.elapsed = took;
                sweep.println(&row(c));
            }
            sweep.inc(1);
            found
        })
        .collect();
    for c in swept {
        cracked.insert(c.bssid);
        cracks.push(c);
    }
    sweep.finish();

    // Cross-BSSID reuse: test every recovered key against the still-uncracked.
    let found: Vec<WepKey> = cracks.iter().map(|c| c.key).collect();
    for b in &wep {
        if cracked.contains(&b.bssid) {
            continue;
        }
        let verifier = Verifier::new(b.enc_frames().to_vec());
        let started = Instant::now();
        if let Some(key) = found.iter().find(|k| verifier.accept(k)) {
            let mut c = result(b, *key, "reuse");
            c.elapsed = started.elapsed();
            sweep.println(&row(&c));
            cracked.insert(b.bssid);
            cracks.push(c);
        }
    }
    // The cheap-attack sweep (seed + sweep + reuse) is everything up to here.
    let sweep_elapsed = phase_start.elapsed();

    // Grind: the 40-bit brute, one BSSID at a time so two jobs never compete.
    let grind_start = Instant::now();
    if attacks.iter().any(|a| a.is_grind()) && lengths.contains(&KeyLen::Wep40) {
        for b in &wep {
            if cracked.contains(&b.bssid) || b.enc_frames().is_empty() {
                continue;
            }
            let verifier = Verifier::new(b.enc_frames().to_vec());
            let started = Instant::now();
            if let Some(key) = grind(b.bssid, &verifier, budget, progress) {
                let mut c = result(b, key, "brute");
                c.elapsed = started.elapsed();
                sweep.println(&row(&c));
                cracked.insert(b.bssid);
                cracks.push(c);
            }
        }
    }
    CrackOutcome { cracks, sweep: sweep_elapsed, grind: grind_start.elapsed() }
}

/// Brute the 40-bit space for one BSSID on the full pool, bounded by `budget`.
///
/// The space is split into fixed chunks searched in parallel. A shared flag and
/// the per-BSSID deadline are polled every `POLL` keys so that once one chunk
/// finds the key -- or the budget runs out (FR-PERF-3) -- the in-flight chunks
/// abandon within microseconds instead of grinding to their ends. The bar names
/// the BSSID and reports percent / keys-per-second / ETA / SIMD tier (FR-UI-3).
fn grind(bssid: Mac, verifier: &Verifier, budget: Option<Duration>, progress: &Progress) -> Option<WepKey> {
    const SPACE: u64 = 1 << 40;
    const CHUNK: u64 = 1 << 24; // 16.7M keys per chunk -> 65536 chunks.
    const POLL: u64 = 1 << 16; // re-check the cancel flag / deadline every 65536 keys.
    let tier = crate::simd::best();
    // The known-plaintext prefilter (FR-SIMD-2): batched RC4 rejects almost every
    // candidate on its leading keystream octets, so the full verify runs only for
    // the rare survivor. Absent a usable frame, fall back to the scalar per-key verify.
    let filter = verifier.prefilter();
    let deadline = budget.and_then(|d| Instant::now().checked_add(d));
    let done = AtomicBool::new(false);
    let bar = progress.brute_bar(SPACE, tier.label());
    bar.set_message(format!("{bssid}  [{}]", tier.label()));
    let starts: Vec<u64> = (0..SPACE / CHUNK).map(|i| i * CHUNK).collect();
    let found = starts.par_iter().find_map_any(|&start| {
        let mut idx = start;
        while idx < start + CHUNK {
            // Poll the shared cancel flag and the deadline every POLL keys, so a key
            // found elsewhere -- or an expired budget (FR-PERF-3) -- abandons the
            // in-flight chunks within microseconds rather than grinding to the end.
            if done.load(Ordering::Relaxed) || deadline.is_some_and(|dl| Instant::now() >= dl) {
                return None;
            }
            let window_end = (idx + POLL).min(start + CHUNK);
            let hit = filter.map_or_else(
                || (idx..window_end).find_map(|i| key_at(i).filter(|k| verifier.accept(k))),
                |f| search_prefiltered(verifier, f, tier, idx, window_end),
            );
            if let Some(key) = hit {
                done.store(true, Ordering::Relaxed);
                return Some(key);
            }
            idx = window_end;
        }
        bar.inc(CHUNK);
        None
    });
    bar.finish();
    found
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{Attack, crack};
    use crate::model::{BssidWep, KeyLen, WepKey};
    use crate::wep::Verifier;

    /// Records the quick-pass flag seen on each `run` call, so the test can assert
    /// the engine sweeps the cheap (quick) pass over every length before the full
    /// pass (FR-PERF-3). Shares the log with the test via `Arc`.
    struct Recorder {
        seen: Arc<Mutex<Vec<bool>>>,
        crack_when_full: bool,
    }

    impl Attack for Recorder {
        fn name(&self) -> &'static str {
            "recorder"
        }
        fn applicable(&self, _bssid: &BssidWep, _len: KeyLen) -> bool {
            true
        }
        fn run(&self, _bssid: &BssidWep, _len: KeyLen, _verifier: &Verifier) -> Option<WepKey> {
            let quick = crate::attack::quick();
            self.seen.lock().expect("lock").push(quick);
            // Optionally "crack" only in the full pass, to prove the full pass runs.
            (self.crack_when_full && !quick).then(|| WepKey::new(&[1, 2, 3, 4, 5]).expect("wep40"))
        }
    }

    #[test]
    fn crack_sweeps_quick_pass_before_full_pass() {
        // A recorder that never cracks: every (pass, length) cell is visited, and
        // the quick pass (true) must precede the full pass (false).
        let seen = Arc::new(Mutex::new(Vec::new()));
        let attacks: [Box<dyn Attack>; 1] = [Box::new(Recorder { seen: Arc::clone(&seen), crack_when_full: false })];
        let result =
            crack(&BssidWep::default(), &Verifier::default(), &attacks, &[KeyLen::Wep40, KeyLen::Wep104], None);
        assert!(result.is_none());
        // Quick pass over both lengths, then full pass over both lengths.
        assert_eq!(*seen.lock().expect("lock"), vec![true, true, false, false]);
    }

    #[test]
    fn crack_runs_the_full_pass_when_quick_finds_nothing() {
        // A recorder that only "cracks" in the full pass: crack must still return
        // it, proving the full pass runs after the quick pass yields nothing.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let attacks: [Box<dyn Attack>; 1] = [Box::new(Recorder { seen, crack_when_full: true })];
        let result = crack(&BssidWep::default(), &Verifier::default(), &attacks, &[KeyLen::Wep40], None);
        assert!(result.is_some(), "the full pass must run after the quick pass");
    }

    /// Records the per-attack deadline state observed at the start of each `run`.
    struct Probe {
        passed: Arc<Mutex<Vec<bool>>>,
    }

    impl Attack for Probe {
        fn name(&self) -> &'static str {
            "probe"
        }
        fn applicable(&self, _bssid: &BssidWep, _len: KeyLen) -> bool {
            true
        }
        fn run(&self, _bssid: &BssidWep, _len: KeyLen, _verifier: &Verifier) -> Option<WepKey> {
            self.passed.lock().expect("lock").push(crate::attack::deadline_passed());
            None
        }
    }

    #[test]
    fn crack_arms_a_per_attack_deadline_from_the_budget() {
        // FR-PERF-3 (fair shot): crack() arms a per-attack deadline derived from the
        // per-BSSID budget and reset before each attack, so each statistical attack
        // runs against its own clock rather than a single shared deadline an earlier
        // attack could have exhausted. A generous budget arms a live window; a
        // near-zero one arms an already-expired window. (Deterministic: no sleeps.)
        let live = Arc::new(Mutex::new(Vec::new()));
        let attacks: [Box<dyn Attack>; 1] = [Box::new(Probe { passed: Arc::clone(&live) })];
        let _ = crack(
            &BssidWep::default(),
            &Verifier::default(),
            &attacks,
            &[KeyLen::Wep40],
            Some(Duration::from_secs(30)),
        );
        assert!(live.lock().expect("lock").iter().all(|&p| !p), "a generous budget arms a live per-attack deadline");

        let expired = Arc::new(Mutex::new(Vec::new()));
        let attacks: [Box<dyn Attack>; 1] = [Box::new(Probe { passed: Arc::clone(&expired) })];
        let _ = crack(
            &BssidWep::default(),
            &Verifier::default(),
            &attacks,
            &[KeyLen::Wep40],
            Some(Duration::from_nanos(1)),
        );
        assert!(expired.lock().expect("lock").iter().all(|&p| p), "a near-zero budget arms an already-expired window");
    }
}
