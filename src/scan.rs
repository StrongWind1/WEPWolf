//! The capture-scanning driver (FR-IN-1, FR-IN-3, FR-IN-5, FR-IN-6, FR-PARSE, FR-CLASSIFY-1, FR-WEP).
//!
//! Packets are pulled one at a time (`reader.next_packet`), so a multi-GB capture
//! is streamed with bounded memory -- only the per-BSSID records are retained,
//! never the whole file (FR-IN-5).
//!
//! With `--debug` it emits a periodic ingest heartbeat (not a line per file -- a
//! megacorpus holds millions) and a bounded per-BSSID material dump: WEP BSSIDs
//! most-IVs-first capped at a few hundred, with the thin remainder and the non-WEP
//! networks collapsed into census counts (FR-DEBUG-2).
//!
//! The input files are ingested in parallel on the work-stealing pool (FR-IN-6):
//! each file is opened, streamed, and folded into its own per-BSSID map and
//! accounting independently, then the per-file maps are merged in input-file order
//! so the result is identical regardless of thread scheduling. Per file the pass
//! is one streaming sweep: open the container, pull packets, strip the link-layer
//! header (with tiered FCS recovery), parse the 802.11 MAC header, and fold every
//! WEP-bearing frame into the per-BSSID harvester. Every packet lands in exactly
//! one accounting bucket so the `STATS.md` identity holds (FR-PARSE-4). The
//! strip/FCS/recover orchestration is ported from `WPAWolf`'s `strip_and_resolve`
//! (C9).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::iter::{IntoParallelRefIterator as _, ParallelIterator as _};

use crate::carve::Carver;
use crate::classify::{self, Carve, ChallengeCache};
use crate::diag::{DebugPrinter, EventTally, LogEvent, Logger, MemMonitor};
use crate::ieee80211::frame::{self, ParseResult, TYPE_DATA, TYPE_MANAGEMENT};
use crate::input::{self, Packet};
use crate::link;
use crate::model::{BssidWep, Encryption, Mac};
use crate::progress::{Bar, Progress};
use crate::stats::Stats;
use crate::types::Result;

/// Files ingested concurrently per batch, as a multiple of the worker count.
///
/// The parallel ingest folds each batch into the result and frees it before the
/// next, so this bounds how many per-file maps are resident at once (and thus peak
/// memory) while keeping every worker busy. Four batches' worth of files per
/// thread saturates the pool through file-size variance without holding every
/// file's material at once.
const INGEST_BATCH_PER_THREAD: usize = 4;

/// Files between `--debug` ingest heartbeats. A megacorpus has millions of files,
/// so a line per file is spam; a count tick every this many keeps the operator
/// informed without flooding stderr (FR-DEBUG-1's bounded-volume intent).
const INGEST_TICK_FILES: u64 = 50_000;

/// Most WEP BSSIDs detailed in the `--debug` per-BSSID material dump before the
/// remainder collapses to a count, so a million-BSSID input stays readable.
const DEBUG_BSSID_ROWS: usize = 256;

/// The outcome of scanning the inputs: per-BSSID WEP records plus run accounting.
#[derive(Debug)]
pub struct ScanResult {
    /// Observed BSSIDs, sorted, with their harvested material and classification.
    pub bssids: BTreeMap<Mac, BssidWep>,
    /// Packet- and BSSID-level accounting (`STATS.md`).
    pub stats: Stats,
}

/// Scan every capture file in `paths` (already expanded), returning the
/// per-BSSID records and the run accounting.
///
/// # Errors
/// Propagates only fatal I/O errors; per-file open failures and per-frame parse
/// errors are counted/logged and the scan continues.
pub fn scan(
    paths: &[PathBuf],
    debug: &DebugPrinter,
    logger: &mut Logger,
    mem: &mut MemMonitor,
    progress: &Progress,
    carve: Option<&mut Carver>,
) -> Result<ScanResult> {
    let spinner = progress.ingest_spinner();
    let log_active = logger.active();
    // The carve output is one shared file (FR-OUT-6); behind a mutex it is fed
    // from every worker while parsing stays parallel. Crack frames are written as
    // they are seen and beacons buffered per BSSID -- order is irrelevant for a
    // re-crackable capture, so the lock (taken only when there is a frame to
    // write) does not serialise the scan.
    let carve = carve.map(Mutex::new);
    // Lock-free counters that drive the live spinner only; the authoritative
    // accounting is the per-file `Stats`, summed exactly during the merge below.
    let packets = AtomicU64::new(0);
    let files_done = AtomicU64::new(0);

    // Ingest in parallel (FR-IN-6), but in input-order batches so only one batch
    // of per-file maps is resident at a time. Each batch is scanned on the pool,
    // then folded into the result in input-file order and freed before the next
    // batch starts. This bounds peak memory to roughly one batch of per-file
    // material plus the merged result -- rather than every file's material at once
    // -- while keeping the merge order-fixed, so the result is still identical
    // regardless of thread scheduling. `par_iter().collect()` over a batch
    // preserves input order, and the batches are processed in order.
    let mut bssids: BTreeMap<Mac, BssidWep> = BTreeMap::new();
    let mut stats = Stats::default();
    let batch_size = rayon::current_num_threads().max(1).saturating_mul(INGEST_BATCH_PER_THREAD);
    // Files at the last emitted `--debug` ingest heartbeat (see INGEST_TICK_FILES).
    let mut ticked = 0u64;
    for batch in paths.chunks(batch_size) {
        let partials: Vec<(String, BTreeMap<Mac, BssidWep>, Stats, EventTally)> = batch
            .par_iter()
            .map(|path| {
                let name = path.display().to_string();
                let mut file_bssids: BTreeMap<Mac, BssidWep> = BTreeMap::new();
                let mut file_stats = Stats::default();
                let mut events = EventTally::default();
                match input::open_reader(path) {
                    Ok(mut reader) => {
                        file_stats.captures_read += 1;
                        // SKA challenge/response pairing is per file: a Shared-Key
                        // exchange is self-contained within one capture, so a per-file
                        // cache loses nothing and avoids cross-thread sharing.
                        let mut challenges = ChallengeCache::new();
                        scan_file(
                            reader.as_mut(),
                            &mut file_bssids,
                            &mut challenges,
                            &mut file_stats,
                            log_active,
                            &mut events,
                            carve.as_ref(),
                            &spinner,
                            &packets,
                            &files_done,
                        );
                    },
                    Err(e) => {
                        if log_active {
                            events.record(LogEvent::CaptureError(format!("{e}")));
                        }
                        debug.say(&format!("skip file={name} reason={e}"));
                    },
                }
                files_done.fetch_add(1, Ordering::Relaxed);
                (name, file_bssids, file_stats, events)
            })
            .collect();
        // The batch's per-file maps and the result so far are both resident here --
        // the run's high-water mark, so sample RSS now (FR-MEM-1).
        mem.sample();
        // Fold the batch into the result in input-file order (FR-IN-3, FR-IN-6),
        // freeing each per-file map as it is consumed.
        for (name, file_bssids, file_stats, events) in partials {
            stats.merge(&file_stats);
            for (mac, record) in file_bssids {
                bssids.entry(mac).or_insert_with(|| BssidWep { bssid: mac, ..BssidWep::default() }).merge_from(record);
            }
            logger.replay(&name, events);
        }
        // A periodic --debug heartbeat instead of a line per file -- a megacorpus
        // holds millions of files, so per-file ingest lines would dominate the log.
        let done = files_done.load(Ordering::Relaxed);
        if debug.enabled() && done - ticked >= INGEST_TICK_FILES {
            ticked = done;
            debug.say(&format!("ingested {done}/{} files", paths.len()));
        }
    }
    spinner.finish();

    tally_bssids(&bssids, &mut stats);
    if debug.enabled() {
        dump_bssid_material(debug, &bssids);
    }
    Ok(ScanResult { bssids, stats })
}

/// Pull every packet from one open reader and account for it (one file's worker).
///
/// Diagnostic events are buffered into `events` (only when `log_active`) rather
/// than written directly, so a parallel ingest can replay them in file order with
/// correct `file=` attribution (FR-IN-6). The spinner is driven by the shared
/// atomic counters; the carve writer, if any, is locked only per written frame.
fn scan_file(
    reader: &mut dyn input::PacketReader,
    bssids: &mut BTreeMap<Mac, BssidWep>,
    challenges: &mut ChallengeCache,
    stats: &mut Stats,
    log_active: bool,
    events: &mut EventTally,
    carve: Option<&Mutex<&mut Carver>>,
    spinner: &Bar,
    packets: &AtomicU64,
    files_done: &AtomicU64,
) {
    loop {
        let packet = match reader.next_packet() {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(e) => {
                if log_active {
                    events.record(LogEvent::CaptureError(format!("read error: {e}")));
                }
                break;
            },
        };
        stats.packets_total += 1;
        // Refresh the spinner every few thousand packets via the shared counters
        // -- often enough to look live, rare enough to add no measurable overhead
        // to the hot read loop and no lock contention between workers.
        if stats.packets_total.is_multiple_of(8192) {
            let total = packets.fetch_add(8192, Ordering::Relaxed) + 8192;
            spinner.set_message(format!("scanning: {} file(s), {total} packets", files_done.load(Ordering::Relaxed)));
        }

        // Classify the packet, then hand its data buffer back to the reader so the
        // next read reuses the allocation instead of allocating afresh (FR-IN-5;
        // the recycle contract the pcap/pcapng readers implement). `process_packet`
        // returns on every skip, so the recycle below runs for every packet.
        if let Some(dlt) = reader.link_type(packet.interface_id) {
            process_packet(&packet, dlt, bssids, challenges, stats, log_active, events, carve);
        } else {
            stats.packets_unknown_link += 1;
            if log_active {
                events.record(LogEvent::UnknownLink(packet.interface_id));
            }
        }
        reader.recycle_buffer(packet.data);
    }
    // Drain any parser warnings the reader coalesced (e.g. a desynchronised pcapng
    // stream trips the same one on millions of blocks) into the per-file tally, so
    // they replay as a single count=N log line instead of flooding stdout
    // (FR-DEBUG-4). Recorded only when --log is active, like the other deferred events.
    if log_active {
        for (reason, count) in reader.take_warnings() {
            events.record_n(LogEvent::ParseWarning(reason), count);
        }
    }
}

/// Classify one packet's frame: strip the link header + FCS, parse the MAC header,
/// and (for data/management frames) hand the body to the classifier and the carver.
///
/// Each skip path is a `return` rather than a loop `continue`, so [`scan_file`] can
/// unconditionally recycle the packet's data buffer after this returns (the buffer
/// is borrowed only for the duration of this call -- the classifier and carver copy
/// out what they keep).
fn process_packet(
    packet: &Packet,
    dlt: u16,
    bssids: &mut BTreeMap<Mac, BssidWep>,
    challenges: &mut ChallengeCache,
    stats: &mut Stats,
    log_active: bool,
    events: &mut EventTally,
    carve: Option<&Mutex<&mut Carver>>,
) {
    let Some(frame_bytes) = strip_and_resolve(packet, dlt, stats, log_active, events) else {
        return; // link_errors already counted
    };

    match frame::parse(frame_bytes) {
        ParseResult::Control => stats.ctrl_frames += 1,
        ParseResult::Malformed(reason) => {
            stats.malformed_mac += 1;
            if log_active {
                events.record(LogEvent::Malformed(reason.to_owned()));
            }
        },
        ParseResult::Frame(hdr) | ParseResult::Lenient(hdr) => {
            if hdr.frame_type == TYPE_MANAGEMENT {
                stats.mgmt_frames += 1;
            } else if hdr.frame_type == TYPE_DATA {
                stats.data_frames += 1;
            } else {
                stats.extension_frames += 1;
                return; // type 3: not body-classified
            }
            let Some(body) = frame_bytes.get(hdr.body_offset..) else {
                stats.truncated += 1;
                return;
            };
            let kind = classify::observe(bssids, challenges, &hdr, body);
            // Carve (FR-OUT-6): write WEP crack frames now; buffer beacons for the
            // BSSID, written later only if it classifies WEP. The writer is shared
            // across workers, so lock only when there is a frame to write (never on
            // the Skip path) and recover a poisoned lock so one worker's panic
            // cannot drop another's frames.
            if let Some(carver) = carve {
                match kind {
                    Carve::Wep => {
                        carver.lock().unwrap_or_else(std::sync::PoisonError::into_inner).wep_frame(frame_bytes);
                    },
                    Carve::Beacon => {
                        carver.lock().unwrap_or_else(std::sync::PoisonError::into_inner).beacon(hdr.ap, frame_bytes);
                    },
                    Carve::Skip => {},
                }
            }
        },
    }
}

/// Strip the link header, resolve the FCS, and fall back to tiered recovery on a
/// strip failure. Ported from `WPAWolf` `main::strip_and_resolve` (C9), trimmed
/// to `WEPWolf`'s accounting (only `link_errors` on total failure). On failure it
/// buffers a deferred `LinkError` event (replayed in file order, FR-IN-6).
fn strip_and_resolve<'a>(
    packet: &'a Packet,
    dlt: u16,
    stats: &mut Stats,
    log_active: bool,
    events: &mut EventTally,
) -> Option<&'a [u8]> {
    match link::strip(&packet.data, dlt) {
        Ok((payload, header_says_fcs)) => {
            let badfcs = dlt == link::DLT_RADIOTAP && link::radiotap::has_badfcs(&packet.data);
            let outcome = link::fcs::resolve(payload, header_says_fcs, badfcs);
            Some(link::fcs::strip_fcs(payload, outcome))
        },
        Err(e) => link::recover::recover(&packet.data, dlt).map(|r| r.frame).or_else(|| {
            stats.link_errors += 1;
            if log_active {
                events.record(LogEvent::LinkError { dlt, reason: format!("{e}") });
            }
            None
        }),
    }
}

/// Resolve every observed BSSID to a classification and fill the BSSID + WEP-frame counters.
fn tally_bssids(bssids: &BTreeMap<Mac, BssidWep>, stats: &mut Stats) {
    for record in bssids.values() {
        stats.bssids_total += 1;
        match record.encryption() {
            Encryption::Wep => stats.wep_bssids += 1,
            Encryption::Wpa => stats.wpa_bssids += 1,
            Encryption::Open => stats.open_bssids += 1,
            Encryption::Unknown => stats.unknown_bssids += 1,
        }
        stats.wep_data_frames += record.wep_data_frames;
        stats.wep_auth_frames += record.wep_auth_frames;
    }
}

/// Bounded per-BSSID material dump for `--debug` (FR-DEBUG-2).
///
/// Only WEP BSSIDs are detailed -- they are the cracker's targets -- most-IVs
/// first and capped at [`DEBUG_BSSID_ROWS`]; the thinner remainder collapses to a
/// count, and the non-WEP networks (the overwhelming majority on a real corpus)
/// become a one-line census instead of millions of per-BSSID lines.
fn dump_bssid_material(debug: &DebugPrinter, bssids: &BTreeMap<Mac, BssidWep>) {
    let mut wep: Vec<&BssidWep> = bssids.values().filter(|b| b.encryption() == Encryption::Wep).collect();
    wep.sort_by(|a, b| {
        crate::attack::unique_iv_count(b).cmp(&crate::attack::unique_iv_count(a)).then(a.bssid.cmp(&b.bssid))
    });
    for r in wep.iter().take(DEBUG_BSSID_ROWS) {
        debug.say(&format!(
            "bssid {} {} ivs={} arp={} ska={} wep_data={} wep_auth={}",
            r.bssid,
            enc_word(r.encryption()),
            r.ivs().len(),
            r.arp_keystreams().len(),
            r.ska_keystream().is_some(),
            r.wep_data_frames,
            r.wep_auth_frames
        ));
    }
    if wep.len() > DEBUG_BSSID_ROWS {
        debug.say(&format!("bssid ... and {} more WEP BSSIDs (fewer IVs, not shown)", wep.len() - DEBUG_BSSID_ROWS));
    }
    // Non-WEP networks are a census count, never per-BSSID spam.
    let (mut wpa, mut open, mut unknown) = (0u64, 0u64, 0u64);
    for b in bssids.values() {
        match b.encryption() {
            Encryption::Wpa => wpa += 1,
            Encryption::Open => open += 1,
            Encryption::Unknown => unknown += 1,
            Encryption::Wep => {},
        }
    }
    debug.say(&format!("bssid census: {} WEP, {wpa} WPA, {open} open, {unknown} unknown", wep.len()));
}

/// A short word for an encryption class, for debug lines.
const fn enc_word(enc: Encryption) -> &'static str {
    match enc {
        Encryption::Open => "open",
        Encryption::Wep => "wep",
        Encryption::Wpa => "wpa",
        Encryption::Unknown => "unknown",
    }
}
