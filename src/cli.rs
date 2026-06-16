//! CLI argument parsing and the oneshot driver (FR-CLI).
//!
//! `wepwolf <paths...>` scans the captures, enumerates BSSIDs, and recovers WEP keys with every applicable attack. `--wordlist` enables the dictionary and keygen attacks; `--keylen` narrows the key-size hypotheses; `--threads` sizes the parallel sweep; `--bssid` targets one network; `--debug` and `--log FILE` drive the diagnostics; `--plain`/`--json` select machine-readable output. Exit code is 0 iff at least one key was recovered.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use crate::attack::{
    self, Attack, CrackResult,
    bias::BiasAttack,
    brute::BruteAttack,
    dict::{self, DictAttack},
    fms::FmsAttack,
    keygen::KeygenAttack,
    korek::KorekAttack,
    ptw::PtwAttack,
};
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::diag::{DebugPrinter, Logger, MemMonitor};
use crate::model::{BssidWep, Encryption, KeyLen, Mac};
use crate::progress::Progress;
use crate::report::Format;
use crate::stats::Stats;
use crate::types::{Error, Result};
use crate::{carve, input, potfile, report, scan};

// FR-CLI-1: exactly one required positional (the capture paths). FR-CLI-2: the
// optional targeting, tuning, output, and diagnostic flags below. Each field's
// doc comment is the clap help text -- the first line shows under `-h`, the full
// paragraph under `--help` -- grouped into sections via `help_heading`.
/// Offline, passive WEP key recovery from 802.11 captures.
///
/// Reads pcap, pcapng, and gzip-compressed captures, pulls the WEP-encrypted
/// frames out of the 802.11 traffic, and recovers each network's key with every
/// applicable attack: PTW, KoreK, FMS, the Sepehrdad RC4-bias database,
/// dictionary and keygen (with --wordlist), and an optional 40-bit brute force.
/// No wordlist or external cracker is required; every reported key is confirmed
/// by RC4-decrypting real frames and checking the CRC-32 ICV. Passive and
/// offline -- it never captures traffic, injects frames, or touches a radio.
#[derive(Parser, Debug)]
#[command(
    name = "wepwolf",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), ")"),
    about,
    long_about = None,
    arg_required_else_help = true,
    after_help = "\x1b[1;33mEXAMPLES:\x1b[0m
    wepwolf capture.pcap
    wepwolf -w rockyou.txt session-*.pcapng.gz
    wepwolf --keylen 104 --threads 8 --json captures/
    wepwolf --bssid 00:11:22:33:44:55 --brute capture.cap

Exit status is 0 when at least one key is recovered, 1 when none is, 2 on a fatal I/O error.",
)]
#[allow(clippy::doc_markdown, reason = "doc comments are clap help text, not rustdoc API surface")]
pub struct Cli {
    /// Capture files or directories to scan.
    ///
    /// Each argument is a capture file or a directory. Directories are walked
    /// recursively and captures are discovered by content, not by extension.
    /// pcap (microsecond and nanosecond), pcapng, and gzip-wrapped captures are
    /// all read; a network's frames are merged across every file it appears in.
    #[arg(required = true, value_name = "PATH", value_hint = clap::ValueHint::AnyPath)]
    pub paths: Vec<PathBuf>,

    /// Wordlist for the dictionary and keygen attacks (one candidate per line).
    ///
    /// Each line is tried three ways: as a raw key, as a hex-encoded key, and as
    /// a passphrase through the Neesus-Datacom (40-bit) and MD5 (104-bit) weak-key
    /// generators. The statistical attacks run with or without this flag; the
    /// wordlist only adds the dictionary and keygen paths.
    #[arg(short = 'w', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Targeting & attacks", display_order = 1)]
    pub wordlist: Option<PathBuf>,

    /// Only try one key strength in bits: 40, 104, or 232 (default: all three).
    ///
    /// Narrows the key-length hypotheses to a single size. By default every WEP
    /// length is tried and the statistical attacks recover the length implicitly,
    /// so set this only to save time when the key strength is already known.
    #[arg(short = 'n', long, value_name = "BITS", value_parser = ["40", "104", "232"], help_heading = "Targeting & attacks", display_order = 2)]
    pub keylen: Option<String>,

    /// Restrict the run to a single BSSID (e.g. 00:11:22:33:44:55).
    ///
    /// Ignore every other network in the capture and attack only this access
    /// point -- useful when one busy BSSID dominates a multi-network capture.
    #[arg(short = 'b', long, value_name = "MAC", help_heading = "Targeting & attacks", display_order = 3)]
    pub bssid: Option<String>,

    /// Brute-force WEP-40 keys no other attack recovered (slow: scalar 2^40).
    ///
    /// A last-resort exhaustive sweep of the full 40-bit keyspace, run only on
    /// networks every statistical and wordlist attack left uncracked. Off by
    /// default; pair it with --time-budget to bound the grind.
    #[arg(long, help_heading = "Targeting & attacks", display_order = 4)]
    pub brute: bool,

    /// KoreK/bias fudge factor: keep octets voting >= top/FACTOR (aircrack -f).
    ///
    /// Widens the statistical search by keeping every candidate octet whose vote
    /// is at least the top vote divided by FACTOR. Higher is wider and slower.
    /// Default: 5 for WEP-40, 2 for longer keys -- raise it for a stubborn key.
    #[arg(short = 'f', long, value_name = "FACTOR", help_heading = "Search tuning", display_order = 10)]
    pub fudge: Option<f32>,

    /// Exhaustively sweep the last N key octets (aircrack -x; default 1, max 4).
    ///
    /// After the statistical vote fixes the strong leading octets, brute-force
    /// the N weakest trailing octets. Each extra octet multiplies the search by
    /// 256, so raise it only when a key is nearly recovered.
    #[arg(
        short = 'x',
        long = "bruteforce",
        value_name = "N",
        default_value_t = 1,
        help_heading = "Search tuning",
        display_order = 11
    )]
    pub bruteforce: usize,

    /// Restrict candidate key octets to printable ASCII (aircrack -c).
    ///
    /// Limits the statistical search to printable-ASCII octets, which is much
    /// faster when the key is known to be a typed passphrase. Any key containing
    /// a non-printable byte is then unreachable.
    #[arg(short = 'c', long, help_heading = "Search tuning", display_order = 12)]
    pub alnum: bool,

    /// Worker threads for the parallel sweep and ingest (default: all cores).
    ///
    /// Sizes the rayon work-stealing pool: networks are cracked in parallel and
    /// capture files are ingested in parallel batches across this many threads.
    /// Defaults to one per logical core; use 1 for a fully serial run.
    #[arg(short = 'j', long, value_name = "N", help_heading = "Performance", display_order = 20)]
    pub threads: Option<usize>,

    /// Per-BSSID time budget in seconds for the sweep and brute.
    ///
    /// Caps the wall-clock each network may spend in the statistical sweep and
    /// the optional brute force. Unset: a 30-second sweep per BSSID and an
    /// unbounded brute. 0 means unlimited.
    #[arg(long, value_name = "SECS", help_heading = "Performance", display_order = 21)]
    pub time_budget: Option<u64>,

    /// Tab-separated records, tagged key / wep / stat (machine-readable).
    ///
    /// Emit the keys, the WEP-BSSID summary, and the stats as tab-separated lines,
    /// each tagged in column 1: `key` (the full per-key record), `wep` (one row per
    /// WEP BSSID), `stat` (one counter). `grep '^key'` or `cut` isolates a section.
    /// Conflicts with --json.
    #[arg(long, conflicts_with = "json", help_heading = "Output", display_order = 30)]
    pub plain: bool,

    /// NDJSON: one typed object per line (key / bssid / stats).
    ///
    /// Emit newline-delimited JSON -- a `{"type":"key"}` object per recovered key,
    /// a `{"type":"bssid"}` object per WEP BSSID, then one `{"type":"stats"}` object
    /// with the full breakdown. Suited to piping into jq.
    #[arg(long, help_heading = "Output", display_order = 31)]
    pub json: bool,

    /// Print only the recovered keys (drop the summary and stats).
    ///
    /// Reduce every surface to the keys section -- no WEP-BSSID summary and no
    /// stats banner. Applies to the table, --plain, and --json alike.
    #[arg(short = 'q', long, help_heading = "Output", display_order = 32)]
    pub quiet: bool,

    /// Read and append recovered keys, hashcat-style (bssid:key_hex).
    ///
    /// Before the run, seed key reuse from this file; after it, append every
    /// newly recovered key. An accumulating potfile lets a key found in one run
    /// crack co-located networks that share it in the next.
    #[arg(long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Output", display_order = 33)]
    pub potfile: Option<PathBuf>,

    /// Carve every parsed WEP frame and each WEP beacon into one standalone pcap.
    ///
    /// Write every WEP frame the parser recovers, plus each WEP network's beacon,
    /// as raw 802.11 with zeroed timestamps. Normalises mixed radiotap/Prism/AVS
    /// inputs into a single capture both wepwolf and aircrack-ng can re-crack.
    #[arg(long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Output", display_order = 34)]
    pub carve: Option<PathBuf>,

    /// Emit timestamped diagnostics to stderr.
    ///
    /// Print phase transitions, per-file deltas, memory checks, and a per-network
    /// "why uncracked" line (thin capture vs enough material but no verified key).
    #[arg(short = 'd', long, help_heading = "Diagnostics", display_order = 40)]
    pub debug: bool,

    /// Write categorized diagnostic lines to FILE.
    ///
    /// Record read, link-layer, and parse errors as categorized lines in FILE for
    /// later review, without cluttering stderr.
    #[arg(short = 'l', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Diagnostics", display_order = 41)]
    pub log: Option<PathBuf>,
}

/// Parse arguments, run the scan + attacks, and render results. Returns the
/// process exit code (0 iff a key was recovered, 2 on a fatal I/O error).
#[must_use]
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match run_inner(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("wepwolf: {e}");
            ExitCode::from(2)
        },
    }
}

/// The fallible body of [`run`].
fn run_inner(cli: &Cli) -> Result<ExitCode> {
    let debug = DebugPrinter::new(cli.debug);
    let mut logger = Logger::new(cli.log.as_deref())?;
    let mut mem = MemMonitor::new();
    // The run clock for the banner's wallclock row (STATS.md).
    let run_start = std::time::Instant::now();

    // Size the work-stealing pool before any parallel work begins. build_global
    // can only be called once per process, which suits a one-shot CLI.
    if let Some(n) = cli.threads
        && let Err(e) = rayon::ThreadPoolBuilder::new().num_threads(n).build_global()
    {
        return Err(Error::Io(std::io::Error::other(format!("thread pool: {e}"))));
    }

    let inputs = input::expand_inputs(&cli.paths)?;
    if inputs.is_empty() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no capture files found (check the paths)",
        )));
    }
    debug.say(&format!("expanded to {} input file(s)", inputs.len()));

    // Progress surfaces: only on a real terminal with the human table -- the
    // machine-readable modes, --quiet, and --debug (own stderr lines) suppress it.
    let progress = Progress::new(!cli.quiet && !cli.json && !cli.plain && !cli.debug);
    // FR-OUT-6: optionally carve the parsed WEP frames to a standalone pcap. The
    // carver streams crack frames during the scan and flushes WEP-network beacons
    // afterwards, before any --bssid narrowing, so it captures every WEP network.
    let mut carver = cli.carve.as_deref().map(carve::Carver::create).transpose().map_err(Error::Io)?;
    let mut result = scan::scan(&inputs, &debug, &mut logger, &mut mem, &progress, carver.as_mut())?;
    if let Some(c) = carver {
        let n = c.finish(&result.bssids).map_err(Error::Io)?;
        if !cli.quiet {
            eprintln!(
                "wepwolf: carved {n} WEP frames to {}",
                cli.carve.as_deref().unwrap_or_else(|| std::path::Path::new("")).display()
            );
        }
    }

    if let Some(spec) = &cli.bssid {
        let target = parse_mac(spec).ok_or_else(|| {
            Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid --bssid: {spec}")))
        })?;
        result.bssids.retain(|mac, _| *mac == target);
    }

    // Attack stage: run every applicable attack against each WEP BSSID. --keylen
    // narrows the hypotheses to a single size; otherwise every length is tried.
    let lengths: Vec<KeyLen> = match &cli.keylen {
        Some(bits) => vec![bits.parse().ok().and_then(KeyLen::from_bits).ok_or_else(|| {
            Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid --keylen: {bits}")))
        })?],
        None => KeyLen::all().to_vec(),
    };
    let attacks = build_attacks(cli)?;
    // A zero or unset budget means unlimited; otherwise bound each brute grind.
    let budget = cli.time_budget.filter(|&s| s > 0).map(std::time::Duration::from_secs);
    // A potfile seeds reuse with previously-recovered keys (hashcat-style).
    let seed_keys: Vec<_> = match &cli.potfile {
        Some(path) => potfile::load(path)?.into_iter().map(|(_, key)| key).collect(),
        None => Vec::new(),
    };
    let outcome = attack::crack_all(&result.bssids, &attacks, &lengths, budget, &seed_keys, &progress);
    let cracks = outcome.cracks;
    // The sweep / grind phase split for the banner's timing rows (STATS.md).
    result.stats.sweep = outcome.sweep;
    result.stats.grind = outcome.grind;
    record_cracks(&mut result.stats, &result.bssids, &cracks);
    // Persist freshly recovered keys (not the ones the potfile already held).
    if let Some(path) = &cli.potfile {
        for cracked in cracks.iter().filter(|c| c.attack != "potfile") {
            if let Err(e) = potfile::append(path, cracked.bssid, &cracked.key) {
                eprintln!("wepwolf: potfile write failed: {e}");
                break;
            }
        }
    }
    attack_diagnostics(&debug, &result.bssids, &cracks);

    mem.sample();
    logger.flush()?;
    result.stats.peak_rss_bytes = mem.peak_rss_bytes();
    result.stats.wallclock = run_start.elapsed();

    let format = if cli.json {
        Format::Json
    } else if cli.plain {
        Format::Plain
    } else {
        Format::Table
    };
    report::render(&result, &cracks, format, cli.quiet);
    // FR-OUT-4: exit non-zero when nothing was recovered, so scripts can branch on it.
    Ok(if cracks.is_empty() { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// Assemble the attack list in cost order from the CLI options.
fn build_attacks(cli: &Cli) -> Result<Vec<Box<dyn Attack>>> {
    // Statistical attacks first (free when there is no material), then the
    // wordlist-driven attacks, then the gated brute fallback. KoreK and bias take
    // the aircrack-style fudge / bruteforce / keyspace tuning from the CLI.
    let tuning = attack::Tuning { ffact: cli.fudge, brute_tail: cli.bruteforce.min(4), alnum: cli.alnum };
    let mut attacks: Vec<Box<dyn Attack>> = vec![
        Box::new(PtwAttack { tuning }),
        Box::new(KorekAttack { tuning }),
        Box::new(FmsAttack),
        Box::new(BiasAttack { tuning }),
    ];
    if let Some(path) = &cli.wordlist {
        let words = dict::load_wordlist(path)?;
        attacks.push(Box::new(DictAttack::from_words(words.clone())));
        attacks.push(Box::new(KeygenAttack::from_words(words)));
    }
    if cli.brute {
        attacks.push(Box::new(BruteAttack));
    }
    Ok(attacks)
}

/// Parse `aa:bb:cc:dd:ee:ff` into a MAC address.
fn parse_mac(spec: &str) -> Option<Mac> {
    let mut octets = [0u8; 6];
    let mut parts = spec.split(':');
    for slot in &mut octets {
        *slot = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(Mac::from_bytes(octets))
}

/// Per-BSSID attack diagnostics for `--debug` (FR-DEBUG-3).
///
/// Reports what each WEP network yielded and, when uncracked, why -- too thin
/// for any attack, or enough material but no single recoverable key.
fn attack_diagnostics(debug: &DebugPrinter, bssids: &BTreeMap<Mac, BssidWep>, cracks: &[CrackResult]) {
    if !debug.enabled() {
        return;
    }
    let cracked: HashMap<Mac, &CrackResult> = cracks.iter().map(|c| (c.bssid, c)).collect();
    let floor = attack::min_samples(KeyLen::Wep40);
    for (mac, b) in bssids.iter().filter(|(_, b)| b.encryption() == Encryption::Wep) {
        // Unique IVs are the real material; raw frames overstate a replayed capture.
        let uniq = attack::unique_iv_count(b);
        let raw = b.ivs.len() + b.arp_keystreams.len();
        let slots = b.key_ids_seen.count_ones();
        if let Some(c) = cracked.get(mac) {
            debug.say(&format!("attack {mac}: cracked via {} (key_id {}, {uniq} unique IVs)", c.attack, c.key_id));
            continue;
        }
        // Which key lengths cleared the feasibility floor on the unique-IV count?
        let feasible: Vec<String> = KeyLen::all()
            .iter()
            .filter(|&&len| uniq >= attack::min_samples(len))
            .map(|&len| len.bits().to_string())
            .collect();
        if feasible.is_empty() {
            // Below even the WEP-40 floor: report how far short the capture falls.
            let short = floor.saturating_sub(uniq);
            debug.say(&format!(
                "attack {mac}: uncracked -- thin ({uniq} unique IVs from {raw} frames; WEP-40 floor is {floor}, ~{short} more needed)"
            ));
        } else {
            // Enough material but no verified key: name the likely cause so the
            // operator can act (more capture, a wordlist, or a rotated key slot).
            let cause = if slots > 1 {
                format!("{slots} key slots in use ({:#06b}) -- votes mix across rekeyed slots", b.key_ids_seen)
            } else {
                "below the practical packet count, or sparse known-plaintext (no ARP/IP)".to_owned()
            };
            debug.say(&format!(
                "attack {mac}: uncracked -- {uniq} unique IVs from {raw} frames, enough for WEP-{} but no key verified ({cause})",
                feasible.join("/")
            ));
        }
    }
}

/// Fold the recovered keys into the crack accounting (`STATS.md` identity 3) and
/// split the uncracked WEP networks into thin vs infeasible (FR-OUT-5).
fn record_cracks(stats: &mut Stats, bssids: &BTreeMap<Mac, BssidWep>, cracks: &[CrackResult]) {
    for cracked in cracks {
        stats.cracked += 1;
        match cracked.attack {
            "ptw" => stats.keys_by_ptw += 1,
            "korek" => stats.keys_by_korek += 1,
            "fms" => stats.keys_by_fms += 1,
            "bias" => stats.keys_by_bias += 1,
            "dictionary" => stats.keys_by_dict += 1,
            "keygen" => stats.keys_by_keygen += 1,
            "ska" => stats.keys_by_ska += 1,
            "brute" => stats.keys_by_brute += 1,
            "reuse" => stats.keys_by_reuse += 1,
            "potfile" => stats.keys_by_potfile += 1,
            _ => {},
        }
    }
    // Split the uncracked WEP networks by the unique-IV feasibility floor: a capture
    // below the WEP-40 floor is "thin" (too little material to ever converge); one
    // above it that still yielded no key is "infeasible" here (rekeyed slots, sparse
    // known-plaintext, or a raw key with no statistical signal). Distinct IVs, not
    // raw frames, decide -- a replayed capture can be frame-rich yet IV-poor.
    let cracked: HashSet<Mac> = cracks.iter().map(|c| c.bssid).collect();
    let floor = attack::min_samples(KeyLen::Wep40);
    let (mut thin, mut infeasible) = (0u64, 0u64);
    for b in bssids.values().filter(|b| b.encryption() == Encryption::Wep && !cracked.contains(&b.bssid)) {
        if attack::unique_iv_count(b) < floor {
            thin += 1;
        } else {
            infeasible += 1;
        }
    }
    stats.uncracked_thin = thin;
    stats.uncracked_infeasible = infeasible;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::cast_possible_truncation, reason = "test module")]

    use super::*;
    use crate::model::IvSample;

    #[test]
    fn record_cracks_splits_thin_from_infeasible() {
        // FR-OUT-5: uncracked WEP BSSIDs split on the unique-IV floor -- below it is
        // "thin" (too little material to ever converge), at/above it yet keyless is
        // "infeasible". The split counts distinct IVs, not raw frames.
        let floor = attack::min_samples(KeyLen::Wep40);
        let thin = BssidWep {
            bssid: Mac::from_bytes([1; 6]),
            saw_wep_data: true,
            ivs: vec![IvSample::new([1, 2, 3], &[0u8; 8])],
            ..Default::default()
        };
        let rich = BssidWep {
            bssid: Mac::from_bytes([2; 6]),
            saw_wep_data: true,
            ivs: (0..floor as u32).map(|c| IvSample::new([c as u8, (c >> 8) as u8, 0], &[0u8; 8])).collect(),
            ..Default::default()
        };
        let mut map = BTreeMap::new();
        map.insert(thin.bssid, thin);
        map.insert(rich.bssid, rich);
        let mut stats = Stats { wep_bssids: 2, ..Default::default() };
        record_cracks(&mut stats, &map, &[]); // nothing cracked
        assert_eq!(stats.uncracked_thin, 1, "the 1-IV BSSID is thin");
        assert_eq!(stats.uncracked_infeasible, 1, "the floor-IV BSSID had material but yielded no key");
    }
}
