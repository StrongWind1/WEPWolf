//! Output surfaces (FR-OUT): the human table, the `--plain` grep stream, and the `--json` NDJSON stream.
//!
//! All three render the same three sections in the same order -- the recovered keys, then the WEP-BSSID summary (most IVs first), then the stats breakdown -- so the surfaces carry identical information and differ only in shape (C10). The default table is column-aligned for humans; `--plain` tags every line `key` / `wep` / `stat` for `grep`/`cut`; `--json` emits one typed object per line (`type` = `key` / `bssid` / `stats`). `--quiet` keeps only the keys on every surface. JSON is hand-rolled to keep the dependency budget tight (no serde). Every surface renders into a `String` so it can be asserted in tests; [`render`] is the thin wrapper that prints it.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use crate::attack::{CrackResult, unique_iv_count};
use crate::classify::Encryption;
use crate::model::{BssidWep, Mac, WepKey};
use crate::scan::ScanResult;
use crate::stats::Stats;

/// Which output surface to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// Human-readable column table: keys, WEP-BSSID summary, then the stats banner.
    #[default]
    Table,
    /// Tab-separated, one record per line, each tagged `key` / `wep` / `stat`.
    Plain,
    /// NDJSON: one typed object per line (`type` = `key` / `bssid` / `stats`).
    Json,
}

/// Render results on the selected surface and print them to stdout.
pub fn render(result: &ScanResult, cracks: &[CrackResult], format: Format, quiet: bool) {
    print!("{}", render_string(result, cracks, format, quiet));
}

/// Render the selected surface into a string (FR-OUT-1: table / plain / JSON).
///
/// Each surface emits the recovered keys, then -- unless `quiet` -- the WEP-BSSID
/// summary and the stats breakdown. `quiet` reduces every surface to keys only.
/// This is the testable core behind [`render`]. All three sections share one
/// deterministic ordering (most IVs first, then BSSID) so the output is stable
/// regardless of the parallel sweep's scheduling (FR-IN-6).
#[must_use]
pub fn render_string(result: &ScanResult, cracks: &[CrackResult], format: Format, quiet: bool) -> String {
    // Unique-IV count per WEP BSSID, computed once and shared by every section
    // (it both orders the rows and is the per-key `ivs` field).
    let iv_counts: HashMap<Mac, usize> = result
        .bssids
        .values()
        .filter(|b| b.encryption() == Encryption::Wep)
        .map(|b| (b.bssid, unique_iv_count(b)))
        .collect();
    let ivs_of = |bssid: Mac| iv_counts.get(&bssid).copied().unwrap_or(0);

    // The recovered keys, most-IVs-first (then BSSID, then slot) for stable order.
    let mut keys: Vec<&CrackResult> = cracks.iter().collect();
    keys.sort_by(|a, b| {
        ivs_of(b.bssid).cmp(&ivs_of(a.bssid)).then(a.bssid.cmp(&b.bssid)).then(a.key_id.cmp(&b.key_id))
    });

    // The WEP BSSIDs, most-IVs-first -- the cracker's target census.
    let mut wep: Vec<&BssidWep> = result.bssids.values().filter(|b| b.encryption() == Encryption::Wep).collect();
    wep.sort_by(|a, b| ivs_of(b.bssid).cmp(&ivs_of(a.bssid)).then(a.bssid.cmp(&b.bssid)));

    // Which attack cracked each BSSID (the first recovered key wins for a
    // multi-slot AP), so the summary can show a per-target `via`.
    let mut via: HashMap<Mac, &'static str> = HashMap::new();
    for c in cracks {
        via.entry(c.bssid).or_insert(c.attack);
    }

    let mut out = String::new();
    match format {
        Format::Table => {
            keys_table(&mut out, &keys, &ivs_of);
            if !quiet {
                summary_table(&mut out, result, &wep, &ivs_of, &via);
                let _ = writeln!(out); // separate the BSSID summary from the stats banner
                banner(&mut out, &result.stats);
            }
        },
        Format::Plain => {
            keys_plain(&mut out, &keys, &ivs_of);
            if !quiet {
                summary_plain(&mut out, &wep, &ivs_of, &via);
                stats_plain(&mut out, &result.stats);
            }
        },
        Format::Json => {
            keys_json(&mut out, &keys, &ivs_of);
            if !quiet {
                summary_json(&mut out, &wep, &ivs_of, &via);
                stats_json(&mut out, &result.stats);
            }
        },
    }
    out
}

// --- Table surface ---

/// The recovered-keys block, column-aligned and printed first as the headline.
/// Columns carry the FR-OUT-2 fields: bssid, essid, key bits, key id, attack, the
/// unique-IV count, the crack time, and the key (hex, with the ASCII form appended
/// when the octets are printable). The ESSID is truncated for column alignment;
/// the full value is in `--plain` / `--json`.
fn keys_table(out: &mut String, keys: &[&CrackResult], ivs_of: &impl Fn(Mac) -> usize) {
    if keys.is_empty() {
        return;
    }
    let _ = writeln!(out, "KEYS RECOVERED");
    let _ = writeln!(
        out,
        "{:<17}  {:<18}  {:>4}  {:>2}  {:<10}  {:>8}  {:>7}  KEY",
        "BSSID", "ESSID", "BITS", "ID", "VIA", "IVS", "TIME"
    );
    for c in keys {
        let keycell = ascii_opt(&c.key).map_or_else(|| c.key.to_string(), |ascii| format!("{}  {ascii}", c.key));
        let _ = writeln!(
            out,
            "{:<17}  {:<18}  {:>4}  {:>2}  {:<10}  {:>8}  {:>7}  {keycell}",
            c.bssid,
            truncate(&essid_display(c.essid.as_deref()), 18),
            c.key.len().bits(),
            c.key_id,
            c.attack,
            ivs_of(c.bssid),
            dur_human(c.elapsed),
        );
    }
    let _ = writeln!(out);
}

/// Maximum WEP BSSID rows shown in the human summary before truncating. The full
/// list is always in `--plain` / `--json`; dumping every observed BSSID is useless
/// on an input with hundreds of thousands.
const WEP_ROWS: usize = 25;

/// The WEP-BSSID summary, most-IVs first, with a per-target `via` (the attack that
/// cracked it, or `-`) and a one-line census of the non-WEP networks.
fn summary_table(
    out: &mut String,
    result: &ScanResult,
    wep: &[&BssidWep],
    ivs_of: &impl Fn(Mac) -> usize,
    via: &HashMap<Mac, &'static str>,
) {
    let (wpa, open, unknown) = non_wep_counts(result);
    if wep.is_empty() {
        let _ = writeln!(out, "No WEP BSSIDs observed ({wpa} WPA, {open} open, {unknown} unknown).");
        return;
    }
    let _ = writeln!(out, "WEP BSSIDs (most IVs first):");
    let _ = writeln!(out, "{:<17}  {:>8}  {:<10}  ESSID", "BSSID", "IVS", "VIA");
    for b in wep.iter().take(WEP_ROWS) {
        let _ = writeln!(
            out,
            "{:<17}  {:>8}  {:<10}  {}",
            b.bssid,
            ivs_of(b.bssid),
            via.get(&b.bssid).copied().unwrap_or("-"),
            essid_display(b.essid.as_deref())
        );
    }
    if wep.len() > WEP_ROWS {
        let _ = writeln!(out, "  ... and {} more WEP BSSIDs with fewer IVs", wep.len() - WEP_ROWS);
    }
    let _ =
        writeln!(out, "({} WEP, {wpa} WPA, {open} open, {unknown} unknown BSSIDs observed; --json for all)", wep.len());
}

/// One dotted banner row: the label left-padded with dots to column 58, then the value.
fn row(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "{:.<58}: {value}", format!("{label} "));
}

/// A banner row printed only when `value` is nonzero, so the zero rows (drop
/// causes, unfired attacks) do not clutter a clean run while the totals stay.
fn nz_row(out: &mut String, label: &str, value: u64) {
    if value != 0 {
        row(out, label, &value.to_string());
    }
}

/// A banner section divider (`-- name ----...`) grouping the ingest / networks /
/// run blocks so the longer accounting stays scannable.
fn section(out: &mut String, name: &str) {
    let _ = writeln!(out, "{:-<64}", format!("-- {name} "));
}

/// The closing accounting banner (`STATS.md`): per-packet and per-BSSID
/// reconciliation grouped into ingest / networks / run sections, crack
/// attribution per attack, the sweep/grind timing split, and peak RSS, closed by
/// a `wepwolf <version> (<git>)` footer. Every read packet stays accounted for --
/// the five packet classes always sum to the total -- while the drop causes, the
/// per-attack rows, and the `(BUG)` row expand only when nonzero, so a clean run
/// reads short without hiding any total.
fn banner(out: &mut String, s: &Stats) {
    let dropped = s.packets_unknown_link + s.link_errors + s.malformed_mac + s.truncated;
    let accounted = s.data_frames + s.mgmt_frames + s.ctrl_frames + s.extension_frames + dropped;
    let unaccounted = s.packets_total.saturating_sub(accounted);
    let uncracked = s.uncracked_thin + s.uncracked_infeasible;
    let peak_mib = s.peak_rss_bytes / (1024 * 1024);

    let _ = writeln!(out, "=== WEPWolf ====================================================");
    section(out, "ingest");
    row(out, "captures read", &s.captures_read.to_string());
    row(out, "packets total", &s.packets_total.to_string());
    row(out, "  data", &s.data_frames.to_string());
    row(out, "  management", &s.mgmt_frames.to_string());
    row(out, "  control", &s.ctrl_frames.to_string());
    row(out, "  extension", &s.extension_frames.to_string());
    row(out, "  dropped", &dropped.to_string());
    // When any packet was dropped, account for it by cause (the four sum to dropped).
    nz_row(out, "    no link type", s.packets_unknown_link);
    nz_row(out, "    link strip failed", s.link_errors);
    nz_row(out, "    malformed MAC header", s.malformed_mac);
    nz_row(out, "    truncated body", s.truncated);
    nz_row(out, "  packets unaccounted (BUG)", unaccounted);

    section(out, "networks");
    row(out, "BSSIDs seen", &s.bssids_total.to_string());
    row(out, "  WEP", &s.wep_bssids.to_string());
    row(out, "    WEP data / auth frames", &format!("{} / {}", s.wep_data_frames, s.wep_auth_frames));
    row(out, "    cracked", &s.cracked.to_string());
    nz_row(out, "      via PTW", s.keys_by_ptw);
    nz_row(out, "      via KoreK", s.keys_by_korek);
    nz_row(out, "      via FMS", s.keys_by_fms);
    nz_row(out, "      via RC4-bias", s.keys_by_bias);
    nz_row(out, "      via dictionary", s.keys_by_dict);
    nz_row(out, "      via keygen", s.keys_by_keygen);
    nz_row(out, "      via shared-key keystream", s.keys_by_ska);
    nz_row(out, "      via brute force", s.keys_by_brute);
    nz_row(out, "      via cross-BSSID reuse", s.keys_by_reuse);
    nz_row(out, "      via potfile", s.keys_by_potfile);
    row(out, "    uncracked", &uncracked.to_string());
    // FR-OUT-5: why each uncracked WEP BSSID went unrecovered (thin / infeasible).
    nz_row(out, "      capture too thin", s.uncracked_thin);
    nz_row(out, "      key infeasible (104/232-bit)", s.uncracked_infeasible);
    row(out, "  WPA", &s.wpa_bssids.to_string());
    row(out, "  open", &s.open_bssids.to_string());
    row(out, "  unknown", &s.unknown_bssids.to_string());

    section(out, "run");
    row(out, "wallclock", &dur_human(s.wallclock));
    row(out, "  sweep / grind", &format!("{} / {}", dur_human(s.sweep), dur_human(s.grind)));
    row(out, "peak RSS", &format!("{peak_mib} MiB"));
    let _ = writeln!(out, "================================================================");
    let _ = writeln!(out, "wepwolf {} ({})", env!("CARGO_PKG_VERSION"), env!("GIT_HASH"));
}

// --- Plain surface ---

/// One `key`-tagged line per recovered key, tab-separated: the FR-OUT-2 record
/// in full -- bssid, essid, key hex, key ASCII (empty when non-printable), key
/// bits, key id, attack, unique IVs, crack seconds.
fn keys_plain(out: &mut String, keys: &[&CrackResult], ivs_of: &impl Fn(Mac) -> usize) {
    for c in keys {
        let _ = writeln!(
            out,
            "key\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            c.bssid,
            essid_display(c.essid.as_deref()),
            c.key,
            ascii_opt(&c.key).unwrap_or_default(),
            c.key.len().bits(),
            c.key_id,
            c.attack,
            ivs_of(c.bssid),
            secs_num(c.elapsed),
        );
    }
}

/// One `wep`-tagged line per WEP BSSID (most IVs first): bssid, essid, unique IVs,
/// and the attack that cracked it (`-` when uncracked).
fn summary_plain(
    out: &mut String,
    wep: &[&BssidWep],
    ivs_of: &impl Fn(Mac) -> usize,
    via: &HashMap<Mac, &'static str>,
) {
    for b in wep {
        let _ = writeln!(
            out,
            "wep\t{}\t{}\t{}\t{}",
            b.bssid,
            essid_display(b.essid.as_deref()),
            ivs_of(b.bssid),
            via.get(&b.bssid).copied().unwrap_or("-")
        );
    }
}

/// One `stat`-tagged `name<TAB>value` line per counter -- the full `STATS.md`
/// breakdown, durations in seconds and RSS in bytes for a machine consumer.
fn stats_plain(out: &mut String, s: &Stats) {
    let dropped = s.packets_unknown_link + s.link_errors + s.malformed_mac + s.truncated;
    let mut st = |name: &str, value: &str| {
        let _ = writeln!(out, "stat\t{name}\t{value}");
    };
    st("captures_read", &s.captures_read.to_string());
    st("packets_total", &s.packets_total.to_string());
    st("data_frames", &s.data_frames.to_string());
    st("mgmt_frames", &s.mgmt_frames.to_string());
    st("ctrl_frames", &s.ctrl_frames.to_string());
    st("extension_frames", &s.extension_frames.to_string());
    st("dropped", &dropped.to_string());
    st("bssids_total", &s.bssids_total.to_string());
    st("wep_bssids", &s.wep_bssids.to_string());
    st("wpa_bssids", &s.wpa_bssids.to_string());
    st("open_bssids", &s.open_bssids.to_string());
    st("unknown_bssids", &s.unknown_bssids.to_string());
    st("wep_data_frames", &s.wep_data_frames.to_string());
    st("wep_auth_frames", &s.wep_auth_frames.to_string());
    st("cracked", &s.cracked.to_string());
    st("keys_by_ptw", &s.keys_by_ptw.to_string());
    st("keys_by_korek", &s.keys_by_korek.to_string());
    st("keys_by_fms", &s.keys_by_fms.to_string());
    st("keys_by_bias", &s.keys_by_bias.to_string());
    st("keys_by_dict", &s.keys_by_dict.to_string());
    st("keys_by_keygen", &s.keys_by_keygen.to_string());
    st("keys_by_ska", &s.keys_by_ska.to_string());
    st("keys_by_brute", &s.keys_by_brute.to_string());
    st("keys_by_reuse", &s.keys_by_reuse.to_string());
    st("keys_by_potfile", &s.keys_by_potfile.to_string());
    st("uncracked_thin", &s.uncracked_thin.to_string());
    st("uncracked_infeasible", &s.uncracked_infeasible.to_string());
    st("wallclock_s", &secs_num(s.wallclock));
    st("sweep_s", &secs_num(s.sweep));
    st("grind_s", &secs_num(s.grind));
    st("peak_rss_bytes", &s.peak_rss_bytes.to_string());
}

// --- JSON surface ---

/// One `{"type":"key",...}` object per recovered key, carrying the FR-OUT-2 record.
fn keys_json(out: &mut String, keys: &[&CrackResult], ivs_of: &impl Fn(Mac) -> usize) {
    for c in keys {
        let _ = writeln!(
            out,
            "{{\"type\":\"key\",\"bssid\":\"{}\",\"essid\":{},\"key_hex\":\"{}\",\"key_ascii\":{},\"key_bits\":{},\"key_id\":{},\"attack\":\"{}\",\"ivs\":{},\"seconds\":{}}}",
            c.bssid,
            json_essid(c.essid.as_deref()),
            c.key,
            json_ascii(&c.key),
            c.key.len().bits(),
            c.key_id,
            c.attack,
            ivs_of(c.bssid),
            secs_num(c.elapsed),
        );
    }
}

/// One `{"type":"bssid",...}` object per WEP BSSID (most IVs first): bssid, essid,
/// unique IVs, whether it cracked, and the attack (`via`, null when uncracked).
fn summary_json(out: &mut String, wep: &[&BssidWep], ivs_of: &impl Fn(Mac) -> usize, via: &HashMap<Mac, &'static str>) {
    for b in wep {
        let cracked = via.get(&b.bssid);
        let _ = writeln!(
            out,
            "{{\"type\":\"bssid\",\"bssid\":\"{}\",\"essid\":{},\"ivs\":{},\"cracked\":{},\"via\":{}}}",
            b.bssid,
            json_essid(b.essid.as_deref()),
            ivs_of(b.bssid),
            cracked.is_some(),
            cracked.map_or_else(|| "null".to_owned(), |a| format!("\"{a}\"")),
        );
    }
}

/// The final `{"type":"stats",...}` object: the full `STATS.md` breakdown nested
/// by section (packets / bssids / wep / `keys_by` / timing), durations in seconds.
fn stats_json(out: &mut String, s: &Stats) {
    let dropped = s.packets_unknown_link + s.link_errors + s.malformed_mac + s.truncated;
    let _ = writeln!(
        out,
        "{{\"type\":\"stats\",\"captures\":{},\"packets\":{{\"total\":{},\"data\":{},\"mgmt\":{},\"control\":{},\"extension\":{},\"dropped\":{}}},\"bssids\":{{\"total\":{},\"wep\":{},\"wpa\":{},\"open\":{},\"unknown\":{}}},\"wep\":{{\"data_frames\":{},\"auth_frames\":{},\"cracked\":{},\"uncracked_thin\":{},\"uncracked_infeasible\":{}}},\"keys_by\":{{\"ptw\":{},\"korek\":{},\"fms\":{},\"bias\":{},\"dict\":{},\"keygen\":{},\"ska\":{},\"brute\":{},\"reuse\":{},\"potfile\":{}}},\"timing\":{{\"wallclock_s\":{},\"sweep_s\":{},\"grind_s\":{}}},\"peak_rss_bytes\":{}}}",
        s.captures_read,
        s.packets_total,
        s.data_frames,
        s.mgmt_frames,
        s.ctrl_frames,
        s.extension_frames,
        dropped,
        s.bssids_total,
        s.wep_bssids,
        s.wpa_bssids,
        s.open_bssids,
        s.unknown_bssids,
        s.wep_data_frames,
        s.wep_auth_frames,
        s.cracked,
        s.uncracked_thin,
        s.uncracked_infeasible,
        s.keys_by_ptw,
        s.keys_by_korek,
        s.keys_by_fms,
        s.keys_by_bias,
        s.keys_by_dict,
        s.keys_by_keygen,
        s.keys_by_ska,
        s.keys_by_brute,
        s.keys_by_reuse,
        s.keys_by_potfile,
        secs_num(s.wallclock),
        secs_num(s.sweep),
        secs_num(s.grind),
        s.peak_rss_bytes,
    );
}

/// JSON-escape and quote a string.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            },
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The ESSID as a JSON string (real bytes, lossy-decoded and escaped), or `null` when hidden.
fn json_essid(essid: Option<&[u8]>) -> String {
    essid.map_or_else(|| "null".to_owned(), |e| json_string(&String::from_utf8_lossy(e)))
}

/// The key's ASCII form as a JSON string, or `null` when any octet is non-printable.
fn json_ascii(key: &WepKey) -> String {
    ascii_opt(key).map_or_else(|| "null".to_owned(), |a| json_string(&a))
}

// --- Shared ---

/// The key as ASCII when every octet is printable, else `None` (FR-OUT-3): the
/// single source of the per-surface ASCII rendering (`--` / empty / `null`).
fn ascii_opt(key: &WepKey) -> Option<String> {
    key.as_slice()
        .iter()
        .all(|&b| b.is_ascii_graphic() || b == b' ')
        .then(|| String::from_utf8_lossy(key.as_slice()).into_owned())
}

/// The ESSID for human display: printable ASCII kept, every other octet shown as
/// `.` so binary/control bytes cannot mangle the terminal or break a TSV field;
/// `<hidden>` when absent and `<N bytes>` when nothing prints. JSON keeps the real
/// (escaped) bytes instead.
fn essid_display(essid: Option<&[u8]>) -> String {
    let Some(bytes) = essid else {
        return "<hidden>".to_owned();
    };
    let shown: String = bytes.iter().map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' }).collect();
    if shown.trim().is_empty() { format!("<{} bytes>", bytes.len()) } else { shown }
}

/// Truncate a display string to `max` characters (a trailing `~` marks a cut), so
/// a long ESSID cannot ragged the column table. The full value stays in plain/JSON.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}~")
}

/// WEP BSSID counts of the other encryption classes, for the summary census.
fn non_wep_counts(result: &ScanResult) -> (u64, u64, u64) {
    let (mut wpa, mut open, mut unknown) = (0u64, 0u64, 0u64);
    for b in result.bssids.values() {
        match b.encryption() {
            Encryption::Wpa => wpa += 1,
            Encryption::Open => open += 1,
            Encryption::Unknown => unknown += 1,
            Encryption::Wep => {},
        }
    }
    (wpa, open, unknown)
}

/// A duration as a short human string: 2 decimals under a second (`0.42s`), else 1 (`5.4s`).
fn dur_human(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 1.0 { format!("{s:.2}s") } else { format!("{s:.1}s") }
}

/// A duration as a bare seconds number (3 decimals) for the machine surfaces.
fn secs_num(d: Duration) -> String {
    format!("{:.3}", d.as_secs_f64())
}
