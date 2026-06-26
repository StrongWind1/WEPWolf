//! The diagnostics counters behind the closing run banner (`specs/STATS.md`).
//!
//! Every packet `WEPWolf` reads and every BSSID it judges lands in exactly one
//! counter here -- nothing is dropped silently. The reconciliation identities
//! in `STATS.md` hold by construction; a break is a bug. `make audit-stats`
//! checks that every field below is documented in `STATS.md`.

use std::time::Duration;

/// Run-wide accounting, accumulated across all captures and emitted once at the
/// end. All counts default to zero.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    // --- Packet accounting (STATS.md identity 1) ---
    /// Capture files successfully opened.
    pub captures_read: u64,
    /// Total packets read from all captures.
    pub packets_total: u64,
    /// Packets carrying a parseable Data MPDU.
    pub data_frames: u64,
    /// Packets carrying a Management MPDU.
    pub mgmt_frames: u64,
    /// Control frames (not body-parsed).
    pub ctrl_frames: u64,
    /// Extension frames (type 3; not body-parsed).
    pub extension_frames: u64,
    /// Dropped: no recognised link type.
    pub packets_unknown_link: u64,
    /// Dropped: link-layer header strip failed every tier.
    pub link_errors: u64,
    /// Dropped: the 802.11 MAC header was unparseable.
    pub malformed_mac: u64,
    /// Dropped: the body ran past the captured length.
    pub truncated: u64,

    // --- BSSID accounting (STATS.md identity 2) ---
    /// Distinct BSSIDs observed.
    pub bssids_total: u64,
    /// BSSIDs advertising/using WEP.
    pub wep_bssids: u64,
    /// BSSIDs using WPA/WPA2/WPA3.
    pub wpa_bssids: u64,
    /// Open (unencrypted) BSSIDs.
    pub open_bssids: u64,
    /// BSSIDs whose encryption could not be determined.
    pub unknown_bssids: u64,
    /// WEP BSSIDs whose key was recovered.
    pub cracked: u64,
    /// WEP BSSIDs left uncracked because the capture was too thin.
    pub uncracked_thin: u64,
    /// WEP BSSIDs left uncracked because a 104/232-bit raw key was infeasible.
    pub uncracked_infeasible: u64,

    // --- WEP material (subsets of data_frames / mgmt_frames, not separate dispositions) ---
    /// WEP-encrypted data frames seen (a subset of `data_frames`).
    pub wep_data_frames: u64,
    /// WEP-encrypted Shared-Key authentication frames seen (a subset of `mgmt_frames`).
    pub wep_auth_frames: u64,

    // --- Crack attribution (STATS.md identity 3) ---
    /// Keys recovered by PTW.
    pub keys_by_ptw: u64,
    /// Keys recovered by the `KoreK` correlations.
    pub keys_by_korek: u64,
    /// Keys recovered by FMS.
    pub keys_by_fms: u64,
    /// Keys recovered by the RC4-bias refinements.
    pub keys_by_bias: u64,
    /// Keys recovered from a wordlist.
    pub keys_by_dict: u64,
    /// Keys recovered by a weak key generator (Neesus-Datacom / MD5).
    pub keys_by_keygen: u64,
    /// Keys recovered from Shared-Key auth keystream.
    pub keys_by_ska: u64,
    /// Keys recovered by 40-bit brute force.
    pub keys_by_brute: u64,
    /// Keys obtained by reusing a network-wide key across BSSIDs.
    pub keys_by_reuse: u64,
    /// Keys supplied by a seeded potfile (a known key verified, not re-attacked).
    pub keys_by_potfile: u64,

    // --- Resource accounting ---
    /// Peak resident set size observed, in bytes.
    pub peak_rss_bytes: u64,
    /// Total wallclock time.
    pub wallclock: Duration,
    /// Time discovering capture files (directory walk + parallel magic filter).
    pub discovery: Duration,
    /// Time ingesting captures (parse + classify + per-file merge).
    pub ingest: Duration,
    /// Time in the key-recovery phase -- the parallel PTW/KoreK/FMS/bias/dictionary/
    /// keygen/SKA attacks plus cross-BSSID reuse, run across all cores (everything
    /// except the 40-bit brute force).
    pub recovery: Duration,
    /// Time in the sequential 40-bit brute-force search.
    pub bruteforce: Duration,
}

impl Stats {
    /// Fold one file's accounting into this total (FR-IN-6). A parallel multi-file
    /// ingest counts each file independently; this sums the per-file counters so
    /// the run banner totals are identical to a sequential scan. Counters add; the
    /// RSS peak takes the max (it is a high-water mark, not a sum). The BSSID block
    /// (identity 2) is filled by `tally_bssids` and the crack attribution (identity
    /// 3) by the engine, both after the merge, so they fold in as zero here; the
    /// run-wide durations are likewise stamped once after the scan.
    pub fn merge(&mut self, other: &Self) {
        // Packet accounting (identity 1) -- the fields a file scan populates.
        self.captures_read += other.captures_read;
        self.packets_total += other.packets_total;
        self.data_frames += other.data_frames;
        self.mgmt_frames += other.mgmt_frames;
        self.ctrl_frames += other.ctrl_frames;
        self.extension_frames += other.extension_frames;
        self.packets_unknown_link += other.packets_unknown_link;
        self.link_errors += other.link_errors;
        self.malformed_mac += other.malformed_mac;
        self.truncated += other.truncated;
        // BSSID accounting (identity 2) -- zero per file, filled by tally_bssids.
        self.bssids_total += other.bssids_total;
        self.wep_bssids += other.wep_bssids;
        self.wpa_bssids += other.wpa_bssids;
        self.open_bssids += other.open_bssids;
        self.unknown_bssids += other.unknown_bssids;
        self.cracked += other.cracked;
        self.uncracked_thin += other.uncracked_thin;
        self.uncracked_infeasible += other.uncracked_infeasible;
        self.wep_data_frames += other.wep_data_frames;
        self.wep_auth_frames += other.wep_auth_frames;
        // Crack attribution (identity 3) -- zero per file, filled by the engine.
        self.keys_by_ptw += other.keys_by_ptw;
        self.keys_by_korek += other.keys_by_korek;
        self.keys_by_fms += other.keys_by_fms;
        self.keys_by_bias += other.keys_by_bias;
        self.keys_by_dict += other.keys_by_dict;
        self.keys_by_keygen += other.keys_by_keygen;
        self.keys_by_ska += other.keys_by_ska;
        self.keys_by_brute += other.keys_by_brute;
        self.keys_by_reuse += other.keys_by_reuse;
        self.keys_by_potfile += other.keys_by_potfile;
        // Resources: peak RSS is a high-water mark; durations are stamped later.
        self.peak_rss_bytes = self.peak_rss_bytes.max(other.peak_rss_bytes);
    }
}
