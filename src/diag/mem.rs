//! Process memory monitor (FR-MEM-1).
//!
//! Samples RSS, tracks the peak for the closing banner, and emits a one-shot `[MEMORY WARNING]` to stderr when RSS crosses a fraction of total RAM. Cross-platform via `sysinfo`. Unlike `WPAWolf`'s monitor this drives no disk-backed fallback (`WEPWolf` holds far less state) -- it is purely diagnostic. The RSS/RAM probes are lifted verbatim from `WPAWolf`'s `progress` helpers (C9).

/// Packets between RSS samples during ingest.
const CHECK_INTERVAL: u64 = 50_000;
/// Default warning threshold in tenths of a percent of total RAM (800 = 80.0%).
const THRESHOLD_TENTHS: u64 = 800;

/// Samples process RSS, tracks the peak, and warns once past the RAM threshold.
#[derive(Debug)]
pub struct MemMonitor {
    total_ram: u64,
    threshold_bytes: u64,
    peak_rss: u64,
    warned: bool,
    packets_since_check: u64,
}

impl MemMonitor {
    /// Probe total RAM once and set the warning threshold (default 80%, override
    /// with `WEPWOLF_MEM_THRESHOLD` as an integer percent, e.g. `=1` for tests).
    #[must_use]
    pub fn new() -> Self {
        let total_ram = total_ram_bytes();
        let tenths = std::env::var("WEPWOLF_MEM_THRESHOLD")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map_or(THRESHOLD_TENTHS, |pct| pct.min(100) * 10);
        let threshold_bytes = total_ram / 1000 * tenths;
        Self { total_ram, threshold_bytes, peak_rss: 0, warned: false, packets_since_check: 0 }
    }

    /// Sample RSS now, update the peak, and emit one `[MEMORY WARNING]` the first
    /// time usage crosses the threshold.
    pub fn sample(&mut self) {
        self.packets_since_check = 0;
        let rss = current_rss_bytes();
        self.peak_rss = self.peak_rss.max(rss);
        if !self.warned && self.threshold_bytes > 0 && rss >= self.threshold_bytes {
            self.warned = true;
            let rss_mib = rss / (1024 * 1024);
            let total_mib = self.total_ram / (1024 * 1024);
            eprintln!("[MEMORY WARNING] RSS {rss_mib} MiB / {total_mib} MiB crossed the memory threshold");
        }
    }

    /// Count one packet and sample RSS once per `CHECK_INTERVAL` packets.
    pub fn tick(&mut self) {
        self.packets_since_check += 1;
        if self.packets_since_check >= CHECK_INTERVAL {
            self.sample();
        }
    }

    /// Highest RSS sample so far, in bytes (a lower bound on the true peak).
    #[must_use]
    pub const fn peak_rss_bytes(&self) -> u64 {
        self.peak_rss
    }
}

impl Default for MemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Current process resident set size in bytes, or 0 if the probe fails.
#[must_use]
pub fn current_rss_bytes() -> u64 {
    let Ok(pid) = sysinfo::get_current_pid() else {
        return 0;
    };
    let mut sys = sysinfo::System::new();
    let refresh = sysinfo::ProcessRefreshKind::nothing().with_memory();
    sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::Some(&[pid]), false, refresh);
    sys.process(pid).map_or(0, sysinfo::Process::memory)
}

/// Total physical RAM in bytes.
#[must_use]
pub fn total_ram_bytes() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory_specifics(sysinfo::MemoryRefreshKind::nothing().with_ram());
    sys.total_memory()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, missing_docs, reason = "test module")]

    use super::*;

    #[test]
    fn monitor_constructs_and_samples() {
        let mut m = MemMonitor::new();
        m.sample();
        assert!(m.peak_rss_bytes() > 0, "a sample must record non-zero RSS");
    }

    #[test]
    fn ram_and_rss_are_nonzero() {
        assert!(total_ram_bytes() > 0);
        assert!(current_rss_bytes() > 0);
    }
}
