//! The `--debug` diagnostic printer (FR-DEBUG-1): a single flag that emits
//! timestamped, context-tagged lines to stderr. A no-op shell when off.
//!
//! Volume is bounded by tagging phases, files, and per-BSSID summaries -- never
//! a line per frame -- so `--debug` on a multi-gigabyte capture stays readable.

use std::time::Instant;

/// Timestamped stderr debug printer; every method is a no-op when disabled.
#[derive(Debug)]
pub struct DebugPrinter {
    enabled: bool,
    start: Instant,
}

impl DebugPrinter {
    /// Build a printer. `enabled=false` (the default, no `--debug`) makes every
    /// method a no-op so call sites stay branch-free.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self { enabled, start: Instant::now() }
    }

    /// Whether debug output is on (lets callers skip building expensive messages).
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Emit one timestamped line. The caller supplies the already-tagged message
    /// (e.g. `"ingest file=foo.pcap"` or `"bssid aa:bb:.. wep ivs=1234"`).
    pub fn say(&self, msg: &str) {
        if self.enabled {
            let elapsed = self.start.elapsed().as_secs_f64();
            eprintln!("[debug +{elapsed:7.3}s] {msg}");
        }
    }
}
