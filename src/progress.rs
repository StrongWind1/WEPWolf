//! Live progress indicators (FR-UI).
//!
//! Three stderr surfaces, all drawn only on a terminal with the default table
//! output: an ingest spinner (FR-UI-1), a sweep bar counting BSSIDs done with
//! elapsed / ETA and the network currently being attacked (FR-UI-1), each
//! recovered key streamed above it as it verifies (FR-UI-2), and a brute
//! keyspace bar naming the network being ground with percent / keys-per-second /
//! ETA / SIMD tier (FR-UI-3). `--plain`, `--json`, `--quiet`, and `--debug`
//! (whose own lines share stderr) disable every surface so those streams stay
//! clean (FR-UI-4).
#![allow(
    clippy::literal_string_with_formatting_args,
    reason = "indicatif templates use {placeholder} syntax that is not a format! macro"
)]

use std::io::IsTerminal;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

/// Factory for the live progress surfaces. When disabled -- no TTY, or a
/// machine-readable output -- every bar it hands out is a no-op.
#[derive(Debug)]
pub struct Progress {
    /// Whether progress should actually draw.
    enabled: bool,
}

impl Progress {
    /// Build the factory. Surfaces draw only when `show` is set and stderr is a
    /// terminal, so piping or redirecting yields clean output (FR-UI-4).
    #[must_use]
    pub fn new(show: bool) -> Self {
        Self { enabled: show && std::io::stderr().is_terminal() }
    }

    /// Whether any progress surface will draw.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// The ingest spinner, ticked with the running file/packet counts.
    #[must_use]
    pub fn ingest_spinner(&self) -> Bar {
        if !self.enabled {
            return Bar::hidden();
        }
        let pb = ProgressBar::new_spinner();
        if let Ok(style) = ProgressStyle::with_template("{spinner:.cyan} {msg}") {
            pb.set_style(style);
        }
        pb.enable_steady_tick(Duration::from_millis(120));
        Bar { pb: Some(pb) }
    }

    /// The sweep bar: `total` BSSIDs to attack, incremented as each completes.
    #[must_use]
    pub fn sweep_bar(&self, total: u64) -> Bar {
        if !self.enabled {
            return Bar::hidden();
        }
        let pb = ProgressBar::new(total);
        if let Ok(style) =
            ProgressStyle::with_template("sweep [{bar:30.green}] {pos}/{len} BSSIDs  {elapsed}  eta {eta}  {msg}")
        {
            pb.set_style(style.progress_chars("=>-"));
        }
        Bar { pb: Some(pb) }
    }

    /// The brute keyspace bar: `total` keys, labelled with the active SIMD tier.
    #[must_use]
    pub fn brute_bar(&self, total: u64, tier: &str) -> Bar {
        if !self.enabled {
            return Bar::hidden();
        }
        let pb = ProgressBar::new(total);
        if let Ok(style) = ProgressStyle::with_template("brute [{bar:30.red}] {percent}% {per_sec} eta {eta} {msg}") {
            pb.set_style(style.progress_chars("=>-"));
        }
        pb.set_message(format!("[{tier}]"));
        Bar { pb: Some(pb) }
    }
}

/// One progress bar (or a no-op when progress is disabled). Cloneable handle so
/// the parallel sweep can share it across worker threads.
#[derive(Debug, Clone)]
pub struct Bar {
    /// `Some` only while progress is active.
    pb: Option<ProgressBar>,
}

impl Bar {
    /// A disabled bar; every method is a no-op.
    #[must_use]
    const fn hidden() -> Self {
        Self { pb: None }
    }

    /// Advance the bar by `n` units.
    pub fn inc(&self, n: u64) {
        if let Some(pb) = &self.pb {
            pb.inc(n);
        }
    }

    /// Replace the trailing message (ingest counts, recovered totals).
    pub fn set_message(&self, msg: String) {
        if let Some(pb) = &self.pb {
            pb.set_message(msg);
        }
    }

    /// Print a line above the bar without disturbing it (streamed key rows).
    pub fn println(&self, line: &str) {
        if let Some(pb) = &self.pb {
            pb.println(line);
        }
    }

    /// Clear the bar from the terminal.
    pub fn finish(&self) {
        if let Some(pb) = &self.pb {
            pb.finish_and_clear();
        }
    }
}
