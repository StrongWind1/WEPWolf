//! Categorized `--log <file>` output (FR-DEBUG-4): one immediate line per event
//! with `file=` context, replayable post-run. A no-op when no path is given.
//!
//! `tracing` is deliberately not adopted -- these flat `[category] key=value`
//! lines cover the structured-output need within the dependency budget.

use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::path::Path;

use crate::types::Result;

/// One diagnostic event captured during a file scan, deferred for ordered replay.
///
/// A parallel multi-file ingest (FR-IN-6) replays events through the logger in
/// input-file order. Recording into a per-file buffer keeps the `file=`
/// attribution correct despite out-of-order parallel execution -- the
/// alternative, sharing the logger across worker threads, would interleave one
/// file's `set_file` with another's lines.
#[derive(Debug, PartialEq, Eq)]
pub enum LogEvent {
    /// A capture file could not be opened or read.
    CaptureError(String),
    /// The link-layer header could not be stripped for a packet.
    LinkError {
        /// The data link type the strip was attempted under.
        dlt: u16,
        /// The strip failure detail.
        reason: String,
    },
    /// The 802.11 MAC header was malformed.
    Malformed(String),
    /// A packet's interface carried no recognised link type.
    UnknownLink(u32),
}

/// A per-file tally of diagnostic events that coalesces identical ones.
///
/// A single corrupt capture can trip the same `[malformed_frame]` or
/// `[link_error]` on millions of frames. Recording each verbatim would flood the
/// log (and balloon the per-file buffer the parallel ingest holds in memory), so
/// identical `(category, reason)` events are folded into one entry with a count.
/// First-seen order is preserved, so the replayed log is still deterministic
/// regardless of thread scheduling (FR-IN-6).
#[derive(Debug, Default)]
pub struct EventTally {
    /// Distinct events in first-seen order, each with how many times it occurred.
    events: Vec<(LogEvent, u64)>,
}

impl EventTally {
    /// Record one event, incrementing the count of an identical earlier event or
    /// appending a new entry. The scan of distinct entries is cheap because a file
    /// produces only a handful of distinct `(category, reason)` pairs, however many
    /// frames trip them.
    pub fn record(&mut self, event: LogEvent) {
        if let Some(entry) = self.events.iter_mut().find(|(seen, _)| *seen == event) {
            entry.1 += 1;
        } else {
            self.events.push((event, 1));
        }
    }

    /// Whether any event was recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Consume the tally, yielding the distinct events with their counts in
    /// first-seen order for ordered replay.
    #[must_use]
    pub fn into_events(self) -> Vec<(LogEvent, u64)> {
        self.events
    }
}

/// Writes categorized diagnostic lines to an optional file.
#[derive(Debug)]
pub struct Logger {
    sink: Option<BufWriter<File>>,
    file: String,
}

impl Logger {
    /// Open the log file for writing, or build a no-op logger when `path` is `None`.
    ///
    /// # Errors
    /// Returns the I/O error if the log file cannot be created.
    pub fn new(path: Option<&Path>) -> Result<Self> {
        let sink = match path {
            Some(p) => Some(BufWriter::new(File::create(p)?)),
            None => None,
        };
        Ok(Self { sink, file: String::new() })
    }

    /// Set the capture filename used as `file=` context on subsequent lines.
    pub fn set_file(&mut self, name: &str) {
        if self.sink.is_some() {
            name.clone_into(&mut self.file);
        }
    }

    /// Whether logging is active (a path was given). Lets the parallel scan skip
    /// buffering events when `--log` is off, so no work is done on the hot path.
    #[must_use]
    pub const fn active(&self) -> bool {
        self.sink.is_some()
    }

    /// Replay one file's coalesced events (FR-IN-6) under its `file=` context, in
    /// first-seen order, after the parallel scan completes. Each distinct event is
    /// one line carrying its occurrence count.
    pub fn replay(&mut self, file: &str, tally: EventTally) {
        if self.sink.is_none() {
            return;
        }
        self.set_file(file);
        for (event, count) in tally.into_events() {
            match event {
                LogEvent::CaptureError(reason) => self.capture_error(&reason, count),
                LogEvent::LinkError { dlt, reason } => self.link_error(dlt, &reason, count),
                LogEvent::Malformed(reason) => self.malformed_frame(&reason, count),
                LogEvent::UnknownLink(interface_id) => self.unknown_linktype(interface_id, count),
            }
        }
    }

    /// Write one categorized line. Detail is a pre-formatted `key=value ...` tail;
    /// `count` is how many identical events were folded into this line (FR-DEBUG-4).
    fn line(&mut self, category: &str, detail: &str, count: u64) {
        let file = &self.file;
        if let Some(sink) = self.sink.as_mut() {
            // Writing to a buffered file: ignore the Result, surfaced on flush.
            let _ = writeln!(sink, "[{category}] file={file} {detail} count={count}");
        }
    }

    /// A capture file could not be opened or read.
    pub fn capture_error(&mut self, reason: &str, count: u64) {
        if self.sink.is_some() {
            self.line("capture_error", &format!("reason={reason:?}"), count);
        }
    }

    /// The link-layer header could not be stripped for one or more packets.
    pub fn link_error(&mut self, dlt: u16, reason: &str, count: u64) {
        if self.sink.is_some() {
            self.line("link_error", &format!("dlt={dlt} reason={reason:?}"), count);
        }
    }

    /// The 802.11 MAC header was malformed on one or more frames.
    pub fn malformed_frame(&mut self, reason: &str, count: u64) {
        if self.sink.is_some() {
            self.line("malformed_frame", &format!("reason={reason:?}"), count);
        }
    }

    /// One or more packets' interface carried no recognised link type.
    pub fn unknown_linktype(&mut self, interface_id: u32, count: u64) {
        if self.sink.is_some() {
            self.line("unknown_linktype", &format!("interface={interface_id}"), count);
        }
    }

    /// Flush buffered lines. Call before exit.
    ///
    /// # Errors
    /// Returns the I/O error if the final flush fails.
    pub fn flush(&mut self) -> Result<()> {
        if let Some(sink) = self.sink.as_mut() {
            sink.flush()?;
        }
        Ok(())
    }
}
