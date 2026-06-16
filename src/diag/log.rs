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
#[derive(Debug)]
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

    /// Replay one file's deferred events (FR-IN-6) under its `file=` context, in
    /// input-file order, after the parallel scan completes.
    pub fn replay(&mut self, file: &str, events: Vec<LogEvent>) {
        if self.sink.is_none() {
            return;
        }
        self.set_file(file);
        for event in events {
            match event {
                LogEvent::CaptureError(reason) => self.capture_error(&reason),
                LogEvent::LinkError { dlt, reason } => self.link_error(dlt, &reason),
                LogEvent::Malformed(reason) => self.malformed_frame(&reason),
                LogEvent::UnknownLink(interface_id) => self.unknown_linktype(interface_id),
            }
        }
    }

    /// Write one categorized line. Detail is a pre-formatted `key=value ...` tail.
    fn line(&mut self, category: &str, detail: &str) {
        let file = &self.file;
        if let Some(sink) = self.sink.as_mut() {
            // Writing to a buffered file: ignore the Result, surfaced on flush.
            let _ = writeln!(sink, "[{category}] file={file} {detail}");
        }
    }

    /// A capture file could not be opened or read.
    pub fn capture_error(&mut self, reason: &str) {
        if self.sink.is_some() {
            self.line("capture_error", &format!("reason={reason:?}"));
        }
    }

    /// The link-layer header could not be stripped for a packet.
    pub fn link_error(&mut self, dlt: u16, reason: &str) {
        if self.sink.is_some() {
            self.line("link_error", &format!("dlt={dlt} reason={reason:?}"));
        }
    }

    /// The 802.11 MAC header was malformed.
    pub fn malformed_frame(&mut self, reason: &str) {
        if self.sink.is_some() {
            self.line("malformed_frame", &format!("reason={reason:?}"));
        }
    }

    /// A packet's interface carried no recognised link type.
    pub fn unknown_linktype(&mut self, interface_id: u32) {
        if self.sink.is_some() {
            self.line("unknown_linktype", &format!("interface={interface_id}"));
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
