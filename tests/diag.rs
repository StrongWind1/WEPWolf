//! Diagnostics surfaces: the memory monitor, the debug printer, and the
//! categorized logger (FR-MEM-1, FR-DEBUG-1, FR-DEBUG-4).

use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;

use wepwolf::diag::{DebugPrinter, EventTally, LogEvent, Logger, MemMonitor};

#[test]
fn mem_monitor_tracks_peak() {
    // FR-MEM-1: a sample records a non-zero peak RSS for the banner.
    let mut m = MemMonitor::new();
    m.sample();
    assert!(m.peak_rss_bytes() > 0, "sampling must record non-zero RSS");
}

#[test]
fn debug_printer_off_emits_nothing() {
    // FR-DEBUG-1: a printer built disabled reports disabled and is a no-op.
    let d = DebugPrinter::new(false);
    assert!(!d.enabled());
    d.say("this line must not be emitted");
}

#[test]
fn logger_writes_categorized_lines() {
    // FR-DEBUG-4: --log writes one categorized line per event with file= context.
    let path = std::env::temp_dir().join(format!("wepwolf_diag_{}.log", std::process::id()));
    let mut logger = Logger::new(Some(&path)).unwrap();
    logger.set_file("cap.pcap");
    logger.malformed_frame("truncated header", 1);
    logger.flush().unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).ok();
    assert!(contents.contains("[malformed_frame]"), "category prefix present");
    assert!(contents.contains("file=cap.pcap"), "file context present");
}

#[test]
fn logger_coalesces_repeated_events() {
    // FR-DEBUG-4: a file that trips the same error on many frames yields ONE line
    // with count=N, not one line per frame -- so a corrupt capture cannot flood the
    // log (or balloon the per-file buffer the parallel ingest holds).
    let mut tally = EventTally::default();
    for _ in 0..5000 {
        tally.record(LogEvent::Malformed("truncated 802.11 MAC header".to_owned()));
    }
    tally.record(LogEvent::LinkError { dlt: 127, reason: "radiotap too short".to_owned() });
    assert!(!tally.is_empty());

    let path = std::env::temp_dir().join(format!("wepwolf_coalesce_{}.log", std::process::id()));
    let mut logger = Logger::new(Some(&path)).unwrap();
    logger.replay("bad.cap", tally);
    logger.flush().unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).ok();

    assert_eq!(contents.lines().count(), 2, "5000 identical + 1 distinct event coalesce to 2 lines: {contents}");
    assert!(
        contents.contains(r#"[malformed_frame] file=bad.cap reason="truncated 802.11 MAC header" count=5000"#),
        "repeated event folds into one line with its count: {contents}"
    );
    assert!(contents.contains("file=bad.cap"), "file context present");
}
