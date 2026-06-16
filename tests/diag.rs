//! Diagnostics surfaces: the memory monitor, the debug printer, and the
//! categorized logger (FR-MEM-1, FR-DEBUG-1, FR-DEBUG-4).

use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;

use wepwolf::diag::{DebugPrinter, Logger, MemMonitor};

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
    logger.malformed_frame("truncated header");
    logger.flush().unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).ok();
    assert!(contents.contains("[malformed_frame]"), "category prefix present");
    assert!(contents.contains("file=cap.pcap"), "file context present");
}
