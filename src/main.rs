//! `wepwolf` binary entry point.
//!
//! The oneshot driver lives in the library (`wepwolf::cli`); this binary is a
//! thin shell that returns its exit code.

// clap drives the library CLI and the rest are used by deeper library layers,
// not directly by this binary; silence the per-target unused-crate-dependencies
// lint (the WPAWolf layout).
use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;

use std::process::ExitCode;

fn main() -> ExitCode {
    wepwolf::cli::run()
}
