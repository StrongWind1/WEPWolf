//! Diagnostics: `--debug`, `--log`, and the RSS memory monitor (FR-DEBUG, FR-MEM).
//!
//! These are operability surfaces, kept separate from the parsing and attack logic they observe.

pub mod debug;
pub mod log;
pub mod mem;

pub use debug::DebugPrinter;
pub use log::{EventTally, LogEvent, Logger};
pub use mem::MemMonitor;
