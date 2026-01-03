//! `sdjournal` is a pure Rust systemd journal reader and query engine.
//!
//! This crate targets Linux systemd journal files (`*.journal`) and intentionally does not depend
//! on `libsystemd` nor invoke `journalctl`.

#![deny(unsafe_op_in_unsafe_fn)]

mod config;
mod cursor;
mod entry;
mod error;
mod file;
mod follow;
mod journal;
mod query;
mod reader;
#[cfg(feature = "verify-seal")]
mod seal;
mod util;

pub use crate::config::JournalConfig;
pub use crate::cursor::Cursor;
pub use crate::entry::{EntryOwned, EntryRef};
pub use crate::error::{Result, SdJournalError};
pub use crate::follow::Follow;
pub use crate::journal::Journal;
pub use crate::query::JournalQuery;
