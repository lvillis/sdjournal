//! `sdjournal` is a pure Rust systemd journal reader and query engine.
//!
//! It opens `*.journal` files directly and does not depend on `libsystemd` or invoke
//! `journalctl`.
//!
//! # Platform
//!
//! This crate targets Linux journal files. Non-Linux builds are supported for compilation, but
//! [`Journal::open_default`] is Linux-only because it depends on the standard journal locations.
//!
//! # Feature Flags
//!
//! - `mmap` (default): use memory mapping when safe to do so for journal file reads.
//! - `lz4` (default): enable LZ4-compressed DATA payload decoding.
//! - `zstd` (default): enable Zstandard-compressed DATA payload decoding.
//! - `xz`: enable XZ-compressed DATA payload decoding.
//! - `tokio`: enable [`JournalQuery::follow_tokio`] and [`TokioFollow`].
//! - `tracing`: emit diagnostics via the `tracing` ecosystem.
//! - `verify-seal`: enable [`Journal::verify_seal`] for Forward Secure Sealing verification.
//!
//! # Main Types
//!
//! - [`Journal`] opens one or more journal roots and deduplicates journal files.
//! - [`JournalQuery`] builds filters, time bounds, cursor resumes, and follow streams.
//! - [`EntryRef`] exposes zero-copy entry views when possible.
//! - [`EntryOwned`] detaches an entry for storage, async use, or cross-thread transfer.
//! - [`Cursor`] provides checkpoint and resume tokens.
//! - [`Follow`] blocks while tailing new matching entries.
//!
//! # Quick Start
//!
//! ```no_run
//! use sdjournal::Journal;
//!
//! let journal = Journal::open_default()?;
//! let mut query = journal.query();
//! query.match_exact("_SYSTEMD_UNIT", b"sshd.service");
//! query.since_realtime(0);
//!
//! for item in query.iter()? {
//!     let entry = item?;
//!     if let Some(message) = entry.get("MESSAGE") {
//!         println!("{}", String::from_utf8_lossy(message));
//!     }
//! }
//! # Ok::<(), sdjournal::SdJournalError>(())
//! ```

#![deny(missing_docs, unsafe_op_in_unsafe_fn)]
#![deny(rustdoc::broken_intra_doc_links)]

mod config;
mod cursor;
mod entry;
mod error;
mod file;
mod follow;
mod format;
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
#[cfg(feature = "tokio")]
pub use crate::follow::TokioFollow;
pub use crate::journal::Journal;
pub use crate::query::JournalQuery;
