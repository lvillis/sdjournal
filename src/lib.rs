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
//! - `tokio`: enable [`LiveSubscription::into_tokio`] and [`TokioSubscription`].
//! - `tracing`: emit diagnostics via the `tracing` ecosystem.
//! - `verify-seal`: enable [`Journal::verify_seal`] for Forward Secure Sealing verification.
//!
//! # Main Types
//!
//! - [`Journal`] opens one or more journal roots and deduplicates journal files.
//! - [`JournalQuery`] builds historical filters, time bounds, and cursor resumes.
//! - [`EntryRef`] exposes zero-copy entry views when possible.
//! - [`EntryOwned`] detaches an entry for storage, async use, or cross-thread transfer.
//! - [`LiveEntry`] is the shared live-delivery wrapper used by subscriptions.
//! - [`Cursor`] provides checkpoint and resume tokens.
//! - [`LiveJournal`] shares one live tail engine across multiple subscriptions.
//! - [`LiveSubscription`] receives shared live entries dispatched by the live engine.
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
mod format;
mod journal;
mod live;
mod query;
mod reader;
#[cfg(feature = "verify-seal")]
mod seal;
mod util;

pub use crate::config::JournalConfig;
pub use crate::cursor::Cursor;
pub use crate::entry::{EntryOwned, EntryRef, LiveEntry};
pub use crate::error::{Result, SdJournalError};
pub use crate::journal::Journal;
#[cfg(feature = "tokio")]
pub use crate::live::TokioSubscription;
pub use crate::live::{
    LiveFilter, LiveJournal, LiveOrGroupBuilder, LiveSubscription, SubscriptionOptions,
};
pub use crate::query::JournalQuery;
