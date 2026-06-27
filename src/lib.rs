//! `sdjournal` is a pure Rust systemd journal reader and query engine.
//!
//! It opens `*.journal` files directly and does not depend on `libsystemd` or invoke
//! `journalctl`.
//!
//! # Platform
//!
//! This crate parses systemd journal files. Core file parsing, queries, cursors, and compression
//! decoding work with user-supplied `*.journal` directories on supported Rust hosts.
//!
//! Linux additionally supports [`Journal::open_default`] for standard system journal roots and
//! inotify-backed live watching. On non-Linux hosts, use [`Journal::open_dir`] or
//! [`Journal::open_dirs`] with exported systemd journal files; [`Journal::open_default`] returns
//! [`SdJournalError::Unsupported`].
//!
//! # Feature Flags
//!
//! - `mmap` (default): allow memory mapping for journal file reads. Runtime use is controlled by
//!   [`JournalConfig::mmap_policy`].
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
//! # Historical vs Live Reads
//!
//! Use [`JournalQuery`] for finite historical reads. Queries snapshot the files opened by
//! [`Journal`] and return matching entries in stable journal order.
//!
//! Use [`LiveJournal`] for tailing. A live engine keeps per-file tail state, watches for appended
//! data, and can fan out each new entry to multiple [`LiveSubscription`]s. Prefer one
//! [`LiveJournal`] with multiple subscriptions over multiple independent live engines when tailing
//! several units or filters. Use [`LiveJournal::open_default`] or [`LiveJournal::open_dirs`] when
//! only live tailing is needed; this avoids keeping a historical [`Journal`] open. Live delivery
//! uses bounded queues and batch sizes configured through [`JournalConfig`].
//!
//! For constrained processes, set [`JournalConfig::max_open_files`] to a small value and
//! [`JournalConfig::mmap_policy`] to [`MmapPolicy::Never`]. Historical queries then use a streaming
//! merge that avoids keeping every discovered journal file mapped or open.
//!
//! # Entry Ownership
//!
//! [`EntryRef`] is the cheapest representation and is what queries yield by default. Convert it to
//! [`EntryOwned`] when the entry must be stored, sent across long-lived boundaries, or detached
//! from the journal reader. Live subscriptions yield [`LiveEntry`], a shared wrapper around
//! [`EntryRef`] designed for efficient fan-out.
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

pub use crate::config::{JournalConfig, LiveQueueFullPolicy, MmapPolicy};
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
