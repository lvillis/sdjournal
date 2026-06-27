# sdjournal

[![crates.io](https://img.shields.io/crates/v/sdjournal.svg)](https://crates.io/crates/sdjournal)
[![docs.rs](https://img.shields.io/docsrs/sdjournal)](https://docs.rs/sdjournal)

`sdjournal` is a **pure Rust** systemd journal reader and query engine. It reads `*.journal` files directly and does **not** depend on `libsystemd` or invoke `journalctl` (tests may use `journalctl` for golden comparisons).

## Overview

- Pure Rust, with no `libsystemd` dependency
- Bounded, corruption-resistant parsing for production use
- Stable merge ordering, cursor checkpoints, and bounded shared live subscriptions
- Low-memory mode with bounded open files and optional mmap disablement
- Optional mmap, compression backends, tracing, Tokio integration, and FSS verification

## Compatibility

- Target OS: **Linux**
- Non-Linux builds compile and can parse user-supplied `*.journal` files; `Journal::open_default()` is Linux-only
- CI coverage includes Ubuntu 22.04 (systemd 249.x), Ubuntu 24.04 (systemd 255.x), and macOS offline checks

## Install

```bash
cargo add sdjournal
```

## Features

- Default: `mmap`, `lz4`, `zstd`
- Optional:
  - `xz`: enable XZ decompression
  - `tracing`: emit diagnostics via `tracing` (caller installs a subscriber)
  - `tokio`: provides an async live-subscription adapter
  - `verify-seal`: verify Forward Secure Sealing (TAG/FSS) with a systemd verification key

For constrained processes, set `JournalConfig::max_open_files` to a small value and
`JournalConfig::mmap_policy` to `MmapPolicy::Never`.

## Quickstart

```rust
use sdjournal::Journal;

let journal = Journal::open_default()?;
let mut q = journal.query();
q.match_exact("_SYSTEMD_UNIT", b"sshd.service");
q.since_realtime(0);

for item in q.iter()? {
    let entry = item?;
    if let Some(msg) = entry.get("MESSAGE") {
        println!("{}", String::from_utf8_lossy(msg));
    }
}
# Ok::<(), sdjournal::SdJournalError>(())
```

## Resume From Cursor

An end-to-end example that persists the last cursor and resumes via `after_cursor` is in:
- `examples/checkpoint_follow.rs`

Run it on Linux:

```bash
cargo run --example checkpoint_follow -- sshd.service /var/tmp/sdjournal.cursor
```

## Start Here

To understand the crate quickly, read or run these examples in order:
- `tour`: guided walkthrough of `Journal`, `JournalQuery`, `EntryRef`/`EntryOwned`, `Cursor`, and `LiveJournal`
- `tail`: the smallest “open default journal and read entries” path
- `match_unit`: the most common production filter shape
- `checkpoint_follow`: resume-safe live subscription for long-running consumers

## Examples

Open / discovery:
- `tour`: guided API overview and mental model
- `open_dir`: open one journal directory and print entries
- `open_dirs`: merge multiple journal roots
- `open_with_config`: customize `JournalConfig`

Query builder patterns:
- `tail`: print the newest entries from the default journal
- `filter_exact`: query by an exact field/value pair
- `match_present`: query by field presence
- `match_unit`: query one systemd unit
- `or_units`: OR across two units with `or_group`
- `recent_unit`: query a unit within a recent time window
- `print_fields`: dump all fields from the newest matching entry
- `collect_owned`: detach results into `EntryOwned`

Cursor / resume:
- `cursor_roundtrip`: print a cursor and resume from it with `seek_cursor`
- `after_cursor`: resume strictly after a saved cursor string
- `checkpoint_follow`: persist cursors while following

Streaming / integration:
- `follow_unit`: block and print a few newly appended entries from a live subscription
- `live_multi_subscriptions`: share one `LiveJournal` across multiple unit subscriptions
- `follow_tokio`: bridge a live subscription into Tokio (`--features tokio`)
- `verify_seal`: verify FSS tags (`--features verify-seal`)
