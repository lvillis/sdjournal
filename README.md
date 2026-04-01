# sdjournal

`sdjournal` is a **pure Rust** systemd journal reader and query engine. It reads `*.journal` files directly and does **not** depend on `libsystemd` or invoke `journalctl` (tests may use `journalctl` for golden comparisons).

## Status

- Target OS: **Linux** (non-Linux builds are supported for compilation, but `Journal::open_default()` is Linux-only).
- Designed for production use: corruption-/truncate-resistant parsing, bounded resource usage, stable merge ordering, cursor checkpoints, follow/tail with rotate support.

## Supported systemd / sample matrix

This project is validated in CI on:
- **Ubuntu 22.04** (systemd 249.x) as the **minimum** tested version
- **Ubuntu 24.04** (systemd 255.x) as the **target** tested version

See `.github/workflows/ci.yml` for the exact matrix and the logged `systemd --version` output.

## Features

- Default: `mmap`, `lz4`, `zstd`
- Optional:
  - `xz`: enable XZ decompression
  - `tracing`: emit diagnostics via `tracing` (caller installs a subscriber)
  - `tokio`: provides an async follow adapter
  - `verify-seal`: verify Forward Secure Sealing (TAG/FSS) with a systemd verification key

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

## Cursor checkpoint (resume after restart)

An end-to-end example that persists the last cursor and resumes via `after_cursor` is in:
- `examples/checkpoint_follow.rs`

Run it on Linux:

```bash
cargo run --example checkpoint_follow -- sshd.service /var/tmp/sdjournal.cursor
```

## Examples

- `open_dir`: open one journal directory and print entries
- `open_dirs`: merge multiple journal roots
- `tail`: print the newest entries from the default journal
- `filter_exact`: query by an exact field/value pair
- `match_unit`: query one systemd unit
- `or_units`: OR across two units with `or_group`
- `recent_unit`: query a unit within a recent time window
- `print_fields`: dump all fields from the newest matching entry
- `cursor_roundtrip`: print a cursor and resume from it with `seek_cursor`
- `after_cursor`: resume strictly after a saved cursor string
- `follow_unit`: block and print a few newly appended entries
- `checkpoint_follow`: persist cursors while following
- `open_with_config`: customize `JournalConfig`
- `follow_tokio`: use the Tokio follow adapter (`--features tokio`)
- `verify_seal`: verify FSS tags (`--features verify-seal`)

## Development

- Format: `cargo fmt`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Test: `cargo test --all-features`
- Fuzz (nightly): `cargo +nightly fuzz run journal_open`
