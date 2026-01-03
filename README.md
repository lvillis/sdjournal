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
- `crates/sdjournal/examples/checkpoint_follow.rs`

Run it on Linux:

```bash
cargo run -p sdjournal --example checkpoint_follow -- sshd.service /var/tmp/sdjournal.cursor
```

## Development

- Format: `cargo fmt`
- Lint: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Test: `cargo test --workspace --all-features`
- Fuzz (nightly): `cargo +nightly fuzz run journal_open`
