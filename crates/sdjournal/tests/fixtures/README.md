# Format fixtures

This directory is reserved for **offline journal file samples** used by `crates/sdjournal/tests/format_fixtures.rs`.

## Layout

Each fixture lives under `tests/fixtures/<name>/`:

- `journal/` — one or more `*.journal` files (optionally with a `<machine-id>/` subdir)
- `expected.json` — a JSON array of normalized entries (field → string), as produced by the test

## Notes

- Keep fixtures **small** and focused (a handful of entries).
- The intent is to collect samples from multiple systemd versions and format variants (regular/compact, compression, keyed-hash).
- If no fixtures are present, the test will skip.

