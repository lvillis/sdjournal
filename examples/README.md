# Examples

Start with [`tour`](tour.rs) for a guided overview.

## Overview

| Example | Purpose | Run |
| --- | --- | --- |
| [`tour`](tour.rs) | Walk through the main API | `cargo run --example tour -- [unit] [limit] [--follow <count>]` |

## Open

| Example | Purpose | Run |
| --- | --- | --- |
| [`open_dir`](open_dir.rs) | Open one journal directory | `cargo run --example open_dir -- <journal-dir> [limit]` |
| [`open_dirs`](open_dirs.rs) | Merge multiple journal roots | `cargo run --example open_dirs -- <dir> <dir> [dir ...]` |
| [`open_with_config`](open_with_config.rs) | Customize discovery limits and options | `cargo run --example open_with_config -- [journal-dir]` |

## Query

| Example | Purpose | Run |
| --- | --- | --- |
| [`tail`](tail.rs) | Print recent entries | `cargo run --example tail -- [limit]` |
| [`match_unit`](match_unit.rs) | Query one systemd unit | `cargo run --example match_unit -- [unit] [limit]` |
| [`filter_exact`](filter_exact.rs) | Match one exact field value | `cargo run --example filter_exact -- <field> <value> [limit]` |
| [`match_present`](match_present.rs) | Match entries containing a field | `cargo run --example match_present -- [field] [limit]` |
| [`or_units`](or_units.rs) | Query either of two units | `cargo run --example or_units -- [unit-a] [unit-b] [limit]` |
| [`recent_unit`](recent_unit.rs) | Query a unit within a recent time window | `cargo run --example recent_unit -- [unit] [seconds] [limit]` |
| [`print_fields`](print_fields.rs) | Print all fields from an entry | `cargo run --example print_fields -- [unit]` |
| [`collect_owned`](collect_owned.rs) | Detach entries from the reader | `cargo run --example collect_owned -- [unit] [limit]` |

## Cursor

| Example | Purpose | Run |
| --- | --- | --- |
| [`cursor_roundtrip`](cursor_roundtrip.rs) | Print and parse a cursor | `cargo run --example cursor_roundtrip -- [unit]` |
| [`after_cursor`](after_cursor.rs) | Resume strictly after a cursor | `cargo run --example after_cursor -- <cursor> [limit]` |
| [`checkpoint_follow`](checkpoint_follow.rs) | Persist a cursor while following | `cargo run --example checkpoint_follow -- [unit] [cursor-file]` |

## Live

| Example | Purpose | Run |
| --- | --- | --- |
| [`follow_unit`](follow_unit.rs) | Follow one unit | `cargo run --example follow_unit -- [unit] [count]` |
| [`live_multi_subscriptions`](live_multi_subscriptions.rs) | Share one live engine across subscriptions | `cargo run --example live_multi_subscriptions -- [--count N] [unit ...]` |
| [`follow_tokio`](follow_tokio.rs) | Bridge live subscriptions into Tokio | `cargo run --features tokio --example follow_tokio -- [unit] [count]` |

## Optional

| Example | Purpose | Run |
| --- | --- | --- |
| [`verify_seal`](verify_seal.rs) | Verify Forward Secure Sealing | `cargo run --features verify-seal --example verify_seal -- [journal-dir] <verification-key>` |
