//! Open journals with a custom `JournalConfig`.

use sdjournal::{EntryRef, Journal, JournalConfig};
use std::error::Error;
use std::time::Duration;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1);

    let config = JournalConfig {
        include_journal_tilde: true,
        allow_mmap_online: false,
        max_journal_files: 256,
        max_query_terms: 32,
        max_decompressed_bytes: 2 * 1024 * 1024,
        poll_interval: Duration::from_millis(500),
        max_follow_backoff: Duration::from_secs(2),
        ..JournalConfig::default()
    };

    let journal = match path {
        Some(path) => Journal::open_dir_with_config(path, config)?,
        None => Journal::open_default_with_config(config)?,
    };

    let mut q = journal.query();
    q.limit(10);
    for item in q.iter()? {
        print_entry(&item?);
    }

    Ok(())
}

fn print_entry(entry: &EntryRef) {
    let msg = entry
        .get("MESSAGE")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<no MESSAGE>".to_string());

    println!(
        "realtime={} seq={} message={}",
        entry.realtime_usec(),
        entry.seqnum(),
        msg
    );
}
