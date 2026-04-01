//! Collect matching entries into `EntryOwned`.
//!
//! This is useful when you need results to outlive the iterator, cross thread boundaries, or feed
//! them into async/background work.

use sdjournal::{EntryOwned, Journal};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let unit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sshd.service".to_string());
    let limit = std::env::args()
        .nth(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(10usize);

    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.match_unit(&unit).seek_tail().limit(limit);

    let entries = q.collect_owned()?;
    println!("collected {} entries for {}", entries.len(), unit);
    for entry in &entries {
        print_entry(entry);
    }

    Ok(())
}

fn print_entry(entry: &EntryOwned) {
    let msg = entry
        .get("MESSAGE")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<no MESSAGE>".to_string());

    println!(
        "realtime={} seq={} cursor={} message={}",
        entry.realtime_usec(),
        entry.seqnum(),
        entry.cursor().map(|c| c.to_string()).unwrap_or_default(),
        msg
    );
}
