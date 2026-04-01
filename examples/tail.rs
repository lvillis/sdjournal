//! Print the newest entries from the default journal.

use sdjournal::{EntryRef, Journal};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let limit = std::env::args()
        .nth(1)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(20usize);

    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.seek_tail().limit(limit);

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
