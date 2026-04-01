//! Query entries where a field is present, regardless of its value.

use sdjournal::{EntryRef, Journal};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let field = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "MESSAGE".to_string());
    let limit = std::env::args()
        .nth(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(20usize);

    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.match_present(&field).limit(limit);

    for item in q.iter()? {
        print_entry(&item?, &field);
    }

    Ok(())
}

fn print_entry(entry: &EntryRef, field: &str) {
    let field_value = entry
        .get(field)
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<present but not printable>".to_string());
    let msg = entry
        .get("MESSAGE")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<no MESSAGE>".to_string());

    println!(
        "realtime={} seq={} {}={} message={}",
        entry.realtime_usec(),
        entry.seqnum(),
        field,
        field_value,
        msg
    );
}
