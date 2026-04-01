//! Print the newest cursor for a unit and resume from it.

use sdjournal::{Cursor, EntryRef, Journal};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let unit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sshd.service".to_string());

    let journal = Journal::open_default()?;
    let mut newest = journal.query();
    newest.match_unit(&unit).seek_tail().limit(1);

    let mut iter = newest.iter()?;
    let Some(item) = iter.next() else {
        eprintln!("no entries matched {unit}");
        return Ok(());
    };
    let entry = item?;
    let cursor_string = entry.cursor()?.to_string();
    println!("cursor={cursor_string}");
    print_entry("newest", &entry);

    let cursor = Cursor::parse(&cursor_string)?;
    let mut resumed = journal.seek_cursor(&cursor)?;
    resumed.limit(1);

    let mut iter = resumed.iter()?;
    if let Some(item) = iter.next() {
        print_entry("seek_cursor", &item?);
    }

    Ok(())
}

fn print_entry(label: &str, entry: &EntryRef) {
    let msg = entry
        .get("MESSAGE")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<no MESSAGE>".to_string());

    println!(
        "{label}: realtime={} seq={} message={}",
        entry.realtime_usec(),
        entry.seqnum(),
        msg
    );
}
