//! Resume strictly after a saved cursor string.

use sdjournal::{Cursor, EntryRef, Journal};
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let cursor_string = args
        .next()
        .ok_or_else(|| usage("usage: cargo run --example after_cursor -- <cursor> [limit]"))?;
    let limit = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(20usize);

    let cursor = Cursor::parse(&cursor_string)?;
    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.after_cursor(cursor).limit(limit);

    for item in q.iter()? {
        print_entry(&item?);
    }

    Ok(())
}

fn usage(message: &str) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message)
}

fn print_entry(entry: &EntryRef) {
    let msg = entry
        .get("MESSAGE")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<no MESSAGE>".to_string());

    println!(
        "realtime={} cursor={} message={}",
        entry.realtime_usec(),
        entry.cursor().map(|c| c.to_string()).unwrap_or_default(),
        msg
    );
}
