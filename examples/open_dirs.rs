//! Open and merge multiple journal roots.

use sdjournal::{EntryRef, Journal};
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let paths: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if paths.is_empty() {
        return Err(usage("usage: cargo run --example open_dirs -- <dir> <dir> [dir ...]").into());
    }

    let journal = Journal::open_dirs(&paths)?;
    let mut q = journal.query();
    q.limit(20);

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
        "realtime={} seq={} cursor={} message={}",
        entry.realtime_usec(),
        entry.seqnum(),
        entry.cursor().map(|c| c.to_string()).unwrap_or_default(),
        msg
    );
}
