//! Open one journal directory and print a few entries.

use sdjournal::{EntryRef, Journal};
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or_else(|| usage("usage: cargo run --example open_dir -- <journal-dir> [limit]"))?;
    let limit = parse_usize_arg(args.next().as_deref(), 20)?;

    let journal = Journal::open_dir(&path)?;
    let mut q = journal.query();
    q.limit(limit);

    for item in q.iter()? {
        print_entry(&item?);
    }

    Ok(())
}

fn usage(message: &str) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message)
}

fn parse_usize_arg(arg: Option<&str>, default: usize) -> Result<usize, Box<dyn Error>> {
    match arg {
        Some(value) => Ok(value.parse()?),
        None => Ok(default),
    }
}

fn print_entry(entry: &EntryRef) {
    let unit = entry
        .get("_SYSTEMD_UNIT")
        .or_else(|| entry.get("UNIT"))
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "-".to_string());
    let msg = entry
        .get("MESSAGE")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<no MESSAGE>".to_string());

    println!(
        "realtime={} seq={} unit={} message={}",
        entry.realtime_usec(),
        entry.seqnum(),
        unit,
        msg
    );
}
