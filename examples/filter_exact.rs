//! Query by an exact field/value match.

use sdjournal::{EntryRef, Journal};
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let field = args.next().ok_or_else(|| {
        usage("usage: cargo run --example filter_exact -- <field> <value> [limit]")
    })?;
    let value = args.next().ok_or_else(|| {
        usage("usage: cargo run --example filter_exact -- <field> <value> [limit]")
    })?;
    let limit = args
        .next()
        .map(|arg| arg.parse())
        .transpose()?
        .unwrap_or(20usize);

    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.match_exact(&field, value.as_bytes()).limit(limit);

    for item in q.iter()? {
        print_entry(&item?, &field);
    }

    Ok(())
}

fn usage(message: &str) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message)
}

fn print_entry(entry: &EntryRef, field: &str) {
    let value = entry
        .get(field)
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "-".to_string());
    let msg = entry
        .get("MESSAGE")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<no MESSAGE>".to_string());

    println!(
        "realtime={} {}={} message={}",
        entry.realtime_usec(),
        field,
        value,
        msg
    );
}
