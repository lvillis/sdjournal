//! High-level guided tour of `sdjournal`.
//!
//! Start with this example if you want to understand the crate quickly. It walks through the
//! main mental model:
//! - `Journal` opens one or more journal roots
//! - `JournalQuery` builds bounded filters
//! - `EntryRef` is the zero-copy result type
//! - `EntryOwned` is the durable, owned form
//! - `Cursor` lets you resume from a known position
//! - `Follow` turns a query into a streaming tail

use sdjournal::{EntryOwned, EntryRef, Journal};
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct Args {
    unit: String,
    limit: usize,
    follow_limit: Option<usize>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let journal = Journal::open_default()?;

    print_section("Journal");
    println!("opened default journal roots");

    print_section("Tail");
    show_tail(&journal, args.limit)?;

    print_section("Unit Query");
    show_unit_query(&journal, &args.unit, args.limit)?;

    print_section("Field Presence");
    show_field_presence_query(&journal, "MESSAGE", args.limit)?;

    print_section("Owned Entries");
    show_owned_entries(&journal, &args.unit, args.limit.min(3))?;

    print_section("Cursor Resume");
    show_cursor_resume(&journal, &args.unit)?;

    print_section("Follow");
    match args.follow_limit {
        Some(n) => follow_unit(&journal, &args.unit, n)?,
        None => println!(
            "pass `--follow <count>` to stream new entries for {unit}",
            unit = args.unit
        ),
    }

    Ok(())
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut unit: Option<String> = None;
    let mut limit: Option<usize> = None;
    let mut follow_limit: Option<usize> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--follow" {
            let value = args
                .next()
                .ok_or_else(|| usage("`--follow` requires a count"))?;
            follow_limit = Some(value.parse()?);
            continue;
        }

        if unit.is_none() {
            unit = Some(arg);
            continue;
        }

        if limit.is_none() {
            limit = Some(arg.parse()?);
            continue;
        }

        return Err(
            usage("usage: cargo run --example tour -- [unit] [limit] [--follow <count>]").into(),
        );
    }

    Ok(Args {
        unit: unit.unwrap_or_else(|| "sshd.service".to_string()),
        limit: limit.unwrap_or(3),
        follow_limit,
    })
}

fn usage(message: &str) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message)
}

fn show_tail(journal: &Journal, limit: usize) -> Result<(), Box<dyn Error>> {
    let mut q = journal.query();
    q.seek_tail().limit(limit);
    print_iter("tail", q.iter()?)?;
    Ok(())
}

fn show_unit_query(journal: &Journal, unit: &str, limit: usize) -> Result<(), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let since = now.saturating_sub(Duration::from_secs(15 * 60));
    let since_usec = u64::try_from(since.as_micros())?;

    let mut q = journal.query();
    q.match_unit(unit).since_realtime(since_usec).limit(limit);
    print_iter("match_unit + since_realtime", q.iter()?)?;
    Ok(())
}

fn show_field_presence_query(
    journal: &Journal,
    field: &str,
    limit: usize,
) -> Result<(), Box<dyn Error>> {
    let mut q = journal.query();
    q.match_present(field).limit(limit);
    print_iter("match_present", q.iter()?)?;
    Ok(())
}

fn show_owned_entries(journal: &Journal, unit: &str, limit: usize) -> Result<(), Box<dyn Error>> {
    let mut q = journal.query();
    q.match_unit(unit).seek_tail().limit(limit);

    // `collect_owned()` is the easy way to detach results from the underlying iterator and keep
    // them around for later processing, async handoff, or serialization.
    let entries = q.collect_owned()?;
    println!("collected {} owned entries", entries.len());
    for entry in &entries {
        print_owned_entry("owned", entry);
    }

    Ok(())
}

fn show_cursor_resume(journal: &Journal, unit: &str) -> Result<(), Box<dyn Error>> {
    let mut newest = journal.query();
    newest.match_unit(unit).seek_tail().limit(1);

    let mut iter = newest.iter()?;
    let Some(item) = iter.next() else {
        println!("no entries matched {unit}");
        return Ok(());
    };
    let entry = item?;
    let cursor = entry.cursor()?;

    println!("saved cursor={cursor}");
    print_borrowed_entry("cursor source", &entry);

    let mut resumed = journal.seek_cursor(&cursor)?;
    resumed.limit(1);
    let mut resumed_iter = resumed.iter()?;
    if let Some(item) = resumed_iter.next() {
        print_borrowed_entry("seek_cursor", &item?);
    }

    let mut after = journal.query();
    after.after_cursor(cursor).limit(1);
    let mut after_iter = after.iter()?;
    if let Some(item) = after_iter.next() {
        print_borrowed_entry("after_cursor", &item?);
    } else {
        println!("after_cursor produced no strictly newer entry");
    }

    Ok(())
}

fn follow_unit(journal: &Journal, unit: &str, limit: usize) -> Result<(), Box<dyn Error>> {
    let mut q = journal.query();
    q.match_unit(unit);

    println!("following up to {limit} new entries for {unit}");
    let mut follow = q.follow()?;
    for item in (&mut follow).take(limit) {
        print_borrowed_entry("follow", &item?);
    }

    Ok(())
}

fn print_iter(
    label: &str,
    iter: impl Iterator<Item = sdjournal::Result<EntryRef>>,
) -> Result<(), Box<dyn Error>> {
    let mut count = 0usize;
    for item in iter {
        count += 1;
        print_borrowed_entry(label, &item?);
    }

    if count == 0 {
        println!("{label}: no entries");
    }
    Ok(())
}

fn print_borrowed_entry(label: &str, entry: &EntryRef) {
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
        "{label}: realtime={} seq={} unit={} cursor={} message={}",
        entry.realtime_usec(),
        entry.seqnum(),
        unit,
        entry.cursor().map(|c| c.to_string()).unwrap_or_default(),
        msg
    );
}

fn print_owned_entry(label: &str, entry: &EntryOwned) {
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
        "{label}: realtime={} seq={} unit={} cursor={} message={}",
        entry.realtime_usec(),
        entry.seqnum(),
        unit,
        entry.cursor().map(|c| c.to_string()).unwrap_or_default(),
        msg
    );
}

fn print_section(name: &str) {
    println!("\n== {name} ==");
}
