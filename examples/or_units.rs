//! Query entries from either of two systemd units.

use sdjournal::{EntryRef, Journal};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let unit_a = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sshd.service".to_string());
    let unit_b = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "systemd-journald.service".to_string());
    let limit = std::env::args()
        .nth(3)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(20usize);

    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.or_group(|g| {
        g.match_exact("_SYSTEMD_UNIT", unit_a.as_bytes());
    });
    q.or_group(|g| {
        g.match_exact("_SYSTEMD_UNIT", unit_b.as_bytes());
    });
    q.seek_tail().limit(limit);

    for item in q.iter()? {
        print_entry(&item?);
    }

    Ok(())
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
        "realtime={} unit={} message={}",
        entry.realtime_usec(),
        unit,
        msg
    );
}
