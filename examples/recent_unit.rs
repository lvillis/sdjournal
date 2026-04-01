//! Query recent entries for one unit.

use sdjournal::{EntryRef, Journal};
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn Error>> {
    let unit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sshd.service".to_string());
    let window_secs = std::env::args()
        .nth(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(300u64);
    let limit = std::env::args()
        .nth(3)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(20usize);

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let since = now.saturating_sub(Duration::from_secs(window_secs));
    let since_usec = u64::try_from(since.as_micros())?;

    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.match_unit(&unit).since_realtime(since_usec).limit(limit);

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
        "realtime={} monotonic={} message={}",
        entry.realtime_usec(),
        entry.monotonic_usec(),
        msg
    );
}
