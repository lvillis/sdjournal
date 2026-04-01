//! Print every field from the newest entry for a unit.

use sdjournal::Journal;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let unit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sshd.service".to_string());

    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.match_unit(&unit).seek_tail().limit(1);

    let mut iter = q.iter()?;
    let Some(item) = iter.next() else {
        eprintln!("no entries matched {unit}");
        return Ok(());
    };
    let entry = item?;

    println!(
        "cursor={} realtime={} seq={}",
        entry.cursor()?,
        entry.realtime_usec(),
        entry.seqnum()
    );
    for (field, value) in entry.iter_fields() {
        println!("{field}={}", String::from_utf8_lossy(value));
    }

    Ok(())
}
