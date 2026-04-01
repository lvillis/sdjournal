//! Follow one unit and print a bounded number of new entries.

use sdjournal::Journal;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let unit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sshd.service".to_string());
    let max_items = std::env::args()
        .nth(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(5usize);

    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.match_unit(&unit);

    let mut follow = q.follow()?;
    for item in (&mut follow).take(max_items) {
        let entry = item?;
        let msg = entry
            .get("MESSAGE")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_else(|| "<no MESSAGE>".to_string());
        println!(
            "cursor={} realtime={} message={}",
            entry.cursor()?,
            entry.realtime_usec(),
            msg
        );
    }

    Ok(())
}
