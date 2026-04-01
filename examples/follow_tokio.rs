//! Follow one unit through the Tokio adapter.

#[cfg(feature = "tokio")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sdjournal::Journal;

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

    let follow = q.follow_tokio()?;
    let mut rx = follow.into_receiver();
    for _ in 0..max_items {
        let item = rx.blocking_recv().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "tokio follow channel closed",
            )
        })?;
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

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!("Build this example with `--features tokio`.");
}
