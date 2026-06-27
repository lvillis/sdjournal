//! Bridge one live subscription into Tokio.

#[cfg(feature = "tokio")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sdjournal::LiveJournal;
    use std::thread;

    let unit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sshd.service".to_string());
    let max_items = std::env::args()
        .nth(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(5usize);

    let mut live = LiveJournal::open_default()?;
    let mut filter = live.filter();
    filter.match_unit(&unit);

    let subscription = live.subscribe(filter)?;
    let _engine = thread::spawn(move || {
        let _ = live.run();
    });
    let mut rx = subscription.into_tokio().into_receiver();
    for _ in 0..max_items {
        let item = rx.blocking_recv().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "tokio live channel closed",
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
