//! Cursor checkpointing example.
//!
//! This subscribes to a unit's live stream and persists a cursor checkpoint to disk. On restart,
//! it resumes strictly after the last persisted cursor.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sdjournal::{Cursor, LiveJournal, SubscriptionOptions};
    use std::path::PathBuf;
    use std::thread;

    let mut args = std::env::args().skip(1);
    let unit = args.next().unwrap_or_else(|| "sshd.service".to_string());
    let checkpoint_path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("sdjournal.cursor"));

    let mut resume_cursor: Option<Cursor> = None;
    match std::fs::read_to_string(&checkpoint_path) {
        Ok(s) => {
            let s = s.trim();
            if !s.is_empty() {
                resume_cursor = Some(Cursor::parse(s)?);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let mut live = LiveJournal::open_default()?;
    let mut filter = live.filter();
    filter.match_exact("_SYSTEMD_UNIT", unit.as_bytes());
    let mut options = SubscriptionOptions::new(filter);
    if let Some(cursor) = resume_cursor {
        options.after_cursor(cursor);
    }

    let subscription = live.subscribe_with_options(options)?;
    let _engine = thread::spawn(move || {
        let _ = live.run();
    });

    loop {
        let entry = subscription.recv()??;
        if let Some(msg) = entry.get("MESSAGE") {
            println!("{}", String::from_utf8_lossy(msg));
        }

        let cursor = entry.cursor()?.to_string();
        let tmp = checkpoint_path.with_extension("tmp");
        std::fs::write(&tmp, &cursor)?;
        std::fs::rename(&tmp, &checkpoint_path)?;
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example only runs on Linux.");
}
