//! Cursor checkpointing example.
//!
//! This tails a unit's logs and persists a cursor checkpoint to disk. On restart, it resumes
//! strictly after the last persisted cursor.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sdjournal::{Cursor, Journal};
    use std::path::PathBuf;

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

    let journal = Journal::open_default()?;
    let mut q = journal.query();
    q.match_exact("_SYSTEMD_UNIT", unit.as_bytes());
    if let Some(c) = resume_cursor {
        q.after_cursor(c);
    }

    let mut follow = q.follow()?;
    for item in &mut follow {
        let entry = item?;
        if let Some(msg) = entry.get("MESSAGE") {
            println!("{}", String::from_utf8_lossy(msg));
        }

        let cursor = entry.cursor()?.to_string();
        let tmp = checkpoint_path.with_extension("tmp");
        std::fs::write(&tmp, &cursor)?;
        std::fs::rename(&tmp, &checkpoint_path)?;
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example only runs on Linux.");
}
