//! Verify Forward Secure Sealing for a journal set.

#[cfg(feature = "verify-seal")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sdjournal::Journal;
    use std::io::{Error as IoError, ErrorKind};

    let mut args = std::env::args().skip(1);
    let first = args.next().ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidInput,
            "usage: cargo run --example verify_seal --features verify-seal -- [journal-dir] <verification-key>",
        )
    })?;

    let (path, verification_key) = match args.next() {
        Some(second) => (Some(first), second),
        None => (None, first),
    };

    let journal = match path {
        Some(path) => Journal::open_dir(path)?,
        None => Journal::open_default()?,
    };
    journal.verify_seal(&verification_key)?;
    println!("seal verification passed");

    Ok(())
}

#[cfg(not(feature = "verify-seal"))]
fn main() {
    eprintln!("Build this example with `--features verify-seal`.");
}
