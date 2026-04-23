//! Share one live engine across multiple unit subscriptions.
//!
//! This is the recommended pattern when you need to tail several units at once. Build one
//! `LiveJournal`, register multiple subscriptions, then drive the engine once in the background.

use sdjournal::Journal;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
struct Args {
    units: Vec<String>,
    count: usize,
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = parse_args()?;
    let journal = Journal::open_default()?;
    let mut live = journal.live()?;

    let mut subscriptions = Vec::new();
    for unit in &args.units {
        let mut filter = live.filter();
        filter.match_unit(unit);
        let subscription = live.subscribe(filter)?;
        subscriptions.push((unit.clone(), subscription));
    }

    let engine = thread::spawn(move || {
        if let Err(err) = live.run() {
            eprintln!("live engine stopped: {err}");
        }
    });

    let workers: Vec<_> = subscriptions
        .into_iter()
        .map(|(unit, subscription)| spawn_subscription_worker(unit, subscription, args.count))
        .collect();

    for worker in workers {
        worker
            .join()
            .map_err(|_| IoError::other("subscription worker panicked"))??;
    }

    engine
        .join()
        .map_err(|_| IoError::other("live engine thread panicked"))?;

    Ok(())
}

fn parse_args() -> Result<Args, Box<dyn Error + Send + Sync>> {
    let mut units = Vec::new();
    let mut count = 5usize;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--count" {
            let value = args
                .next()
                .ok_or_else(|| usage("`--count` requires a value"))?;
            count = value.parse()?;
            continue;
        }

        units.push(arg);
    }

    if units.is_empty() {
        units.push("sshd.service".to_string());
        units.push("docker.service".to_string());
    }

    Ok(Args { units, count })
}

fn usage(message: &str) -> IoError {
    IoError::new(
        ErrorKind::InvalidInput,
        format!(
            "{message}; usage: cargo run --example live_multi_subscriptions -- [--count N] [unit ...]"
        ),
    )
}

fn spawn_subscription_worker(
    unit: String,
    subscription: sdjournal::LiveSubscription,
    count: usize,
) -> thread::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> {
    thread::spawn(move || {
        for _ in 0..count {
            let Some(entry) = recv_live_entry(&unit, &subscription)? else {
                break;
            };
            print_live_entry(&unit, &entry)?;
        }
        Ok(())
    })
}

fn recv_live_entry(
    unit: &str,
    subscription: &sdjournal::LiveSubscription,
) -> Result<Option<sdjournal::EntryOwned>, Box<dyn Error + Send + Sync>> {
    match subscription.recv_timeout(Duration::from_secs(30)) {
        Ok(item) => Ok(Some(item?)),
        Err(RecvTimeoutError::Timeout) => {
            eprintln!("[{unit}] timed out waiting for a new entry");
            Ok(None)
        }
        Err(RecvTimeoutError::Disconnected) => Err(Box::new(IoError::new(
            ErrorKind::UnexpectedEof,
            format!("[{unit}] subscription closed"),
        ))),
    }
}

fn print_live_entry(
    unit: &str,
    entry: &sdjournal::EntryOwned,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let msg = entry
        .get("MESSAGE")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<no MESSAGE>".to_string());
    println!(
        "[{unit}] cursor={} realtime={} message={}",
        entry.cursor()?,
        entry.realtime_usec(),
        msg
    );
    Ok(())
}
