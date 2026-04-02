use super::Follow;
use crate::entry::EntryOwned;
use crate::error::Result;
use std::thread;

const DEFAULT_TOKIO_FOLLOW_BUFFER: usize = 1024;

/// An async follow adapter for Tokio.
///
/// This is available when the `tokio` feature is enabled.
///
/// Internally it spawns a blocking worker thread that drives [`Follow`] and forwards owned entries
/// through a bounded Tokio channel.
pub struct TokioFollow {
    rx: tokio::sync::mpsc::Receiver<Result<EntryOwned>>,
}

impl TokioFollow {
    pub(crate) fn spawn(follow: Follow) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(DEFAULT_TOKIO_FOLLOW_BUFFER);
        thread::spawn(move || {
            let mut f = follow;
            loop {
                let item = match f.next() {
                    Some(v) => v,
                    None => break,
                };

                let owned = match item {
                    Ok(e) => Ok(e.to_owned()),
                    Err(e) => Err(e),
                };

                if tx.blocking_send(owned).is_err() {
                    break;
                }
            }
        });
        Self { rx }
    }

    /// Receive the next followed entry.
    ///
    /// Returns `None` once the background worker exits and the channel is closed.
    pub async fn next(&mut self) -> Option<Result<EntryOwned>> {
        self.rx.recv().await
    }

    /// Convert into the underlying Tokio receiver.
    ///
    /// This is useful when the caller wants to integrate follow output with `tokio::select!` or a
    /// custom receive loop.
    pub fn into_receiver(self) -> tokio::sync::mpsc::Receiver<Result<EntryOwned>> {
        self.rx
    }
}
