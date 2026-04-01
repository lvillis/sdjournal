use super::Follow;
use crate::entry::EntryOwned;
use crate::error::Result;
use std::thread;

const DEFAULT_TOKIO_FOLLOW_BUFFER: usize = 1024;

/// An async follow adapter for Tokio.
///
/// This is available when the `tokio` feature is enabled.
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
    pub async fn next(&mut self) -> Option<Result<EntryOwned>> {
        self.rx.recv().await
    }

    /// Convert into the underlying Tokio receiver.
    pub fn into_receiver(self) -> tokio::sync::mpsc::Receiver<Result<EntryOwned>> {
        self.rx
    }
}
