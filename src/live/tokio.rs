use super::LiveSubscription;
use crate::entry::LiveEntry;
use crate::error::Result;
use std::thread;

const DEFAULT_TOKIO_SUBSCRIPTION_BUFFER: usize = 1024;

/// Tokio adapter for [`LiveSubscription`].
///
/// Internally this spawns a blocking worker thread that drains the subscription receiver and
/// forwards shared live entries through a bounded Tokio channel.
pub struct TokioSubscription {
    rx: tokio::sync::mpsc::Receiver<Result<LiveEntry>>,
}

impl TokioSubscription {
    pub(crate) fn spawn(subscription: LiveSubscription) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(DEFAULT_TOKIO_SUBSCRIPTION_BUFFER);
        thread::spawn(move || {
            while let Ok(item) = subscription.recv() {
                if tx.blocking_send(item).is_err() {
                    break;
                }
            }
        });
        Self { rx }
    }

    /// Receive the next entry from the Tokio adapter.
    pub async fn next(&mut self) -> Option<Result<LiveEntry>> {
        self.rx.recv().await
    }

    /// Convert into the underlying Tokio receiver.
    pub fn into_receiver(self) -> tokio::sync::mpsc::Receiver<Result<LiveEntry>> {
        self.rx
    }
}

impl LiveSubscription {
    /// Convert this blocking subscription into a Tokio adapter.
    pub fn into_tokio(self) -> TokioSubscription {
        TokioSubscription::spawn(self)
    }
}
