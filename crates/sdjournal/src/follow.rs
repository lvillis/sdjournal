use crate::cursor::Cursor;
use crate::entry::EntryOwned;
use crate::entry::EntryRef;
use crate::error::{Result, SdJournalError};
use crate::journal::Journal;
use crate::query::JournalQuery;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[cfg(feature = "tracing")]
use tracing::warn;

#[cfg(all(feature = "tracing", target_os = "linux"))]
use tracing::debug;

#[cfg(feature = "tokio")]
const DEFAULT_TOKIO_FOLLOW_BUFFER: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FollowStage {
    CatchUp,
    Stream,
}

#[cfg(target_os = "linux")]
struct InotifyWatcher {
    inotify: inotify::Inotify,
    buffer: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl InotifyWatcher {
    fn new(watch_paths: &[PathBuf]) -> Option<Self> {
        use inotify::WatchMask;

        let mut inotify = match inotify::Inotify::init() {
            Ok(v) => v,
            Err(_) => return None,
        };

        let mask = WatchMask::MODIFY
            | WatchMask::CLOSE_WRITE
            | WatchMask::ATTRIB
            | WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO
            | WatchMask::MOVE_SELF
            | WatchMask::DELETE_SELF;

        let mut added = 0usize;
        for p in watch_paths {
            if inotify.watches().add(p, mask).is_ok() {
                added = added.saturating_add(1);
            }
        }
        if added == 0 {
            return None;
        }

        Some(Self {
            inotify,
            buffer: vec![0u8; 4096],
        })
    }

    fn wait(&mut self, timeout: Duration) -> bool {
        use std::os::unix::io::AsRawFd as _;

        let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let fd = self.inotify.as_raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        loop {
            let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if r > 0 {
                let _ = self.inotify.read_events(&mut self.buffer);
                return true;
            }
            if r == 0 {
                return false;
            }

            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
    }
}

/// A blocking follow/tail iterator.
///
/// Semantics are specified in `docs/prd.md`.
pub struct Follow {
    roots: Vec<PathBuf>,
    config: crate::config::JournalConfig,
    template: JournalQuery,

    stage: FollowStage,
    catchup_iter: Option<Box<dyn Iterator<Item = Result<EntryRef>> + Send>>,
    stream_iter: Option<Box<dyn Iterator<Item = Result<EntryRef>> + Send>>,
    last_cursor: Option<Cursor>,

    backoff: Duration,

    #[cfg(target_os = "linux")]
    inotify: Option<InotifyWatcher>,
}

/// An async follow adapter for Tokio.
///
/// This is available when the `tokio` feature is enabled.
#[cfg(feature = "tokio")]
pub struct TokioFollow {
    rx: tokio::sync::mpsc::Receiver<Result<EntryOwned>>,
}

#[cfg(feature = "tokio")]
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

impl Follow {
    pub(crate) fn new(
        roots: Vec<PathBuf>,
        config: crate::config::JournalConfig,
        template: JournalQuery,
        catchup_iter: Box<dyn Iterator<Item = Result<EntryRef>> + Send>,
        last_cursor: Option<Cursor>,
    ) -> Self {
        Self {
            roots,
            config: config.clone(),
            template,
            stage: FollowStage::CatchUp,
            catchup_iter: Some(catchup_iter),
            stream_iter: None,
            last_cursor,
            backoff: config.poll_interval,
            #[cfg(target_os = "linux")]
            inotify: None,
        }
    }

    fn reset_backoff(&mut self) {
        self.backoff = self.config.poll_interval;
    }

    fn wait_poll(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(w) = self.inotify.as_mut() {
            let _ = w.wait(self.config.poll_interval);
            return;
        }

        thread::sleep(self.config.poll_interval);
    }

    fn sleep_backoff(&mut self) {
        let max = self.config.max_follow_backoff;
        self.backoff = std::cmp::min(self.backoff.saturating_mul(2), max);
        thread::sleep(self.backoff);
    }

    fn update_last_cursor(&mut self, entry: &EntryRef) -> Result<()> {
        let c = entry.cursor()?;
        self.last_cursor = Some(c);
        Ok(())
    }

    fn refresh_stream_iter(&mut self) -> Result<()> {
        let journal = Journal::open_dirs_with_config(&self.roots, self.config.clone())?;

        #[cfg(target_os = "linux")]
        {
            let mut watch_paths: Vec<PathBuf> = Vec::new();
            watch_paths.extend(self.roots.iter().cloned());
            for f in &journal.inner.files {
                watch_paths.push(f.path().to_path_buf());
                if let Some(parent) = f.path().parent() {
                    watch_paths.push(parent.to_path_buf());
                }
            }
            watch_paths.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
            watch_paths.dedup();

            self.inotify = InotifyWatcher::new(&watch_paths);
            #[cfg(feature = "tracing")]
            debug!(
                inotify = self.inotify.is_some(),
                n_watch_paths = watch_paths.len(),
                "follow watcher refreshed"
            );
        }

        let mut q = self.template.with_journal(journal);
        if let Some(c) = &self.last_cursor {
            q.set_cursor_start(c.clone(), false)?;
        }
        let it = q.iter()?;
        self.stream_iter = Some(Box::new(it));
        Ok(())
    }
}

impl Iterator for Follow {
    type Item = Result<EntryRef>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.stage {
                FollowStage::CatchUp => {
                    let it = match self.catchup_iter.as_mut() {
                        Some(it) => it,
                        None => {
                            self.stage = FollowStage::Stream;
                            continue;
                        }
                    };

                    match it.next() {
                        Some(Ok(entry)) => {
                            if let Err(e) = self.update_last_cursor(&entry) {
                                return Some(Err(e));
                            }
                            self.reset_backoff();
                            return Some(Ok(entry));
                        }
                        Some(Err(e)) => return Some(Err(e)),
                        None => {
                            self.catchup_iter = None;
                            self.stage = FollowStage::Stream;
                            continue;
                        }
                    }
                }
                FollowStage::Stream => {
                    if self.stream_iter.is_none()
                        && let Err(e) = self.refresh_stream_iter()
                    {
                        if matches!(
                            e,
                            SdJournalError::NotFound | SdJournalError::Transient { .. }
                        ) {
                            #[cfg(feature = "tracing")]
                            warn!(error = %e, "follow refresh failed, retrying with backoff");
                            self.sleep_backoff();
                            continue;
                        }
                        return Some(Err(e));
                    }

                    let it = match self.stream_iter.as_mut() {
                        Some(it) => it,
                        None => {
                            self.wait_poll();
                            continue;
                        }
                    };

                    match it.next() {
                        Some(Ok(entry)) => {
                            if let Err(e) = self.update_last_cursor(&entry) {
                                return Some(Err(e));
                            }
                            self.reset_backoff();
                            return Some(Ok(entry));
                        }
                        Some(Err(e)) => {
                            self.stream_iter = None;
                            if matches!(e, SdJournalError::Transient { .. }) {
                                self.sleep_backoff();
                                continue;
                            }
                            return Some(Err(e));
                        }
                        None => {
                            self.stream_iter = None;
                            self.wait_poll();
                            continue;
                        }
                    }
                }
            }
        }
    }
}
