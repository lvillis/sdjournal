#[cfg(feature = "tokio")]
mod tokio;
#[cfg(target_os = "linux")]
mod watcher;

use crate::cursor::Cursor;
use crate::entry::EntryRef;
use crate::error::{Result, SdJournalError};
use crate::journal::Journal;
use crate::query::JournalQuery;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[cfg(feature = "tokio")]
pub use self::tokio::TokioFollow;
#[cfg(target_os = "linux")]
use self::watcher::InotifyWatcher;

#[cfg(all(feature = "tracing", target_os = "linux"))]
use tracing::debug;
#[cfg(feature = "tracing")]
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FollowStage {
    CatchUp,
    Stream,
}

/// A blocking follow/tail iterator.
///
/// The iterator first drains matching backlog entries, then reopens the journal set and polls
/// for new entries while preserving the query template and last observed cursor.
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
        self.stream_iter = Some(Box::new(q.iter()?));
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
