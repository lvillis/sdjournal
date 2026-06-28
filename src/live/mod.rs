mod filter;
mod replay;
mod tail;
#[cfg(feature = "tokio")]
mod tokio;
#[cfg(target_os = "linux")]
mod watcher;

use crate::config::{JournalConfig, LiveQueueFullPolicy};
use crate::cursor::{Cursor, SdJournalEntryKey};
use crate::entry::{EntryRef, LiveEntry};
use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::JournalFile;
use crate::journal::{Journal, discover_journal_candidates};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering as AtomicOrdering},
};
use std::thread;
use std::time::Duration;

use self::filter::CompiledFilter;
pub use self::filter::{LiveFilter, LiveOrGroupBuilder};
use self::replay::{
    JournalSnapshot, PendingTopologyCatchup, ReplayState, collect_entries_after_key,
    collect_replay_batch,
};
#[cfg(target_os = "linux")]
use self::tail::collect_watch_paths;
use self::tail::{
    FallbackDirState, TrackedFile, build_live_snapshot, build_tracked_files_from_open_files,
    build_tracked_files_from_paths, collect_fallback_dirs,
};
#[cfg(feature = "tokio")]
pub use self::tokio::TokioSubscription;
#[cfg(target_os = "linux")]
use self::watcher::InotifyWatcher;

#[cfg(all(feature = "tracing", target_os = "linux"))]
use tracing::debug;
#[cfg(feature = "tracing")]
use tracing::warn;

struct SubscriptionState {
    filter: CompiledFilter,
    tx: SyncSender<Result<LiveEntry>>,
    start_after: Option<SdJournalEntryKey>,
    alive: Arc<AtomicBool>,
    replay: Option<ReplayState>,
}

pub(super) struct WatchChange {
    pub(super) topology_changed: bool,
    pub(super) modified_paths: Vec<PathBuf>,
}

impl WatchChange {
    fn is_empty(&self) -> bool {
        !self.topology_changed && self.modified_paths.is_empty()
    }
}

enum SendOutcome {
    Delivered,
    Dropped,
    Closed,
}

/// Shared live journal engine for multi-subscription tailing.
///
/// `LiveJournal` keeps one watcher plus lightweight per-file tail checkpoints. Ordinary appends
/// open only the modified journal file, read newly appended entries, update the checkpoint, and
/// dispatch each entry once to all matching subscriptions. Full directory rescans are reserved for
/// topology changes such as file creation, removal, or rotation.
///
/// Live delivery is bounded per cycle by [`JournalConfig::live_channel_capacity`] and
/// [`JournalConfig::max_live_batch_entries`]. Historical replay can also have a configured total
/// cap through [`JournalConfig::max_live_replay_entries`].
/// The default queue-full behavior is [`LiveQueueFullPolicy::Block`], which applies backpressure
/// instead of silently dropping entries.
///
/// Corrupt or transiently unreadable files are skipped when at least one healthy file remains;
/// enable the `tracing` feature to observe skipped-file diagnostics.
///
/// Create it through [`Journal::live`](crate::Journal::live), register one or more
/// [`LiveSubscription`]s, then drive the engine with [`LiveJournal::poll_once`] or
/// [`LiveJournal::run`].
///
/// # Model
///
/// Subscriptions are passive receivers. The engine only observes new journal data while
/// [`LiveJournal::poll_once`] or [`LiveJournal::run`] is being called. A subscription created with
/// [`LiveJournal::subscribe`] is live-only: it starts after the engine's current tail checkpoint
/// and does not replay existing entries. Use [`SubscriptionOptions`] when a replay window is
/// needed.
///
/// # Example
///
/// ```no_run
/// use sdjournal::LiveJournal;
/// use std::thread;
///
/// let mut live = LiveJournal::open_default()?;
///
/// let mut sshd_filter = live.filter();
/// sshd_filter.match_unit("sshd.service");
/// let sshd = live.subscribe(sshd_filter)?;
///
/// let mut systemd_filter = live.filter();
/// systemd_filter.match_unit("systemd.service");
/// let systemd = live.subscribe(systemd_filter)?;
///
/// let engine = thread::spawn(move || live.run());
///
/// let _entry = sshd.recv().expect("engine stopped")?;
/// let _entry = systemd.recv().expect("engine stopped")?;
///
/// drop(sshd);
/// drop(systemd);
/// engine.join().expect("live engine thread panicked")?;
/// # Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
/// ```
pub struct LiveJournal {
    roots: Vec<PathBuf>,
    config: JournalConfig,
    tracked_files: Vec<TrackedFile>,
    path_index: HashMap<PathBuf, usize>,
    fallback_dirs: Vec<FallbackDirState>,
    subscriptions: Vec<SubscriptionState>,
    last_seen: Option<SdJournalEntryKey>,
    pending_modified_paths: Vec<PathBuf>,
    pending_topology: Option<PendingTopologyCatchup>,
    next_replay_index: usize,
    #[cfg(target_os = "linux")]
    inotify: Option<InotifyWatcher>,
    #[cfg(target_os = "linux")]
    watch_paths: Vec<PathBuf>,
}

impl LiveJournal {
    pub(crate) fn from_journal(journal: Journal) -> Result<Self> {
        let roots = journal.inner.roots.clone();
        let config = journal.inner.config.clone();
        validate_live_config(&config)?;
        let tracked = match journal.inner.opened_files() {
            Some(files) => build_tracked_files_from_open_files(&files)?,
            None => {
                let paths = journal.inner.file_paths();
                build_tracked_files_from_paths(&paths, &config)?
            }
        };

        let mut out = Self {
            roots,
            config,
            tracked_files: tracked.files,
            path_index: tracked.path_index,
            fallback_dirs: Vec::new(),
            subscriptions: Vec::new(),
            last_seen: tracked.last_seen,
            pending_modified_paths: Vec::new(),
            pending_topology: None,
            next_replay_index: 0,
            #[cfg(target_os = "linux")]
            inotify: None,
            #[cfg(target_os = "linux")]
            watch_paths: Vec::new(),
        };
        out.refresh_fallback_dirs();
        out.refresh_watchers();
        Ok(out)
    }

    /// Create a live engine from the default system journal roots on Linux.
    ///
    /// This avoids opening a historical [`Journal`] first. Prefer this constructor when the
    /// application only needs live tailing.
    ///
    /// On non-Linux targets this returns [`SdJournalError::Unsupported`].
    pub fn open_default() -> Result<Self> {
        Self::open_default_with_config(JournalConfig::default())
    }

    /// Create a live engine from the default system journal roots with a custom configuration.
    ///
    /// See [`LiveJournal::open_default`] for platform behavior.
    pub fn open_default_with_config(config: JournalConfig) -> Result<Self> {
        core::cfg_select! {
            target_os = "linux" => {
                let paths = vec![
                    PathBuf::from("/run/log/journal"),
                    PathBuf::from("/var/log/journal"),
                ];
                Self::open_dirs_with_config(&paths, config)
            }
            _ => {
                let _ = config;
                Err(SdJournalError::Unsupported {
                    reason: "LiveJournal::open_default is only supported on Linux".to_string(),
                })
            }
        }
    }

    /// Create a live engine from journal files discovered under one root directory.
    ///
    /// This is the live-tail counterpart to [`Journal::open_dir`].
    pub fn open_dir(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_dir_with_config(path, JournalConfig::default())
    }

    /// Create a live engine from one root directory with a custom configuration.
    pub fn open_dir_with_config(path: impl AsRef<Path>, config: JournalConfig) -> Result<Self> {
        let paths = vec![path.as_ref().to_path_buf()];
        Self::open_dirs_with_config(&paths, config)
    }

    /// Create a live engine from journal files discovered under multiple root directories.
    ///
    /// Unlike [`Journal::open_dirs`], this opens files one at a time during initialization and
    /// stores only lightweight tail checkpoints afterward. Journal files are opened briefly when
    /// refreshing topology or reading appended entries.
    pub fn open_dirs(paths: &[PathBuf]) -> Result<Self> {
        Self::open_dirs_with_config(paths, JournalConfig::default())
    }

    /// Create a live engine from multiple root directories with a custom configuration.
    pub fn open_dirs_with_config(paths: &[PathBuf], config: JournalConfig) -> Result<Self> {
        validate_live_config(&config)?;
        let discovery = discover_journal_candidates(paths, &config)?;
        let tracked = build_tracked_files_from_paths(&discovery.candidates, &config)?;

        let mut out = Self {
            roots: discovery.roots,
            config,
            tracked_files: tracked.files,
            path_index: tracked.path_index,
            fallback_dirs: Vec::new(),
            subscriptions: Vec::new(),
            last_seen: tracked.last_seen,
            pending_modified_paths: Vec::new(),
            pending_topology: None,
            next_replay_index: 0,
            #[cfg(target_os = "linux")]
            inotify: None,
            #[cfg(target_os = "linux")]
            watch_paths: Vec::new(),
        };
        out.refresh_fallback_dirs();
        out.refresh_watchers();
        Ok(out)
    }

    /// Create a new live filter builder using this engine's runtime limits.
    ///
    /// Build one filter per subscription. Filters are cheap and do not start watching the journal
    /// until they are registered with [`LiveJournal::subscribe`] or
    /// [`LiveJournal::subscribe_with_options`].
    pub fn filter(&self) -> LiveFilter {
        LiveFilter::new(self.config.clone())
    }

    /// Register a live-only subscription.
    ///
    /// The returned subscription only receives entries after the engine's current tail checkpoint.
    /// It does not scan historical entries. This is the preferred path for normal tailing because
    /// registering the subscription does not rebuild query state.
    pub fn subscribe(&mut self, filter: LiveFilter) -> Result<LiveSubscription> {
        self.subscribe_with_options(SubscriptionOptions::new(filter))
    }

    /// Register a subscription with explicit replay or resume bounds.
    ///
    /// Matching backlog covered by `options` is replayed by subsequent
    /// [`LiveJournal::poll_once`] or [`LiveJournal::run`] calls before future live entries are
    /// dispatched to that subscription.
    /// Replay work is bounded by [`JournalConfig::max_live_batch_entries`] per engine cycle.
    /// [`JournalConfig::max_live_replay_entries`] can add an optional per-subscription total cap.
    ///
    /// This opens an isolated snapshot to establish the replay boundary. Prefer
    /// [`LiveJournal::subscribe`] when only future entries are needed.
    pub fn subscribe_with_options(
        &mut self,
        options: SubscriptionOptions,
    ) -> Result<LiveSubscription> {
        let compiled = options.filter.compile()?;
        let (tx, rx) = mpsc::sync_channel(self.config.live_channel_capacity);
        let alive = Arc::new(AtomicBool::new(true));
        let needs_replay = options.after_cursor.is_some() || options.since_realtime.is_some();

        let (start_after, replay) = if needs_replay {
            let snapshot = self.open_replay_snapshot()?;
            let start_after = snapshot.last_seen;
            let replay = ReplayState::new(
                snapshot,
                options.after_cursor,
                options.since_realtime,
                &self.config,
            );
            (start_after, Some(replay))
        } else {
            (self.last_seen, None)
        };

        self.subscriptions.push(SubscriptionState {
            filter: compiled,
            tx,
            start_after,
            alive: alive.clone(),
            replay,
        });

        Ok(LiveSubscription { rx, alive })
    }

    /// Poll for live changes once and dispatch any newly appended entries.
    ///
    /// Returns the total number of subscription deliveries performed during this cycle.
    /// This may be larger than the number of journal entries because one entry can match multiple
    /// subscriptions.
    ///
    /// The call blocks for at most [`JournalConfig::poll_interval`] when no platform watcher is
    /// available. On Linux it uses inotify when possible and falls back to polling.
    pub fn poll_once(&mut self) -> Result<usize> {
        self.remove_closed_subscriptions();
        if self.subscriptions.is_empty() {
            return Ok(0);
        }

        if let Some(deliveries) = self.dispatch_ready_live_work()?
            && deliveries != 0
        {
            self.remove_closed_subscriptions();
            return Ok(deliveries);
        }

        if let Some(deliveries) = self.dispatch_next_replay_batch()? {
            self.remove_closed_subscriptions();
            return Ok(deliveries);
        }

        let change = self.wait_for_change();
        self.dispatch_change(change)
    }

    fn dispatch_ready_live_work(&mut self) -> Result<Option<usize>> {
        if self.pending_topology.is_some() {
            return self.dispatch_pending_topology_batch().map(Some);
        }

        if !self.pending_modified_paths.is_empty() {
            let paths = std::mem::take(&mut self.pending_modified_paths);
            return self.dispatch_modified_paths(&paths).map(Some);
        }

        let change = self.try_collect_ready_change();
        if change.is_empty() {
            return Ok(None);
        }

        self.dispatch_change(change).map(Some)
    }

    fn dispatch_change(&mut self, change: WatchChange) -> Result<usize> {
        if change.is_empty() {
            self.remove_closed_subscriptions();
            return Ok(0);
        }

        if change.topology_changed {
            return self.refresh_topology_and_dispatch();
        }

        self.dispatch_modified_paths(&change.modified_paths)
    }

    /// Run the live engine until every subscription has been dropped.
    ///
    /// This is the simplest way to drive live delivery from a background thread. Dropping all
    /// [`LiveSubscription`] handles causes the loop to exit after the next polling cycle.
    pub fn run(mut self) -> Result<()> {
        while !self.subscriptions.is_empty() {
            self.poll_once()?;
        }
        Ok(())
    }

    fn wait_for_change(&mut self) -> WatchChange {
        core::cfg_select! {
            target_os = "linux" => {
                if let Some(w) = self.inotify.as_mut() {
                    w.wait(self.config.poll_interval)
                } else {
                    self.poll_all_files_after_sleep()
                }
            }
            _ => {
                self.poll_all_files_after_sleep()
            }
        }
    }

    fn try_collect_ready_change(&mut self) -> WatchChange {
        core::cfg_select! {
            target_os = "linux" => {
                if let Some(w) = self.inotify.as_mut() {
                    w.wait(Duration::ZERO)
                } else {
                    self.scan_all_files()
                }
            }
            _ => {
                self.scan_all_files()
            }
        }
    }

    fn poll_all_files_after_sleep(&mut self) -> WatchChange {
        thread::sleep(self.config.poll_interval);
        self.scan_all_files()
    }

    fn scan_all_files(&mut self) -> WatchChange {
        let mut topology_changed = false;
        for dir in &self.fallback_dirs {
            match std::fs::metadata(&dir.path).and_then(|meta| meta.modified()) {
                Ok(modified) if Some(modified) != dir.modified => {
                    topology_changed = true;
                    break;
                }
                Err(_) => {
                    topology_changed = true;
                    break;
                }
                _ => {}
            }
        }

        let mut modified_paths = Vec::new();
        for tracked in &self.tracked_files {
            match std::fs::metadata(&tracked.path) {
                Ok(meta) => {
                    let len = meta.len();
                    let known = tracked.live_state.used_size;
                    if len < known {
                        topology_changed = true;
                        break;
                    }
                    if len > known {
                        modified_paths.push(tracked.path.clone());
                    }
                }
                Err(_) => {
                    topology_changed = true;
                    break;
                }
            }
        }

        WatchChange {
            topology_changed,
            modified_paths,
        }
    }

    fn open_replay_snapshot(&self) -> Result<JournalSnapshot> {
        let discovery = discover_journal_candidates(&self.roots, &self.config)?;
        let snapshot = build_live_snapshot(&discovery.candidates, &self.config)?;
        Ok(JournalSnapshot {
            journal: snapshot.journal,
            last_seen: snapshot.tracked.last_seen,
        })
    }

    fn dispatch_next_replay_batch(&mut self) -> Result<Option<usize>> {
        let Some(idx) = self.next_replay_subscription_index() else {
            return Ok(None);
        };
        self.next_replay_index = idx.saturating_add(1);

        let Some(replay) = self.subscriptions[idx].replay.as_ref() else {
            return Ok(None);
        };
        if matches!(replay.remaining, Some(0)) {
            let limit = self.config.max_live_replay_entries.unwrap_or(0);
            return Err(SdJournalError::LimitExceeded {
                kind: LimitKind::LiveReplayEntries,
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
            });
        }

        let limit = replay
            .remaining
            .map_or(self.config.max_live_batch_entries, |remaining| {
                self.config.max_live_batch_entries.min(remaining)
            });
        let batch = collect_replay_batch(replay, &self.subscriptions[idx].filter, limit)?;
        let consumed = batch.entries.len();
        let batch_last_key = batch.last_key;
        let batch_exhausted = batch.exhausted;

        let mut delivered = 0usize;
        let mut closed = false;
        let sub = &mut self.subscriptions[idx];
        for entry in batch.entries {
            match send_live_item(
                &sub.tx,
                Ok(LiveEntry::new(entry)),
                self.config.live_queue_full_policy,
            ) {
                SendOutcome::Delivered => delivered = delivered.saturating_add(1),
                SendOutcome::Dropped => {}
                SendOutcome::Closed => {
                    closed = true;
                    break;
                }
            }
        }

        if closed {
            self.subscriptions[idx]
                .alive
                .store(false, AtomicOrdering::Release);
            return Ok(Some(delivered));
        }

        let replay_upper = self.subscriptions[idx]
            .replay
            .as_ref()
            .and_then(|replay| replay.upper_key);
        let catchup_upper = if batch_exhausted {
            match (replay_upper, self.last_seen) {
                (Some(old_upper), Some(live_upper))
                    if compare_keys(&live_upper, &old_upper) == Ordering::Greater =>
                {
                    Some((old_upper, live_upper))
                }
                _ => None,
            }
        } else {
            None
        };
        let catchup_journal = if catchup_upper.is_some() {
            Some(self.open_replay_snapshot()?.journal)
        } else {
            None
        };

        let sub = &mut self.subscriptions[idx];
        if let Some(replay) = sub.replay.as_mut() {
            replay.cursor = None;
            replay.last_key = batch_last_key.or(replay.last_key);
            if let Some(remaining) = replay.remaining.as_mut() {
                *remaining = remaining.saturating_sub(consumed);
            }
        }
        if batch_exhausted {
            sub.replay = match (catchup_journal, catchup_upper) {
                (Some(journal), Some((after_key, upper_key))) => Some(ReplayState::catch_up(
                    journal,
                    after_key,
                    upper_key,
                    &self.config,
                )),
                _ => None,
            };
        }

        Ok(Some(delivered))
    }

    fn next_replay_subscription_index(&self) -> Option<usize> {
        if self.subscriptions.is_empty() {
            return None;
        }

        let start = self.next_replay_index.min(self.subscriptions.len());
        self.subscriptions[start..]
            .iter()
            .position(|sub| sub.replay.is_some())
            .map(|offset| start + offset)
            .or_else(|| {
                self.subscriptions[..start]
                    .iter()
                    .position(|sub| sub.replay.is_some())
            })
    }

    fn refresh_topology_and_dispatch(&mut self) -> Result<usize> {
        let previous_last_seen = self.last_seen;
        let discovery = discover_journal_candidates(&self.roots, &self.config)?;
        let snapshot = build_live_snapshot(&discovery.candidates, &self.config)?;
        let last_seen = snapshot.tracked.last_seen;
        let batch = collect_entries_after_key(
            &snapshot.journal,
            previous_last_seen,
            last_seen,
            self.config.max_live_batch_entries,
        )?;

        self.tracked_files = snapshot.tracked.files;
        self.path_index = snapshot.tracked.path_index;
        self.advance_last_seen(last_seen);
        self.refresh_fallback_dirs();
        self.refresh_watchers();
        self.pending_topology = if batch.exhausted {
            None
        } else {
            Some(PendingTopologyCatchup {
                journal: snapshot.journal,
                last_key: Some(
                    batch
                        .last_key
                        .expect("non-exhausted topology batch has an entry"),
                ),
                upper_key: last_seen,
            })
        };

        Ok(self.dispatch_entries(batch.entries, true))
    }

    fn dispatch_pending_topology_batch(&mut self) -> Result<usize> {
        let mut catchup = self
            .pending_topology
            .take()
            .expect("pending topology catch-up state is available");
        let batch = collect_entries_after_key(
            &catchup.journal,
            catchup.last_key,
            catchup.upper_key,
            self.config.max_live_batch_entries,
        )?;
        if !batch.exhausted {
            catchup.last_key = Some(
                batch
                    .last_key
                    .expect("non-exhausted topology batch has an entry"),
            );
            self.pending_topology = Some(catchup);
        }
        Ok(self.dispatch_entries(batch.entries, true))
    }

    fn dispatch_modified_paths(&mut self, paths: &[PathBuf]) -> Result<usize> {
        let mut pending = Vec::new();
        let mut active_files = 0usize;

        for (pos, path) in paths.iter().enumerate() {
            let Some(&idx) = self.path_index.get(path) else {
                if is_candidate_journal_path(path) {
                    return self.refresh_topology_and_dispatch();
                }
                continue;
            };

            let Some(mut entries) = self.refresh_tracked_file(idx)? else {
                return self.refresh_topology_and_dispatch();
            };
            if !entries.is_empty() {
                active_files = active_files.saturating_add(1);
            }
            pending.append(&mut entries);
            if pending.len() >= self.config.max_live_batch_entries {
                self.pending_modified_paths
                    .extend_from_slice(&paths[pos + 1..]);
                break;
            }
        }

        Ok(self.dispatch_entries(pending, active_files <= 1))
    }

    fn refresh_tracked_file(&mut self, idx: usize) -> Result<Option<Vec<EntryRef>>> {
        let old_state = self.tracked_files[idx].live_state;
        let reopened = match JournalFile::open(self.tracked_files[idx].path.clone(), &self.config) {
            Ok(file) => file,
            Err(SdJournalError::Transient { .. }) | Err(SdJournalError::Corrupt { .. }) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        let tracked = &mut self.tracked_files[idx];
        if reopened.file_id() != tracked.file_id {
            return Ok(None);
        }

        let new_state = reopened.live_state();
        if new_state.used_size < old_state.used_size || new_state.n_entries < old_state.n_entries {
            return Ok(None);
        }
        if new_state == old_state {
            tracked.live_state = new_state;
            return Ok(Some(Vec::new()));
        }

        let batch = match tracked
            .tail
            .drain_new_offsets(&reopened, self.config.max_live_batch_entries)
        {
            Ok(batch) => batch,
            Err(SdJournalError::Transient { .. }) | Err(SdJournalError::Corrupt { .. }) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        let mut entries = Vec::with_capacity(batch.offsets.len());
        for offset in batch.offsets {
            match reopened.read_entry_ref(offset) {
                Ok(entry) => entries.push(entry),
                Err(err) if is_skippable_live_file_error(&err) => {
                    warn_live_file_error("skipping corrupt live entry", &err);
                    return Ok(None);
                }
                Err(err) => return Err(err),
            }
        }
        if batch.exhausted {
            tracked.live_state = new_state;
        } else {
            self.pending_modified_paths.push(tracked.path.clone());
        }
        Ok(Some(entries))
    }

    fn dispatch_entries(&mut self, mut pending: Vec<EntryRef>, already_sorted: bool) -> usize {
        if pending.is_empty() {
            self.remove_closed_subscriptions();
            return 0;
        }

        if !already_sorted && pending.len() > 1 {
            pending.sort_by(|left, right| {
                compare_keys(&key_from_entry_ref(left), &key_from_entry_ref(right))
            });
        }

        let mut deliveries = 0usize;
        let mut dead = vec![false; self.subscriptions.len()];
        let mut matched = Vec::with_capacity(self.subscriptions.len());

        for owned in pending {
            let key = key_from_entry_ref(&owned);
            matched.clear();

            for (idx, sub) in self.subscriptions.iter_mut().enumerate() {
                if sub.replay.is_some() {
                    continue;
                }

                if let Some(start_after) = sub.start_after {
                    if compare_keys(&key, &start_after) != Ordering::Greater {
                        continue;
                    }
                    sub.start_after = None;
                }

                if sub.filter.matches(&owned) {
                    matched.push(idx);
                }
            }

            if !matched.is_empty() {
                let mut shared = Some(LiveEntry::new(owned));
                let last_idx = matched.len().saturating_sub(1);
                for (pos, idx) in matched.iter().copied().enumerate() {
                    let entry = if pos == last_idx {
                        shared.take().expect("shared live entry is available")
                    } else {
                        shared
                            .as_ref()
                            .expect("shared live entry is available")
                            .clone()
                    };
                    match send_live_item(
                        &self.subscriptions[idx].tx,
                        Ok(entry),
                        self.config.live_queue_full_policy,
                    ) {
                        SendOutcome::Delivered => deliveries = deliveries.saturating_add(1),
                        SendOutcome::Dropped => {}
                        SendOutcome::Closed => dead[idx] = true,
                    }
                }
            }

            self.advance_last_seen(Some(key));
        }

        if dead.iter().any(|dead| *dead) {
            let mut idx = 0usize;
            self.subscriptions.retain(|_| {
                let keep = !dead[idx];
                idx = idx.saturating_add(1);
                keep
            });
            self.next_replay_index = self.next_replay_index.min(self.subscriptions.len());
        }

        deliveries
    }

    fn refresh_watchers(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let watch_paths = collect_watch_paths(&self.roots, &self.tracked_files);
            if watch_paths != self.watch_paths {
                self.inotify = InotifyWatcher::new(&watch_paths);
                self.watch_paths = watch_paths;
                self.queue_tracked_paths_for_recheck();
                #[cfg(feature = "tracing")]
                debug!(
                    inotify = self.inotify.is_some(),
                    n_watch_paths = self.watch_paths.len(),
                    "live watcher refreshed"
                );
            }
        }
    }

    fn refresh_fallback_dirs(&mut self) {
        self.fallback_dirs = collect_fallback_dirs(&self.roots, &self.tracked_files);
    }

    fn queue_tracked_paths_for_recheck(&mut self) {
        self.pending_modified_paths.extend(
            self.tracked_files
                .iter()
                .map(|tracked| tracked.path.clone()),
        );
        self.pending_modified_paths.sort();
        self.pending_modified_paths.dedup();
    }

    fn remove_closed_subscriptions(&mut self) {
        self.subscriptions
            .retain(|sub| sub.alive.load(AtomicOrdering::Acquire));
        self.next_replay_index = self.next_replay_index.min(self.subscriptions.len());
    }

    fn advance_last_seen(&mut self, key: Option<SdJournalEntryKey>) {
        let Some(key) = key else {
            return;
        };
        if self
            .last_seen
            .as_ref()
            .is_none_or(|last| compare_keys(&key, last) == Ordering::Greater)
        {
            self.last_seen = Some(key);
        }
    }
}

/// Options for `LiveJournal` subscriptions.
///
/// Without additional bounds, subscriptions are live-only and start after the current tail.
/// Adding [`SubscriptionOptions::after_cursor`] or [`SubscriptionOptions::since_realtime`]
/// requests a replay before the subscription switches to live delivery.
#[derive(Clone)]
pub struct SubscriptionOptions {
    filter: LiveFilter,
    after_cursor: Option<Cursor>,
    since_realtime: Option<u64>,
}

impl SubscriptionOptions {
    /// Create subscription options from a live filter.
    pub fn new(filter: LiveFilter) -> Self {
        Self {
            filter,
            after_cursor: None,
            since_realtime: None,
        }
    }

    /// Replay matching entries strictly after `cursor` before switching to live delivery.
    ///
    /// This is intended for checkpoint-based consumers that persist [`crate::Cursor`] values.
    pub fn after_cursor(&mut self, cursor: Cursor) -> &mut Self {
        self.after_cursor = Some(cursor);
        self
    }

    /// Replay matching entries from `usec` before switching to live delivery.
    ///
    /// `usec` is a realtime timestamp in microseconds since the Unix epoch.
    pub fn since_realtime(&mut self, usec: u64) -> &mut Self {
        self.since_realtime = Some(usec);
        self
    }
}

/// Receiving end of a live subscription.
///
/// Values are delivered as shared [`LiveEntry`] handles so one decoded entry can be fanned out to
/// multiple subscribers without duplicating field storage.
/// Each subscription has a bounded queue controlled by [`JournalConfig::live_channel_capacity`].
///
/// Dropping a subscription unregisters it from the engine. When all subscriptions are dropped,
/// [`LiveJournal::run`] exits.
pub struct LiveSubscription {
    rx: Receiver<Result<LiveEntry>>,
    alive: Arc<AtomicBool>,
}

impl LiveSubscription {
    /// Receive the next entry, blocking until the subscription closes or a value arrives.
    ///
    /// The outer `Result` reports channel closure. The inner crate [`Result`] reports journal
    /// decoding or I/O errors produced by the live engine.
    pub fn recv(&self) -> std::result::Result<Result<LiveEntry>, mpsc::RecvError> {
        self.rx.recv()
    }

    /// Receive the next entry, waiting at most `timeout`.
    ///
    /// The outer `Result` distinguishes timeout or channel closure from a delivered value. The
    /// delivered value is still a crate [`Result`] because reading the journal can fail.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> std::result::Result<Result<LiveEntry>, mpsc::RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }

    /// Try to receive the next queued entry without blocking.
    ///
    /// This is useful when integrating [`LiveJournal::poll_once`] into an existing event loop.
    pub fn try_recv(&self) -> std::result::Result<Result<LiveEntry>, mpsc::TryRecvError> {
        self.rx.try_recv()
    }
}

impl Drop for LiveSubscription {
    fn drop(&mut self) {
        self.alive.store(false, AtomicOrdering::Release);
    }
}

fn validate_live_config(config: &JournalConfig) -> Result<()> {
    if config.max_open_files == 0 {
        return Err(SdJournalError::InvalidQuery {
            reason: "max_open_files must be greater than zero".to_string(),
        });
    }
    if config.live_channel_capacity == 0 {
        return Err(SdJournalError::InvalidQuery {
            reason: "live_channel_capacity must be greater than zero".to_string(),
        });
    }
    if config.max_live_batch_entries == 0 {
        return Err(SdJournalError::InvalidQuery {
            reason: "max_live_batch_entries must be greater than zero".to_string(),
        });
    }
    if config.max_live_replay_entries == Some(0) {
        return Err(SdJournalError::InvalidQuery {
            reason: "max_live_replay_entries must be greater than zero".to_string(),
        });
    }
    if config.live_queue_full_policy == LiveQueueFullPolicy::Block
        && config.max_live_batch_entries > config.live_channel_capacity
    {
        return Err(SdJournalError::InvalidQuery {
            reason: "max_live_batch_entries must not exceed live_channel_capacity when live_queue_full_policy is Block".to_string(),
        });
    }
    Ok(())
}

fn send_live_item(
    tx: &SyncSender<Result<LiveEntry>>,
    item: Result<LiveEntry>,
    policy: LiveQueueFullPolicy,
) -> SendOutcome {
    match policy {
        LiveQueueFullPolicy::Block => match tx.send(item) {
            Ok(()) => SendOutcome::Delivered,
            Err(_) => SendOutcome::Closed,
        },
        LiveQueueFullPolicy::DropNewest => match tx.try_send(item) {
            Ok(()) => SendOutcome::Delivered,
            Err(TrySendError::Full(_)) => SendOutcome::Dropped,
            Err(TrySendError::Disconnected(_)) => SendOutcome::Closed,
        },
        LiveQueueFullPolicy::Disconnect => match tx.try_send(item) {
            Ok(()) => SendOutcome::Delivered,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => SendOutcome::Closed,
        },
    }
}

fn is_skippable_live_file_error(err: &SdJournalError) -> bool {
    matches!(
        err,
        SdJournalError::Corrupt { .. }
            | SdJournalError::Transient { .. }
            | SdJournalError::Io { .. }
            | SdJournalError::LimitExceeded {
                kind: LimitKind::ObjectChainSteps,
                ..
            }
    )
}

fn warn_skipped_live_file(path: &std::path::Path, err: &SdJournalError) {
    #[cfg(feature = "tracing")]
    warn!(
        path = %path.display(),
        error = %err,
        "skipping journal file for live tailing"
    );

    let _ = (path, err);
}

fn warn_live_file_error(message: &'static str, err: &SdJournalError) {
    #[cfg(feature = "tracing")]
    warn!(error = %err, "{message}");

    let _ = (message, err);
}

fn is_candidate_journal_path(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("journal") | Some("journal~")
    )
}

fn key_from_entry_ref(entry: &EntryRef) -> SdJournalEntryKey {
    SdJournalEntryKey {
        file_id: entry.file_id_raw(),
        entry_offset: entry.entry_offset_raw(),
        seqnum: entry.seqnum(),
        realtime_usec: entry.realtime_usec(),
    }
}

fn cursor_from_key(key: SdJournalEntryKey) -> Cursor {
    Cursor::new_entry_key(key.file_id, key.entry_offset, key.seqnum, key.realtime_usec)
}

fn compare_keys(left: &SdJournalEntryKey, right: &SdJournalEntryKey) -> Ordering {
    left.realtime_usec
        .cmp(&right.realtime_usec)
        .then_with(|| left.seqnum.cmp(&right.seqnum))
        .then_with(|| left.file_id.cmp(&right.file_id))
        .then_with(|| left.entry_offset.cmp(&right.entry_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_keys_matches_historical_query_ordering() {
        let earlier = SdJournalEntryKey {
            file_id: [0x11; 16],
            entry_offset: 1,
            seqnum: 2,
            realtime_usec: 3,
        };
        let later = SdJournalEntryKey {
            file_id: [0x22; 16],
            entry_offset: 4,
            seqnum: 5,
            realtime_usec: 6,
        };

        assert_eq!(compare_keys(&earlier, &later), Ordering::Less);
        assert_eq!(compare_keys(&later, &earlier), Ordering::Greater);
        assert_eq!(compare_keys(&earlier, &earlier), Ordering::Equal);
    }

    #[test]
    fn validate_live_config_rejects_unbounded_or_blocking_unsafe_values() {
        let mut cfg = JournalConfig {
            live_channel_capacity: 0,
            ..Default::default()
        };
        assert!(matches!(
            validate_live_config(&cfg),
            Err(SdJournalError::InvalidQuery { .. })
        ));

        cfg = JournalConfig {
            max_open_files: 0,
            ..Default::default()
        };
        assert!(matches!(
            validate_live_config(&cfg),
            Err(SdJournalError::InvalidQuery { .. })
        ));

        cfg = JournalConfig {
            max_live_batch_entries: 0,
            ..Default::default()
        };
        assert!(matches!(
            validate_live_config(&cfg),
            Err(SdJournalError::InvalidQuery { .. })
        ));

        cfg = JournalConfig {
            max_live_replay_entries: Some(0),
            ..Default::default()
        };
        assert!(matches!(
            validate_live_config(&cfg),
            Err(SdJournalError::InvalidQuery { .. })
        ));

        cfg = JournalConfig {
            live_channel_capacity: 1,
            max_live_batch_entries: 2,
            live_queue_full_policy: LiveQueueFullPolicy::Block,
            ..Default::default()
        };
        assert!(matches!(
            validate_live_config(&cfg),
            Err(SdJournalError::InvalidQuery { .. })
        ));

        cfg.live_queue_full_policy = LiveQueueFullPolicy::Disconnect;
        assert!(validate_live_config(&cfg).is_ok());
    }
}
