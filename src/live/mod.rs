#[cfg(feature = "tokio")]
mod tokio;
#[cfg(target_os = "linux")]
mod watcher;

use crate::config::JournalConfig;
use crate::cursor::{Cursor, SdJournalEntryKey};
use crate::entry::{EntryOwned, EntryRef, LiveEntry};
use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::JournalFile;
use crate::journal::Journal;
use crate::util::is_ascii_field_name;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering as AtomicOrdering},
};
use std::thread;
use std::time::{Duration, SystemTime};

#[cfg(feature = "tokio")]
pub use self::tokio::TokioSubscription;
#[cfg(target_os = "linux")]
use self::watcher::InotifyWatcher;

#[cfg(all(feature = "tracing", target_os = "linux"))]
use tracing::debug;

#[derive(Debug, Clone)]
enum MatchTerm {
    Exact { field: String, value: Vec<u8> },
    Present { field: String },
}

#[derive(Debug, Clone)]
struct CompiledFilter {
    branches: Vec<Vec<MatchTerm>>,
}

impl CompiledFilter {
    fn matches<E: MatchableEntry>(&self, entry: &E) -> bool {
        self.branches
            .iter()
            .any(|branch| branch.iter().all(|term| term_matches(entry, term)))
    }
}

trait MatchableEntry {
    fn get_field(&self, field: &str) -> Option<&[u8]>;
    fn any_field_equals(&self, field: &str, value: &[u8]) -> bool;
}

impl MatchableEntry for EntryOwned {
    fn get_field(&self, field: &str) -> Option<&[u8]> {
        self.get(field)
    }

    fn any_field_equals(&self, field: &str, value: &[u8]) -> bool {
        self.iter_fields()
            .any(|(name, field_value)| name == field && field_value == value)
    }
}

impl MatchableEntry for EntryRef {
    fn get_field(&self, field: &str) -> Option<&[u8]> {
        self.get(field)
    }

    fn any_field_equals(&self, field: &str, value: &[u8]) -> bool {
        self.iter_fields()
            .any(|(name, field_value)| name == field && field_value == value)
    }
}

struct SubscriptionState {
    filter: CompiledFilter,
    tx: Sender<Result<LiveEntry>>,
    start_after: Option<SdJournalEntryKey>,
    alive: Arc<AtomicBool>,
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

struct TrackedFile {
    path: PathBuf,
    file_id: [u8; 16],
    file: JournalFile,
    tail: FileTailCursor,
}

struct TrackedFiles {
    files: Vec<TrackedFile>,
    path_index: HashMap<PathBuf, usize>,
    last_seen: Option<SdJournalEntryKey>,
}

struct FallbackDirState {
    path: PathBuf,
    modified: Option<SystemTime>,
}

struct FileTailCursor {
    known_arrays: Vec<u64>,
    next_array_idx: usize,
    next_item_idx: usize,
    last_entry_offset: Option<u64>,
}

impl FileTailCursor {
    fn at_end(file: &JournalFile) -> Result<Self> {
        let known_arrays = file.entry_array_offsets()?;
        let (next_array_idx, next_item_idx, last_entry_offset) = match known_arrays.last().copied()
        {
            Some(last) => {
                let items = file.read_entry_array_items(last)?;
                (known_arrays.len() - 1, items.len(), items.last().copied())
            }
            None => (0, 0, None),
        };

        Ok(Self {
            known_arrays,
            next_array_idx,
            next_item_idx,
            last_entry_offset,
        })
    }

    fn drain_new_offsets(&mut self, file: &JournalFile) -> Result<Vec<u64>> {
        if self.known_arrays.is_empty() {
            self.known_arrays = file.entry_array_offsets()?;
        } else {
            let mut next =
                file.read_entry_array_next_offset(*self.known_arrays.last().unwrap_or(&0))?;
            let mut steps = 0usize;
            while next != 0 {
                self.known_arrays.push(next);
                next = file.read_entry_array_next_offset(next)?;
                steps = steps.saturating_add(1);
                if steps > file.max_object_chain_steps() {
                    return Err(SdJournalError::Transient {
                        path: Some(file.path().to_path_buf()),
                        reason: "entry array chain refresh exceeded expected growth".to_string(),
                    });
                }
            }
        }

        if self.known_arrays.is_empty() {
            self.known_arrays.clear();
            self.next_array_idx = 0;
            self.next_item_idx = 0;
            self.last_entry_offset = None;
            return Ok(Vec::new());
        }

        let start_idx = self.next_array_idx.min(self.known_arrays.len() - 1);
        let mut out = Vec::new();
        let mut last_len = 0usize;

        for (idx, array_offset) in self
            .known_arrays
            .iter()
            .copied()
            .enumerate()
            .skip(start_idx)
        {
            let items = file.read_entry_array_items(array_offset)?;
            let start = if idx == start_idx {
                self.next_item_idx.min(items.len())
            } else {
                0
            };
            out.extend(items[start..].iter().copied().filter(|offset| *offset != 0));
            if idx + 1 == self.known_arrays.len() {
                last_len = items.len();
            }
        }

        self.next_array_idx = self.known_arrays.len() - 1;
        self.next_item_idx = last_len;
        if let Some(last) = out.last().copied() {
            self.last_entry_offset = Some(last);
        }
        Ok(out)
    }
}

/// Shared live journal engine for multi-subscription tailing.
///
/// `LiveJournal` keeps one watcher plus persistent per-file tail state. Ordinary appends are read
/// incrementally from already-known journal files and dispatched once to all matching
/// subscriptions. Full directory rescans are reserved for topology changes such as file creation,
/// removal, or rotation.
///
/// Create it through [`Journal::live`](crate::Journal::live), register one or more
/// [`LiveSubscription`]s, then drive the engine with [`LiveJournal::poll_once`] or
/// [`LiveJournal::run`].
///
/// # Model
///
/// Subscriptions are passive receivers. The engine only observes new journal data while
/// [`LiveJournal::poll_once`] or [`LiveJournal::run`] is being called. A subscription created with
/// [`LiveJournal::subscribe`] is live-only: it starts after the current tail and does not replay
/// existing entries. Use [`SubscriptionOptions`] when a replay window is needed.
///
/// # Example
///
/// ```no_run
/// use sdjournal::Journal;
/// use std::thread;
///
/// let journal = Journal::open_default()?;
/// let mut live = journal.live()?;
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
    journal: Journal,
    tracked_files: Vec<TrackedFile>,
    path_index: HashMap<PathBuf, usize>,
    fallback_dirs: Vec<FallbackDirState>,
    subscriptions: Vec<SubscriptionState>,
    last_seen: Option<SdJournalEntryKey>,
    #[cfg(target_os = "linux")]
    inotify: Option<InotifyWatcher>,
    #[cfg(target_os = "linux")]
    watch_paths: Vec<PathBuf>,
}

impl LiveJournal {
    pub(crate) fn from_journal(journal: Journal) -> Result<Self> {
        let roots = journal.inner.roots.clone();
        let config = journal.inner.config.clone();
        let tracked = build_tracked_files(&journal)?;

        let mut out = Self {
            roots,
            config,
            journal,
            tracked_files: tracked.files,
            path_index: tracked.path_index,
            fallback_dirs: Vec::new(),
            subscriptions: Vec::new(),
            last_seen: tracked.last_seen,
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
    /// The returned subscription only receives entries appended after the current live tail.
    /// It does not scan historical entries. This is the preferred path for normal tailing because
    /// registering the subscription does not rebuild query state.
    pub fn subscribe(&mut self, filter: LiveFilter) -> Result<LiveSubscription> {
        self.subscribe_with_options(SubscriptionOptions::new(filter))
    }

    /// Register a subscription with explicit replay or resume bounds.
    ///
    /// Any matching backlog covered by `options` is queued to the subscription immediately.
    /// Future live entries are then dispatched through the shared engine.
    ///
    /// This may perform a full snapshot refresh to establish the replay boundary. Prefer
    /// [`LiveJournal::subscribe`] when only future entries are needed.
    pub fn subscribe_with_options(
        &mut self,
        options: SubscriptionOptions,
    ) -> Result<LiveSubscription> {
        let compiled = options.filter.compile()?;
        let (tx, rx) = mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));
        let needs_replay = options.after_cursor.is_some() || options.since_realtime.is_some();

        let snapshot_tail = if needs_replay {
            self.refresh_snapshot_full()?;
            let snapshot_tail = tail_entry_key(&self.journal)?;
            self.last_seen = snapshot_tail;
            snapshot_tail
        } else {
            self.last_seen
        };

        if needs_replay {
            let mut q = self.journal.query();
            if let Some(since) = options.since_realtime {
                q.since_realtime(since);
            }
            if let Some(cursor) = options.after_cursor {
                q.after_cursor(cursor);
            }

            for item in q.iter()? {
                let entry = item?;
                if compiled.matches(&entry) {
                    let _ = tx.send(Ok(LiveEntry::new(entry)));
                }
            }
        }

        self.subscriptions.push(SubscriptionState {
            filter: compiled,
            tx,
            start_after: snapshot_tail,
            alive: alive.clone(),
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

        let change = self.wait_for_change();
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

    fn poll_all_files_after_sleep(&mut self) -> WatchChange {
        thread::sleep(self.config.poll_interval);

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
                    let known = tracked.file.live_state().used_size;
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

    fn refresh_snapshot_full(&mut self) -> Result<()> {
        let journal = Journal::open_dirs_with_config(&self.roots, self.config.clone())?;
        let tracked = build_tracked_files(&journal)?;
        self.journal = journal;
        self.tracked_files = tracked.files;
        self.path_index = tracked.path_index;
        self.refresh_fallback_dirs();
        self.refresh_watchers();
        Ok(())
    }

    fn refresh_topology_and_dispatch(&mut self) -> Result<usize> {
        let journal = Journal::open_dirs_with_config(&self.roots, self.config.clone())?;
        let mut pending = Vec::new();
        let mut q = journal.query();
        if let Some(last_seen) = self.last_seen {
            q.after_cursor(cursor_from_key(last_seen));
        }
        for item in q.iter()? {
            pending.push(item?);
        }

        let tracked = build_tracked_files(&journal)?;
        self.journal = journal;
        self.tracked_files = tracked.files;
        self.path_index = tracked.path_index;
        self.refresh_fallback_dirs();
        self.refresh_watchers();

        Ok(self.dispatch_entries(pending, true))
    }

    fn dispatch_modified_paths(&mut self, paths: &[PathBuf]) -> Result<usize> {
        let mut pending = Vec::new();
        let mut active_files = 0usize;

        for path in paths {
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
        }

        Ok(self.dispatch_entries(pending, active_files <= 1))
    }

    fn refresh_tracked_file(&mut self, idx: usize) -> Result<Option<Vec<EntryRef>>> {
        let old_state = self.tracked_files[idx].file.live_state();
        let reopened = match self.tracked_files[idx].file.refresh_from_current_handle() {
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
            tracked.file = reopened;
            return Ok(Some(Vec::new()));
        }

        let offsets = match tracked.tail.drain_new_offsets(&reopened) {
            Ok(offsets) => offsets,
            Err(SdJournalError::Transient { .. }) | Err(SdJournalError::Corrupt { .. }) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        tracked.file = reopened;
        let file = tracked.file.clone();
        let mut entries = Vec::with_capacity(offsets.len());
        for offset in offsets {
            entries.push(file.read_entry_ref(offset)?);
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
                    if self.subscriptions[idx].tx.send(Ok(entry)).is_ok() {
                        deliveries = deliveries.saturating_add(1);
                    } else {
                        dead[idx] = true;
                    }
                }
            }

            self.last_seen = Some(key);
        }

        if dead.iter().any(|dead| *dead) {
            let mut idx = 0usize;
            self.subscriptions.retain(|_| {
                let keep = !dead[idx];
                idx = idx.saturating_add(1);
                keep
            });
        }

        deliveries
    }

    fn refresh_watchers(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let watch_paths = collect_watch_paths(&self.roots, &self.journal);
            if watch_paths != self.watch_paths {
                self.inotify = InotifyWatcher::new(&watch_paths);
                self.watch_paths = watch_paths;
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
        self.fallback_dirs = collect_fallback_dirs(&self.roots, &self.journal);
    }

    fn remove_closed_subscriptions(&mut self) {
        self.subscriptions
            .retain(|sub| sub.alive.load(AtomicOrdering::Acquire));
    }
}

/// In-memory filter builder for live subscriptions.
///
/// The filter DSL mirrors the historical query builder, but it only describes live matching
/// predicates. Time bounds and cursor resumes are configured through [`SubscriptionOptions`].
///
/// Direct terms are AND-ed together. Each [`LiveFilter::or_group`] call adds one alternative
/// branch whose terms are also AND-ed together.
#[derive(Clone)]
pub struct LiveFilter {
    config: JournalConfig,
    global_terms: Vec<MatchTerm>,
    or_groups: Vec<Vec<MatchTerm>>,
    invalid_reason: Option<String>,
    too_many_terms: bool,
}

impl LiveFilter {
    pub(crate) fn new(config: JournalConfig) -> Self {
        Self {
            config,
            global_terms: Vec::new(),
            or_groups: Vec::new(),
            invalid_reason: None,
            too_many_terms: false,
        }
    }

    /// Match entries whose field equals `value` byte-for-byte.
    ///
    /// Multiple terms added directly to a filter are AND-ed together. Validation is deferred until
    /// the filter is registered with [`LiveJournal::subscribe`] or
    /// [`LiveJournal::subscribe_with_options`].
    pub fn match_exact(&mut self, field: &str, value: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.count_terms() >= self.config.max_query_terms {
            self.too_many_terms = true;
            return self;
        }

        self.global_terms.push(MatchTerm::Exact {
            field: field.to_string(),
            value: value.to_vec(),
        });
        self
    }

    /// Match entries that contain `field`, regardless of its value.
    ///
    /// Multiple terms added directly to a filter are AND-ed together. Validation is deferred until
    /// the filter is registered with [`LiveJournal::subscribe`] or
    /// [`LiveJournal::subscribe_with_options`].
    pub fn match_present(&mut self, field: &str) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.count_terms() >= self.config.max_query_terms {
            self.too_many_terms = true;
            return self;
        }

        self.global_terms.push(MatchTerm::Present {
            field: field.to_string(),
        });
        self
    }

    /// Match entries for a specific systemd unit.
    ///
    /// This expands to an OR over `_SYSTEMD_UNIT`, `UNIT`, and `OBJECT_SYSTEMD_UNIT`.
    pub fn match_unit(&mut self, unit: &str) -> &mut Self {
        self.match_unit_bytes(unit.as_bytes())
    }

    /// Same as [`LiveFilter::match_unit`], but accepts raw unit bytes.
    pub fn match_unit_bytes(&mut self, unit: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }

        let max_terms = self.config.max_query_terms;
        let global_len = self.global_terms.len();
        let new_total_terms = if self.or_groups.is_empty() {
            global_len.saturating_add(3)
        } else {
            let old_group_terms = self.or_groups.iter().map(Vec::len).sum::<usize>();
            let old_groups = self.or_groups.len();
            global_len
                .saturating_add(old_group_terms.saturating_mul(3))
                .saturating_add(old_groups.saturating_mul(3))
        };

        if new_total_terms > max_terms {
            self.too_many_terms = true;
            return self;
        }

        fn unit_term(field: &str, unit: &[u8]) -> MatchTerm {
            MatchTerm::Exact {
                field: field.to_string(),
                value: unit.to_vec(),
            }
        }

        let unit_fields = ["_SYSTEMD_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT"];

        if self.or_groups.is_empty() {
            self.or_groups = unit_fields
                .iter()
                .map(|field| vec![unit_term(field, unit)])
                .collect();
            return self;
        }

        let mut next = Vec::with_capacity(self.or_groups.len().saturating_mul(3));
        for group in &self.or_groups {
            for field in unit_fields {
                let mut branch = group.clone();
                branch.push(unit_term(field, unit));
                next.push(branch);
            }
        }
        self.or_groups = next;
        self
    }

    /// Add an OR-group to the filter.
    ///
    /// Each call creates one OR branch. Terms added inside the closure are AND-ed together within
    /// that branch. Empty groups are ignored.
    ///
    /// ```no_run
    /// # use sdjournal::Journal;
    /// # let journal = Journal::open_default()?;
    /// let mut live = journal.live()?;
    /// let mut filter = live.filter();
    /// filter
    ///     .match_present("MESSAGE")
    ///     .or_group(|g| {
    ///         g.match_exact("_SYSTEMD_UNIT", b"sshd.service");
    ///     })
    ///     .or_group(|g| {
    ///         g.match_exact("_SYSTEMD_UNIT", b"systemd.service");
    ///     });
    /// let _subscription = live.subscribe(filter)?;
    /// # Ok::<(), sdjournal::SdJournalError>(())
    /// ```
    pub fn or_group<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut LiveOrGroupBuilder),
    {
        if self.invalid_reason.is_some() {
            return self;
        }

        let remaining = self
            .config
            .max_query_terms
            .saturating_sub(self.count_terms());
        let mut builder = LiveOrGroupBuilder {
            terms: Vec::new(),
            config: self.config.clone(),
            invalid_reason: None,
            too_many_terms: false,
            remaining,
        };
        f(&mut builder);
        if let Some(reason) = builder.invalid_reason {
            self.invalid_reason = Some(reason);
            return self;
        }
        if builder.too_many_terms {
            self.too_many_terms = true;
            return self;
        }
        if !builder.terms.is_empty() {
            self.or_groups.push(builder.terms);
        }
        self
    }

    fn compile(&self) -> Result<CompiledFilter> {
        self.validate()?;
        Ok(CompiledFilter {
            branches: build_branches(self),
        })
    }

    fn validate(&self) -> Result<()> {
        if let Some(reason) = &self.invalid_reason {
            return Err(SdJournalError::InvalidQuery {
                reason: reason.clone(),
            });
        }
        if self.too_many_terms {
            return Err(SdJournalError::LimitExceeded {
                kind: LimitKind::QueryTerms,
                limit: u64::try_from(self.config.max_query_terms).unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }

    fn count_terms(&self) -> usize {
        let mut n = self.global_terms.len();
        for group in &self.or_groups {
            n = n.saturating_add(group.len());
        }
        n
    }
}

/// Builder used inside [`LiveFilter::or_group`].
///
/// Multiple terms added to the same builder are AND-ed together.
pub struct LiveOrGroupBuilder {
    terms: Vec<MatchTerm>,
    config: JournalConfig,
    invalid_reason: Option<String>,
    too_many_terms: bool,
    remaining: usize,
}

impl LiveOrGroupBuilder {
    /// Add an exact field match to this OR-group.
    pub fn match_exact(&mut self, field: &str, value: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.terms.len() >= self.remaining {
            self.too_many_terms = true;
            return self;
        }

        self.terms.push(MatchTerm::Exact {
            field: field.to_string(),
            value: value.to_vec(),
        });
        self
    }

    /// Add a field-presence match to this OR-group.
    pub fn match_present(&mut self, field: &str) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.terms.len() >= self.remaining {
            self.too_many_terms = true;
            return self;
        }

        self.terms.push(MatchTerm::Present {
            field: field.to_string(),
        });
        self
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

#[cfg(target_os = "linux")]
fn collect_watch_paths(roots: &[PathBuf], journal: &Journal) -> Vec<PathBuf> {
    let mut watch_paths: Vec<PathBuf> = roots.to_vec();
    for file in &journal.inner.files {
        watch_paths.push(file.path().to_path_buf());
        if let Some(parent) = file.path().parent() {
            watch_paths.push(parent.to_path_buf());
        }
    }
    watch_paths.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    watch_paths.dedup();
    watch_paths
}

fn collect_fallback_dirs(roots: &[PathBuf], journal: &Journal) -> Vec<FallbackDirState> {
    let mut dirs: Vec<PathBuf> = roots.to_vec();
    for file in &journal.inner.files {
        if let Some(parent) = file.path().parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    dirs.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    dirs.dedup();
    dirs.into_iter()
        .map(|path| FallbackDirState {
            modified: std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok(),
            path,
        })
        .collect()
}

fn build_tracked_files(journal: &Journal) -> Result<TrackedFiles> {
    let mut tracked_files = Vec::with_capacity(journal.inner.files.len());
    let mut path_index = HashMap::with_capacity(journal.inner.files.len());
    let mut last_seen = None;

    for file in &journal.inner.files {
        let path = file.path().to_path_buf();
        let tail = FileTailCursor::at_end(file)?;
        if let Some(offset) = tail.last_entry_offset {
            let meta = file.read_entry_meta(offset)?;
            let key = SdJournalEntryKey {
                file_id: meta.file_id,
                entry_offset: meta.entry_offset,
                seqnum: meta.seqnum,
                realtime_usec: meta.realtime_usec,
            };
            if last_seen
                .as_ref()
                .is_none_or(|last| compare_keys(&key, last) == Ordering::Greater)
            {
                last_seen = Some(key);
            }
        }

        let tracked = TrackedFile {
            path: path.clone(),
            file_id: file.file_id(),
            file: file.clone(),
            tail,
        };
        path_index.insert(path, tracked_files.len());
        tracked_files.push(tracked);
    }

    Ok(TrackedFiles {
        files: tracked_files,
        path_index,
        last_seen,
    })
}

fn is_candidate_journal_path(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("journal") | Some("journal~")
    )
}

fn tail_entry_key(journal: &Journal) -> Result<Option<SdJournalEntryKey>> {
    let mut q = journal.query();
    q.seek_tail().limit(1);
    let mut iter = q.iter()?;
    let Some(item) = iter.next() else {
        return Ok(None);
    };
    let entry = item?;
    entry
        .cursor()?
        .sdjournal_entry_key()
        .ok_or(SdJournalError::InvalidQuery {
            reason: "sdjournal-generated entry cursor must contain an entry key".to_string(),
        })
        .map(Some)
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

fn validate_field_name(field: &str, config: &JournalConfig) -> Result<()> {
    if field.len() > config.max_field_name_len {
        return Err(SdJournalError::InvalidQuery {
            reason: "field name too long".to_string(),
        });
    }
    if !is_ascii_field_name(field.as_bytes()) {
        return Err(SdJournalError::InvalidQuery {
            reason: "field name must be ASCII and must not contain '='".to_string(),
        });
    }
    Ok(())
}

fn build_branches(filter: &LiveFilter) -> Vec<Vec<MatchTerm>> {
    if filter.or_groups.is_empty() {
        return vec![filter.global_terms.clone()];
    }

    let mut out = Vec::with_capacity(filter.or_groups.len());
    for group in &filter.or_groups {
        let mut branch = filter.global_terms.clone();
        branch.extend_from_slice(group);
        out.push(branch);
    }
    out
}

fn term_matches<E: MatchableEntry>(entry: &E, term: &MatchTerm) -> bool {
    match term {
        MatchTerm::Exact { field, value } => entry.any_field_equals(field, value.as_slice()),
        MatchTerm::Present { field } => entry.get_field(field).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> EntryOwned {
        EntryOwned::new(
            [0x11; 16],
            7,
            9,
            11,
            13,
            [0x22; 16],
            vec![
                ("MESSAGE".to_string(), b"hello".to_vec()),
                ("_SYSTEMD_UNIT".to_string(), b"sshd.service".to_vec()),
                ("UNIT".to_string(), b"sshd.service".to_vec()),
            ],
        )
    }

    #[test]
    fn live_filter_match_unit_matches_common_unit_fields() {
        let mut filter = LiveFilter::new(JournalConfig::default());
        filter.match_unit("sshd.service");
        let compiled = filter.compile().expect("filter should compile");

        assert!(compiled.matches(&sample_entry()));
    }

    #[test]
    fn live_filter_or_group_matches_existing_branch_style() {
        let mut filter = LiveFilter::new(JournalConfig::default());
        filter.match_present("MESSAGE");
        filter.or_group(|group| {
            group.match_exact("PRIORITY", b"3");
        });
        filter.or_group(|group| {
            group.match_exact("_SYSTEMD_UNIT", b"sshd.service");
        });
        let compiled = filter.compile().expect("filter should compile");

        assert!(compiled.matches(&sample_entry()));
    }

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
    fn term_matches_handles_exact_and_present_terms() {
        let entry = sample_entry();

        assert!(term_matches(
            &entry,
            &MatchTerm::Exact {
                field: "MESSAGE".to_string(),
                value: b"hello".to_vec(),
            }
        ));
        assert!(term_matches(
            &entry,
            &MatchTerm::Present {
                field: "_SYSTEMD_UNIT".to_string(),
            }
        ));
        assert!(!term_matches(
            &entry,
            &MatchTerm::Exact {
                field: "MESSAGE".to_string(),
                value: b"missing".to_vec(),
            }
        ));
    }
}
