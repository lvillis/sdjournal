#[cfg(feature = "tokio")]
mod tokio;
#[cfg(target_os = "linux")]
mod watcher;

use crate::config::JournalConfig;
use crate::cursor::{Cursor, SdJournalEntryKey};
use crate::entry::EntryOwned;
use crate::error::{LimitKind, Result, SdJournalError};
use crate::journal::Journal;
use crate::util::is_ascii_field_name;
use std::cmp::Ordering;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering as AtomicOrdering},
};
use std::thread;
use std::time::Duration;

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
    fn matches(&self, entry: &EntryOwned) -> bool {
        self.branches
            .iter()
            .any(|branch| branch.iter().all(|term| term_matches(entry, term)))
    }
}

struct SubscriptionState {
    filter: CompiledFilter,
    tx: Sender<Result<EntryOwned>>,
    start_after: Option<SdJournalEntryKey>,
    alive: Arc<AtomicBool>,
}

/// Shared live journal engine for multi-subscription tailing.
///
/// `LiveJournal` owns one watcher, one reopened journal snapshot, and one global live cursor. New
/// entries are read once and then dispatched to all matching subscriptions.
///
/// Create it through [`Journal::live`](crate::Journal::live), register one or more
/// [`LiveSubscription`]s, then drive the engine with [`LiveJournal::poll_once`] or
/// [`LiveJournal::run`].
pub struct LiveJournal {
    roots: Vec<PathBuf>,
    config: JournalConfig,
    journal: Journal,
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
        let last_seen = tail_entry_key(&journal)?;

        let mut out = Self {
            roots,
            config,
            journal,
            subscriptions: Vec::new(),
            last_seen,
            #[cfg(target_os = "linux")]
            inotify: None,
            #[cfg(target_os = "linux")]
            watch_paths: Vec::new(),
        };
        out.refresh_watchers();
        Ok(out)
    }

    /// Create a new live filter builder using this engine's runtime limits.
    pub fn filter(&self) -> LiveFilter {
        LiveFilter::new(self.config.clone())
    }

    /// Register a live-only subscription.
    ///
    /// The returned subscription only receives entries appended after the current live tail.
    pub fn subscribe(&mut self, filter: LiveFilter) -> Result<LiveSubscription> {
        self.subscribe_with_options(SubscriptionOptions::new(filter))
    }

    /// Register a subscription with explicit replay or resume bounds.
    ///
    /// Any matching backlog covered by `options` is queued to the subscription immediately.
    /// Future live entries are then dispatched through the shared engine.
    pub fn subscribe_with_options(
        &mut self,
        options: SubscriptionOptions,
    ) -> Result<LiveSubscription> {
        self.refresh_snapshot()?;

        let snapshot_tail = tail_entry_key(&self.journal)?;
        let compiled = options.filter.compile()?;
        let (tx, rx) = mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));

        if options.after_cursor.is_some() || options.since_realtime.is_some() {
            let mut q = self.journal.query();
            if let Some(since) = options.since_realtime {
                q.since_realtime(since);
            }
            if let Some(cursor) = options.after_cursor {
                q.after_cursor(cursor);
            }

            for item in q.iter()? {
                let owned = item?.to_owned();
                if compiled.matches(&owned) {
                    let _ = tx.send(Ok(owned));
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
    pub fn poll_once(&mut self) -> Result<usize> {
        self.remove_closed_subscriptions();
        if self.subscriptions.is_empty() {
            return Ok(0);
        }

        let changed = self.wait_for_change();
        if !changed {
            self.remove_closed_subscriptions();
            return Ok(0);
        }

        self.refresh_snapshot()?;

        let mut q = self.journal.query();
        if let Some(last_seen) = self.last_seen {
            q.after_cursor(cursor_from_key(last_seen));
        }

        let mut deliveries = 0usize;
        let mut dead = vec![false; self.subscriptions.len()];

        for item in q.iter()? {
            let owned = item?.to_owned();
            let key = key_from_owned(&owned);

            for (idx, sub) in self.subscriptions.iter_mut().enumerate() {
                if let Some(start_after) = sub.start_after
                    && compare_keys(&key, &start_after) != Ordering::Greater
                {
                    continue;
                }

                if sub.filter.matches(&owned) {
                    if sub.tx.send(Ok(owned.clone())).is_ok() {
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

        Ok(deliveries)
    }

    /// Run the live engine until every subscription has been dropped.
    pub fn run(mut self) -> Result<()> {
        while !self.subscriptions.is_empty() {
            self.poll_once()?;
        }
        Ok(())
    }

    fn wait_for_change(&mut self) -> bool {
        core::cfg_select! {
            target_os = "linux" => {
                if let Some(w) = self.inotify.as_mut() {
                    w.wait(self.config.poll_interval)
                } else {
                    thread::sleep(self.config.poll_interval);
                    true
                }
            }
            _ => {
                thread::sleep(self.config.poll_interval);
                true
            }
        }
    }

    fn refresh_snapshot(&mut self) -> Result<()> {
        let journal = Journal::open_dirs_with_config(&self.roots, self.config.clone())?;
        self.journal = journal;
        self.refresh_watchers();
        Ok(())
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

    fn remove_closed_subscriptions(&mut self) {
        self.subscriptions
            .retain(|sub| sub.alive.load(AtomicOrdering::Acquire));
    }
}

/// In-memory filter builder for live subscriptions.
///
/// The filter DSL mirrors the historical query builder, but it only describes live matching
/// predicates. Time bounds and cursor resumes are configured through [`SubscriptionOptions`].
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
    /// Terms added inside the closure are OR-ed together, then AND-ed with the rest of the
    /// filter. Empty groups are ignored.
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
    pub fn after_cursor(&mut self, cursor: Cursor) -> &mut Self {
        self.after_cursor = Some(cursor);
        self
    }

    /// Replay matching entries from `usec` before switching to live delivery.
    pub fn since_realtime(&mut self, usec: u64) -> &mut Self {
        self.since_realtime = Some(usec);
        self
    }
}

/// Receiving end of a live subscription.
///
/// Values are delivered as owned entries so they can cross thread boundaries cleanly.
pub struct LiveSubscription {
    rx: Receiver<Result<EntryOwned>>,
    alive: Arc<AtomicBool>,
}

impl LiveSubscription {
    /// Receive the next entry, blocking until the subscription closes or a value arrives.
    pub fn recv(&self) -> std::result::Result<Result<EntryOwned>, mpsc::RecvError> {
        self.rx.recv()
    }

    /// Receive the next entry, waiting at most `timeout`.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> std::result::Result<Result<EntryOwned>, mpsc::RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }

    /// Try to receive the next queued entry without blocking.
    pub fn try_recv(&self) -> std::result::Result<Result<EntryOwned>, mpsc::TryRecvError> {
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

fn key_from_owned(entry: &EntryOwned) -> SdJournalEntryKey {
    SdJournalEntryKey {
        file_id: entry.file_id,
        entry_offset: entry.entry_offset,
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

fn term_matches(entry: &EntryOwned, term: &MatchTerm) -> bool {
    match term {
        MatchTerm::Exact { field, value } => entry
            .iter_fields()
            .any(|(name, field_value)| name == field.as_str() && field_value == value.as_slice()),
        MatchTerm::Present { field } => entry.get(field).is_some(),
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
}
