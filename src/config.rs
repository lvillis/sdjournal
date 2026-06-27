use std::time::Duration;

/// Runtime mmap policy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmapPolicy {
    /// Use mmap for stable journal files when the `mmap` feature is enabled.
    ///
    /// Online files are still read through file I/O unless
    /// [`JournalConfig::allow_mmap_online`] is also enabled.
    Auto,

    /// Never mmap journal files.
    ///
    /// Use this for processes with strict virtual-memory limits or deployments where mapping a
    /// large archived journal file is undesirable.
    Never,
}

/// Behavior when a live subscription queue is full.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveQueueFullPolicy {
    /// Wait until the subscriber receives enough entries to make room.
    ///
    /// This preserves entries but can block [`crate::LiveJournal::poll_once`] or
    /// [`crate::LiveJournal::run`] when consumers are slow.
    Block,

    /// Drop the newest delivery for that subscriber and keep the subscription alive.
    ///
    /// Use this only when occasional live-entry loss is acceptable.
    DropNewest,

    /// Close the slow subscription when its queue is full.
    ///
    /// This avoids blocking the engine and does not silently drop entries.
    Disconnect,
}

/// Runtime configuration for [`crate::Journal`].
///
/// These limits are primarily defensive: they bound memory use and traversal work when reading
/// malformed, truncated, or unexpectedly large journal files.
///
/// Defaults are conservative for general-purpose readers. Increase limits only for known-good
/// deployments with unusually large entries or many journal files. Lower
/// [`JournalConfig::poll_interval`] when live tail latency matters and a platform watcher is not
/// available.
#[derive(Clone, Debug)]
pub struct JournalConfig {
    /// Maximum object size accepted from the journal file.
    ///
    /// This bounds allocation when reading ENTRY, DATA, and related objects.
    pub max_object_size_bytes: u64,

    /// Maximum bytes allowed after decompressing a DATA payload.
    ///
    /// This protects callers from compressed payloads that expand unexpectedly.
    pub max_decompressed_bytes: usize,

    /// Maximum length of a field name.
    ///
    /// systemd field names are normally short uppercase identifiers such as `MESSAGE` or
    /// `_SYSTEMD_UNIT`.
    pub max_field_name_len: usize,

    /// Maximum number of fields accepted per entry.
    ///
    /// Entries exceeding this limit are treated as malformed or unsupported for this reader.
    pub max_fields_per_entry: usize,

    /// Maximum number of journal files included from a single scan.
    ///
    /// Discovery fails with [`crate::SdJournalError::LimitExceeded`] if this limit is exceeded.
    pub max_journal_files: usize,

    /// Maximum journal files kept open by one reader.
    ///
    /// Queries switch to a low-memory streaming merge when discovery finds more files than this
    /// limit. Set this to `1` for the lowest file-descriptor and mmap footprint.
    pub max_open_files: usize,

    /// Runtime mmap policy.
    ///
    /// [`MmapPolicy::Never`] forces bounded file I/O even when the `mmap` feature is enabled.
    pub mmap_policy: MmapPolicy,

    /// Maximum number of steps when traversing any `next_*` chain.
    ///
    /// This bounds work when following linked object chains in corrupt or adversarial files.
    pub max_object_chain_steps: usize,

    /// Maximum number of query terms (matches) accepted per query.
    ///
    /// Unit helpers and OR groups can expand into several internal terms.
    pub max_query_terms: usize,

    /// Whether to allow mmap for `STATE_ONLINE` journal files that may still be written.
    ///
    /// The default is `false` because concurrently modified files are safer to read through
    /// explicit file I/O. Offline and archived files may still use mmap when the `mmap` feature is
    /// enabled, unless [`JournalConfig::mmap_policy`] is [`MmapPolicy::Never`].
    pub allow_mmap_online: bool,

    /// Whether to include `*.journal~` temporary or incomplete files during discovery.
    ///
    /// Keep this disabled unless the application explicitly wants best-effort access to temporary
    /// journal files.
    pub include_journal_tilde: bool,

    /// Polling interval used as fallback when inotify is unavailable or unreliable.
    ///
    /// This affects [`crate::LiveJournal`] latency only on fallback polling paths.
    pub poll_interval: Duration,

    /// Maximum queued live entries per subscription.
    ///
    /// Live subscriptions use bounded queues. This prevents slow consumers from growing memory
    /// without limit.
    pub live_channel_capacity: usize,

    /// Maximum entries decoded or dispatched by one live-engine cycle.
    ///
    /// Replay, topology refresh, and modified-file reads are split across multiple
    /// [`crate::LiveJournal::poll_once`] cycles when more entries remain.
    pub max_live_batch_entries: usize,

    /// Maximum matching historical entries replayed for a single subscription.
    ///
    /// This bounds catch-up work when subscribing with [`crate::SubscriptionOptions::after_cursor`]
    /// or [`crate::SubscriptionOptions::since_realtime`].
    pub max_live_replay_entries: usize,

    /// Behavior when a subscription queue is full.
    pub live_queue_full_policy: LiveQueueFullPolicy,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            max_object_size_bytes: 16 * 1024 * 1024,
            max_decompressed_bytes: 1024 * 1024,
            max_field_name_len: 128,
            max_fields_per_entry: 256,
            max_journal_files: 1024,
            max_open_files: 64,
            mmap_policy: MmapPolicy::Auto,
            max_object_chain_steps: 1_000_000,
            max_query_terms: 64,
            allow_mmap_online: false,
            include_journal_tilde: false,
            poll_interval: Duration::from_millis(2000),
            live_channel_capacity: 64,
            max_live_batch_entries: 64,
            max_live_replay_entries: 4096,
            live_queue_full_policy: LiveQueueFullPolicy::Block,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values_are_stable() {
        let cfg = JournalConfig::default();

        assert_eq!(cfg.max_object_size_bytes, 16 * 1024 * 1024);
        assert_eq!(cfg.max_decompressed_bytes, 1024 * 1024);
        assert_eq!(cfg.max_field_name_len, 128);
        assert_eq!(cfg.max_fields_per_entry, 256);
        assert_eq!(cfg.max_journal_files, 1024);
        assert_eq!(cfg.max_open_files, 64);
        assert_eq!(cfg.mmap_policy, MmapPolicy::Auto);
        assert_eq!(cfg.max_object_chain_steps, 1_000_000);
        assert_eq!(cfg.max_query_terms, 64);
        assert!(!cfg.allow_mmap_online);
        assert!(!cfg.include_journal_tilde);
        assert_eq!(cfg.poll_interval, Duration::from_millis(2000));
        assert_eq!(cfg.live_channel_capacity, 64);
        assert_eq!(cfg.max_live_batch_entries, 64);
        assert_eq!(cfg.max_live_replay_entries, 4096);
        assert_eq!(cfg.live_queue_full_policy, LiveQueueFullPolicy::Block);
    }
}
