use std::time::Duration;

/// Runtime configuration for `Journal`.
#[derive(Clone, Debug)]
pub struct JournalConfig {
    /// Maximum object size accepted from the journal file.
    pub max_object_size_bytes: u64,

    /// Maximum bytes allowed after decompressing a DATA payload.
    pub max_decompressed_bytes: usize,

    /// Maximum length of a field name.
    pub max_field_name_len: usize,

    /// Maximum number of fields accepted per entry.
    pub max_fields_per_entry: usize,

    /// Maximum number of journal files included from a single scan.
    pub max_journal_files: usize,

    /// Maximum number of steps when traversing any `next_*` chain.
    pub max_object_chain_steps: usize,

    /// Maximum number of query terms (matches) accepted per query.
    pub max_query_terms: usize,

    /// Whether to allow mmap for `STATE_ONLINE` (potentially still being written) journal files.
    pub allow_mmap_online: bool,

    /// Whether to include `*.journal~` temporary/incomplete files during discovery.
    pub include_journal_tilde: bool,

    /// Maximum follow retry backoff.
    pub max_follow_backoff: Duration,

    /// Polling interval used as fallback when inotify is unavailable/unreliable.
    pub poll_interval: Duration,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            max_object_size_bytes: 16 * 1024 * 1024,
            max_decompressed_bytes: 1024 * 1024,
            max_field_name_len: 128,
            max_fields_per_entry: 256,
            max_journal_files: 1024,
            max_object_chain_steps: 1_000_000,
            max_query_terms: 64,
            allow_mmap_online: false,
            include_journal_tilde: false,
            max_follow_backoff: Duration::from_millis(2000),
            poll_interval: Duration::from_millis(2000),
        }
    }
}
