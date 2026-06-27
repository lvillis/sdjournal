use crate::config::JournalConfig;
use crate::cursor::{Cursor, SdJournalEntryKey};
use crate::entry::EntryRef;
use crate::error::Result;
use crate::journal::Journal;
use std::cmp::Ordering;

use super::filter::{CompiledFilter, MatchTerm};
use super::{
    compare_keys, cursor_from_key, is_skippable_live_file_error, key_from_entry_ref,
    warn_live_file_error,
};

pub(super) struct JournalSnapshot {
    pub(super) journal: Journal,
    pub(super) last_seen: Option<SdJournalEntryKey>,
}

pub(super) struct ReplayState {
    pub(super) journal: Journal,
    pub(super) cursor: Option<Cursor>,
    pub(super) since_realtime: Option<u64>,
    pub(super) last_key: Option<SdJournalEntryKey>,
    pub(super) upper_key: Option<SdJournalEntryKey>,
    pub(super) remaining: usize,
}

impl ReplayState {
    pub(super) fn new(
        snapshot: JournalSnapshot,
        after_cursor: Option<Cursor>,
        since_realtime: Option<u64>,
        config: &JournalConfig,
    ) -> Self {
        let (cursor, last_key) = match after_cursor {
            Some(cursor) => match cursor.sdjournal_entry_key() {
                Some(key) => (None, Some(key)),
                None => (Some(cursor), None),
            },
            None => (None, None),
        };

        Self {
            journal: snapshot.journal,
            cursor,
            since_realtime,
            last_key,
            upper_key: snapshot.last_seen,
            remaining: config.max_live_replay_entries,
        }
    }

    pub(super) fn catch_up(
        journal: Journal,
        after_key: SdJournalEntryKey,
        upper_key: SdJournalEntryKey,
        config: &JournalConfig,
    ) -> Self {
        Self {
            journal,
            cursor: None,
            since_realtime: None,
            last_key: Some(after_key),
            upper_key: Some(upper_key),
            remaining: config.max_live_replay_entries,
        }
    }
}

pub(super) struct PendingTopologyCatchup {
    pub(super) journal: Journal,
    pub(super) last_key: Option<SdJournalEntryKey>,
    pub(super) upper_key: Option<SdJournalEntryKey>,
}

pub(super) struct EntryBatch {
    pub(super) entries: Vec<EntryRef>,
    pub(super) last_key: Option<SdJournalEntryKey>,
    pub(super) exhausted: bool,
}

pub(super) fn collect_replay_batch(
    replay: &ReplayState,
    filter: &CompiledFilter,
    limit: usize,
) -> Result<EntryBatch> {
    let Some(upper_key) = replay.upper_key else {
        return Ok(EntryBatch {
            entries: Vec::new(),
            last_key: None,
            exhausted: true,
        });
    };

    let mut q = replay.journal.query();
    apply_compiled_filter(&mut q, filter);
    if let Some(since) = replay.since_realtime {
        q.since_realtime(since);
    }
    if let Some(key) = replay.last_key {
        q.after_cursor(cursor_from_key(key));
    } else if let Some(cursor) = replay.cursor.clone() {
        q.after_cursor(cursor);
    }
    q.limit(limit.saturating_add(1));

    collect_entry_batch(q, limit, Some(upper_key), "skipping live replay entry")
}

pub(super) fn collect_entries_after_key(
    journal: &Journal,
    after_key: Option<SdJournalEntryKey>,
    upper_key: Option<SdJournalEntryKey>,
    limit: usize,
) -> Result<EntryBatch> {
    let mut q = journal.query();
    if let Some(key) = after_key {
        q.after_cursor(cursor_from_key(key));
    }
    q.limit(limit.saturating_add(1));

    collect_entry_batch(q, limit, upper_key, "skipping live refresh entry")
}

fn collect_entry_batch(
    query: crate::JournalQuery,
    limit: usize,
    upper_key: Option<SdJournalEntryKey>,
    skip_message: &'static str,
) -> Result<EntryBatch> {
    let mut entries = Vec::with_capacity(limit.min(64));
    let mut exhausted = true;
    for item in query.iter()? {
        match item {
            Ok(entry) => {
                let key = key_from_entry_ref(&entry);
                if let Some(upper_key) = upper_key
                    && compare_keys(&key, &upper_key) == Ordering::Greater
                {
                    break;
                }
                if entries.len() >= limit {
                    exhausted = false;
                    break;
                }
                entries.push(entry);
            }
            Err(err) if is_skippable_live_file_error(&err) => {
                warn_live_file_error(skip_message, &err);
            }
            Err(err) => return Err(err),
        }
    }

    let last_key = entries.last().map(key_from_entry_ref);
    Ok(EntryBatch {
        entries,
        last_key,
        exhausted,
    })
}

fn apply_compiled_filter(query: &mut crate::JournalQuery, filter: &CompiledFilter) {
    match filter.branches.as_slice() {
        [] => {}
        [branch] => {
            for term in branch {
                apply_term_to_query(query, term);
            }
        }
        branches => {
            for branch in branches {
                query.or_group(|group| {
                    for term in branch {
                        apply_term_to_or_group(group, term);
                    }
                });
            }
        }
    }
}

fn apply_term_to_query(query: &mut crate::JournalQuery, term: &MatchTerm) {
    match term {
        MatchTerm::Exact { field, value } => {
            query.match_exact(field, value);
        }
        MatchTerm::Present { field } => {
            query.match_present(field);
        }
    }
}

fn apply_term_to_or_group(group: &mut crate::query::OrGroupBuilder, term: &MatchTerm) {
    match term {
        MatchTerm::Exact { field, value } => {
            group.match_exact(field, value);
        }
        MatchTerm::Present { field } => {
            group.match_present(field);
        }
    }
}
