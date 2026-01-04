use crate::cursor::Cursor;
use crate::entry::{EntryOwned, EntryRef};
use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::{DataEntryOffsetIter, DataObjectRef, EntryMeta, FileEntryIter};
use crate::follow::Follow;
use crate::journal::Journal;
use crate::util::is_ascii_field_name;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

#[derive(Debug, Clone)]
enum MatchTerm {
    Exact {
        field: String,
        value: Vec<u8>,
        payload: Vec<u8>,
    },
    Present {
        field: String,
    },
}

/// A query builder for reading entries from a `Journal`.
#[derive(Clone)]
pub struct JournalQuery {
    journal: Journal,

    global_terms: Vec<MatchTerm>,
    or_groups: Vec<Vec<MatchTerm>>,

    since_realtime: Option<u64>,
    until_realtime: Option<u64>,
    cursor_start: Option<(Cursor, bool)>, // (cursor, inclusive)
    reverse: bool,
    limit: Option<usize>,
    invalid_reason: Option<String>,
    too_many_terms: bool,
}

impl JournalQuery {
    pub(crate) fn new(journal: Journal) -> Self {
        Self {
            journal,
            global_terms: Vec::new(),
            or_groups: Vec::new(),
            since_realtime: None,
            until_realtime: None,
            cursor_start: None,
            reverse: false,
            limit: None,
            invalid_reason: None,
            too_many_terms: false,
        }
    }

    pub fn match_exact(&mut self, field: &str, value: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.journal.inner.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.count_terms() >= self.journal.inner.config.max_query_terms {
            self.too_many_terms = true;
            return self;
        }

        let mut payload =
            Vec::with_capacity(field.len().saturating_add(1).saturating_add(value.len()));
        payload.extend_from_slice(field.as_bytes());
        payload.push(b'=');
        payload.extend_from_slice(value);

        self.global_terms.push(MatchTerm::Exact {
            field: field.to_string(),
            value: value.to_vec(),
            payload,
        });
        self
    }

    pub fn match_present(&mut self, field: &str) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.journal.inner.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.count_terms() >= self.journal.inner.config.max_query_terms {
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
    /// This expands to an OR over common unit fields:
    /// `(_SYSTEMD_UNIT=unit) OR (UNIT=unit) OR (OBJECT_SYSTEMD_UNIT=unit)`.
    ///
    /// The resulting unit filter is AND-ed with any existing query terms.
    pub fn match_unit(&mut self, unit: &str) -> &mut Self {
        self.match_unit_bytes(unit.as_bytes())
    }

    /// Same as [`JournalQuery::match_unit`], but accepts the unit name as bytes.
    pub fn match_unit_bytes(&mut self, unit: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }

        let max_terms = self.journal.inner.config.max_query_terms;
        let global_len = self.global_terms.len();
        let new_total_terms = if self.or_groups.is_empty() {
            global_len.saturating_add(3)
        } else {
            let mut old_groups_terms = 0usize;
            for g in &self.or_groups {
                old_groups_terms = old_groups_terms.saturating_add(g.len());
            }
            let old_groups = self.or_groups.len();

            // Distribute a 3-way OR across existing OR branches:
            // (G1 OR G2 OR ...) AND (U1 OR U2 OR U3)
            // => (G1+U1) OR (G1+U2) OR (G1+U3) OR (G2+U1) ...
            global_len
                .saturating_add(old_groups_terms.saturating_mul(3))
                .saturating_add(old_groups.saturating_mul(3))
        };

        if new_total_terms > max_terms {
            self.too_many_terms = true;
            return self;
        }

        fn unit_term(field: &str, unit: &[u8]) -> MatchTerm {
            let mut payload =
                Vec::with_capacity(field.len().saturating_add(1).saturating_add(unit.len()));
            payload.extend_from_slice(field.as_bytes());
            payload.push(b'=');
            payload.extend_from_slice(unit);
            MatchTerm::Exact {
                field: field.to_string(),
                value: unit.to_vec(),
                payload,
            }
        }

        let unit_terms = ["_SYSTEMD_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT"];

        if self.or_groups.is_empty() {
            self.or_groups = unit_terms
                .iter()
                .map(|f| vec![unit_term(f, unit)])
                .collect();
            return self;
        }

        let mut next = Vec::with_capacity(self.or_groups.len().saturating_mul(3));
        for group in &self.or_groups {
            for field in unit_terms {
                let mut g = group.clone();
                g.push(unit_term(field, unit));
                next.push(g);
            }
        }
        self.or_groups = next;
        self
    }

    pub fn or_group<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut OrGroupBuilder),
    {
        if self.invalid_reason.is_some() {
            return self;
        }
        let remaining = self
            .journal
            .inner
            .config
            .max_query_terms
            .saturating_sub(self.count_terms());
        let mut b = OrGroupBuilder {
            terms: Vec::new(),
            config: self.journal.inner.config.clone(),
            invalid_reason: None,
            too_many_terms: false,
            remaining,
        };
        f(&mut b);
        if let Some(r) = b.invalid_reason {
            self.invalid_reason = Some(r);
            return self;
        }
        if b.too_many_terms {
            self.too_many_terms = true;
            return self;
        }
        if !b.terms.is_empty() {
            self.or_groups.push(b.terms);
        }
        self
    }

    pub fn since_realtime(&mut self, usec: u64) -> &mut Self {
        self.since_realtime = Some(usec);
        self
    }

    pub fn until_realtime(&mut self, usec: u64) -> &mut Self {
        self.until_realtime = Some(usec);
        self
    }

    pub fn after_cursor(&mut self, cursor: Cursor) -> &mut Self {
        self.cursor_start = Some((cursor, false));
        self
    }

    /// Seek to the start of the journal (oldest entries).
    ///
    /// This clears any cursor-based starting position and disables `reverse`.
    pub fn seek_head(&mut self) -> &mut Self {
        self.cursor_start = None;
        self.reverse = false;
        self
    }

    /// Seek to the end of the journal (newest entries).
    ///
    /// This clears any cursor-based starting position and enables `reverse`.
    pub fn seek_tail(&mut self) -> &mut Self {
        self.cursor_start = None;
        self.reverse = true;
        self
    }

    pub fn reverse(&mut self, reverse: bool) -> &mut Self {
        self.reverse = reverse;
        self
    }

    pub fn limit(&mut self, n: usize) -> &mut Self {
        self.limit = Some(n);
        self
    }

    pub fn iter(&self) -> Result<impl Iterator<Item = Result<EntryRef>> + use<>> {
        self.validate()?;
        JournalIter::new(self.clone())
    }

    pub fn collect_owned(&self) -> Result<Vec<EntryOwned>> {
        let mut out = Vec::new();
        for item in self.iter()? {
            let entry = item?;
            out.push(entry.to_owned());
        }
        Ok(out)
    }

    pub fn follow(&self) -> Result<Follow> {
        self.validate()?;
        self.validate_follow()?;

        let roots = self.journal.inner.roots.clone();
        let config = self.journal.inner.config.clone();

        let live_journal = Journal::open_dirs_with_config(&roots, config.clone())?;
        let mut template = self.with_journal(live_journal.clone());
        template.limit = None;

        let mut catchup_query = self.with_journal(live_journal);
        let mut last_cursor: Option<Cursor> = None;

        let has_lower_bound = self.cursor_start.is_some() || self.since_realtime.is_some();
        if !has_lower_bound {
            let mut tail_probe = template.clone();
            tail_probe.reverse(true);
            tail_probe.limit(1);

            for item in tail_probe.iter()? {
                match item {
                    Ok(entry) => {
                        let c = entry.cursor()?;
                        catchup_query.set_cursor_start(c.clone(), false)?;
                        last_cursor = Some(c);
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }

        let catchup_iter: Box<dyn Iterator<Item = Result<EntryRef>> + Send> =
            Box::new(catchup_query.iter()?);
        Ok(Follow::new(
            roots,
            config,
            template,
            catchup_iter,
            last_cursor,
        ))
    }

    /// Create an async follow adapter for Tokio.
    #[cfg(feature = "tokio")]
    pub fn follow_tokio(&self) -> Result<crate::follow::TokioFollow> {
        Ok(crate::follow::TokioFollow::spawn(self.follow()?))
    }

    pub(crate) fn set_cursor_start(&mut self, cursor: Cursor, inclusive: bool) -> Result<()> {
        self.cursor_start = Some((cursor, inclusive));
        Ok(())
    }

    pub(crate) fn with_journal(&self, journal: Journal) -> Self {
        let mut q = self.clone();
        q.journal = journal;
        q
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
                limit: u64::try_from(self.journal.inner.config.max_query_terms).unwrap_or(u64::MAX),
            });
        }

        if let (Some(since), Some(until)) = (self.since_realtime, self.until_realtime)
            && since > until
        {
            return Err(SdJournalError::InvalidQuery {
                reason: "since_realtime must be <= until_realtime".to_string(),
            });
        }

        Ok(())
    }

    fn validate_follow(&self) -> Result<()> {
        if self.reverse {
            return Err(SdJournalError::InvalidQuery {
                reason: "follow() requires reverse=false".to_string(),
            });
        }
        if self.until_realtime.is_some() {
            return Err(SdJournalError::InvalidQuery {
                reason: "follow() does not allow until_realtime".to_string(),
            });
        }
        Ok(())
    }

    fn count_terms(&self) -> usize {
        let mut n = self.global_terms.len();
        for g in &self.or_groups {
            n = n.saturating_add(g.len());
        }
        n
    }
}

pub struct OrGroupBuilder {
    terms: Vec<MatchTerm>,
    config: crate::config::JournalConfig,
    invalid_reason: Option<String>,
    too_many_terms: bool,
    remaining: usize,
}

impl OrGroupBuilder {
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
        let mut payload =
            Vec::with_capacity(field.len().saturating_add(1).saturating_add(value.len()));
        payload.extend_from_slice(field.as_bytes());
        payload.push(b'=');
        payload.extend_from_slice(value);

        self.terms.push(MatchTerm::Exact {
            field: field.to_string(),
            value: value.to_vec(),
            payload,
        });
        self
    }

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

fn validate_field_name(field: &str, config: &crate::config::JournalConfig) -> Result<()> {
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

fn build_branches(query: &JournalQuery) -> Vec<Vec<MatchTerm>> {
    if query.or_groups.is_empty() {
        return vec![query.global_terms.clone()];
    }

    let mut out = Vec::with_capacity(query.or_groups.len());
    for group in &query.or_groups {
        let mut terms = query.global_terms.clone();
        terms.extend_from_slice(group);
        out.push(terms);
    }
    out
}

enum FileMetaIter {
    Empty,
    Single(FileBranchIter),
    Or(FileOrIter),
}

impl FileMetaIter {
    fn from_branch_iters(mut iters: Vec<FileBranchIter>, reverse: bool) -> Self {
        iters.retain(|it| !matches!(&it.kind, BranchKind::Empty));
        match iters.len() {
            0 => FileMetaIter::Empty,
            1 => FileMetaIter::Single(iters.remove(0)),
            _ => FileMetaIter::Or(FileOrIter::new(iters, reverse)),
        }
    }
}

impl Iterator for FileMetaIter {
    type Item = Result<EntryMeta>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            FileMetaIter::Empty => None,
            FileMetaIter::Single(it) => it.next(),
            FileMetaIter::Or(it) => it.next(),
        }
    }
}

struct FileOrIter {
    reverse: bool,
    forward_heap: BinaryHeap<Reverse<FileOrHeapItem>>,
    reverse_heap: BinaryHeap<FileOrHeapItem>,
    iters: Vec<FileBranchIter>,
    pending_errors: Vec<SdJournalError>,
    done: bool,
}

#[derive(Clone, Copy)]
struct FileOrHeapItem {
    meta: EntryMeta,
    branch_idx: usize,
}

impl PartialEq for FileOrHeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.meta == other.meta && self.branch_idx == other.branch_idx
    }
}

impl Eq for FileOrHeapItem {}

impl PartialOrd for FileOrHeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FileOrHeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.meta.cmp_key(&other.meta)
    }
}

impl FileOrIter {
    fn new(mut iters: Vec<FileBranchIter>, reverse: bool) -> Self {
        let mut pending_errors = Vec::new();
        let mut forward_heap: BinaryHeap<Reverse<FileOrHeapItem>> = BinaryHeap::new();
        let mut reverse_heap: BinaryHeap<FileOrHeapItem> = BinaryHeap::new();

        for (idx, it) in iters.iter_mut().enumerate() {
            if let Some(meta) = next_ok_meta(it, &mut pending_errors) {
                let item = FileOrHeapItem {
                    meta,
                    branch_idx: idx,
                };
                if reverse {
                    reverse_heap.push(item);
                } else {
                    forward_heap.push(Reverse(item));
                }
            }
        }

        Self {
            reverse,
            forward_heap,
            reverse_heap,
            iters,
            pending_errors,
            done: false,
        }
    }

    fn pop_next(&mut self) -> Option<FileOrHeapItem> {
        if self.reverse {
            self.reverse_heap.pop()
        } else {
            self.forward_heap.pop().map(|r| r.0)
        }
    }

    fn push_next(&mut self, item: FileOrHeapItem) {
        if self.reverse {
            self.reverse_heap.push(item);
        } else {
            self.forward_heap.push(Reverse(item));
        }
    }
}

impl Iterator for FileOrIter {
    type Item = Result<EntryMeta>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if let Some(err) = self.pending_errors.pop() {
            return Some(Err(err));
        }

        let item = match self.pop_next() {
            Some(item) => item,
            None => {
                self.done = true;
                return None;
            }
        };

        if let Some(next_meta) =
            next_ok_meta(&mut self.iters[item.branch_idx], &mut self.pending_errors)
        {
            self.push_next(FileOrHeapItem {
                meta: next_meta,
                branch_idx: item.branch_idx,
            });
        }

        Some(Ok(item.meta))
    }
}

struct AndOffsetIter {
    reverse: bool,
    iters: Vec<DataEntryOffsetIter>,
    cursors: Vec<Option<u64>>,
    initialized: bool,
    pending_error: Option<SdJournalError>,
    done: bool,
}

impl AndOffsetIter {
    fn new(iters: Vec<DataEntryOffsetIter>, reverse: bool) -> Self {
        let cursors = vec![None; iters.len()];
        Self {
            reverse,
            iters,
            cursors,
            initialized: false,
            pending_error: None,
            done: false,
        }
    }

    fn init(&mut self) -> Option<Result<()>> {
        if self.initialized {
            return Some(Ok(()));
        }
        for i in 0..self.iters.len() {
            match self.iters[i].next() {
                Some(Ok(v)) => self.cursors[i] = Some(v),
                Some(Err(e)) => return Some(Err(e)),
                None => return None,
            }
        }
        self.initialized = true;
        Some(Ok(()))
    }

    fn target(&self) -> Option<u64> {
        let mut it = self.cursors.iter().copied();
        let mut target = it.next()??;
        for v in it {
            let v = v?;
            target = if self.reverse {
                target.min(v)
            } else {
                target.max(v)
            };
        }
        Some(target)
    }

    fn advance_to(&mut self, idx: usize, target: u64) -> Option<Result<()>> {
        loop {
            let cur = self.cursors.get(idx).copied().flatten()?;

            let needs_advance = if self.reverse {
                cur > target
            } else {
                cur < target
            };
            if !needs_advance {
                return Some(Ok(()));
            }

            match self.iters[idx].next() {
                Some(Ok(v)) => self.cursors[idx] = Some(v),
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    self.cursors[idx] = None;
                    return None;
                }
            }
        }
    }
}

impl Iterator for AndOffsetIter {
    type Item = Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if let Some(err) = self.pending_error.take() {
            self.done = true;
            return Some(Err(err));
        }

        match self.init() {
            Some(Ok(())) => {}
            Some(Err(e)) => {
                self.done = true;
                return Some(Err(e));
            }
            None => {
                self.done = true;
                return None;
            }
        }

        loop {
            let target = match self.target() {
                Some(v) => v,
                None => {
                    self.done = true;
                    return None;
                }
            };

            for i in 0..self.iters.len() {
                match self.advance_to(i, target) {
                    Some(Ok(())) => {}
                    Some(Err(e)) => {
                        self.done = true;
                        return Some(Err(e));
                    }
                    None => {
                        self.done = true;
                        return None;
                    }
                }
            }

            let first = self.cursors.first().copied().flatten();
            let all_equal =
                first.is_some() && self.cursors.iter().all(|v| v.is_some() && *v == first);

            if !all_equal {
                continue;
            }

            let out = first.unwrap_or(0);
            for i in 0..self.iters.len() {
                match self.iters[i].next() {
                    Some(Ok(v)) => self.cursors[i] = Some(v),
                    Some(Err(e)) => {
                        self.cursors[i] = None;
                        self.pending_error = Some(e);
                    }
                    None => self.cursors[i] = None,
                }
            }

            return Some(Ok(out));
        }
    }
}

struct FileBranchIter {
    file: crate::file::JournalFile,
    kind: BranchKind,
}

enum BranchKind {
    Empty,
    Indexed {
        offset_iter: AndOffsetIter,
        present_fields: Vec<String>,
    },
    Scan {
        iter: FileEntryIter,
        terms: Vec<MatchTerm>,
    },
}

impl FileBranchIter {
    fn new(
        file: crate::file::JournalFile,
        terms: Vec<MatchTerm>,
        reverse: bool,
        since_realtime: Option<u64>,
        until_realtime: Option<u64>,
    ) -> Result<Self> {
        let mut present_fields = Vec::new();
        let mut exact_terms = Vec::new();

        for t in &terms {
            match t {
                MatchTerm::Exact { .. } => exact_terms.push(t),
                MatchTerm::Present { field } => present_fields.push(field.clone()),
            }
        }

        if exact_terms.is_empty() {
            let iter = file.entry_iter_seek_realtime(reverse, since_realtime, until_realtime)?;
            return Ok(Self {
                file,
                kind: BranchKind::Scan { iter, terms },
            });
        }

        let mut data_refs: Vec<DataObjectRef> = Vec::new();
        for t in &exact_terms {
            let payload = match t {
                MatchTerm::Exact { payload, .. } => payload.as_slice(),
                _ => continue,
            };

            match file.find_data_object(payload) {
                Ok(Some(d)) => data_refs.push(d),
                Ok(None) => {
                    return Ok(Self {
                        file,
                        kind: BranchKind::Empty,
                    });
                }
                Err(_) => {
                    let iter =
                        file.entry_iter_seek_realtime(reverse, since_realtime, until_realtime)?;
                    return Ok(Self {
                        file,
                        kind: BranchKind::Scan { iter, terms },
                    });
                }
            }
        }

        data_refs.sort_by_key(|d| d.n_entries);

        let mut iters = Vec::with_capacity(data_refs.len());
        for d in data_refs {
            match file.data_entry_offsets(d, reverse) {
                Ok(it) => iters.push(it),
                Err(_) => {
                    let iter =
                        file.entry_iter_seek_realtime(reverse, since_realtime, until_realtime)?;
                    return Ok(Self {
                        file,
                        kind: BranchKind::Scan { iter, terms },
                    });
                }
            }
        }

        Ok(Self {
            file,
            kind: BranchKind::Indexed {
                offset_iter: AndOffsetIter::new(iters, reverse),
                present_fields,
            },
        })
    }
}

impl Iterator for FileBranchIter {
    type Item = Result<EntryMeta>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.kind {
                BranchKind::Empty => return None,
                BranchKind::Indexed {
                    offset_iter,
                    present_fields,
                } => {
                    let entry_offset = match offset_iter.next()? {
                        Ok(v) => v,
                        Err(e) => {
                            self.kind = BranchKind::Empty;
                            return Some(Err(e));
                        }
                    };

                    let meta = match self.file.read_entry_meta(entry_offset) {
                        Ok(m) => m,
                        Err(e) => return Some(Err(e)),
                    };

                    if present_fields.is_empty() {
                        return Some(Ok(meta));
                    }

                    let owned = match self.file.read_entry_owned(entry_offset) {
                        Ok(e) => e,
                        Err(e) => return Some(Err(e)),
                    };

                    if present_fields.iter().all(|f| owned.get(f).is_some()) {
                        return Some(Ok(meta));
                    }

                    continue;
                }
                BranchKind::Scan { iter, terms } => match iter.next()? {
                    Ok(meta) => {
                        if terms.is_empty() {
                            return Some(Ok(meta));
                        }

                        let owned = match self.file.read_entry_owned(meta.entry_offset) {
                            Ok(e) => e,
                            Err(e) => return Some(Err(e)),
                        };

                        if terms.iter().all(|t| term_matches(&owned, t)) {
                            return Some(Ok(meta));
                        }

                        continue;
                    }
                    Err(e) => return Some(Err(e)),
                },
            }
        }
    }
}

struct JournalIter {
    query: JournalQuery,
    cursor_key: Option<(EntryMeta, bool)>, // (cursor meta, inclusive)
    produced: usize,
    last_emitted: Option<EntryMeta>,
    forward_heap: BinaryHeap<Reverse<HeapItem>>,
    reverse_heap: BinaryHeap<HeapItem>,
    iters: Vec<FileMetaIter>,
    pending_errors: Vec<SdJournalError>,
    done: bool,
}

#[derive(Clone, Copy)]
struct HeapItem {
    meta: EntryMeta,
    file_idx: usize,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.meta == other.meta && self.file_idx == other.file_idx
    }
}

impl Eq for HeapItem {}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.meta
            .cmp_key(&other.meta)
            .then_with(|| self.file_idx.cmp(&other.file_idx))
    }
}

impl JournalIter {
    fn new(query: JournalQuery) -> Result<Self> {
        if matches!(query.limit, Some(0)) {
            return Ok(Self {
                query,
                cursor_key: None,
                produced: 0,
                last_emitted: None,
                forward_heap: BinaryHeap::new(),
                reverse_heap: BinaryHeap::new(),
                iters: Vec::new(),
                pending_errors: Vec::new(),
                done: true,
            });
        }

        let mut pending_errors = Vec::new();
        let cursor_key = build_cursor_key(&query)?;
        let branches = build_branches(&query);

        let mut iters = Vec::with_capacity(query.journal.inner.files.len());
        for f in &query.journal.inner.files {
            let mut branch_iters = Vec::with_capacity(branches.len());
            for terms in &branches {
                match FileBranchIter::new(
                    f.clone(),
                    terms.clone(),
                    query.reverse,
                    query.since_realtime,
                    query.until_realtime,
                ) {
                    Ok(it) => branch_iters.push(it),
                    Err(e) => pending_errors.push(e),
                }
            }
            iters.push(FileMetaIter::from_branch_iters(branch_iters, query.reverse));
        }

        let mut forward_heap: BinaryHeap<Reverse<HeapItem>> = BinaryHeap::new();
        let mut reverse_heap: BinaryHeap<HeapItem> = BinaryHeap::new();

        for (idx, it) in iters.iter_mut().enumerate() {
            if let Some(meta) = next_ok_meta(it, &mut pending_errors) {
                let item = HeapItem {
                    meta,
                    file_idx: idx,
                };
                if query.reverse {
                    reverse_heap.push(item);
                } else {
                    forward_heap.push(Reverse(item));
                }
            }
        }

        Ok(Self {
            query,
            cursor_key,
            produced: 0,
            last_emitted: None,
            forward_heap,
            reverse_heap,
            iters,
            pending_errors,
            done: false,
        })
    }

    fn pop_next(&mut self) -> Option<HeapItem> {
        if self.query.reverse {
            self.reverse_heap.pop()
        } else {
            self.forward_heap.pop().map(|r| r.0)
        }
    }

    fn push_next(&mut self, item: HeapItem) {
        if self.query.reverse {
            self.reverse_heap.push(item);
        } else {
            self.forward_heap.push(Reverse(item));
        }
    }

    fn passes_filters(&self, meta: &EntryMeta) -> bool {
        if let Some((cursor_meta, inclusive)) = &self.cursor_key {
            let ord = meta.cmp_key(cursor_meta);
            if *inclusive {
                if ord == std::cmp::Ordering::Less {
                    return false;
                }
            } else if ord != std::cmp::Ordering::Greater {
                return false;
            }
        }

        if let Some(since) = self.query.since_realtime
            && meta.realtime_usec < since
        {
            return false;
        }
        if let Some(until) = self.query.until_realtime
            && meta.realtime_usec > until
        {
            return false;
        }

        true
    }
}

impl Iterator for JournalIter {
    type Item = Result<EntryRef>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if let Some(err) = self.pending_errors.pop() {
            return Some(Err(err));
        }

        if let Some(limit) = self.query.limit
            && (limit == 0 || self.produced >= limit)
        {
            self.done = true;
            return None;
        }

        loop {
            let item = match self.pop_next() {
                Some(item) => item,
                None => {
                    self.done = true;
                    return None;
                }
            };

            if let Some(next_meta) =
                next_ok_meta(&mut self.iters[item.file_idx], &mut self.pending_errors)
            {
                self.push_next(HeapItem {
                    meta: next_meta,
                    file_idx: item.file_idx,
                });
            }

            if !self.passes_filters(&item.meta) {
                continue;
            }

            if self.last_emitted == Some(item.meta) {
                continue;
            }

            let file = &self.query.journal.inner.files[item.file_idx];
            let entry = match file.read_entry_ref(item.meta.entry_offset) {
                Ok(e) => e,
                Err(e) => {
                    self.pending_errors.push(e);
                    if let Some(err) = self.pending_errors.pop() {
                        return Some(Err(err));
                    }
                    continue;
                }
            };

            self.last_emitted = Some(item.meta);
            self.produced = self.produced.saturating_add(1);
            return Some(Ok(entry));
        }
    }
}

fn next_ok_meta<I>(it: &mut I, pending: &mut Vec<SdJournalError>) -> Option<EntryMeta>
where
    I: Iterator<Item = Result<EntryMeta>>,
{
    for item in it.by_ref() {
        match item {
            Ok(m) => return Some(m),
            Err(e) => pending.push(e),
        }
    }
    None
}

fn build_cursor_key(query: &JournalQuery) -> Result<Option<(EntryMeta, bool)>> {
    let (cursor, inclusive) = match &query.cursor_start {
        Some(v) => v,
        None => return Ok(None),
    };

    if let Some(k) = cursor.sdjournal_entry_key() {
        return Ok(Some((
            EntryMeta {
                file_id: k.file_id,
                entry_offset: k.entry_offset,
                seqnum: k.seqnum,
                realtime_usec: k.realtime_usec,
            },
            *inclusive,
        )));
    }

    if let Some((file_id, entry_offset)) = cursor.file_offset() {
        let file = query
            .journal
            .inner
            .files
            .iter()
            .find(|f| f.file_id() == file_id)
            .ok_or(SdJournalError::NotFound)?;

        let meta = file
            .read_entry_meta(entry_offset)
            .map_err(|_| SdJournalError::NotFound)?;
        return Ok(Some((meta, *inclusive)));
    }

    if let Some(sys) = cursor.systemd() {
        let meta = resolve_systemd_cursor_key(query, sys)?;
        return Ok(Some((meta, *inclusive)));
    }

    Err(SdJournalError::InvalidQuery {
        reason: "unsupported cursor format".to_string(),
    })
}

fn resolve_systemd_cursor_key(
    query: &JournalQuery,
    sys: &crate::cursor::SystemdCursor,
) -> Result<EntryMeta> {
    match find_exact_systemd_cursor(query, sys) {
        Ok(Some(meta)) => return Ok(meta),
        Ok(None) => {}
        Err(e) => {
            if sys.realtime_usec.is_none() {
                return Err(e);
            }
        }
    }

    let realtime_usec = sys.realtime_usec.ok_or(SdJournalError::NotFound)?;
    Ok(EntryMeta {
        file_id: [0u8; 16],
        entry_offset: 0,
        seqnum: sys.seqnum.unwrap_or(0),
        realtime_usec,
    })
}

fn find_exact_systemd_cursor(
    query: &JournalQuery,
    sys: &crate::cursor::SystemdCursor,
) -> Result<Option<EntryMeta>> {
    let mut candidates: Vec<&crate::file::JournalFile> = Vec::new();
    if let Some(seqnum_id) = sys.seqnum_id {
        for f in &query.journal.inner.files {
            if f.seqnum_id() == seqnum_id {
                candidates.push(f);
            }
        }
        if candidates.is_empty() {
            candidates.extend(query.journal.inner.files.iter());
        }
    } else {
        candidates.extend(query.journal.inner.files.iter());
    }

    let mut first_error: Option<SdJournalError> = None;

    for file in candidates {
        match find_exact_systemd_cursor_in_file(file, sys) {
            Ok(Some(meta)) => return Ok(Some(meta)),
            Ok(None) => {}
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    match first_error {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

fn find_exact_systemd_cursor_in_file(
    file: &crate::file::JournalFile,
    sys: &crate::cursor::SystemdCursor,
) -> Result<Option<EntryMeta>> {
    if let Some(seqnum_id) = sys.seqnum_id
        && file.seqnum_id() != seqnum_id
    {
        return Ok(None);
    }

    let iter = file.entry_iter_seek_realtime(false, sys.realtime_usec, None)?;
    for item in iter {
        let meta = item?;

        if let Some(want_realtime) = sys.realtime_usec
            && meta.realtime_usec != want_realtime
        {
            continue;
        }
        if let Some(want_seqnum) = sys.seqnum
            && meta.seqnum != want_seqnum
        {
            continue;
        }

        let fields = file.read_entry_cursor_fields(meta.entry_offset)?;

        if let Some(want_realtime) = sys.realtime_usec
            && fields.realtime_usec != want_realtime
        {
            continue;
        }
        if let Some(want_seqnum) = sys.seqnum
            && fields.seqnum != want_seqnum
        {
            continue;
        }
        if let Some(want_boot_id) = sys.boot_id
            && fields.boot_id != want_boot_id
        {
            continue;
        }
        if let Some(want_monotonic) = sys.monotonic_usec
            && fields.monotonic_usec != want_monotonic
        {
            continue;
        }
        if let Some(want_xor) = sys.xor_hash
            && fields.xor_hash != want_xor
        {
            continue;
        }

        return Ok(Some(meta));
    }

    Ok(None)
}

fn term_matches(entry: &EntryOwned, term: &MatchTerm) -> bool {
    match term {
        MatchTerm::Exact { field, value, .. } => entry
            .iter_fields()
            .any(|(k, v)| k == field.as_str() && v == value.as_slice()),
        MatchTerm::Present { field } => entry.get(field).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JournalConfig;
    use crate::journal::JournalInner;
    use std::sync::Arc;

    fn empty_journal_with_config(config: JournalConfig) -> Journal {
        Journal {
            inner: Arc::new(JournalInner {
                config,
                roots: Vec::new(),
                files: Vec::new(),
            }),
        }
    }

    #[test]
    fn invalid_field_name_rejected_on_iter() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.match_exact("BAD=FIELD", b"x");
        match q.iter() {
            Ok(_) => panic!("expected InvalidQuery"),
            Err(err) => assert!(matches!(err, SdJournalError::InvalidQuery { .. })),
        }
    }

    #[test]
    fn too_many_terms_rejected_on_iter() {
        let cfg = JournalConfig {
            max_query_terms: 1,
            ..Default::default()
        };
        let journal = empty_journal_with_config(cfg);
        let mut q = JournalQuery::new(journal);
        q.match_present("A");
        q.match_present("B");
        match q.iter() {
            Ok(_) => panic!("expected QueryTerms limit error"),
            Err(err) => assert!(matches!(
                err,
                SdJournalError::LimitExceeded {
                    kind: LimitKind::QueryTerms,
                    ..
                }
            )),
        }
    }

    #[test]
    fn match_unit_builds_three_or_branches() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.match_present("PRIORITY");
        q.match_unit("sshd.service");

        assert_eq!(q.or_groups.len(), 3);
        let branches = build_branches(&q);
        assert_eq!(branches.len(), 3);
        for b in &branches {
            assert_eq!(b.len(), 2);
            assert!(matches!(&b[0], MatchTerm::Present { field } if field == "PRIORITY"));
        }

        let unit_fields: std::collections::BTreeSet<&str> = branches
            .iter()
            .map(|b| match &b[1] {
                MatchTerm::Exact {
                    field,
                    value,
                    payload,
                } => {
                    assert_eq!(value, b"sshd.service");
                    let expected = [field.as_bytes(), b"=", value.as_slice()].concat();
                    assert_eq!(payload, &expected);
                    field.as_str()
                }
                _ => panic!("expected exact unit match term"),
            })
            .collect();
        assert_eq!(
            unit_fields,
            std::collections::BTreeSet::from(["_SYSTEMD_UNIT", "OBJECT_SYSTEMD_UNIT", "UNIT"])
        );
    }

    #[test]
    fn match_unit_distributes_over_existing_or_groups() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.or_group(|g| {
            g.match_present("A");
        });
        q.or_group(|g| {
            g.match_present("B");
        });
        q.match_unit("foo.service");

        assert_eq!(q.or_groups.len(), 6);
        for g in &q.or_groups {
            assert_eq!(g.len(), 2);
            assert!(matches!(&g[0], MatchTerm::Present { .. }));
            assert!(matches!(&g[1], MatchTerm::Exact { .. }));
        }

        let mut a = 0usize;
        let mut b = 0usize;
        for g in &q.or_groups {
            match &g[0] {
                MatchTerm::Present { field } if field == "A" => a += 1,
                MatchTerm::Present { field } if field == "B" => b += 1,
                _ => panic!("unexpected first term"),
            }
        }
        assert_eq!(a, 3);
        assert_eq!(b, 3);
    }

    #[test]
    fn match_unit_respects_max_query_terms() {
        let cfg = JournalConfig {
            max_query_terms: 2,
            ..Default::default()
        };
        let journal = empty_journal_with_config(cfg);
        let mut q = JournalQuery::new(journal);
        q.match_unit("sshd.service");

        assert!(q.too_many_terms);
        assert!(q.or_groups.is_empty());
    }
}
