use super::cursor::build_cursor_key;
use super::{JournalQuery, MatchTerm, build_branches, term_matches};
use crate::cursor::Cursor;
use crate::entry::EntryRef;
use crate::error::{Result, SdJournalError};
use crate::file::{DataEntryOffsetIter, EntryMeta, FileEntryIter};
use crate::journal::{JournalFileInfo, journal_from_open_files};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

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
    iters: Vec<OffsetIter>,
    cursors: Vec<Option<u64>>,
    initialized: bool,
    pending_error: Option<SdJournalError>,
    done: bool,
}

impl AndOffsetIter {
    fn new(iters: Vec<OffsetIter>, reverse: bool) -> Self {
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

enum OffsetIter {
    Single(DataEntryOffsetIter),
    Or(OffsetOrIter),
}

impl Iterator for OffsetIter {
    type Item = Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            OffsetIter::Single(iter) => iter.next(),
            OffsetIter::Or(iter) => iter.next(),
        }
    }
}

struct OffsetOrIter {
    reverse: bool,
    forward_heap: BinaryHeap<Reverse<OffsetHeapItem>>,
    reverse_heap: BinaryHeap<OffsetHeapItem>,
    iters: Vec<DataEntryOffsetIter>,
    pending_errors: Vec<SdJournalError>,
    last_emitted: Option<u64>,
    done: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct OffsetHeapItem {
    offset: u64,
    iter_idx: usize,
}

impl PartialOrd for OffsetHeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OffsetHeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.offset
            .cmp(&other.offset)
            .then_with(|| self.iter_idx.cmp(&other.iter_idx))
    }
}

impl OffsetOrIter {
    fn new(mut iters: Vec<DataEntryOffsetIter>, reverse: bool) -> Self {
        let mut pending_errors = Vec::new();
        let mut forward_heap = BinaryHeap::new();
        let mut reverse_heap = BinaryHeap::new();

        for (idx, iter) in iters.iter_mut().enumerate() {
            if let Some(offset) = next_ok_offset(iter, &mut pending_errors) {
                let item = OffsetHeapItem {
                    offset,
                    iter_idx: idx,
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
            last_emitted: None,
            done: false,
        }
    }

    fn pop_next(&mut self) -> Option<OffsetHeapItem> {
        if self.reverse {
            self.reverse_heap.pop()
        } else {
            self.forward_heap.pop().map(|r| r.0)
        }
    }

    fn push_next(&mut self, item: OffsetHeapItem) {
        if self.reverse {
            self.reverse_heap.push(item);
        } else {
            self.forward_heap.push(Reverse(item));
        }
    }
}

impl Iterator for OffsetOrIter {
    type Item = Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if let Some(err) = self.pending_errors.pop() {
            return Some(Err(err));
        }

        loop {
            let item = match self.pop_next() {
                Some(item) => item,
                None => {
                    self.done = true;
                    return None;
                }
            };

            if let Some(offset) =
                next_ok_offset(&mut self.iters[item.iter_idx], &mut self.pending_errors)
            {
                self.push_next(OffsetHeapItem {
                    offset,
                    iter_idx: item.iter_idx,
                });
            }

            if self.last_emitted == Some(item.offset) {
                continue;
            }

            self.last_emitted = Some(item.offset);
            return Some(Ok(item.offset));
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

        let mut data_refs = Vec::new();
        for t in &exact_terms {
            let payload = match t {
                MatchTerm::Exact { payload, .. } => payload.as_slice(),
                _ => continue,
            };

            match file.find_data_objects(payload) {
                Ok(refs) if refs.is_empty() => {
                    return Ok(Self {
                        file,
                        kind: BranchKind::Empty,
                    });
                }
                Ok(refs) => data_refs.push(refs),
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

        data_refs.sort_by_key(|refs| {
            refs.iter()
                .fold(0u64, |total, data| total.saturating_add(data.n_entries))
        });

        let mut iters = Vec::with_capacity(data_refs.len());
        for refs in data_refs {
            let mut term_iters = Vec::with_capacity(refs.len());
            for data_ref in refs {
                match file.data_entry_offsets(data_ref, reverse) {
                    Ok(iter) => term_iters.push(iter),
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
            match term_iters.len() {
                0 => {
                    return Ok(Self {
                        file,
                        kind: BranchKind::Empty,
                    });
                }
                1 => iters.push(OffsetIter::Single(
                    term_iters.pop().expect("single term iterator is available"),
                )),
                _ => iters.push(OffsetIter::Or(OffsetOrIter::new(term_iters, reverse))),
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

pub(super) enum JournalIter {
    Eager(EagerJournalIter),
    Lazy(LazyJournalIter),
}

impl JournalIter {
    pub(super) fn new(query: JournalQuery) -> Result<Self> {
        if query.journal.inner.is_lazy() {
            LazyJournalIter::new(query).map(JournalIter::Lazy)
        } else {
            EagerJournalIter::new(query).map(JournalIter::Eager)
        }
    }
}

impl Iterator for JournalIter {
    type Item = Result<EntryRef>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            JournalIter::Eager(iter) => iter.next(),
            JournalIter::Lazy(iter) => iter.next(),
        }
    }
}

pub(super) struct EagerJournalIter {
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
    iter_idx: usize,
    file_idx: usize,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.meta == other.meta
            && self.iter_idx == other.iter_idx
            && self.file_idx == other.file_idx
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

fn matching_file_indexes(
    query: &JournalQuery,
    cursor_key: Option<(EntryMeta, bool)>,
) -> Vec<usize> {
    (0..query.journal.inner.file_count())
        .filter(|idx| {
            let Some(info) = query.journal.inner.file_info(*idx) else {
                return false;
            };
            info_may_match_query(query, cursor_key, info)
        })
        .collect()
}

fn info_may_match_query(
    query: &JournalQuery,
    cursor_key: Option<(EntryMeta, bool)>,
    info: &JournalFileInfo,
) -> bool {
    if !info.entry_range_known {
        return true;
    }

    let Some(range) = info.entry_range else {
        return false;
    };

    if let Some(since) = query.since_realtime
        && range.last.realtime_usec < since
    {
        return false;
    }
    if let Some(until) = query.until_realtime
        && range.first.realtime_usec > until
    {
        return false;
    }
    if let Some((cursor, inclusive)) = cursor_key {
        let ord = range.last.cmp_key(&cursor);
        if inclusive {
            if ord == std::cmp::Ordering::Less {
                return false;
            }
        } else if ord != std::cmp::Ordering::Greater {
            return false;
        }
    }

    true
}

impl EagerJournalIter {
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
        let file_indexes = matching_file_indexes(&query, cursor_key);

        let mut iters = Vec::with_capacity(file_indexes.len());
        let mut iter_file_indexes = Vec::with_capacity(file_indexes.len());
        for file_idx in file_indexes.iter().copied() {
            let file = match query.journal.inner.open_file_by_index(file_idx) {
                Ok(file) => file,
                Err(e) => {
                    pending_errors.push(e);
                    continue;
                }
            };
            let mut branch_iters = Vec::with_capacity(branches.len());
            for terms in &branches {
                match FileBranchIter::new(
                    file.clone(),
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
            iter_file_indexes.push(file_idx);
        }

        let mut forward_heap: BinaryHeap<Reverse<HeapItem>> = BinaryHeap::new();
        let mut reverse_heap: BinaryHeap<HeapItem> = BinaryHeap::new();

        for (idx, it) in iters.iter_mut().enumerate() {
            if let Some(meta) = next_ok_meta(it, &mut pending_errors) {
                let item = HeapItem {
                    meta,
                    iter_idx: idx,
                    file_idx: iter_file_indexes[idx],
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

impl Iterator for EagerJournalIter {
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
                next_ok_meta(&mut self.iters[item.iter_idx], &mut self.pending_errors)
            {
                self.push_next(HeapItem {
                    meta: next_meta,
                    iter_idx: item.iter_idx,
                    file_idx: item.file_idx,
                });
            }

            if !self.passes_filters(&item.meta) {
                continue;
            }

            if self.last_emitted == Some(item.meta) {
                continue;
            }

            let file = match self.query.journal.inner.open_file_by_index(item.file_idx) {
                Ok(file) => file,
                Err(e) => {
                    self.pending_errors.push(e);
                    if let Some(err) = self.pending_errors.pop() {
                        return Some(Err(err));
                    }
                    continue;
                }
            };
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

pub(super) struct LazyJournalIter {
    query: JournalQuery,
    cursor_key: Option<(EntryMeta, bool)>,
    produced: usize,
    last_emitted: Option<EntryMeta>,
    forward_heap: BinaryHeap<Reverse<LazyHeapItem>>,
    reverse_heap: BinaryHeap<LazyHeapItem>,
    cache: LazyFileCache,
    pending_errors: Vec<SdJournalError>,
    done: bool,
}

struct LazyFileCache {
    capacity: usize,
    clock: u64,
    entries: Vec<LazyFileCursor>,
}

struct LazyFileCursor {
    file_idx: usize,
    last_used: u64,
    iter: EagerJournalIter,
}

struct LazyHeapItem {
    meta: EntryMeta,
    entry: EntryRef,
    file_idx: usize,
}

impl PartialEq for LazyHeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.meta == other.meta && self.file_idx == other.file_idx
    }
}

impl Eq for LazyHeapItem {}

impl PartialOrd for LazyHeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LazyHeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.meta
            .cmp_key(&other.meta)
            .then_with(|| self.file_idx.cmp(&other.file_idx))
    }
}

impl LazyFileCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            clock: 0,
            entries: Vec::new(),
        }
    }

    fn next_entry(
        &mut self,
        query: &JournalQuery,
        file_idx: usize,
        cursor_key: Option<(EntryMeta, bool)>,
        after_meta: Option<EntryMeta>,
    ) -> Result<Option<EntryRef>> {
        self.clock = self.clock.saturating_add(1);

        if let Some(pos) = self
            .entries
            .iter()
            .position(|entry| entry.file_idx == file_idx)
        {
            let result =
                next_entry_from_file_iter(&mut self.entries[pos].iter, query.reverse, after_meta);
            return match result {
                Ok(Some(entry)) => {
                    self.entries[pos].last_used = self.clock;
                    Ok(Some(entry))
                }
                Ok(None) => {
                    self.entries.swap_remove(pos);
                    Ok(None)
                }
                Err(err) => {
                    self.entries.swap_remove(pos);
                    Err(err)
                }
            };
        }

        let mut iter = build_lazy_file_iter(query, file_idx, cursor_key, after_meta)?;
        match next_entry_from_file_iter(&mut iter, query.reverse, after_meta) {
            Ok(Some(entry)) => {
                self.insert(file_idx, iter);
                Ok(Some(entry))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn insert(&mut self, file_idx: usize, iter: EagerJournalIter) {
        if self.entries.len() >= self.capacity
            && let Some((idx, _)) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_used)
        {
            self.entries.swap_remove(idx);
        }

        self.entries.push(LazyFileCursor {
            file_idx,
            last_used: self.clock,
            iter,
        });
    }
}

impl LazyJournalIter {
    fn new(query: JournalQuery) -> Result<Self> {
        if matches!(query.limit, Some(0)) {
            return Ok(Self {
                query,
                cursor_key: None,
                produced: 0,
                last_emitted: None,
                forward_heap: BinaryHeap::new(),
                reverse_heap: BinaryHeap::new(),
                cache: LazyFileCache::new(1),
                pending_errors: Vec::new(),
                done: true,
            });
        }

        let cursor_key = build_cursor_key(&query)?;
        let mut pending_errors = Vec::new();
        let mut forward_heap = BinaryHeap::new();
        let mut reverse_heap = BinaryHeap::new();
        let mut cache = LazyFileCache::new(query.journal.inner.config.max_open_files);
        let file_indexes = matching_file_indexes(&query, cursor_key);

        for file_idx in file_indexes {
            match cache.next_entry(&query, file_idx, cursor_key, None) {
                Ok(Some(entry)) => {
                    let item = LazyHeapItem {
                        meta: meta_from_entry_ref(&entry),
                        entry,
                        file_idx,
                    };
                    if query.reverse {
                        reverse_heap.push(item);
                    } else {
                        forward_heap.push(Reverse(item));
                    }
                }
                Ok(None) => {}
                Err(err) => pending_errors.push(err),
            }
        }

        Ok(Self {
            query,
            cursor_key,
            produced: 0,
            last_emitted: None,
            forward_heap,
            reverse_heap,
            cache,
            pending_errors,
            done: false,
        })
    }

    fn pop_next(&mut self) -> Option<LazyHeapItem> {
        if self.query.reverse {
            self.reverse_heap.pop()
        } else {
            self.forward_heap.pop().map(|r| r.0)
        }
    }

    fn push_next(&mut self, item: LazyHeapItem) {
        if self.query.reverse {
            self.reverse_heap.push(item);
        } else {
            self.forward_heap.push(Reverse(item));
        }
    }
}

impl Iterator for LazyJournalIter {
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

            match self.cache.next_entry(
                &self.query,
                item.file_idx,
                self.cursor_key,
                Some(item.meta),
            ) {
                Ok(Some(entry)) => {
                    self.push_next(LazyHeapItem {
                        meta: meta_from_entry_ref(&entry),
                        entry,
                        file_idx: item.file_idx,
                    });
                }
                Ok(None) => {}
                Err(err) => self.pending_errors.push(err),
            }

            if self.last_emitted == Some(item.meta) {
                continue;
            }

            self.last_emitted = Some(item.meta);
            self.produced = self.produced.saturating_add(1);
            return Some(Ok(item.entry));
        }
    }
}

fn build_lazy_file_iter(
    query: &JournalQuery,
    file_idx: usize,
    cursor_key: Option<(EntryMeta, bool)>,
    after_meta: Option<EntryMeta>,
) -> Result<EagerJournalIter> {
    let file = query.journal.inner.open_file_by_index(file_idx)?;
    let journal = journal_from_open_files(query.journal.inner.config.clone(), vec![file])?;
    let mut q = query.clone();
    q.journal = journal;
    q.limit = None;

    if query.reverse {
        if let Some((meta, inclusive)) = cursor_key {
            q.cursor_start = Some((cursor_from_meta(meta), inclusive));
        }
    } else if let Some(meta) = after_meta {
        q.cursor_start = Some((cursor_from_meta(meta), false));
    } else if let Some((meta, inclusive)) = cursor_key {
        q.cursor_start = Some((cursor_from_meta(meta), inclusive));
    }

    EagerJournalIter::new(q)
}

fn next_entry_from_file_iter(
    iter: &mut EagerJournalIter,
    reverse: bool,
    after_meta: Option<EntryMeta>,
) -> Result<Option<EntryRef>> {
    for item in iter {
        let entry = item?;
        let meta = meta_from_entry_ref(&entry);
        if let Some(after_meta) = after_meta {
            let ord = meta.cmp_key(&after_meta);
            if reverse {
                if ord != std::cmp::Ordering::Less {
                    continue;
                }
            } else if ord != std::cmp::Ordering::Greater {
                continue;
            }
        }
        return Ok(Some(entry));
    }

    Ok(None)
}

fn cursor_from_meta(meta: EntryMeta) -> Cursor {
    Cursor::new_entry_key(
        meta.file_id,
        meta.entry_offset,
        meta.seqnum,
        meta.realtime_usec,
    )
}

fn meta_from_entry_ref(entry: &EntryRef) -> EntryMeta {
    EntryMeta {
        file_id: entry.file_id_raw(),
        entry_offset: entry.entry_offset_raw(),
        seqnum: entry.seqnum(),
        realtime_usec: entry.realtime_usec(),
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

fn next_ok_offset<I>(it: &mut I, pending: &mut Vec<SdJournalError>) -> Option<u64>
where
    I: Iterator<Item = Result<u64>>,
{
    for item in it.by_ref() {
        match item {
            Ok(offset) => return Some(offset),
            Err(e) => pending.push(e),
        }
    }
    None
}
