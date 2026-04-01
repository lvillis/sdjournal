use super::cursor::build_cursor_key;
use super::{JournalQuery, MatchTerm, build_branches, term_matches};
use crate::entry::EntryRef;
use crate::error::{Result, SdJournalError};
use crate::file::{DataEntryOffsetIter, DataObjectRef, EntryMeta, FileEntryIter};
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

pub(super) struct JournalIter {
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
    pub(super) fn new(query: JournalQuery) -> Result<Self> {
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
