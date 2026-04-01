use super::JournalFile;
use super::index::DataObjectRef;
use crate::error::{LimitKind, Result, SdJournalError};
use crate::format::{OBJECT_ENTRY_ARRAY, ObjectHeader};
use crate::util::{read_u32_le, read_u64_le};
use std::cmp::Ordering;
use std::collections::VecDeque;

pub(crate) struct DataEntryOffsetIter {
    file: JournalFile,
    reverse: bool,
    first_entry_offset: u64,
    first_pending: bool,
    arrays: Vec<u64>,
    current_array_idx: isize,
    current_items: VecDeque<u64>,
    arrays_exhausted: bool,
    exhausted: bool,
}

impl DataEntryOffsetIter {
    pub(crate) fn new(file: JournalFile, data: DataObjectRef, reverse: bool) -> Result<Self> {
        let mut arrays = Vec::new();
        let mut next = data.entry_array_offset;
        let mut steps = 0usize;

        while next != 0 {
            arrays.push(next);
            next = read_entry_array_next_offset(&file, next)?;

            steps = steps.saturating_add(1);
            if steps > file.inner.config.max_object_chain_steps {
                return Err(SdJournalError::LimitExceeded {
                    kind: LimitKind::ObjectChainSteps,
                    limit: u64::try_from(file.inner.config.max_object_chain_steps)
                        .unwrap_or(u64::MAX),
                });
            }
        }

        let current_array_idx = if reverse {
            isize::try_from(arrays.len()).unwrap_or(0) - 1
        } else {
            0
        };

        Ok(Self {
            file,
            reverse,
            first_entry_offset: data.entry_offset,
            first_pending: true,
            arrays,
            current_array_idx,
            current_items: VecDeque::new(),
            arrays_exhausted: false,
            exhausted: false,
        })
    }

    fn refill(&mut self) -> Result<()> {
        if !self.current_items.is_empty() || self.arrays_exhausted {
            return Ok(());
        }

        if self.arrays.is_empty() {
            self.arrays_exhausted = true;
            return Ok(());
        }

        let idx = usize::try_from(self.current_array_idx).ok();
        let idx = match idx {
            Some(idx) if idx < self.arrays.len() => idx,
            _ => {
                self.arrays_exhausted = true;
                return Ok(());
            }
        };

        let array_offset = self.arrays[idx];
        let array = read_entry_array_object(&self.file, array_offset)?;
        let mut items = array.items;

        while matches!(items.last(), Some(0)) {
            items.pop();
        }

        if self.reverse {
            items.reverse();
            self.current_array_idx -= 1;
        } else {
            self.current_array_idx += 1;
        }

        self.current_items = items.into();
        Ok(())
    }
}

impl Iterator for DataEntryOffsetIter {
    type Item = Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }

        if !self.reverse && self.first_pending {
            self.first_pending = false;
            if self.first_entry_offset != 0 {
                return Some(Ok(self.first_entry_offset));
            }
        }

        loop {
            if let Err(e) = self.refill() {
                self.exhausted = true;
                return Some(Err(e));
            }

            match self.current_items.pop_front() {
                Some(0) => continue,
                Some(off) => return Some(Ok(off)),
                None => {
                    if self.arrays_exhausted {
                        break;
                    }
                    continue;
                }
            }
        }

        if self.reverse && self.first_pending {
            self.first_pending = false;
            if self.first_entry_offset != 0 {
                return Some(Ok(self.first_entry_offset));
            }
        }

        self.exhausted = true;
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntryMeta {
    pub(crate) file_id: [u8; 16],
    pub(crate) entry_offset: u64,
    pub(crate) seqnum: u64,
    pub(crate) realtime_usec: u64,
}

impl EntryMeta {
    pub(crate) fn cmp_key(&self, other: &EntryMeta) -> Ordering {
        self.realtime_usec
            .cmp(&other.realtime_usec)
            .then_with(|| self.seqnum.cmp(&other.seqnum))
            .then_with(|| self.file_id.cmp(&other.file_id))
            .then_with(|| self.entry_offset.cmp(&other.entry_offset))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EntryCursorFields {
    pub(crate) seqnum: u64,
    pub(crate) realtime_usec: u64,
    pub(crate) monotonic_usec: u64,
    pub(crate) boot_id: [u8; 16],
    pub(crate) xor_hash: u64,
}

pub(crate) struct FileEntryIter {
    file: JournalFile,
    reverse: bool,
    arrays: Vec<u64>,
    current_array_idx: isize,
    current_items: VecDeque<u64>,
    exhausted: bool,
}

impl FileEntryIter {
    pub(crate) fn new_with_seek_realtime(
        file: JournalFile,
        reverse: bool,
        since_realtime: Option<u64>,
        until_realtime: Option<u64>,
    ) -> Result<Self> {
        let mut arrays = Vec::new();
        let mut next = file.inner.header.entry_array_offset;
        let mut steps = 0usize;

        while next != 0 {
            arrays.push(next);
            next = read_entry_array_next_offset(&file, next)?;

            steps = steps.saturating_add(1);
            if steps > file.inner.config.max_object_chain_steps {
                return Err(SdJournalError::LimitExceeded {
                    kind: LimitKind::ObjectChainSteps,
                    limit: u64::try_from(file.inner.config.max_object_chain_steps)
                        .unwrap_or(u64::MAX),
                });
            }
        }

        let seek_time = if reverse {
            until_realtime
        } else {
            since_realtime
        };
        if seek_time.is_none() || arrays.is_empty() {
            let current_array_idx = if reverse {
                isize::try_from(arrays.len()).unwrap_or(0) - 1
            } else {
                0
            };

            return Ok(Self {
                file,
                reverse,
                arrays,
                current_array_idx,
                current_items: VecDeque::new(),
                exhausted: false,
            });
        }

        let seek_time = seek_time.unwrap_or(0);

        let mut left = 0usize;
        let mut right = arrays.len();
        while left < right {
            let mid = (left + right) / 2;
            let array = read_entry_array_object(&file, arrays[mid])?;
            let mut items = array.items;
            while matches!(items.last(), Some(0)) {
                items.pop();
            }
            let last_off = match items.last().copied() {
                Some(v) => v,
                None => {
                    right = mid;
                    continue;
                }
            };

            let last_meta = file.read_entry_meta(last_off)?;
            if last_meta.realtime_usec < seek_time {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        if left >= arrays.len() {
            if reverse {
                let current_array_idx = isize::try_from(arrays.len()).unwrap_or(0) - 1;
                return Ok(Self {
                    file,
                    reverse,
                    arrays,
                    current_array_idx,
                    current_items: VecDeque::new(),
                    exhausted: false,
                });
            }

            return Ok(Self {
                file,
                reverse,
                arrays,
                current_array_idx: 0,
                current_items: VecDeque::new(),
                exhausted: true,
            });
        }

        let array_idx = left;
        let array = read_entry_array_object(&file, arrays[array_idx])?;
        let mut items = array.items;
        while matches!(items.last(), Some(0)) {
            items.pop();
        }

        if items.is_empty() {
            return Ok(Self {
                file,
                reverse,
                arrays,
                current_array_idx: 0,
                current_items: VecDeque::new(),
                exhausted: true,
            });
        }

        if reverse {
            let mut low = 0usize;
            let mut high = items.len();
            while low < high {
                let mid = (low + high) / 2;
                let meta = file.read_entry_meta(items[mid])?;
                if meta.realtime_usec <= seek_time {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }

            if low == 0 {
                if array_idx == 0 {
                    return Ok(Self {
                        file,
                        reverse,
                        arrays,
                        current_array_idx: 0,
                        current_items: VecDeque::new(),
                        exhausted: true,
                    });
                }

                let current_array_idx = isize::try_from(array_idx).unwrap_or(0) - 1;
                return Ok(Self {
                    file,
                    reverse,
                    arrays,
                    current_array_idx,
                    current_items: VecDeque::new(),
                    exhausted: false,
                });
            }

            let start_idx = low.saturating_sub(1);
            let mut slice = items[..=start_idx].to_vec();
            slice.reverse();
            let current_items: VecDeque<u64> = slice.into();
            let current_array_idx = isize::try_from(array_idx).unwrap_or(0) - 1;
            Ok(Self {
                file,
                reverse,
                arrays,
                current_array_idx,
                current_items,
                exhausted: false,
            })
        } else {
            let mut low = 0usize;
            let mut high = items.len();
            while low < high {
                let mid = (low + high) / 2;
                let meta = file.read_entry_meta(items[mid])?;
                if meta.realtime_usec < seek_time {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }

            if low >= items.len() {
                return Ok(Self {
                    file,
                    reverse,
                    arrays,
                    current_array_idx: isize::try_from(array_idx).unwrap_or(0) + 1,
                    current_items: VecDeque::new(),
                    exhausted: false,
                });
            }

            let current_items: VecDeque<u64> = items[low..].to_vec().into();
            let current_array_idx = isize::try_from(array_idx).unwrap_or(0) + 1;
            Ok(Self {
                file,
                reverse,
                arrays,
                current_array_idx,
                current_items,
                exhausted: false,
            })
        }
    }

    fn refill(&mut self) -> Result<()> {
        if !self.current_items.is_empty() || self.exhausted {
            return Ok(());
        }

        if self.arrays.is_empty() {
            self.exhausted = true;
            return Ok(());
        }

        let idx = usize::try_from(self.current_array_idx).ok();
        let idx = match idx {
            Some(idx) if idx < self.arrays.len() => idx,
            _ => {
                self.exhausted = true;
                return Ok(());
            }
        };

        let array_offset = self.arrays[idx];
        let array = read_entry_array_object(&self.file, array_offset)?;
        let mut items = array.items;

        while matches!(items.last(), Some(0)) {
            items.pop();
        }

        if self.reverse {
            items.reverse();
            self.current_array_idx -= 1;
        } else {
            self.current_array_idx += 1;
        }

        self.current_items = items.into();
        Ok(())
    }
}

impl Iterator for FileEntryIter {
    type Item = Result<EntryMeta>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }
        if let Err(e) = self.refill() {
            self.exhausted = true;
            return Some(Err(e));
        }
        let entry_offset = match self.current_items.pop_front() {
            Some(off) => off,
            None => {
                self.exhausted = true;
                return None;
            }
        };
        if entry_offset == 0 {
            return self.next();
        }
        Some(self.file.read_entry_meta(entry_offset))
    }
}

#[derive(Debug)]
struct EntryArrayObject {
    items: Vec<u64>,
}

fn read_entry_array_next_offset(file: &JournalFile, offset: u64) -> Result<u64> {
    let buf = file.read_bytes(offset, 24)?;
    let oh = ObjectHeader::parse(buf.as_slice(), file.path(), offset)?;
    if oh.object_type != OBJECT_ENTRY_ARRAY {
        return Err(SdJournalError::Corrupt {
            path: Some(file.inner.path.clone()),
            offset: Some(offset),
            reason: format!("expected ENTRY_ARRAY object, found type {}", oh.object_type),
        });
    }
    if oh.size < 24 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.inner.path.clone()),
            offset: Some(offset),
            reason: format!("ENTRY_ARRAY object too small: {}", oh.size),
        });
    }

    let next_entry_array_offset =
        read_u64_le(buf.as_slice(), 16).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(file.inner.path.clone()),
            offset: Some(offset + 16),
            reason: "missing next_entry_array_offset".to_string(),
        })?;

    Ok(next_entry_array_offset)
}

fn read_entry_array_object(file: &JournalFile, offset: u64) -> Result<EntryArrayObject> {
    let oh_bytes = file.read_bytes(offset, 24)?;
    let oh = ObjectHeader::parse(oh_bytes.as_slice(), file.path(), offset)?;
    if oh.object_type != OBJECT_ENTRY_ARRAY {
        return Err(SdJournalError::Corrupt {
            path: Some(file.inner.path.clone()),
            offset: Some(offset),
            reason: format!("expected ENTRY_ARRAY object, found type {}", oh.object_type),
        });
    }
    if oh.size < 24 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.inner.path.clone()),
            offset: Some(offset),
            reason: format!("ENTRY_ARRAY object too small: {}", oh.size),
        });
    }

    let obj = file.read_object(offset, oh.size)?;
    let obj = obj.as_slice();

    let items_bytes = obj.get(24..).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.inner.path.clone()),
        offset: Some(offset + 24),
        reason: "missing ENTRY_ARRAY items".to_string(),
    })?;

    let mut items = Vec::new();
    if file.inner.header.is_compact() {
        if items_bytes.len() % 4 != 0 {
            return Err(SdJournalError::Corrupt {
                path: Some(file.inner.path.clone()),
                offset: Some(offset),
                reason: "ENTRY_ARRAY compact items not aligned".to_string(),
            });
        }
        let mut i = 0;
        while i < items_bytes.len() {
            let off = read_u32_le(items_bytes, i).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(file.inner.path.clone()),
                offset: Some(offset),
                reason: "ENTRY_ARRAY item truncated".to_string(),
            })?;
            items.push(u64::from(off));
            i += 4;
        }
    } else {
        if items_bytes.len() % 8 != 0 {
            return Err(SdJournalError::Corrupt {
                path: Some(file.inner.path.clone()),
                offset: Some(offset),
                reason: "ENTRY_ARRAY regular items not aligned".to_string(),
            });
        }
        let mut i = 0;
        while i < items_bytes.len() {
            let off = read_u64_le(items_bytes, i).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(file.inner.path.clone()),
                offset: Some(offset),
                reason: "ENTRY_ARRAY item truncated".to_string(),
            })?;
            items.push(off);
            i += 8;
        }
    }

    Ok(EntryArrayObject { items })
}
