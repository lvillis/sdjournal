mod decompress;
mod entries;
mod index;
mod iter;

use crate::config::JournalConfig;
#[cfg(feature = "mmap")]
use crate::config::MmapPolicy;
use crate::error::{LimitKind, Result, SdJournalError};
use crate::format::{Header, STATE_ARCHIVED};
#[cfg(feature = "mmap")]
use crate::format::{STATE_OFFLINE, STATE_ONLINE};
#[cfg(feature = "mmap")]
use crate::reader::MmapAccess;
use crate::reader::{ByteBuf, FileAccess};
use crate::util::checked_add_u64;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(feature = "tracing")]
use tracing::debug;

pub(crate) use self::iter::{
    DataEntryOffsetIter, EntryCursorFields, EntryMeta, EntryRange, FileEntryIter,
};

#[derive(Clone)]
pub(crate) struct JournalFile {
    inner: Arc<JournalFileInner>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LiveFileState {
    pub(crate) used_size: u64,
    pub(crate) n_entries: u64,
    pub(crate) entry_array_offset: u64,
    pub(crate) tail_object_offset: u64,
}

struct JournalFileInner {
    path: PathBuf,
    config: JournalConfig,
    header: Header,
    used_size: u64,
    access: Mutex<Access>,
}

#[derive(Clone)]
enum Access {
    #[cfg(feature = "mmap")]
    Mmap(MmapAccess),
    File(FileAccess),
}

impl JournalFile {
    pub(crate) fn open(path: PathBuf, config: &JournalConfig) -> Result<Self> {
        let file = Arc::new(File::open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                SdJournalError::PermissionDenied { path: path.clone() }
            } else {
                SdJournalError::io("open", Some(path.clone()), e)
            }
        })?);

        Self::open_from_file(path, file, config)
    }

    fn open_from_file(path: PathBuf, file: Arc<File>, config: &JournalConfig) -> Result<Self> {
        let file_len = file
            .metadata()
            .map_err(|e| SdJournalError::io("metadata", Some(path.clone()), e))?
            .len();

        let file_access = FileAccess::new(path.clone(), file.clone());
        let header_len = usize::try_from(file_len).unwrap_or(usize::MAX).min(272);
        let header_buf = file_access.read_known_valid(0, header_len)?;
        let header = Header::parse(header_buf.as_slice(), &path)?;
        let used_size = checked_add_u64(
            header.header_size,
            header.arena_size,
            "header_size+arena_size",
        )?;

        #[cfg(feature = "tracing")]
        debug!(
            path = %path.display(),
            state = header.state,
            compact = header.is_compact(),
            keyed_hash = header.is_keyed_hash(),
            sealed = header.is_sealed(),
            sealed_continuous = header.is_sealed_continuous(),
            compressed_xz = header.incompatible_flags & crate::format::HEADER_INCOMPATIBLE_COMPRESSED_XZ != 0,
            compressed_lz4 = header.incompatible_flags & crate::format::HEADER_INCOMPATIBLE_COMPRESSED_LZ4 != 0,
            compressed_zstd = header.incompatible_flags & crate::format::HEADER_INCOMPATIBLE_COMPRESSED_ZSTD != 0,
            file_len,
            used_size,
            "parsed journal header"
        );
        if used_size > file_len {
            return Err(SdJournalError::Transient {
                path: Some(path.clone()),
                reason: format!(
                    "file shorter than header reports (file_len={file_len}, used_size={used_size})"
                ),
            });
        }
        if header.state > STATE_ARCHIVED {
            return Err(SdJournalError::Corrupt {
                path: Some(path.clone()),
                offset: Some(16),
                reason: format!("unknown header state: {}", header.state),
            });
        }

        #[cfg(feature = "mmap")]
        let access: Access = {
            let use_mmap = match config.mmap_policy {
                MmapPolicy::Never => false,
                MmapPolicy::Auto => match header.state {
                    STATE_ONLINE => config.allow_mmap_online,
                    STATE_OFFLINE | STATE_ARCHIVED => true,
                    _ => false,
                },
            };

            if use_mmap {
                // SAFETY: Mapping a file is inherently `unsafe` because the file may change on disk.
                // We reduce risk by:
                // - validating `used_size <= file_len` before mapping;
                // - defaulting to mmap only for STATE_OFFLINE/STATE_ARCHIVED files unless explicitly enabled;
                // - performing bounds checks on every read.
                let mmap = unsafe { memmap2::MmapOptions::new().map(file.as_ref()) }
                    .map_err(|e| SdJournalError::io("mmap", Some(path.clone()), e))?;
                Access::Mmap(MmapAccess::new(path.clone(), file.clone(), Arc::new(mmap)))
            } else {
                Access::File(file_access)
            }
        };

        #[cfg(not(feature = "mmap"))]
        let access: Access = Access::File(file_access);

        Ok(Self {
            inner: Arc::new(JournalFileInner {
                path,
                config: config.clone(),
                header,
                used_size,
                access: Mutex::new(access),
            }),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.inner.path
    }

    pub(crate) fn file_id(&self) -> [u8; 16] {
        self.inner.header.file_id
    }

    pub(crate) fn seqnum_id(&self) -> [u8; 16] {
        self.inner.header.seqnum_id
    }

    pub(crate) fn entry_range(&self) -> Result<Option<EntryRange>> {
        if self.inner.header.n_entries == 0 || self.inner.header.entry_array_offset == 0 {
            return Ok(None);
        }

        let Some(first) = self.first_entry_meta_from_entry_arrays()? else {
            return Ok(None);
        };

        let last = match self.fast_tail_entry_meta() {
            Ok(Some(meta)) => meta,
            Ok(None) | Err(_) => match self.last_entry_meta_from_entry_arrays()? {
                Some(meta) => meta,
                None => first,
            },
        };

        Ok(Some(EntryRange { first, last }))
    }

    fn first_entry_meta_from_entry_arrays(&self) -> Result<Option<EntryMeta>> {
        let mut current = self.inner.header.entry_array_offset;
        let mut steps = 0usize;

        while current != 0 {
            let items = self.read_entry_array_items(current)?;
            if let Some(offset) = items.into_iter().find(|offset| *offset != 0) {
                return Ok(Some(self.read_entry_meta(offset)?));
            }

            current = self.next_entry_array_offset_checked(current, &mut steps)?;
        }

        Ok(None)
    }

    fn last_entry_meta_from_entry_arrays(&self) -> Result<Option<EntryMeta>> {
        let mut current = self.inner.header.entry_array_offset;
        let mut last_offset = None;
        let mut steps = 0usize;

        while current != 0 {
            let items = self.read_entry_array_items(current)?;
            if let Some(offset) = items.into_iter().rev().find(|offset| *offset != 0) {
                last_offset = Some(offset);
            }

            current = self.next_entry_array_offset_checked(current, &mut steps)?;
        }

        last_offset
            .map(|offset| self.read_entry_meta(offset))
            .transpose()
    }

    fn next_entry_array_offset_checked(&self, current: u64, steps: &mut usize) -> Result<u64> {
        let next = self.read_entry_array_next_offset(current)?;
        *steps = steps.saturating_add(1);
        if *steps > self.inner.config.max_object_chain_steps {
            return Err(SdJournalError::LimitExceeded {
                kind: LimitKind::ObjectChainSteps,
                limit: u64::try_from(self.inner.config.max_object_chain_steps).unwrap_or(u64::MAX),
            });
        }
        Ok(next)
    }

    fn fast_tail_entry_meta(&self) -> Result<Option<EntryMeta>> {
        if let Some(offset) = self
            .inner
            .header
            .tail_entry_offset
            .filter(|offset| *offset != 0)
        {
            let meta = self.read_entry_meta(offset)?;
            if self.tail_meta_matches_header(meta) {
                return Ok(Some(meta));
            }
        }

        if self.inner.header.tail_object_offset == 0 {
            return Ok(None);
        }

        let meta = self.read_entry_meta(self.inner.header.tail_object_offset)?;
        Ok(self.tail_meta_matches_header(meta).then_some(meta))
    }

    fn tail_meta_matches_header(&self, meta: EntryMeta) -> bool {
        if let Some(seqnum) = self
            .inner
            .header
            .tail_entry_seqnum
            .filter(|seqnum| *seqnum != 0)
            && meta.seqnum != seqnum
        {
            return false;
        }

        if let Some(realtime_usec) = self
            .inner
            .header
            .tail_entry_realtime
            .filter(|realtime_usec| *realtime_usec != 0)
            && meta.realtime_usec != realtime_usec
        {
            return false;
        }

        true
    }

    pub(crate) fn live_state(&self) -> LiveFileState {
        LiveFileState {
            used_size: self.inner.used_size,
            n_entries: self.inner.header.n_entries,
            entry_array_offset: self.inner.header.entry_array_offset,
            tail_object_offset: self.inner.header.tail_object_offset,
        }
    }

    pub(crate) fn max_object_chain_steps(&self) -> usize {
        self.inner.config.max_object_chain_steps
    }

    #[cfg(feature = "verify-seal")]
    pub(crate) fn header(&self) -> &Header {
        &self.inner.header
    }

    #[cfg(feature = "verify-seal")]
    pub(crate) fn used_size(&self) -> u64 {
        self.inner.used_size
    }

    #[cfg(feature = "verify-seal")]
    pub(crate) fn config(&self) -> &JournalConfig {
        &self.inner.config
    }

    pub(crate) fn entry_iter_seek_realtime(
        &self,
        reverse: bool,
        since_realtime: Option<u64>,
        until_realtime: Option<u64>,
    ) -> Result<FileEntryIter> {
        FileEntryIter::new_with_seek_realtime(self.clone(), reverse, since_realtime, until_realtime)
    }

    pub(crate) fn read_bytes(&self, offset: u64, len: usize) -> Result<ByteBuf> {
        let end = checked_add_u64(offset, u64::try_from(len).unwrap_or(u64::MAX), "read range")?;
        if end > self.inner.used_size {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(offset),
                reason: "read out of bounds".to_string(),
            });
        }

        let access = self
            .inner
            .access
            .lock()
            .map_err(|_| SdJournalError::Io {
                op: "lock",
                path: Some(self.inner.path.clone()),
                source: std::io::Error::other("poisoned lock"),
            })?
            .clone();

        match access {
            Access::File(access) => access.read_known_valid(offset, len),
            #[cfg(feature = "mmap")]
            Access::Mmap(access) => access.read_known_valid(offset, len),
        }
    }

    pub(crate) fn read_object(&self, offset: u64, size: u64) -> Result<ByteBuf> {
        let max = usize::try_from(self.inner.config.max_object_size_bytes).unwrap_or(usize::MAX);
        let size_usize = usize::try_from(size).map_err(|_| SdJournalError::LimitExceeded {
            kind: LimitKind::ObjectSizeBytes,
            limit: self.inner.config.max_object_size_bytes,
        })?;
        crate::util::ensure_limit_usize(LimitKind::ObjectSizeBytes, max, size_usize)?;
        self.read_bytes(offset, size_usize)
    }
}
