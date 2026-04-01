mod decompress;
mod entries;
mod index;
mod iter;

use crate::config::JournalConfig;
use crate::error::{LimitKind, Result, SdJournalError};
use crate::format::{Header, STATE_ARCHIVED};
#[cfg(feature = "mmap")]
use crate::format::{STATE_OFFLINE, STATE_ONLINE};
#[cfg(feature = "mmap")]
use crate::reader::MmapAccess;
use crate::reader::{ByteBuf, FileAccess, RandomAccess};
use crate::util::checked_add_u64;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(feature = "tracing")]
use tracing::debug;

pub(crate) use self::index::DataObjectRef;
pub(crate) use self::iter::{DataEntryOffsetIter, EntryCursorFields, EntryMeta, FileEntryIter};

#[derive(Clone)]
pub(crate) struct JournalFile {
    inner: Arc<JournalFileInner>,
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

        let file_len = file
            .metadata()
            .map_err(|e| SdJournalError::io("metadata", Some(path.clone()), e))?
            .len();

        let file_access = FileAccess::new(path.clone(), file.clone());
        let header_len = usize::try_from(file_len).unwrap_or(usize::MAX).min(272);
        let header_buf = file_access.read(0, header_len)?;
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
            let use_mmap = match header.state {
                STATE_ONLINE => config.allow_mmap_online,
                STATE_OFFLINE | STATE_ARCHIVED => true,
                _ => false,
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
            Access::File(access) => access.read(offset, len),
            #[cfg(feature = "mmap")]
            Access::Mmap(access) => match access.read(offset, len) {
                Ok(buf) => Ok(buf),
                Err(SdJournalError::Transient { .. }) => {
                    let file_access = FileAccess::new(self.inner.path.clone(), access.file());
                    {
                        let mut g = self.inner.access.lock().map_err(|_| SdJournalError::Io {
                            op: "lock",
                            path: Some(self.inner.path.clone()),
                            source: std::io::Error::other("poisoned lock"),
                        })?;
                        *g = Access::File(file_access.clone());
                    }
                    file_access.read(offset, len)
                }
                Err(e) => Err(e),
            },
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
