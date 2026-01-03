use crate::config::JournalConfig;
use crate::entry::{EntryOwned, EntryRef};
use crate::error::{CompressionAlgo, LimitKind, Result, SdJournalError};
use crate::reader::{ByteBuf, FileAccess, MmapAccess, RandomAccess};
use crate::util::{
    checked_add_u64, is_ascii_field_name, read_id128, read_u8, read_u32_le, read_u64_le,
};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(feature = "tracing")]
use tracing::debug;

const HEADER_SIGNATURE: &[u8; 8] = b"LPKSHHRH";

const HEADER_INCOMPATIBLE_COMPRESSED_XZ: u32 = 1 << 0;
const HEADER_INCOMPATIBLE_COMPRESSED_LZ4: u32 = 1 << 1;
const HEADER_INCOMPATIBLE_KEYED_HASH: u32 = 1 << 2;
const HEADER_INCOMPATIBLE_COMPRESSED_ZSTD: u32 = 1 << 3;
const HEADER_INCOMPATIBLE_COMPACT: u32 = 1 << 4;

#[cfg(any(feature = "tracing", feature = "verify-seal"))]
const HEADER_COMPATIBLE_SEALED: u32 = 1 << 0;
#[cfg(any(feature = "tracing", feature = "verify-seal"))]
const HEADER_COMPATIBLE_SEALED_CONTINUOUS: u32 = 1 << 2;

const KNOWN_INCOMPATIBLE_FLAGS: u32 = HEADER_INCOMPATIBLE_COMPRESSED_XZ
    | HEADER_INCOMPATIBLE_COMPRESSED_LZ4
    | HEADER_INCOMPATIBLE_KEYED_HASH
    | HEADER_INCOMPATIBLE_COMPRESSED_ZSTD
    | HEADER_INCOMPATIBLE_COMPACT;

const STATE_OFFLINE: u8 = 0;
const STATE_ONLINE: u8 = 1;
const STATE_ARCHIVED: u8 = 2;

const OBJECT_DATA: u8 = 1;
const OBJECT_ENTRY: u8 = 3;
const OBJECT_ENTRY_ARRAY: u8 = 6;

const OBJECT_COMPRESSED_XZ: u8 = 1 << 0;
const OBJECT_COMPRESSED_LZ4: u8 = 1 << 1;
const OBJECT_COMPRESSED_ZSTD: u8 = 1 << 2;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct Header {
    pub(crate) compatible_flags: u32,
    pub(crate) incompatible_flags: u32,
    pub(crate) state: u8,
    pub(crate) file_id: [u8; 16],
    pub(crate) machine_id: [u8; 16],
    pub(crate) boot_id: [u8; 16],
    pub(crate) seqnum_id: [u8; 16],
    pub(crate) header_size: u64,
    pub(crate) arena_size: u64,
    pub(crate) data_hash_table_offset: u64,
    pub(crate) data_hash_table_size: u64,
    pub(crate) field_hash_table_offset: u64,
    pub(crate) field_hash_table_size: u64,
    pub(crate) tail_object_offset: u64,
    pub(crate) n_entries: u64,
    pub(crate) entry_array_offset: u64,
}

impl Header {
    fn parse(buf: &[u8], path: &Path) -> Result<Self> {
        if buf.len() < 184 {
            return Err(SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
                offset: Some(0),
                reason: "file too small for journal header".to_string(),
            });
        }

        let sig = buf.get(0..8).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(0),
            reason: "missing signature".to_string(),
        })?;
        if sig != HEADER_SIGNATURE {
            return Err(SdJournalError::Unsupported {
                reason: "not a systemd journal file (bad signature)".to_string(),
            });
        }

        let compatible_flags = read_u32_le(buf, 8).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(8),
            reason: "missing compatible_flags".to_string(),
        })?;
        let incompatible_flags = read_u32_le(buf, 12).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(12),
            reason: "missing incompatible_flags".to_string(),
        })?;
        let state = read_u8(buf, 16).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(16),
            reason: "missing state".to_string(),
        })?;

        if incompatible_flags & !KNOWN_INCOMPATIBLE_FLAGS != 0 {
            return Err(SdJournalError::Unsupported {
                reason: format!("unknown incompatible flags: 0x{incompatible_flags:08x}"),
            });
        }

        let file_id = read_id128(buf, 24).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(24),
            reason: "missing file_id".to_string(),
        })?;
        let machine_id = read_id128(buf, 40).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(40),
            reason: "missing machine_id".to_string(),
        })?;

        let boot_id = read_id128(buf, 56).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(56),
            reason: "missing boot_id".to_string(),
        })?;
        let seqnum_id = read_id128(buf, 72).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(72),
            reason: "missing seqnum_id".to_string(),
        })?;

        let header_size = read_u64_le(buf, 88).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(88),
            reason: "missing header_size".to_string(),
        })?;
        let arena_size = read_u64_le(buf, 96).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(96),
            reason: "missing arena_size".to_string(),
        })?;
        let data_hash_table_offset =
            read_u64_le(buf, 104).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
                offset: Some(104),
                reason: "missing data_hash_table_offset".to_string(),
            })?;
        let data_hash_table_size =
            read_u64_le(buf, 112).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
                offset: Some(112),
                reason: "missing data_hash_table_size".to_string(),
            })?;
        let field_hash_table_offset =
            read_u64_le(buf, 120).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
                offset: Some(120),
                reason: "missing field_hash_table_offset".to_string(),
            })?;
        let field_hash_table_size =
            read_u64_le(buf, 128).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
                offset: Some(128),
                reason: "missing field_hash_table_size".to_string(),
            })?;
        let tail_object_offset = read_u64_le(buf, 136).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(136),
            reason: "missing tail_object_offset".to_string(),
        })?;
        let n_entries = read_u64_le(buf, 152).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(152),
            reason: "missing n_entries".to_string(),
        })?;
        let entry_array_offset = read_u64_le(buf, 176).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(176),
            reason: "missing entry_array_offset".to_string(),
        })?;

        Ok(Self {
            compatible_flags,
            incompatible_flags,
            state,
            file_id,
            machine_id,
            boot_id,
            seqnum_id,
            header_size,
            arena_size,
            data_hash_table_offset,
            data_hash_table_size,
            field_hash_table_offset,
            field_hash_table_size,
            tail_object_offset,
            n_entries,
            entry_array_offset,
        })
    }

    pub(crate) fn is_compact(&self) -> bool {
        self.incompatible_flags & HEADER_INCOMPATIBLE_COMPACT != 0
    }

    #[allow(dead_code)]
    pub(crate) fn is_keyed_hash(&self) -> bool {
        self.incompatible_flags & HEADER_INCOMPATIBLE_KEYED_HASH != 0
    }

    #[cfg(any(feature = "tracing", feature = "verify-seal"))]
    pub(crate) fn is_sealed(&self) -> bool {
        self.compatible_flags & HEADER_COMPATIBLE_SEALED != 0
    }

    #[cfg(any(feature = "tracing", feature = "verify-seal"))]
    pub(crate) fn is_sealed_continuous(&self) -> bool {
        self.compatible_flags & HEADER_COMPATIBLE_SEALED_CONTINUOUS != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ObjectHeader {
    pub(crate) object_type: u8,
    pub(crate) flags: u8,
    pub(crate) size: u64,
}

impl ObjectHeader {
    pub(crate) fn parse(buf: &[u8], path: &Path, offset: u64) -> Result<Self> {
        if buf.len() < 16 {
            return Err(SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
                offset: Some(offset),
                reason: "object header truncated".to_string(),
            });
        }

        let object_type = buf[0];
        let flags = buf[1];
        let size = read_u64_le(buf, 8).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(path.to_path_buf()),
            offset: Some(offset),
            reason: "object size missing".to_string(),
        })?;

        Ok(Self {
            object_type,
            flags,
            size,
        })
    }
}

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
            compressed_xz = header.incompatible_flags & HEADER_INCOMPATIBLE_COMPRESSED_XZ != 0,
            compressed_lz4 = header.incompatible_flags & HEADER_INCOMPATIBLE_COMPRESSED_LZ4 != 0,
            compressed_zstd = header.incompatible_flags & HEADER_INCOMPATIBLE_COMPRESSED_ZSTD != 0,
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

    pub(crate) fn read_entry_meta(&self, entry_offset: u64) -> Result<EntryMeta> {
        let base = self.read_bytes(entry_offset, 64)?;
        let base = base.as_slice();
        let oh = ObjectHeader::parse(base, self.path(), entry_offset)?;
        if oh.object_type != OBJECT_ENTRY {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset),
                reason: format!("expected ENTRY object, found type {}", oh.object_type),
            });
        }
        if oh.size < 64 {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset),
                reason: format!("ENTRY object too small: {}", oh.size),
            });
        }

        let seqnum = read_u64_le(base, 16).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 16),
            reason: "missing seqnum".to_string(),
        })?;
        let realtime_usec = read_u64_le(base, 24).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 24),
            reason: "missing realtime".to_string(),
        })?;

        Ok(EntryMeta {
            file_id: self.inner.header.file_id,
            entry_offset,
            seqnum,
            realtime_usec,
        })
    }

    pub(crate) fn read_entry_cursor_fields(&self, entry_offset: u64) -> Result<EntryCursorFields> {
        let base = self.read_bytes(entry_offset, 64)?;
        let base = base.as_slice();
        let oh = ObjectHeader::parse(base, self.path(), entry_offset)?;
        if oh.object_type != OBJECT_ENTRY {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset),
                reason: format!("expected ENTRY object, found type {}", oh.object_type),
            });
        }
        if oh.size < 64 {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset),
                reason: format!("ENTRY object too small: {}", oh.size),
            });
        }

        let seqnum = read_u64_le(base, 16).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 16),
            reason: "missing seqnum".to_string(),
        })?;
        let realtime_usec = read_u64_le(base, 24).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 24),
            reason: "missing realtime".to_string(),
        })?;
        let monotonic_usec = read_u64_le(base, 32).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 32),
            reason: "missing monotonic".to_string(),
        })?;
        let boot_id = read_id128(base, 40).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 40),
            reason: "missing boot_id".to_string(),
        })?;
        let xor_hash = read_u64_le(base, 56).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 56),
            reason: "missing xor_hash".to_string(),
        })?;

        Ok(EntryCursorFields {
            seqnum,
            realtime_usec,
            monotonic_usec,
            boot_id,
            xor_hash,
        })
    }

    pub(crate) fn read_entry_owned(&self, entry_offset: u64) -> Result<EntryOwned> {
        let oh_bytes = self.read_bytes(entry_offset, 16)?;
        let oh = ObjectHeader::parse(oh_bytes.as_slice(), self.path(), entry_offset)?;
        if oh.object_type != OBJECT_ENTRY {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset),
                reason: format!("expected ENTRY object, found type {}", oh.object_type),
            });
        }
        if oh.size < 64 {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset),
                reason: format!("ENTRY object too small: {}", oh.size),
            });
        }

        let entry_bytes = self.read_object(entry_offset, oh.size)?;
        let entry_bytes = entry_bytes.as_slice();
        let seqnum = read_u64_le(entry_bytes, 16).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 16),
            reason: "missing seqnum".to_string(),
        })?;
        let realtime_usec =
            read_u64_le(entry_bytes, 24).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset + 24),
                reason: "missing realtime".to_string(),
            })?;
        let monotonic_usec =
            read_u64_le(entry_bytes, 32).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset + 32),
                reason: "missing monotonic".to_string(),
            })?;
        let boot_id = read_id128(entry_bytes, 40).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 40),
            reason: "missing boot_id".to_string(),
        })?;

        let items_bytes = entry_bytes
            .get(64..)
            .ok_or_else(|| SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset + 64),
                reason: "missing entry items".to_string(),
            })?;

        let mut data_offsets = Vec::new();
        if self.inner.header.is_compact() {
            if items_bytes.len() % 4 != 0 {
                return Err(SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(entry_offset),
                    reason: "ENTRY compact items not aligned".to_string(),
                });
            }
            crate::util::ensure_limit_usize(
                LimitKind::FieldsPerEntry,
                self.inner.config.max_fields_per_entry,
                items_bytes.len() / 4,
            )?;

            let mut i = 0;
            while i < items_bytes.len() {
                let off = read_u32_le(items_bytes, i).ok_or_else(|| SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(entry_offset),
                    reason: "ENTRY compact item truncated".to_string(),
                })?;
                if off == 0 {
                    break;
                }
                data_offsets.push(u64::from(off));
                i += 4;
            }
        } else {
            if items_bytes.len() % 16 != 0 {
                return Err(SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(entry_offset),
                    reason: "ENTRY regular items not aligned".to_string(),
                });
            }
            crate::util::ensure_limit_usize(
                LimitKind::FieldsPerEntry,
                self.inner.config.max_fields_per_entry,
                items_bytes.len() / 16,
            )?;

            let mut i = 0;
            while i < items_bytes.len() {
                let object_offset =
                    read_u64_le(items_bytes, i).ok_or_else(|| SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(entry_offset),
                        reason: "ENTRY item truncated".to_string(),
                    })?;
                if object_offset == 0 {
                    break;
                }
                data_offsets.push(object_offset);
                i += 16;
            }
        }

        let mut fields_in_order: Vec<(String, Vec<u8>)> = Vec::new();
        for data_offset in data_offsets {
            let (name, value) = self.read_data_payload(data_offset)?;

            if !is_ascii_field_name(name.as_bytes()) {
                return Err(SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(data_offset),
                    reason: "DATA payload contains invalid field name".to_string(),
                });
            }
            crate::util::ensure_limit_usize(
                LimitKind::FieldNameLen,
                self.inner.config.max_field_name_len,
                name.len(),
            )?;

            fields_in_order.push((name, value));
            crate::util::ensure_limit_usize(
                LimitKind::FieldsPerEntry,
                self.inner.config.max_fields_per_entry,
                fields_in_order.len(),
            )?;
        }

        Ok(EntryOwned::new(
            self.inner.header.file_id,
            entry_offset,
            seqnum,
            realtime_usec,
            monotonic_usec,
            boot_id,
            fields_in_order,
        ))
    }

    pub(crate) fn read_entry_ref(&self, entry_offset: u64) -> Result<EntryRef> {
        let oh_bytes = self.read_bytes(entry_offset, 16)?;
        let oh = ObjectHeader::parse(oh_bytes.as_slice(), self.path(), entry_offset)?;
        if oh.object_type != OBJECT_ENTRY {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset),
                reason: format!("expected ENTRY object, found type {}", oh.object_type),
            });
        }
        if oh.size < 64 {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset),
                reason: format!("ENTRY object too small: {}", oh.size),
            });
        }

        let entry_bytes = self.read_object(entry_offset, oh.size)?;
        let entry_bytes = entry_bytes.as_slice();

        let seqnum = read_u64_le(entry_bytes, 16).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 16),
            reason: "missing seqnum".to_string(),
        })?;
        let realtime_usec =
            read_u64_le(entry_bytes, 24).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset + 24),
                reason: "missing realtime".to_string(),
            })?;
        let monotonic_usec =
            read_u64_le(entry_bytes, 32).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset + 32),
                reason: "missing monotonic".to_string(),
            })?;
        let boot_id = read_id128(entry_bytes, 40).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(entry_offset + 40),
            reason: "missing boot_id".to_string(),
        })?;

        let items_bytes = entry_bytes
            .get(64..)
            .ok_or_else(|| SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(entry_offset + 64),
                reason: "missing entry items".to_string(),
            })?;

        let mut data_offsets = Vec::new();
        if self.inner.header.is_compact() {
            if items_bytes.len() % 4 != 0 {
                return Err(SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(entry_offset),
                    reason: "ENTRY compact items not aligned".to_string(),
                });
            }
            crate::util::ensure_limit_usize(
                LimitKind::FieldsPerEntry,
                self.inner.config.max_fields_per_entry,
                items_bytes.len() / 4,
            )?;

            let mut i = 0;
            while i < items_bytes.len() {
                let off = read_u32_le(items_bytes, i).ok_or_else(|| SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(entry_offset),
                    reason: "ENTRY compact item truncated".to_string(),
                })?;
                if off == 0 {
                    break;
                }
                data_offsets.push(u64::from(off));
                i += 4;
            }
        } else {
            if items_bytes.len() % 16 != 0 {
                return Err(SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(entry_offset),
                    reason: "ENTRY regular items not aligned".to_string(),
                });
            }
            crate::util::ensure_limit_usize(
                LimitKind::FieldsPerEntry,
                self.inner.config.max_fields_per_entry,
                items_bytes.len() / 16,
            )?;

            let mut i = 0;
            while i < items_bytes.len() {
                let object_offset =
                    read_u64_le(items_bytes, i).ok_or_else(|| SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(entry_offset),
                        reason: "ENTRY item truncated".to_string(),
                    })?;
                if object_offset == 0 {
                    break;
                }
                data_offsets.push(object_offset);
                i += 16;
            }
        }

        let mut fields_in_order = Vec::new();
        for data_offset in data_offsets {
            let payload = self.read_data_payload_bytes_for_object(data_offset)?;
            let eq = payload
                .as_slice()
                .iter()
                .position(|&b| b == b'=')
                .ok_or_else(|| SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(data_offset),
                    reason: "DATA payload missing '=' separator".to_string(),
                })?;

            let name_bytes =
                payload
                    .as_slice()
                    .get(0..eq)
                    .ok_or_else(|| SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(data_offset),
                        reason: "DATA payload missing field name".to_string(),
                    })?;

            if !is_ascii_field_name(name_bytes) {
                return Err(SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(data_offset),
                    reason: "DATA payload contains invalid field name".to_string(),
                });
            }
            crate::util::ensure_limit_usize(
                LimitKind::FieldNameLen,
                self.inner.config.max_field_name_len,
                name_bytes.len(),
            )?;

            let name = std::str::from_utf8(name_bytes).map_err(|_| SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(data_offset),
                reason: "DATA field name is not valid UTF-8".to_string(),
            })?;

            fields_in_order.push((name.to_string(), payload, eq));
            crate::util::ensure_limit_usize(
                LimitKind::FieldsPerEntry,
                self.inner.config.max_fields_per_entry,
                fields_in_order.len(),
            )?;
        }

        Ok(EntryRef::new_parsed(
            self.inner.header.file_id,
            entry_offset,
            seqnum,
            realtime_usec,
            monotonic_usec,
            boot_id,
            fields_in_order,
        ))
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

    pub(crate) fn read_data_payload_bytes_for_object(&self, data_offset: u64) -> Result<ByteBuf> {
        let meta = self.read_data_object_meta(data_offset)?;
        self.read_data_payload_bytes(data_offset, &meta)
    }

    fn read_data_payload(&self, data_offset: u64) -> Result<(String, Vec<u8>)> {
        let oh_bytes = self.read_bytes(data_offset, 16)?;
        let oh = ObjectHeader::parse(oh_bytes.as_slice(), self.path(), data_offset)?;
        if oh.object_type != OBJECT_DATA {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(data_offset),
                reason: format!("expected DATA object, found type {}", oh.object_type),
            });
        }
        if oh.size < 64 {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(data_offset),
                reason: format!("DATA object too small: {}", oh.size),
            });
        }

        let obj = self.read_object(data_offset, oh.size)?;
        let obj = obj.as_slice();
        let payload_offset = if self.inner.header.is_compact() {
            72usize
        } else {
            64usize
        };
        let payload = obj
            .get(payload_offset..)
            .ok_or_else(|| SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(data_offset),
                reason: "DATA payload missing".to_string(),
            })?;

        let payload = match compression_from_object_flags(oh.flags)? {
            None => payload.to_vec(),
            Some(CompressionAlgo::Xz) => {
                if self.inner.header.incompatible_flags & HEADER_INCOMPATIBLE_COMPRESSED_XZ == 0 {
                    return Err(SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(data_offset),
                        reason: "DATA has XZ flag but file header missing incompatible flag"
                            .to_string(),
                    });
                }
                decompress_xz(payload, self.inner.config.max_decompressed_bytes)?
            }
            Some(CompressionAlgo::Lz4) => {
                if self.inner.header.incompatible_flags & HEADER_INCOMPATIBLE_COMPRESSED_LZ4 == 0 {
                    return Err(SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(data_offset),
                        reason: "DATA has LZ4 flag but file header missing incompatible flag"
                            .to_string(),
                    });
                }
                decompress_lz4(payload, self.inner.config.max_decompressed_bytes)?
            }
            Some(CompressionAlgo::Zstd) => {
                if self.inner.header.incompatible_flags & HEADER_INCOMPATIBLE_COMPRESSED_ZSTD == 0 {
                    return Err(SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(data_offset),
                        reason: "DATA has ZSTD flag but file header missing incompatible flag"
                            .to_string(),
                    });
                }
                decompress_zstd(payload, self.inner.config.max_decompressed_bytes)?
            }
        };

        let eq =
            payload
                .iter()
                .position(|&b| b == b'=')
                .ok_or_else(|| SdJournalError::Corrupt {
                    path: Some(self.inner.path.clone()),
                    offset: Some(data_offset),
                    reason: "DATA payload missing '=' separator".to_string(),
                })?;

        let name_bytes = payload.get(0..eq).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(data_offset),
            reason: "DATA payload missing field name".to_string(),
        })?;
        let value = payload
            .get(eq + 1..)
            .ok_or_else(|| SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(data_offset),
                reason: "DATA payload missing field value".to_string(),
            })?;

        let name = std::str::from_utf8(name_bytes).map_err(|_| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(data_offset),
            reason: "DATA field name is not valid UTF-8".to_string(),
        })?;

        Ok((name.to_string(), value.to_vec()))
    }

    pub(crate) fn find_data_object(&self, payload: &[u8]) -> Result<Option<DataObjectRef>> {
        let table_offset = self.inner.header.data_hash_table_offset;
        let table_size = self.inner.header.data_hash_table_size;
        if table_offset == 0 || table_size == 0 {
            return Ok(None);
        }
        if !table_size.is_multiple_of(16) {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(table_offset),
                reason: "DATA_HASH_TABLE size is not a multiple of 16".to_string(),
            });
        }

        let buckets = table_size / 16;
        if buckets == 0 {
            return Ok(None);
        }

        let want_hash = self.payload_hash(payload);
        let bucket = want_hash % buckets;
        let item_offset = checked_add_u64(
            table_offset,
            bucket.saturating_mul(16),
            "data_hash_table index",
        )?;
        let item = self.read_hash_item(item_offset)?;

        let mut current = item.head_hash_offset;
        let mut steps = 0usize;
        while current != 0 {
            steps = steps.saturating_add(1);
            if steps > self.inner.config.max_object_chain_steps {
                return Err(SdJournalError::LimitExceeded {
                    kind: LimitKind::ObjectChainSteps,
                    limit: u64::try_from(self.inner.config.max_object_chain_steps)
                        .unwrap_or(u64::MAX),
                });
            }

            let meta = self.read_data_object_meta(current)?;
            if meta.hash == want_hash {
                let have_payload = self.read_data_payload_bytes(current, &meta)?;
                if have_payload.as_slice() == payload {
                    return Ok(Some(DataObjectRef {
                        entry_offset: meta.entry_offset,
                        entry_array_offset: meta.entry_array_offset,
                        n_entries: meta.n_entries,
                    }));
                }
            }

            current = meta.next_hash_offset;
        }

        Ok(None)
    }

    pub(crate) fn data_entry_offsets(
        &self,
        data: DataObjectRef,
        reverse: bool,
    ) -> Result<DataEntryOffsetIter> {
        DataEntryOffsetIter::new(self.clone(), data, reverse)
    }

    fn payload_hash(&self, payload: &[u8]) -> u64 {
        if self.inner.header.is_keyed_hash() {
            crate::util::hash::siphash24(&self.inner.header.file_id, payload)
        } else {
            crate::util::hash::jenkins_hash64(payload)
        }
    }

    fn read_hash_item(&self, offset: u64) -> Result<HashItem> {
        let buf = self.read_bytes(offset, 16)?;
        let buf = buf.as_slice();
        let head_hash_offset = read_u64_le(buf, 0).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(offset),
            reason: "HASH_TABLE item truncated".to_string(),
        })?;
        let tail_hash_offset = read_u64_le(buf, 8).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(offset + 8),
            reason: "HASH_TABLE item truncated".to_string(),
        })?;
        Ok(HashItem {
            head_hash_offset,
            tail_hash_offset,
        })
    }

    fn read_data_object_meta(&self, offset: u64) -> Result<DataObjectMeta> {
        let oh_bytes = self.read_bytes(offset, 16)?;
        let oh = ObjectHeader::parse(oh_bytes.as_slice(), self.path(), offset)?;
        if oh.object_type != OBJECT_DATA {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(offset),
                reason: format!("expected DATA object, found type {}", oh.object_type),
            });
        }

        let min_size = if self.inner.header.is_compact() {
            72u64
        } else {
            64u64
        };
        if oh.size < min_size {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(offset),
                reason: format!("DATA object too small: {}", oh.size),
            });
        }

        let buf = self.read_bytes(offset, usize::try_from(min_size).unwrap_or(usize::MAX))?;
        let buf = buf.as_slice();

        let hash = read_u64_le(buf, 16).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(offset + 16),
            reason: "missing DATA.hash".to_string(),
        })?;
        let next_hash_offset = read_u64_le(buf, 24).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(offset + 24),
            reason: "missing DATA.next_hash_offset".to_string(),
        })?;
        let next_field_offset = read_u64_le(buf, 32).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(offset + 32),
            reason: "missing DATA.next_field_offset".to_string(),
        })?;
        let entry_offset = read_u64_le(buf, 40).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(offset + 40),
            reason: "missing DATA.entry_offset".to_string(),
        })?;
        let entry_array_offset = read_u64_le(buf, 48).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(offset + 48),
            reason: "missing DATA.entry_array_offset".to_string(),
        })?;
        let n_entries = read_u64_le(buf, 56).ok_or_else(|| SdJournalError::Corrupt {
            path: Some(self.inner.path.clone()),
            offset: Some(offset + 56),
            reason: "missing DATA.n_entries".to_string(),
        })?;

        let (tail_entry_array_offset, tail_entry_array_n_entries) =
            if self.inner.header.is_compact() {
                let tail_entry_array_offset =
                    read_u32_le(buf, 64).ok_or_else(|| SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(offset + 64),
                        reason: "missing DATA.tail_entry_array_offset".to_string(),
                    })?;
                let tail_entry_array_n_entries =
                    read_u32_le(buf, 68).ok_or_else(|| SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(offset + 68),
                        reason: "missing DATA.tail_entry_array_n_entries".to_string(),
                    })?;
                (
                    Some(tail_entry_array_offset),
                    Some(tail_entry_array_n_entries),
                )
            } else {
                (None, None)
            };

        Ok(DataObjectMeta {
            hash,
            next_hash_offset,
            next_field_offset,
            entry_offset,
            entry_array_offset,
            n_entries,
            tail_entry_array_offset,
            tail_entry_array_n_entries,
            flags: oh.flags,
            size: oh.size,
        })
    }

    fn read_data_payload_bytes(&self, offset: u64, meta: &DataObjectMeta) -> Result<ByteBuf> {
        if meta.size > self.inner.config.max_object_size_bytes {
            return Err(SdJournalError::LimitExceeded {
                kind: LimitKind::ObjectSizeBytes,
                limit: self.inner.config.max_object_size_bytes,
            });
        }

        let payload_offset = if self.inner.header.is_compact() {
            72u64
        } else {
            64u64
        };
        if meta.size < payload_offset {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(offset),
                reason: "DATA object size smaller than payload offset".to_string(),
            });
        }

        let payload_len_u64 = meta.size - payload_offset;
        let payload_len =
            usize::try_from(payload_len_u64).map_err(|_| SdJournalError::LimitExceeded {
                kind: LimitKind::ObjectSizeBytes,
                limit: self.inner.config.max_object_size_bytes,
            })?;

        let payload_offset = checked_add_u64(offset, payload_offset, "DATA payload offset")?;
        let payload = self.read_bytes(payload_offset, payload_len)?;

        let payload = match compression_from_object_flags(meta.flags)? {
            None => payload,
            Some(CompressionAlgo::Xz) => {
                if self.inner.header.incompatible_flags & HEADER_INCOMPATIBLE_COMPRESSED_XZ == 0 {
                    return Err(SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(offset),
                        reason: "DATA has XZ flag but file header missing incompatible flag"
                            .to_string(),
                    });
                }
                ByteBuf::from_vec(decompress_xz(
                    payload.as_slice(),
                    self.inner.config.max_decompressed_bytes,
                )?)
            }
            Some(CompressionAlgo::Lz4) => {
                if self.inner.header.incompatible_flags & HEADER_INCOMPATIBLE_COMPRESSED_LZ4 == 0 {
                    return Err(SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(offset),
                        reason: "DATA has LZ4 flag but file header missing incompatible flag"
                            .to_string(),
                    });
                }
                ByteBuf::from_vec(decompress_lz4(
                    payload.as_slice(),
                    self.inner.config.max_decompressed_bytes,
                )?)
            }
            Some(CompressionAlgo::Zstd) => {
                if self.inner.header.incompatible_flags & HEADER_INCOMPATIBLE_COMPRESSED_ZSTD == 0 {
                    return Err(SdJournalError::Corrupt {
                        path: Some(self.inner.path.clone()),
                        offset: Some(offset),
                        reason: "DATA has ZSTD flag but file header missing incompatible flag"
                            .to_string(),
                    });
                }
                ByteBuf::from_vec(decompress_zstd(
                    payload.as_slice(),
                    self.inner.config.max_decompressed_bytes,
                )?)
            }
        };

        if !payload.as_slice().contains(&b'=') {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(offset),
                reason: "DATA payload missing '=' separator".to_string(),
            });
        }

        Ok(payload)
    }
}

#[derive(Debug, Clone, Copy)]
struct HashItem {
    head_hash_offset: u64,
    #[allow(dead_code)]
    tail_hash_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct DataObjectMeta {
    hash: u64,
    next_hash_offset: u64,
    #[allow(dead_code)]
    next_field_offset: u64,
    entry_offset: u64,
    entry_array_offset: u64,
    n_entries: u64,
    #[allow(dead_code)]
    tail_entry_array_offset: Option<u32>,
    #[allow(dead_code)]
    tail_entry_array_n_entries: Option<u32>,
    flags: u8,
    size: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DataObjectRef {
    pub(crate) n_entries: u64,
    entry_offset: u64,
    entry_array_offset: u64,
}

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
    fn new(file: JournalFile, data: DataObjectRef, reverse: bool) -> Result<Self> {
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
    fn new_with_seek_realtime(
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

pub(crate) fn compression_from_object_flags(flags: u8) -> Result<Option<CompressionAlgo>> {
    let algo = if flags & OBJECT_COMPRESSED_XZ != 0 {
        Some(CompressionAlgo::Xz)
    } else if flags & OBJECT_COMPRESSED_LZ4 != 0 {
        Some(CompressionAlgo::Lz4)
    } else if flags & OBJECT_COMPRESSED_ZSTD != 0 {
        Some(CompressionAlgo::Zstd)
    } else {
        None
    };

    let mut count = 0;
    for bit in [
        OBJECT_COMPRESSED_XZ,
        OBJECT_COMPRESSED_LZ4,
        OBJECT_COMPRESSED_ZSTD,
    ] {
        if flags & bit != 0 {
            count += 1;
        }
    }
    if count > 1 {
        return Err(SdJournalError::Corrupt {
            path: None,
            offset: None,
            reason: "multiple compression flags set".to_string(),
        });
    }
    Ok(algo)
}

#[cfg(feature = "lz4")]
fn decompress_lz4(src: &[u8], max: usize) -> Result<Vec<u8>> {
    if src.len() <= 8 {
        return Err(SdJournalError::DecompressFailed {
            algo: CompressionAlgo::Lz4,
            reason: "lz4 payload too short".to_string(),
        });
    }

    let size = read_u64_le(src, 0).ok_or_else(|| SdJournalError::DecompressFailed {
        algo: CompressionAlgo::Lz4,
        reason: "missing uncompressed size".to_string(),
    })?;

    let size_usize = usize::try_from(size).map_err(|_| SdJournalError::LimitExceeded {
        kind: LimitKind::DecompressedBytes,
        limit: u64::try_from(max).unwrap_or(u64::MAX),
    })?;
    crate::util::ensure_limit_usize(LimitKind::DecompressedBytes, max, size_usize)?;

    let compressed = &src[8..];
    lz4_flex::block::decompress(compressed, size_usize).map_err(|e| {
        SdJournalError::DecompressFailed {
            algo: CompressionAlgo::Lz4,
            reason: e.to_string(),
        }
    })
}

#[cfg(not(feature = "lz4"))]
fn decompress_lz4(_src: &[u8], _max: usize) -> Result<Vec<u8>> {
    Err(SdJournalError::Unsupported {
        reason: "lz4 support is disabled (feature lz4)".to_string(),
    })
}

#[cfg(feature = "zstd")]
fn decompress_zstd(src: &[u8], max: usize) -> Result<Vec<u8>> {
    use ruzstd::decoding::StreamingDecoder;
    use ruzstd::io::Read as _;

    let mut reader: &[u8] = src;
    let mut decoder =
        StreamingDecoder::new(&mut reader).map_err(|e| SdJournalError::DecompressFailed {
            algo: CompressionAlgo::Zstd,
            reason: e.to_string(),
        })?;

    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| SdJournalError::DecompressFailed {
                algo: CompressionAlgo::Zstd,
                reason: e.to_string(),
            })?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > max {
            return Err(SdJournalError::LimitExceeded {
                kind: LimitKind::DecompressedBytes,
                limit: u64::try_from(max).unwrap_or(u64::MAX),
            });
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(not(feature = "zstd"))]
fn decompress_zstd(_src: &[u8], _max: usize) -> Result<Vec<u8>> {
    Err(SdJournalError::Unsupported {
        reason: "zstd support is disabled (feature zstd)".to_string(),
    })
}

#[cfg(feature = "xz")]
fn decompress_xz(src: &[u8], max: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;
    use xz2::read::XzDecoder;

    let mut decoder = XzDecoder::new(src);
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];

    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| SdJournalError::DecompressFailed {
                algo: CompressionAlgo::Xz,
                reason: e.to_string(),
            })?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > max {
            return Err(SdJournalError::LimitExceeded {
                kind: LimitKind::DecompressedBytes,
                limit: u64::try_from(max).unwrap_or(u64::MAX),
            });
        }
        out.extend_from_slice(&buf[..n]);
    }

    Ok(out)
}

#[cfg(not(feature = "xz"))]
fn decompress_xz(_src: &[u8], _max: usize) -> Result<Vec<u8>> {
    Err(SdJournalError::Unsupported {
        reason: "xz support is disabled (feature xz)".to_string(),
    })
}
