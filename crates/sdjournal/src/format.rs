use crate::error::{CompressionAlgo, LimitKind, Result, SdJournalError};
use crate::util::{read_id128, read_u8, read_u32_le, read_u64_le};
use std::path::Path;

pub(crate) type FileOffset = u64;

pub(crate) const HEADER_SIGNATURE: &[u8; 8] = b"LPKSHHRH";

pub(crate) const HEADER_INCOMPATIBLE_COMPRESSED_XZ: u32 = 1 << 0;
pub(crate) const HEADER_INCOMPATIBLE_COMPRESSED_LZ4: u32 = 1 << 1;
pub(crate) const HEADER_INCOMPATIBLE_KEYED_HASH: u32 = 1 << 2;
pub(crate) const HEADER_INCOMPATIBLE_COMPRESSED_ZSTD: u32 = 1 << 3;
pub(crate) const HEADER_INCOMPATIBLE_COMPACT: u32 = 1 << 4;

#[cfg(any(feature = "tracing", feature = "verify-seal"))]
pub(crate) const HEADER_COMPATIBLE_SEALED: u32 = 1 << 0;
#[cfg(any(feature = "tracing", feature = "verify-seal"))]
pub(crate) const HEADER_COMPATIBLE_SEALED_CONTINUOUS: u32 = 1 << 2;

const KNOWN_INCOMPATIBLE_FLAGS: u32 = HEADER_INCOMPATIBLE_COMPRESSED_XZ
    | HEADER_INCOMPATIBLE_COMPRESSED_LZ4
    | HEADER_INCOMPATIBLE_KEYED_HASH
    | HEADER_INCOMPATIBLE_COMPRESSED_ZSTD
    | HEADER_INCOMPATIBLE_COMPACT;

#[allow(dead_code)]
pub(crate) const STATE_OFFLINE: u8 = 0;
#[allow(dead_code)]
pub(crate) const STATE_ONLINE: u8 = 1;
pub(crate) const STATE_ARCHIVED: u8 = 2;

pub(crate) const OBJECT_DATA: u8 = 1;
#[cfg(feature = "verify-seal")]
pub(crate) const OBJECT_FIELD: u8 = 2;
pub(crate) const OBJECT_ENTRY: u8 = 3;
#[cfg(feature = "verify-seal")]
pub(crate) const OBJECT_DATA_HASH_TABLE: u8 = 4;
#[cfg(feature = "verify-seal")]
pub(crate) const OBJECT_FIELD_HASH_TABLE: u8 = 5;
pub(crate) const OBJECT_ENTRY_ARRAY: u8 = 6;
#[cfg(feature = "verify-seal")]
pub(crate) const OBJECT_TAG: u8 = 7;

pub(crate) const OBJECT_COMPRESSED_XZ: u8 = 1 << 0;
pub(crate) const OBJECT_COMPRESSED_LZ4: u8 = 1 << 1;
pub(crate) const OBJECT_COMPRESSED_ZSTD: u8 = 1 << 2;

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
    pub(crate) fn parse(buf: &[u8], path: &Path) -> Result<Self> {
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
    pub(crate) fn parse(buf: &[u8], path: &Path, offset: FileOffset) -> Result<Self> {
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

pub(crate) fn parse_entry_data_offsets_bytes(
    items_bytes: &[u8],
    compact: bool,
    max_fields_per_entry: usize,
    path: &Path,
    entry_offset: FileOffset,
) -> Result<Vec<FileOffset>> {
    let mut data_offsets = Vec::new();
    if compact {
        // In compact format, each ENTRY item is 4 bytes:
        // - object_offset: u32
        // (the per-item hash is not stored in compact mode)
        if !items_bytes.len().is_multiple_of(4) {
            return Err(SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
                offset: Some(entry_offset),
                reason: "ENTRY compact items not aligned".to_string(),
            });
        }
        crate::util::ensure_limit_usize(
            LimitKind::FieldsPerEntry,
            max_fields_per_entry,
            items_bytes.len() / 4,
        )?;

        let mut i = 0;
        while i < items_bytes.len() {
            let off = read_u32_le(items_bytes, i).ok_or_else(|| SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
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
        // In regular format, each ENTRY item is 16 bytes:
        // - object_offset: u64
        // - hash: u64
        if !items_bytes.len().is_multiple_of(16) {
            return Err(SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
                offset: Some(entry_offset),
                reason: "ENTRY regular items not aligned".to_string(),
            });
        }
        crate::util::ensure_limit_usize(
            LimitKind::FieldsPerEntry,
            max_fields_per_entry,
            items_bytes.len() / 16,
        )?;

        let mut i = 0;
        while i < items_bytes.len() {
            let object_offset =
                read_u64_le(items_bytes, i).ok_or_else(|| SdJournalError::Corrupt {
                    path: Some(path.to_path_buf()),
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

    Ok(data_offsets)
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

#[cfg(test)]
mod tests {
    use super::parse_entry_data_offsets_bytes;
    use std::path::Path;

    #[test]
    fn compact_entry_items_offsets_only() {
        let mut items = Vec::new();

        items.extend_from_slice(&100u32.to_le_bytes());
        items.extend_from_slice(&200u32.to_le_bytes());
        items.extend_from_slice(&0u32.to_le_bytes());

        let got = parse_entry_data_offsets_bytes(&items, true, 1024, Path::new("dummy"), 0)
            .expect("parse compact entry items");
        assert_eq!(got, vec![100, 200]);
    }

    #[test]
    fn regular_entry_items_skip_hashes() {
        let mut items = Vec::new();

        items.extend_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        items.extend_from_slice(&0u64.to_le_bytes());

        items.extend_from_slice(&0u64.to_le_bytes());
        items.extend_from_slice(&0xffff_eeee_dddd_ccccu64.to_le_bytes());

        let got = parse_entry_data_offsets_bytes(&items, false, 1024, Path::new("dummy"), 0)
            .expect("parse regular entry items");
        assert_eq!(got, vec![0x1111_2222_3333_4444]);
    }
}
