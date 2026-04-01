use super::JournalFile;
use crate::entry::{EntryOwned, EntryRef};
use crate::error::{CompressionAlgo, LimitKind, Result, SdJournalError};
use crate::format::{
    HEADER_INCOMPATIBLE_COMPRESSED_LZ4, HEADER_INCOMPATIBLE_COMPRESSED_XZ,
    HEADER_INCOMPATIBLE_COMPRESSED_ZSTD, OBJECT_DATA, OBJECT_ENTRY, ObjectHeader,
    compression_from_object_flags, parse_entry_data_offsets_bytes,
};
use crate::util::{is_ascii_field_name, read_id128, read_u64_le};

use super::decompress::{decompress_lz4, decompress_xz, decompress_zstd};
use super::{EntryCursorFields, EntryMeta};

impl JournalFile {
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

        let data_offsets = parse_entry_data_offsets_bytes(
            items_bytes,
            self.inner.header.is_compact(),
            self.inner.config.max_fields_per_entry,
            self.path(),
            entry_offset,
        )?;

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

        let data_offsets = parse_entry_data_offsets_bytes(
            items_bytes,
            self.inner.header.is_compact(),
            self.inner.config.max_fields_per_entry,
            self.path(),
            entry_offset,
        )?;

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
        let min_size = if self.inner.header.is_compact() {
            72
        } else {
            64
        };
        if oh.size < min_size {
            return Err(SdJournalError::Corrupt {
                path: Some(self.inner.path.clone()),
                offset: Some(data_offset),
                reason: format!("DATA object too small: {} (min {})", oh.size, min_size),
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
}
