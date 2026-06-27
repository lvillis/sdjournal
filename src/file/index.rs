use super::decompress::{decompress_lz4, decompress_xz, decompress_zstd};
use super::{DataEntryOffsetIter, JournalFile};
use crate::error::{CompressionAlgo, LimitKind, Result, SdJournalError};
use crate::format::{
    HEADER_INCOMPATIBLE_COMPRESSED_LZ4, HEADER_INCOMPATIBLE_COMPRESSED_XZ,
    HEADER_INCOMPATIBLE_COMPRESSED_ZSTD, OBJECT_DATA, ObjectHeader, compression_from_object_flags,
};
use crate::reader::ByteBuf;
use crate::util::{checked_add_u64, read_u32_le, read_u64_le};

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
    pub(crate) entry_offset: u64,
    pub(crate) entry_array_offset: u64,
}

impl JournalFile {
    pub(crate) fn read_data_payload_bytes_for_object(&self, data_offset: u64) -> Result<ByteBuf> {
        let meta = self.read_data_object_meta(data_offset)?;
        self.read_data_payload_bytes(data_offset, &meta)
    }

    pub(crate) fn find_data_objects(&self, payload: &[u8]) -> Result<Vec<DataObjectRef>> {
        let table_offset = self.inner.header.data_hash_table_offset;
        let table_size = self.inner.header.data_hash_table_size;
        if table_offset == 0 || table_size == 0 {
            return Ok(Vec::new());
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
            return Ok(Vec::new());
        }

        let want_hash = self.payload_hash(payload);
        let bucket = want_hash % buckets;
        let item_offset = checked_add_u64(
            table_offset,
            bucket.saturating_mul(16),
            "data_hash_table index",
        )?;
        let item = self.read_hash_item(item_offset)?;

        let mut out = Vec::new();
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
                    out.push(DataObjectRef {
                        entry_offset: meta.entry_offset,
                        entry_array_offset: meta.entry_array_offset,
                        n_entries: meta.n_entries,
                    });
                }
            }

            current = meta.next_hash_offset;
        }

        Ok(out)
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
