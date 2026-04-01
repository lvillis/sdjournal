use super::fsprg::{FsprgParams, FsprgState};
use super::{HmacSha256, TAG_LENGTH, VERIFY_READ_CHUNK_SIZE};
use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::JournalFile;
use crate::format::{
    OBJECT_DATA, OBJECT_DATA_HASH_TABLE, OBJECT_ENTRY, OBJECT_ENTRY_ARRAY, OBJECT_FIELD,
    OBJECT_FIELD_HASH_TABLE, OBJECT_TAG, ObjectHeader,
};
use crate::util::{checked_add_u64, read_u64_le};
use hmac::{KeyInit as _, Mac as _};

pub(crate) fn verify_file_seal(file: &JournalFile, params: &FsprgParams) -> Result<()> {
    let header = file.header();
    if !header.is_sealed() {
        return Ok(());
    }

    let header_size = header.header_size;
    let tail_object_offset = header.tail_object_offset;
    let used_size = file.used_size();

    if header_size < 184 || header_size > used_size || !header_size.is_multiple_of(8) {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(88),
            reason: format!("invalid header_size: {header_size}"),
        });
    }

    if tail_object_offset == 0 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(136),
            reason: "sealed journal contains no objects".to_string(),
        });
    }
    if tail_object_offset < header_size || tail_object_offset >= used_size {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(136),
            reason: format!(
                "invalid tail_object_offset: {tail_object_offset} (header_size={header_size}, used_size={used_size})"
            ),
        });
    }

    let mut fsprg = FsprgState::new(params);
    let mut n_tags: u64 = 0;
    let mut last_epoch: u64 = 0;
    let mut last_tag_end: u64 = 0;

    let mut p = header_size;
    while p <= tail_object_offset {
        let oh = read_object_header(file, p)?;

        if oh.object_type == OBJECT_ENTRY && n_tags == 0 {
            return Err(SdJournalError::Corrupt {
                path: Some(file.path().to_path_buf()),
                offset: Some(p),
                reason: "sealed journal has ENTRY before first TAG".to_string(),
            });
        }

        if oh.object_type == OBJECT_TAG {
            let tag = read_tag_object(file, p, &oh)?;

            if tag.seqnum != n_tags.saturating_add(1) {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: format!(
                        "tag sequence number out of sync ({} != {})",
                        tag.seqnum,
                        n_tags.saturating_add(1)
                    ),
                });
            }

            if header.is_sealed_continuous() {
                if !(n_tags == 0
                    || (n_tags == 1 && tag.epoch == last_epoch)
                    || tag.epoch == last_epoch.saturating_add(1))
                {
                    return Err(SdJournalError::Corrupt {
                        path: Some(file.path().to_path_buf()),
                        offset: Some(p),
                        reason: format!(
                            "epoch sequence not continuous ({} vs {})",
                            tag.epoch, last_epoch
                        ),
                    });
                }
            } else if tag.epoch < last_epoch {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: format!(
                        "epoch sequence out of sync ({} < {})",
                        tag.epoch, last_epoch
                    ),
                });
            }

            fsprg.seek(tag.epoch)?;
            let hmac_key = fsprg.get_key(TAG_LENGTH, 0);
            let mut mac =
                HmacSha256::new_from_slice(&hmac_key).map_err(|_| SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: "failed to initialize HMAC".to_string(),
                })?;

            if last_tag_end == 0 {
                hmac_put_header(file, &mut mac)?;
            }

            let mut q = if last_tag_end == 0 {
                header_size
            } else {
                last_tag_end
            };
            while q <= p {
                let qh = read_object_header(file, q)?;
                hmac_put_object(file, &mut mac, q, &qh)?;
                let adv = align64(qh.size)?;
                q = checked_add_u64(q, adv, "verify-seal next object")?;
            }

            let digest = mac.finalize().into_bytes();
            if digest.as_slice() != tag.tag.as_slice() {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: "tag failed verification".to_string(),
                });
            }

            last_tag_end = checked_add_u64(p, align64(oh.size)?, "verify-seal tag end")?;
            last_epoch = tag.epoch;
            n_tags = n_tags.saturating_add(1);
        }

        p = checked_add_u64(p, align64(oh.size)?, "verify-seal advance")?;
    }

    if n_tags == 0 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(136),
            reason: "sealed journal contains no TAG objects".to_string(),
        });
    }

    Ok(())
}

fn read_object_header(file: &JournalFile, offset: u64) -> Result<ObjectHeader> {
    let buf = file.read_bytes(offset, 16)?;
    let oh = ObjectHeader::parse(buf.as_slice(), file.path(), offset)?;

    if oh.size < 16 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(offset),
            reason: format!("object size too small: {}", oh.size),
        });
    }
    if oh.size > file.config().max_object_size_bytes {
        return Err(SdJournalError::LimitExceeded {
            kind: LimitKind::ObjectSizeBytes,
            limit: file.config().max_object_size_bytes,
        });
    }
    if oh.size % 8 != 0 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(offset),
            reason: format!("object size is not 8-byte aligned: {}", oh.size),
        });
    }

    Ok(oh)
}

fn hmac_put_header(file: &JournalFile, mac: &mut HmacSha256) -> Result<()> {
    let header_bytes = file.read_bytes(0, 136)?;
    let b = header_bytes.as_slice();

    mac.update(b.get(0..16).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(0),
        reason: "header too short for sealing verification".to_string(),
    })?);
    mac.update(b.get(24..56).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(24),
        reason: "header too short for sealing verification".to_string(),
    })?);
    mac.update(b.get(72..96).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(72),
        reason: "header too short for sealing verification".to_string(),
    })?);
    mac.update(b.get(104..136).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(104),
        reason: "header too short for sealing verification".to_string(),
    })?);

    Ok(())
}

fn hmac_put_object(
    file: &JournalFile,
    mac: &mut HmacSha256,
    offset: u64,
    oh: &ObjectHeader,
) -> Result<()> {
    hmac_update_range(file, mac, offset, 16)?;

    match oh.object_type {
        OBJECT_DATA => {
            hmac_update_range(file, mac, checked_add_u64(offset, 16, "data.hash")?, 8)?;

            let payload_offset = if file.header().is_compact() {
                72u64
            } else {
                64u64
            };
            if oh.size < payload_offset {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(offset),
                    reason: format!("DATA object too small: {}", oh.size),
                });
            }

            let payload_len = oh.size - payload_offset;
            hmac_update_range(
                file,
                mac,
                checked_add_u64(offset, payload_offset, "data.payload")?,
                payload_len,
            )?;
        }
        OBJECT_FIELD => {
            const PAYLOAD_OFFSET: u64 = 40;
            hmac_update_range(file, mac, checked_add_u64(offset, 16, "field.hash")?, 8)?;
            if oh.size < PAYLOAD_OFFSET {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(offset),
                    reason: format!("FIELD object too small: {}", oh.size),
                });
            }
            hmac_update_range(
                file,
                mac,
                checked_add_u64(offset, PAYLOAD_OFFSET, "field.payload")?,
                oh.size - PAYLOAD_OFFSET,
            )?;
        }
        OBJECT_ENTRY => {
            let payload_len = oh
                .size
                .checked_sub(16)
                .ok_or_else(|| SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(offset),
                    reason: "ENTRY object too small".to_string(),
                })?;
            hmac_update_range(
                file,
                mac,
                checked_add_u64(offset, 16, "entry.payload")?,
                payload_len,
            )?;
        }
        OBJECT_DATA_HASH_TABLE | OBJECT_FIELD_HASH_TABLE | OBJECT_ENTRY_ARRAY => {}
        OBJECT_TAG => {
            if oh.size != 64 {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(offset),
                    reason: format!("TAG object has invalid size: {}", oh.size),
                });
            }
            hmac_update_range(file, mac, checked_add_u64(offset, 16, "tag.seqnum")?, 16)?;
        }
        other => {
            return Err(SdJournalError::Unsupported {
                reason: format!("unsupported object type in sealing verification: {other}"),
            });
        }
    }

    Ok(())
}

fn hmac_update_range(
    file: &JournalFile,
    mac: &mut HmacSha256,
    offset: u64,
    len: u64,
) -> Result<()> {
    let mut off = offset;
    let mut remaining = len;
    while remaining > 0 {
        let take_u64 = std::cmp::min(remaining, VERIFY_READ_CHUNK_SIZE as u64);
        let take = usize::try_from(take_u64).unwrap_or(VERIFY_READ_CHUNK_SIZE);
        let buf = file.read_bytes(off, take)?;
        mac.update(buf.as_slice());
        off = checked_add_u64(off, take_u64, "verify-seal range")?;
        remaining -= take_u64;
    }
    Ok(())
}

#[derive(Debug)]
struct TagObject {
    seqnum: u64,
    epoch: u64,
    tag: [u8; TAG_LENGTH],
}

fn read_tag_object(file: &JournalFile, offset: u64, oh: &ObjectHeader) -> Result<TagObject> {
    if oh.size != 64 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(offset),
            reason: format!("TAG object has invalid size: {}", oh.size),
        });
    }

    let buf = file.read_bytes(offset, 64)?;
    let b = buf.as_slice();
    let seqnum = read_u64_le(b, 16).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(offset + 16),
        reason: "TAG.seqnum truncated".to_string(),
    })?;
    let epoch = read_u64_le(b, 24).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(offset + 24),
        reason: "TAG.epoch truncated".to_string(),
    })?;
    let tag_bytes = b.get(32..64).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(offset + 32),
        reason: "TAG.tag truncated".to_string(),
    })?;
    let mut tag = [0u8; TAG_LENGTH];
    tag.copy_from_slice(tag_bytes);

    Ok(TagObject { seqnum, epoch, tag })
}

fn align64(size: u64) -> Result<u64> {
    let added = checked_add_u64(size, 7, "align64")?;
    Ok(added & !7u64)
}
