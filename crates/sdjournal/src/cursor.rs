use crate::error::{Result, SdJournalError};
use crate::util::{hex_decode, hex_encode};
use std::fmt;

const PREFIX_V1: &str = "SJ1:";

const TAG_FILE_OFFSET: u8 = 0x01;
const TAG_SYSTEMD_RAW: u8 = 0x02;
const TAG_SYSTEMD_FIELDS: u8 = 0x03;
const TAG_ENTRY_KEY: u8 = 0x04;

const SYSTEMD_MASK_SEQNUM_ID: u8 = 1 << 0;
const SYSTEMD_MASK_SEQNUM: u8 = 1 << 1;
const SYSTEMD_MASK_BOOT_ID: u8 = 1 << 2;
const SYSTEMD_MASK_MONOTONIC: u8 = 1 << 3;
const SYSTEMD_MASK_REALTIME: u8 = 1 << 4;
const SYSTEMD_MASK_XOR_HASH: u8 = 1 << 5;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CursorKind {
    FileOffset {
        file_id: [u8; 16],
        entry_offset: u64,
    },
    EntryKey(SdJournalEntryKey),
    Systemd(SystemdCursor),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SdJournalEntryKey {
    pub(crate) file_id: [u8; 16],
    pub(crate) entry_offset: u64,
    pub(crate) seqnum: u64,
    pub(crate) realtime_usec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SystemdCursor {
    pub(crate) seqnum_id: Option<[u8; 16]>,
    pub(crate) seqnum: Option<u64>,
    pub(crate) boot_id: Option<[u8; 16]>,
    pub(crate) monotonic_usec: Option<u64>,
    pub(crate) realtime_usec: Option<u64>,
    pub(crate) xor_hash: Option<u64>,
}

impl SystemdCursor {
    fn is_valid(&self) -> bool {
        (self.seqnum_id.is_some() && self.seqnum.is_some())
            || (self.boot_id.is_some() && self.monotonic_usec.is_some())
            || self.realtime_usec.is_some()
    }

    fn systemd_wire_string(&self) -> Option<String> {
        let seqnum_id = self.seqnum_id?;
        let seqnum = self.seqnum?;
        let boot_id = self.boot_id?;
        let monotonic_usec = self.monotonic_usec?;
        let realtime_usec = self.realtime_usec?;
        let xor_hash = self.xor_hash?;

        Some(format!(
            "s={};i={seqnum:x};b={};m={monotonic_usec:x};t={realtime_usec:x};x={xor_hash:x}",
            crate::util::hex_encode(&seqnum_id),
            crate::util::hex_encode(&boot_id),
        ))
    }
}

/// Opaque cursor for checkpointing and resuming journal iteration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cursor {
    kind: CursorKind,
}

impl Cursor {
    pub(crate) fn new_entry_key(
        file_id: [u8; 16],
        entry_offset: u64,
        seqnum: u64,
        realtime_usec: u64,
    ) -> Self {
        Self {
            kind: CursorKind::EntryKey(SdJournalEntryKey {
                file_id,
                entry_offset,
                seqnum,
                realtime_usec,
            }),
        }
    }

    pub(crate) fn file_offset(&self) -> Option<([u8; 16], u64)> {
        match &self.kind {
            CursorKind::FileOffset {
                file_id,
                entry_offset,
            } => Some((*file_id, *entry_offset)),
            CursorKind::EntryKey(k) => Some((k.file_id, k.entry_offset)),
            CursorKind::Systemd(_) => None,
        }
    }

    pub(crate) fn sdjournal_entry_key(&self) -> Option<SdJournalEntryKey> {
        match &self.kind {
            CursorKind::EntryKey(k) => Some(*k),
            CursorKind::FileOffset { .. } | CursorKind::Systemd(_) => None,
        }
    }

    pub(crate) fn systemd(&self) -> Option<&SystemdCursor> {
        match &self.kind {
            CursorKind::Systemd(v) => Some(v),
            CursorKind::FileOffset { .. } | CursorKind::EntryKey(_) => None,
        }
    }

    /// Parse a cursor from a string.
    ///
    /// This accepts both the `sdjournal` versioned format (`SJ1:...`) and systemd cursor strings
    /// (best-effort).
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix(PREFIX_V1) {
            let bytes = hex_decode(rest)?;
            let tag = *bytes.first().ok_or_else(|| SdJournalError::InvalidQuery {
                reason: "empty cursor payload".to_string(),
            })?;
            match tag {
                TAG_FILE_OFFSET => {
                    if bytes.len() != 1 + 16 + 8 {
                        return Err(SdJournalError::InvalidQuery {
                            reason: "invalid cursor length for SJ1 FileOffset".to_string(),
                        });
                    }
                    let mut file_id = [0u8; 16];
                    file_id.copy_from_slice(&bytes[1..17]);
                    let mut off = [0u8; 8];
                    off.copy_from_slice(&bytes[17..25]);
                    Ok(Cursor {
                        kind: CursorKind::FileOffset {
                            file_id,
                            entry_offset: u64::from_le_bytes(off),
                        },
                    })
                }
                TAG_ENTRY_KEY => {
                    if bytes.len() != 1 + 16 + 8 + 8 + 8 {
                        return Err(SdJournalError::InvalidQuery {
                            reason: "invalid cursor length for SJ1 EntryKey".to_string(),
                        });
                    }

                    let mut file_id = [0u8; 16];
                    file_id.copy_from_slice(&bytes[1..17]);

                    let mut entry_offset = [0u8; 8];
                    entry_offset.copy_from_slice(&bytes[17..25]);

                    let mut seqnum = [0u8; 8];
                    seqnum.copy_from_slice(&bytes[25..33]);

                    let mut realtime = [0u8; 8];
                    realtime.copy_from_slice(&bytes[33..41]);

                    Ok(Cursor {
                        kind: CursorKind::EntryKey(SdJournalEntryKey {
                            file_id,
                            entry_offset: u64::from_le_bytes(entry_offset),
                            seqnum: u64::from_le_bytes(seqnum),
                            realtime_usec: u64::from_le_bytes(realtime),
                        }),
                    })
                }
                TAG_SYSTEMD_RAW => {
                    let raw = String::from_utf8(bytes[1..].to_vec()).map_err(|_| {
                        SdJournalError::InvalidQuery {
                            reason: "invalid UTF-8 in SJ1 systemd cursor".to_string(),
                        }
                    })?;
                    Ok(Cursor {
                        kind: CursorKind::Systemd(parse_systemd_cursor(&raw)?),
                    })
                }
                TAG_SYSTEMD_FIELDS => Ok(Cursor {
                    kind: CursorKind::Systemd(parse_systemd_fields(&bytes[1..])?),
                }),
                _ => Err(SdJournalError::Unsupported {
                    reason: "unknown SJ1 cursor variant".to_string(),
                }),
            }
        } else {
            Ok(Cursor {
                kind: CursorKind::Systemd(parse_systemd_cursor(s)?),
            })
        }
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::new();
        match &self.kind {
            CursorKind::FileOffset {
                file_id,
                entry_offset,
            } => {
                bytes.push(TAG_FILE_OFFSET);
                bytes.extend_from_slice(file_id);
                bytes.extend_from_slice(&entry_offset.to_le_bytes());
            }
            CursorKind::EntryKey(k) => {
                bytes.push(TAG_ENTRY_KEY);
                bytes.extend_from_slice(&k.file_id);
                bytes.extend_from_slice(&k.entry_offset.to_le_bytes());
                bytes.extend_from_slice(&k.seqnum.to_le_bytes());
                bytes.extend_from_slice(&k.realtime_usec.to_le_bytes());
            }
            CursorKind::Systemd(fields) => {
                if let Some(raw) = fields.systemd_wire_string() {
                    bytes.push(TAG_SYSTEMD_RAW);
                    bytes.extend_from_slice(raw.as_bytes());
                } else {
                    bytes.push(TAG_SYSTEMD_FIELDS);
                    let mut mask = 0u8;
                    if fields.seqnum_id.is_some() {
                        mask |= SYSTEMD_MASK_SEQNUM_ID;
                    }
                    if fields.seqnum.is_some() {
                        mask |= SYSTEMD_MASK_SEQNUM;
                    }
                    if fields.boot_id.is_some() {
                        mask |= SYSTEMD_MASK_BOOT_ID;
                    }
                    if fields.monotonic_usec.is_some() {
                        mask |= SYSTEMD_MASK_MONOTONIC;
                    }
                    if fields.realtime_usec.is_some() {
                        mask |= SYSTEMD_MASK_REALTIME;
                    }
                    if fields.xor_hash.is_some() {
                        mask |= SYSTEMD_MASK_XOR_HASH;
                    }

                    bytes.push(mask);
                    if let Some(v) = fields.seqnum_id {
                        bytes.extend_from_slice(&v);
                    }
                    if let Some(v) = fields.seqnum {
                        bytes.extend_from_slice(&v.to_le_bytes());
                    }
                    if let Some(v) = fields.boot_id {
                        bytes.extend_from_slice(&v);
                    }
                    if let Some(v) = fields.monotonic_usec {
                        bytes.extend_from_slice(&v.to_le_bytes());
                    }
                    if let Some(v) = fields.realtime_usec {
                        bytes.extend_from_slice(&v.to_le_bytes());
                    }
                    if let Some(v) = fields.xor_hash {
                        bytes.extend_from_slice(&v.to_le_bytes());
                    }
                }
            }
        }
        write!(f, "{PREFIX_V1}{}", hex_encode(&bytes))
    }
}

fn parse_systemd_fields(mut bytes: &[u8]) -> Result<SystemdCursor> {
    let mask = *bytes.first().ok_or_else(|| SdJournalError::InvalidQuery {
        reason: "missing systemd cursor mask".to_string(),
    })?;
    bytes = &bytes[1..];

    fn take<const N: usize>(bytes: &mut &[u8], reason: &'static str) -> Result<[u8; N]> {
        if bytes.len() < N {
            return Err(SdJournalError::InvalidQuery {
                reason: reason.to_string(),
            });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes[..N]);
        *bytes = &bytes[N..];
        Ok(out)
    }

    let seqnum_id = if mask & SYSTEMD_MASK_SEQNUM_ID != 0 {
        Some(take::<16>(&mut bytes, "systemd cursor missing seqnum_id")?)
    } else {
        None
    };
    let seqnum = if mask & SYSTEMD_MASK_SEQNUM != 0 {
        Some(u64::from_le_bytes(take::<8>(
            &mut bytes,
            "systemd cursor missing seqnum",
        )?))
    } else {
        None
    };
    let boot_id = if mask & SYSTEMD_MASK_BOOT_ID != 0 {
        Some(take::<16>(&mut bytes, "systemd cursor missing boot_id")?)
    } else {
        None
    };
    let monotonic_usec = if mask & SYSTEMD_MASK_MONOTONIC != 0 {
        Some(u64::from_le_bytes(take::<8>(
            &mut bytes,
            "systemd cursor missing monotonic_usec",
        )?))
    } else {
        None
    };
    let realtime_usec = if mask & SYSTEMD_MASK_REALTIME != 0 {
        Some(u64::from_le_bytes(take::<8>(
            &mut bytes,
            "systemd cursor missing realtime_usec",
        )?))
    } else {
        None
    };
    let xor_hash = if mask & SYSTEMD_MASK_XOR_HASH != 0 {
        Some(u64::from_le_bytes(take::<8>(
            &mut bytes,
            "systemd cursor missing xor_hash",
        )?))
    } else {
        None
    };

    if !bytes.is_empty() {
        return Err(SdJournalError::InvalidQuery {
            reason: "trailing bytes in systemd cursor payload".to_string(),
        });
    }

    let out = SystemdCursor {
        seqnum_id,
        seqnum,
        boot_id,
        monotonic_usec,
        realtime_usec,
        xor_hash,
    };
    if !out.is_valid() {
        return Err(SdJournalError::InvalidQuery {
            reason: "systemd cursor missing required fields".to_string(),
        });
    }

    Ok(out)
}

fn parse_systemd_cursor(s: &str) -> Result<SystemdCursor> {
    let s = s.trim();
    if s.is_empty() {
        return Err(SdJournalError::InvalidQuery {
            reason: "empty cursor".to_string(),
        });
    }

    fn parse_id128(s: &str, kind: &'static str) -> Result<[u8; 16]> {
        use std::borrow::Cow;

        let cleaned = if s.contains('-') {
            Cow::Owned(s.chars().filter(|&c| c != '-').collect::<String>())
        } else {
            Cow::Borrowed(s)
        };

        let bytes = hex_decode(cleaned.as_ref())?;
        if bytes.len() != 16 {
            return Err(SdJournalError::InvalidQuery {
                reason: format!("{kind} must be 16 bytes (32 hex chars)"),
            });
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn parse_hex_u64(s: &str, kind: &'static str) -> Result<u64> {
        u64::from_str_radix(s, 16).map_err(|_| SdJournalError::InvalidQuery {
            reason: format!("{kind} is not valid hex"),
        })
    }

    let mut out = SystemdCursor {
        seqnum_id: None,
        seqnum: None,
        boot_id: None,
        monotonic_usec: None,
        realtime_usec: None,
        xor_hash: None,
    };

    for part in s.split(';') {
        if part.is_empty() {
            return Err(SdJournalError::InvalidQuery {
                reason: "invalid systemd cursor: empty segment".to_string(),
            });
        }
        let bytes = part.as_bytes();
        if bytes.len() < 2 || bytes[1] != b'=' {
            return Err(SdJournalError::InvalidQuery {
                reason: "invalid systemd cursor segment".to_string(),
            });
        }
        let key = bytes[0];
        let value = &part[2..];
        match key {
            b's' => out.seqnum_id = Some(parse_id128(value, "seqnum_id")?),
            b'i' => out.seqnum = Some(parse_hex_u64(value, "seqnum")?),
            b'b' => out.boot_id = Some(parse_id128(value, "boot_id")?),
            b'm' => out.monotonic_usec = Some(parse_hex_u64(value, "monotonic_usec")?),
            b't' => out.realtime_usec = Some(parse_hex_u64(value, "realtime_usec")?),
            b'x' => out.xor_hash = Some(parse_hex_u64(value, "xor_hash")?),
            _ => {}
        }
    }

    if !out.is_valid() {
        return Err(SdJournalError::InvalidQuery {
            reason: "systemd cursor missing required fields".to_string(),
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_file_offset_roundtrip() {
        let file_id = [0x11u8; 16];
        let entry_offset = 0x1122334455667788u64;

        let mut bytes = Vec::new();
        bytes.push(TAG_FILE_OFFSET);
        bytes.extend_from_slice(&file_id);
        bytes.extend_from_slice(&entry_offset.to_le_bytes());
        let s = format!("{PREFIX_V1}{}", hex_encode(&bytes));
        assert!(s.starts_with(PREFIX_V1));

        let parsed = Cursor::parse(&s).unwrap();
        assert_eq!(parsed.file_offset(), Some((file_id, entry_offset)));
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn cursor_systemd_string_is_parsed() {
        let c = Cursor::parse(
            "s=0123456789abcdef0123456789abcdef;i=1;b=11111111111111111111111111111111;m=2;t=3;x=4",
        )
        .unwrap();
        let s = c.to_string();
        assert!(s.starts_with(PREFIX_V1));

        let parsed = Cursor::parse(&s).unwrap();
        assert_eq!(parsed.to_string(), s);
        assert!(parsed.file_offset().is_none());
        assert!(parsed.systemd().is_some());
    }

    #[test]
    fn cursor_entry_key_roundtrip() {
        let file_id = [0x11u8; 16];
        let entry_offset = 0x1122334455667788u64;
        let seqnum = 0x99aabbccddu64;
        let realtime_usec = 0x11220000u64;
        let c = Cursor::new_entry_key(file_id, entry_offset, seqnum, realtime_usec);
        let s = c.to_string();
        assert!(s.starts_with(PREFIX_V1));

        let parsed = Cursor::parse(&s).unwrap();
        assert_eq!(
            parsed.sdjournal_entry_key(),
            Some(SdJournalEntryKey {
                file_id,
                entry_offset,
                seqnum,
                realtime_usec
            })
        );
        assert_eq!(parsed.to_string(), s);
    }
}
