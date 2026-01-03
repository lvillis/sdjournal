use crate::error::{LimitKind, Result, SdJournalError};

pub(crate) fn checked_add_u64(a: u64, b: u64, context: &'static str) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| SdJournalError::Corrupt {
        path: None,
        offset: None,
        reason: format!("{context}: overflow when adding {a} + {b}"),
    })
}

pub(crate) fn take<const N: usize>(buf: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let slice = buf.get(offset..end)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Some(out)
}

pub(crate) fn read_u8(buf: &[u8], offset: usize) -> Option<u8> {
    buf.get(offset).copied()
}

pub(crate) fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = take::<4>(buf, offset)?;
    Some(u32::from_le_bytes(bytes))
}

pub(crate) fn read_u64_le(buf: &[u8], offset: usize) -> Option<u64> {
    let bytes = take::<8>(buf, offset)?;
    Some(u64::from_le_bytes(bytes))
}

pub(crate) fn read_id128(buf: &[u8], offset: usize) -> Option<[u8; 16]> {
    take::<16>(buf, offset)
}

pub(crate) fn is_ascii_field_name(name: &[u8]) -> bool {
    name.iter().all(|&b| b.is_ascii() && b != b'=' && b != 0)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize]);
        out.push(LUT[(b & 0x0f) as usize]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(SdJournalError::InvalidQuery {
            reason: "hex string must have even length".to_string(),
        });
    }

    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = val(bytes[i]).ok_or_else(|| SdJournalError::InvalidQuery {
            reason: "invalid hex digit".to_string(),
        })?;
        let lo = val(bytes[i + 1]).ok_or_else(|| SdJournalError::InvalidQuery {
            reason: "invalid hex digit".to_string(),
        })?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

pub(crate) fn ensure_limit_usize(kind: LimitKind, limit: usize, value: usize) -> Result<()> {
    if value > limit {
        return Err(SdJournalError::LimitExceeded {
            kind,
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

pub(crate) mod hash {
    use siphasher::sip::SipHasher24;
    use std::hash::Hasher;

    pub(crate) fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
        let mut hasher = SipHasher24::new_with_key(key);
        hasher.write(data);
        hasher.finish()
    }

    pub(crate) fn jenkins_hash64(data: &[u8]) -> u64 {
        let (pc, pb) = jenkins_hashlittle2(data, 0, 0);
        ((u64::from(pc)) << 32) | u64::from(pb)
    }

    fn jenkins_hashlittle2(key: &[u8], init_pc: u32, init_pb: u32) -> (u32, u32) {
        let mut a = 0xdeadbeefu32
            .wrapping_add(u32::try_from(key.len()).unwrap_or(u32::MAX))
            .wrapping_add(init_pc);
        let mut b = a;
        let mut c = a.wrapping_add(init_pb);

        fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
            *a = a.wrapping_sub(*c);
            *a ^= c.rotate_left(4);
            *c = c.wrapping_add(*b);

            *b = b.wrapping_sub(*a);
            *b ^= a.rotate_left(6);
            *a = a.wrapping_add(*c);

            *c = c.wrapping_sub(*b);
            *c ^= b.rotate_left(8);
            *b = b.wrapping_add(*a);

            *a = a.wrapping_sub(*c);
            *a ^= c.rotate_left(16);
            *c = c.wrapping_add(*b);

            *b = b.wrapping_sub(*a);
            *b ^= a.rotate_left(19);
            *a = a.wrapping_add(*c);

            *c = c.wrapping_sub(*b);
            *c ^= b.rotate_left(4);
            *b = b.wrapping_add(*a);
        }

        fn final_(a: &mut u32, b: &mut u32, c: &mut u32) {
            *c ^= *b;
            *c = c.wrapping_sub(b.rotate_left(14));

            *a ^= *c;
            *a = a.wrapping_sub(c.rotate_left(11));

            *b ^= *a;
            *b = b.wrapping_sub(a.rotate_left(25));

            *c ^= *b;
            *c = c.wrapping_sub(b.rotate_left(16));

            *a ^= *c;
            *a = a.wrapping_sub(c.rotate_left(4));

            *b ^= *a;
            *b = b.wrapping_sub(a.rotate_left(14));

            *c ^= *b;
            *c = c.wrapping_sub(b.rotate_left(24));
        }

        let mut i = 0usize;
        while key.len().saturating_sub(i) > 12 {
            let a_part = u32::from_le_bytes([key[i], key[i + 1], key[i + 2], key[i + 3]]);
            let b_part = u32::from_le_bytes([key[i + 4], key[i + 5], key[i + 6], key[i + 7]]);
            let c_part = u32::from_le_bytes([key[i + 8], key[i + 9], key[i + 10], key[i + 11]]);

            a = a.wrapping_add(a_part);
            b = b.wrapping_add(b_part);
            c = c.wrapping_add(c_part);
            mix(&mut a, &mut b, &mut c);

            i += 12;
        }

        let tail = &key[i..];
        if tail.is_empty() {
            return (c, b);
        }

        let n = tail.len();
        if n >= 12 {
            c = c.wrapping_add((u32::from(tail[11])) << 24);
        }
        if n >= 11 {
            c = c.wrapping_add((u32::from(tail[10])) << 16);
        }
        if n >= 10 {
            c = c.wrapping_add((u32::from(tail[9])) << 8);
        }
        if n >= 9 {
            c = c.wrapping_add(u32::from(tail[8]));
        }
        if n >= 8 {
            b = b.wrapping_add((u32::from(tail[7])) << 24);
        }
        if n >= 7 {
            b = b.wrapping_add((u32::from(tail[6])) << 16);
        }
        if n >= 6 {
            b = b.wrapping_add((u32::from(tail[5])) << 8);
        }
        if n >= 5 {
            b = b.wrapping_add(u32::from(tail[4]));
        }
        if n >= 4 {
            a = a.wrapping_add((u32::from(tail[3])) << 24);
        }
        if n >= 3 {
            a = a.wrapping_add((u32::from(tail[2])) << 16);
        }
        if n >= 2 {
            a = a.wrapping_add((u32::from(tail[1])) << 8);
        }
        if n >= 1 {
            a = a.wrapping_add(u32::from(tail[0]));
        }

        final_(&mut a, &mut b, &mut c);
        (c, b)
    }
}
