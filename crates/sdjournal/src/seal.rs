use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::{JournalFile, ObjectHeader};
use crate::util::{checked_add_u64, read_u64_le};
use hmac::{Hmac, Mac as _};
use num_bigint::{BigInt, BigUint};
use num_traits::{One as _, Signed as _, Zero as _};
use sha2::Digest as _;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const FSPRG_RECOMMENDED_SECPAR: u16 = 1536;
const FSPRG_RECOMMENDED_SEEDLEN: usize = 96 / 8;

const RND_GEN_P: u32 = 0x01;
const RND_GEN_Q: u32 = 0x02;
const RND_GEN_X: u32 = 0x03;

const TAG_LENGTH: usize = 256 / 8;

const OBJECT_DATA: u8 = 1;
const OBJECT_FIELD: u8 = 2;
const OBJECT_ENTRY: u8 = 3;
const OBJECT_DATA_HASH_TABLE: u8 = 4;
const OBJECT_FIELD_HASH_TABLE: u8 = 5;
const OBJECT_ENTRY_ARRAY: u8 = 6;
const OBJECT_TAG: u8 = 7;

const VERIFY_READ_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct VerificationKey {
    seed: [u8; FSPRG_RECOMMENDED_SEEDLEN],
    start_usec: u64,
    interval_usec: u64,
}

impl VerificationKey {
    pub(crate) fn seed(&self) -> &[u8; FSPRG_RECOMMENDED_SEEDLEN] {
        &self.seed
    }

    #[allow(dead_code)]
    pub(crate) fn start_usec(&self) -> u64 {
        self.start_usec
    }

    #[allow(dead_code)]
    pub(crate) fn interval_usec(&self) -> u64 {
        self.interval_usec
    }
}

pub(crate) fn parse_verification_key(s: &str) -> Result<VerificationKey> {
    fn hex_nibble(c: char) -> Option<u8> {
        match c {
            '0'..='9' => Some((c as u8) - b'0'),
            'a'..='f' => Some((c as u8) - b'a' + 10),
            'A'..='F' => Some((c as u8) - b'A' + 10),
            _ => None,
        }
    }

    let s = s.trim();
    if s.is_empty() {
        return Err(SdJournalError::InvalidQuery {
            reason: "empty verification key".to_string(),
        });
    }

    let mut seed = [0u8; FSPRG_RECOMMENDED_SEEDLEN];
    let mut chars = s.chars().peekable();
    for b in &mut seed {
        while matches!(chars.peek(), Some('-')) {
            chars.next();
        }

        let hi = chars.next().ok_or_else(|| SdJournalError::InvalidQuery {
            reason: "verification key seed is too short".to_string(),
        })?;
        let lo = chars.next().ok_or_else(|| SdJournalError::InvalidQuery {
            reason: "verification key seed is too short".to_string(),
        })?;

        let hi = hex_nibble(hi).ok_or_else(|| SdJournalError::InvalidQuery {
            reason: "verification key seed contains non-hex".to_string(),
        })?;
        let lo = hex_nibble(lo).ok_or_else(|| SdJournalError::InvalidQuery {
            reason: "verification key seed contains non-hex".to_string(),
        })?;

        *b = (hi << 4) | lo;
    }

    match chars.next() {
        Some('/') => {}
        _ => {
            return Err(SdJournalError::InvalidQuery {
                reason: "verification key missing '/' separator".to_string(),
            });
        }
    }

    let rest: String = chars.collect();
    let (start_s, interval_s) =
        rest.split_once('-')
            .ok_or_else(|| SdJournalError::InvalidQuery {
                reason: "verification key missing 'start-interval'".to_string(),
            })?;
    if start_s.is_empty() || interval_s.is_empty() {
        return Err(SdJournalError::InvalidQuery {
            reason: "verification key has empty start/interval".to_string(),
        });
    }

    let start = u64::from_str_radix(start_s, 16).map_err(|_| SdJournalError::InvalidQuery {
        reason: "verification key start is not valid hex".to_string(),
    })?;
    let interval =
        u64::from_str_radix(interval_s, 16).map_err(|_| SdJournalError::InvalidQuery {
            reason: "verification key interval is not valid hex".to_string(),
        })?;
    if interval == 0 {
        return Err(SdJournalError::InvalidQuery {
            reason: "verification key interval must be non-zero".to_string(),
        });
    }

    let start_usec = start
        .checked_mul(interval)
        .ok_or_else(|| SdJournalError::InvalidQuery {
            reason: "verification key start*interval overflows u64".to_string(),
        })?;

    Ok(VerificationKey {
        seed,
        start_usec,
        interval_usec: interval,
    })
}

#[derive(Debug)]
pub(crate) struct FsprgParams {
    p: BigUint,
    q: BigUint,
    n: BigUint,
    x0: BigUint,
    inv_p_mod_q: BigUint,
    n_bytes: usize,
}

impl FsprgParams {
    pub(crate) fn new(seed: &[u8; FSPRG_RECOMMENDED_SEEDLEN]) -> Result<Self> {
        let secpar = FSPRG_RECOMMENDED_SECPAR as usize;
        if !secpar.is_multiple_of(16) || !(16..=16384).contains(&secpar) {
            return Err(SdJournalError::Unsupported {
                reason: "unsupported FSPRG security parameter".to_string(),
            });
        }

        let half = secpar / 2;
        let p = genprime3mod4(half, seed, RND_GEN_P)?;
        let q = genprime3mod4(half, seed, RND_GEN_Q)?;

        let n = &p * &q;
        let n_bits = bit_length(&n);
        if n_bits != secpar {
            return Err(SdJournalError::Corrupt {
                path: None,
                offset: None,
                reason: format!(
                    "FSPRG modulus size mismatch (expected {secpar} bits, got {n_bits})"
                ),
            });
        }

        let x0 = gensquare(&n, seed, RND_GEN_X, secpar)?;
        let inv_p_mod_q = modinv(&p, &q).ok_or_else(|| SdJournalError::Corrupt {
            path: None,
            offset: None,
            reason: "FSPRG CRT inverse does not exist".to_string(),
        })?;

        Ok(Self {
            p,
            q,
            n,
            x0,
            inv_p_mod_q,
            n_bytes: secpar / 8,
        })
    }
}

#[derive(Debug)]
struct FsprgState<'a> {
    params: &'a FsprgParams,
    epoch: u64,
    x: BigUint,
}

impl<'a> FsprgState<'a> {
    fn new(params: &'a FsprgParams) -> Self {
        Self {
            params,
            epoch: 0,
            x: params.x0.clone(),
        }
    }

    fn seek(&mut self, goal: u64) -> Result<()> {
        if goal == self.epoch {
            return Ok(());
        }
        if goal == self.epoch.saturating_add(1) {
            return self.evolve();
        }

        let xp0 = &self.params.x0 % &self.params.p;
        let xq0 = &self.params.x0 % &self.params.q;

        let kp = twopowmodphi(goal, &self.params.p);
        let kq = twopowmodphi(goal, &self.params.q);

        let xp = xp0.modpow(&kp, &self.params.p);
        let xq = xq0.modpow(&kq, &self.params.q);

        self.x = crt_compose(
            &xp,
            &xq,
            &self.params.p,
            &self.params.q,
            &self.params.inv_p_mod_q,
        )?;
        self.epoch = goal;

        Ok(())
    }

    fn evolve(&mut self) -> Result<()> {
        self.x = (&self.x * &self.x) % &self.params.n;
        self.epoch = self.epoch.saturating_add(1);
        Ok(())
    }

    fn get_key(&self, keylen: usize, idx: u32) -> Vec<u8> {
        let mut seed = Vec::with_capacity(self.params.n_bytes * 2 + 8);
        seed.extend_from_slice(&to_be_padded(&self.params.n, self.params.n_bytes));
        seed.extend_from_slice(&to_be_padded(&self.x, self.params.n_bytes));
        seed.extend_from_slice(&self.epoch.to_be_bytes());

        let mut out = vec![0u8; keylen];
        det_randomize(&mut out, &seed, idx);
        out
    }
}

pub(crate) fn verify_file_seal(
    file: &JournalFile,
    key: &VerificationKey,
    params: &FsprgParams,
) -> Result<()> {
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

    let _ = key;
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

fn det_randomize(buf: &mut [u8], seed: &[u8], idx: u32) {
    let mut base = Sha256::new();
    base.update(seed);
    base.update(idx.to_be_bytes());

    let mut ctr = 0u32;
    let mut out = buf;
    while !out.is_empty() {
        let mut h = base.clone();
        h.update(ctr.to_be_bytes());
        let digest = h.finalize();
        let take = std::cmp::min(out.len(), digest.len());
        out[..take].copy_from_slice(&digest[..take]);
        out = &mut out[take..];
        ctr = ctr.wrapping_add(1);
    }
}

fn genprime3mod4(bits: usize, seed: &[u8], idx: u32) -> Result<BigUint> {
    if !bits.is_multiple_of(8) || bits == 0 {
        return Err(SdJournalError::Unsupported {
            reason: "unsupported prime size for FSPRG".to_string(),
        });
    }

    let len = bits / 8;
    let mut buf = vec![0u8; len];
    det_randomize(&mut buf, seed, idx);
    buf[0] |= 0xc0;
    buf[len - 1] |= 0x03;

    let mut p = BigUint::from_bytes_be(&buf);
    while !is_probable_prime(&p) {
        p += 4u8;
    }
    Ok(p)
}

fn gensquare(n: &BigUint, seed: &[u8], idx: u32, secpar: usize) -> Result<BigUint> {
    if !secpar.is_multiple_of(8) {
        return Err(SdJournalError::Unsupported {
            reason: "unsupported FSPRG security parameter".to_string(),
        });
    }

    let len = secpar / 8;
    let mut buf = vec![0u8; len];
    det_randomize(&mut buf, seed, idx);
    buf[0] &= 0x7f;

    let x = BigUint::from_bytes_be(&buf);
    if x >= *n {
        return Err(SdJournalError::Corrupt {
            path: None,
            offset: None,
            reason: "FSPRG seed produced x >= n".to_string(),
        });
    }

    Ok((&x * &x) % n)
}

fn twopowmodphi(epoch: u64, p: &BigUint) -> BigUint {
    let two: BigUint = BigUint::from(2u8);
    let phi = p - BigUint::one();
    two.modpow(&BigUint::from(epoch), &phi)
}

fn crt_compose(
    xp: &BigUint,
    xq: &BigUint,
    p: &BigUint,
    q: &BigUint,
    inv_p_mod_q: &BigUint,
) -> Result<BigUint> {
    let xp_mod_q = xp % q;
    let mut a = if xq >= &xp_mod_q {
        xq - &xp_mod_q
    } else {
        (xq + q) - &xp_mod_q
    };
    if a >= *q {
        a %= q;
    }

    a = (a * inv_p_mod_q) % q;
    Ok(p * a + xp)
}

fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = BigInt::from(m.clone());
    let mut new_r = BigInt::from(a.clone());

    while !new_r.is_zero() {
        let q = &r / &new_r;
        let next_t = &t - &q * &new_t;
        t = new_t;
        new_t = next_t;

        let next_r = &r - &q * &new_r;
        r = new_r;
        new_r = next_r;
    }

    if r != BigInt::one() {
        return None;
    }

    if t.is_negative() {
        t += BigInt::from(m.clone());
    }

    t.to_biguint()
}

fn bit_length(n: &BigUint) -> usize {
    let bytes = n.to_bytes_be();
    let Some((&first, rest)) = bytes.split_first() else {
        return 0;
    };
    let leading = first.leading_zeros() as usize;
    rest.len().saturating_add(1).saturating_mul(8) - leading
}

fn to_be_padded(n: &BigUint, len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    if bytes.len() >= len {
        if bytes.len() == len {
            return bytes;
        }
        return bytes[bytes.len() - len..].to_vec();
    }

    let mut out = vec![0u8; len];
    out[len - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn is_probable_prime(n: &BigUint) -> bool {
    let one: BigUint = BigUint::one();
    let two: BigUint = BigUint::from(2u8);
    let three: BigUint = BigUint::from(3u8);

    if n < &two {
        return false;
    }
    if n == &two || n == &three {
        return true;
    }
    if (n & &one).is_zero() {
        return false;
    }

    // Trial division by small primes to reject trivial composites quickly.
    const SMALL_PRIMES: &[u32] = &[
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    ];
    for &p in SMALL_PRIMES {
        if (n % p).is_zero() {
            return false;
        }
    }

    miller_rabin(n, 32)
}

fn miller_rabin(n: &BigUint, rounds: usize) -> bool {
    let one: BigUint = BigUint::one();
    let two: BigUint = BigUint::from(2u8);

    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0u32;
    while (&d & &one).is_zero() {
        d >>= 1;
        s = s.saturating_add(1);
    }

    let n_bytes = n.to_bytes_be();
    for i in 0..rounds {
        let mut h = Sha256::new();
        h.update(&n_bytes);
        h.update((i as u32).to_be_bytes());
        let digest = h.finalize();

        let mut a = BigUint::from_bytes_be(&digest);
        if a >= n_minus_one {
            a %= &n_minus_one;
        }
        if a < two {
            a += &two;
        }

        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }

        let mut witness = true;
        for _ in 0..s.saturating_sub(1) {
            x = (&x * &x) % n;
            if x == n_minus_one {
                witness = false;
                break;
            }
            if x == one {
                return false;
            }
        }
        if witness {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_key_parses_hyphenated_seed() {
        let k = parse_verification_key("01-23-45-67-89-ab-cd-ef-01-23-45-67/1-10").unwrap();
        assert_eq!(
            k.seed,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67
            ]
        );
        assert_eq!(k.start_usec, 0x10);
        assert_eq!(k.interval_usec, 0x10);
    }

    #[test]
    fn fsprg_seek_matches_evolve_small_secpar() {
        let seed = [0x11u8; FSPRG_RECOMMENDED_SEEDLEN];

        // A small deterministic setup to validate seek/evolve agreement without heavy 1536-bit work.
        let secpar = 128usize;
        let half = secpar / 2;
        let p = genprime3mod4(half, &seed, RND_GEN_P).unwrap();
        let q = genprime3mod4(half, &seed, RND_GEN_Q).unwrap();
        let n = &p * &q;
        let x0 = gensquare(&n, &seed, RND_GEN_X, secpar).unwrap();
        let inv = modinv(&p, &q).unwrap();
        let params = FsprgParams {
            p,
            q,
            n,
            x0,
            inv_p_mod_q: inv,
            n_bytes: secpar / 8,
        };

        let mut a = FsprgState::new(&params);
        let mut b = FsprgState::new(&params);

        for epoch in 0..32u64 {
            if epoch > 0 {
                a.evolve().unwrap();
            }
            b.seek(epoch).unwrap();
            assert_eq!(a.epoch, epoch);
            assert_eq!(b.epoch, epoch);
            assert_eq!(a.x, b.x);

            let ka = a.get_key(32, 0);
            let kb = b.get_key(32, 0);
            assert_eq!(ka, kb);
        }
    }
}
