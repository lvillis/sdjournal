use super::FSPRG_RECOMMENDED_SEEDLEN;
use crate::error::{Result, SdJournalError};

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

    #[expect(
        dead_code,
        reason = "seal timing metadata is reserved for future verification checks"
    )]
    pub(crate) fn start_usec(&self) -> u64 {
        self.start_usec
    }

    #[expect(
        dead_code,
        reason = "seal timing metadata is reserved for future verification checks"
    )]
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

#[cfg(test)]
mod tests {
    use super::parse_verification_key;

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
}
