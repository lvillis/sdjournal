use crate::error::{Result, SdJournalError};

#[cfg(any(feature = "lz4", feature = "zstd", feature = "xz"))]
use crate::error::{CompressionAlgo, LimitKind};
#[cfg(feature = "lz4")]
use crate::util::read_u64_le;

#[cfg(feature = "lz4")]
pub(super) fn decompress_lz4(src: &[u8], max: usize) -> Result<Vec<u8>> {
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
pub(super) fn decompress_lz4(_src: &[u8], _max: usize) -> Result<Vec<u8>> {
    Err(SdJournalError::Unsupported {
        reason: "lz4 support is disabled (feature lz4)".to_string(),
    })
}

#[cfg(feature = "zstd")]
pub(super) fn decompress_zstd(src: &[u8], max: usize) -> Result<Vec<u8>> {
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
pub(super) fn decompress_zstd(_src: &[u8], _max: usize) -> Result<Vec<u8>> {
    Err(SdJournalError::Unsupported {
        reason: "zstd support is disabled (feature zstd)".to_string(),
    })
}

#[cfg(feature = "xz")]
pub(super) fn decompress_xz(src: &[u8], max: usize) -> Result<Vec<u8>> {
    use xz4rust::{DICT_SIZE_PROFILE_6, XzDecoder};

    let dict_limit = max.max(DICT_SIZE_PROFILE_6);
    let mut decoder = XzDecoder::with_alloc_dict_size(DICT_SIZE_PROFILE_6, dict_limit);
    let mut input_pos = 0usize;
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];

    loop {
        if input_pos >= src.len() {
            return Err(SdJournalError::DecompressFailed {
                algo: CompressionAlgo::Xz,
                reason: "unexpected end of xz stream".to_string(),
            });
        }

        let remaining = max.saturating_sub(out.len());
        let mut overflow_probe = [0u8; 1];
        let output = if remaining == 0 {
            overflow_probe.as_mut_slice()
        } else {
            let n = remaining.min(buf.len());
            &mut buf[..n]
        };

        let result = decoder.decode(&src[input_pos..], output).map_err(|e| {
            SdJournalError::DecompressFailed {
                algo: CompressionAlgo::Xz,
                reason: e.to_string(),
            }
        })?;

        input_pos = input_pos.saturating_add(result.input_consumed());
        let produced = result.output_produced();
        if remaining == 0 && produced != 0 {
            return Err(SdJournalError::LimitExceeded {
                kind: LimitKind::DecompressedBytes,
                limit: u64::try_from(max).unwrap_or(u64::MAX),
            });
        }
        out.extend_from_slice(&output[..produced]);

        if result.is_end_of_stream() {
            return Ok(out);
        }
        if !result.made_progress() {
            return Err(SdJournalError::DecompressFailed {
                algo: CompressionAlgo::Xz,
                reason: "xz decoder made no progress".to_string(),
            });
        }
    }
}

#[cfg(not(feature = "xz"))]
pub(super) fn decompress_xz(_src: &[u8], _max: usize) -> Result<Vec<u8>> {
    Err(SdJournalError::Unsupported {
        reason: "xz support is disabled (feature xz)".to_string(),
    })
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "lz4", feature = "zstd", feature = "xz"))]
    use super::*;

    #[cfg(feature = "lz4")]
    #[test]
    fn lz4_roundtrip_and_limit_checks() {
        let plain = b"hello from lz4";
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(plain.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&lz4_flex::block::compress(plain));

        assert_eq!(decompress_lz4(&encoded, plain.len()).unwrap(), plain);

        match decompress_lz4(&encoded, plain.len() - 1) {
            Err(SdJournalError::LimitExceeded { kind, limit }) => {
                assert_eq!(kind, LimitKind::DecompressedBytes);
                assert_eq!(limit, (plain.len() - 1) as u64);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn lz4_rejects_short_payload() {
        match decompress_lz4(&[0u8; 8], 128) {
            Err(SdJournalError::DecompressFailed { algo, reason }) => {
                assert_eq!(algo, CompressionAlgo::Lz4);
                assert_eq!(reason, "lz4 payload too short");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_rejects_invalid_payload() {
        match decompress_zstd(b"not zstd", 128) {
            Err(SdJournalError::DecompressFailed { algo, .. }) => {
                assert_eq!(algo, CompressionAlgo::Zstd);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[cfg(feature = "xz")]
    #[test]
    fn xz_roundtrip_and_limit_checks() {
        let plain = b"hello from xz";
        let encoded = xz_fixture();

        assert_eq!(decompress_xz(encoded, plain.len()).unwrap(), plain);

        match decompress_xz(encoded, plain.len() - 1) {
            Err(SdJournalError::LimitExceeded { kind, limit }) => {
                assert_eq!(kind, LimitKind::DecompressedBytes);
                assert_eq!(limit, (plain.len() - 1) as u64);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[cfg(feature = "xz")]
    #[test]
    fn xz_rejects_invalid_payload() {
        match decompress_xz(b"not xz", 128) {
            Err(SdJournalError::DecompressFailed { algo, .. }) => {
                assert_eq!(algo, CompressionAlgo::Xz);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[cfg(feature = "xz")]
    fn xz_fixture() -> &'static [u8] {
        &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00,
            0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3, 0x01, 0x00, 0x0c, 0x68,
            0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x78, 0x7a, 0x00, 0x00,
            0x00, 0x00, 0xa5, 0xb3, 0x18, 0x76, 0x67, 0x14, 0xad, 0x57, 0x00, 0x01, 0x25, 0x0d,
            0x71, 0x19, 0xc4, 0xb6, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x59, 0x5a,
        ]
    }
}
