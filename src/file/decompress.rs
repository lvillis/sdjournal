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
        use std::io::Write as _;

        let plain = b"hello from xz";
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(plain).unwrap();
        let encoded = encoder.finish().unwrap();

        assert_eq!(decompress_xz(&encoded, plain.len()).unwrap(), plain);

        match decompress_xz(&encoded, plain.len() - 1) {
            Err(SdJournalError::LimitExceeded { kind, limit }) => {
                assert_eq!(kind, LimitKind::DecompressedBytes);
                assert_eq!(limit, (plain.len() - 1) as u64);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
