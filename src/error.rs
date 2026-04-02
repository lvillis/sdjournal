use std::fmt;
use std::path::PathBuf;

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, SdJournalError>;

/// Compression algorithm used in journal DATA payloads.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgo {
    /// XZ-compressed payloads.
    Xz,
    /// LZ4-compressed payloads.
    Lz4,
    /// Zstandard-compressed payloads.
    Zstd,
}

impl fmt::Display for CompressionAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompressionAlgo::Xz => write!(f, "xz"),
            CompressionAlgo::Lz4 => write!(f, "lz4"),
            CompressionAlgo::Zstd => write!(f, "zstd"),
        }
    }
}

/// Limit category for `SdJournalError::LimitExceeded`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// Maximum decoded object size accepted from the journal file.
    ObjectSizeBytes,
    /// Maximum number of bytes accepted after decompressing a DATA payload.
    DecompressedBytes,
    /// Maximum accepted field-name length.
    FieldNameLen,
    /// Maximum number of fields accepted in a single entry.
    FieldsPerEntry,
    /// Maximum traversal length for linked object chains.
    ObjectChainSteps,
    /// Maximum number of journal files accepted from discovery.
    JournalFiles,
    /// Maximum number of query terms accepted in a single query.
    QueryTerms,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitKind::ObjectSizeBytes => write!(f, "object_size_bytes"),
            LimitKind::DecompressedBytes => write!(f, "decompressed_bytes"),
            LimitKind::FieldNameLen => write!(f, "field_name_len"),
            LimitKind::FieldsPerEntry => write!(f, "fields_per_entry"),
            LimitKind::ObjectChainSteps => write!(f, "object_chain_steps"),
            LimitKind::JournalFiles => write!(f, "journal_files"),
            LimitKind::QueryTerms => write!(f, "query_terms"),
        }
    }
}

/// A structured error type for journal operations.
#[non_exhaustive]
#[derive(Debug)]
pub enum SdJournalError {
    /// An operating-system or filesystem I/O failure.
    Io {
        /// Short operation name such as `open`, `read_dir`, or `mmap`.
        op: &'static str,
        /// Path associated with the operation, when available.
        path: Option<PathBuf>,
        /// Underlying I/O error reported by the OS.
        source: std::io::Error,
    },
    /// The process lacks permission to open a journal file.
    PermissionDenied {
        /// Journal path that failed to open.
        path: PathBuf,
    },
    /// The caller supplied an invalid query, cursor, or verification key.
    InvalidQuery {
        /// Human-readable validation failure.
        reason: String,
    },
    /// The journal file or requested operation uses an unsupported capability.
    Unsupported {
        /// Human-readable reason for the unsupported case.
        reason: String,
    },
    /// The journal file is malformed, truncated, or internally inconsistent.
    Corrupt {
        /// Path to the offending journal file, when known.
        path: Option<PathBuf>,
        /// Offset associated with the corruption, when known.
        offset: Option<u64>,
        /// Human-readable corruption detail.
        reason: String,
    },
    /// The journal appears to be in a temporary state, such as concurrent truncation or growth.
    Transient {
        /// Path to the affected journal file, when known.
        path: Option<PathBuf>,
        /// Human-readable description of the transient condition.
        reason: String,
    },
    /// A compressed DATA payload could not be decoded.
    DecompressFailed {
        /// Compression algorithm that was being decoded.
        algo: CompressionAlgo,
        /// Decoder error detail.
        reason: String,
    },
    /// A configured defensive limit was exceeded.
    LimitExceeded {
        /// Which limit was exceeded.
        kind: LimitKind,
        /// Configured limit value.
        limit: u64,
    },
    /// No matching journal files or entries were found.
    NotFound,
}

impl SdJournalError {
    pub(crate) fn io(op: &'static str, path: Option<PathBuf>, source: std::io::Error) -> Self {
        SdJournalError::Io { op, path, source }
    }
}

impl fmt::Display for SdJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdJournalError::Io { op, path, source } => match path {
                Some(path) => write!(f, "io error during {op} for {}: {source}", path.display()),
                None => write!(f, "io error during {op}: {source}"),
            },
            SdJournalError::PermissionDenied { path } => {
                write!(f, "permission denied: {}", path.display())
            }
            SdJournalError::InvalidQuery { reason } => write!(f, "invalid query: {reason}"),
            SdJournalError::Unsupported { reason } => write!(f, "unsupported: {reason}"),
            SdJournalError::Corrupt {
                path,
                offset,
                reason,
            } => match (path, offset) {
                (Some(path), Some(offset)) => write!(
                    f,
                    "corrupt journal at {} (offset {offset}): {reason}",
                    path.display()
                ),
                (Some(path), None) => write!(f, "corrupt journal at {}: {reason}", path.display()),
                (None, Some(offset)) => write!(f, "corrupt journal at offset {offset}: {reason}"),
                (None, None) => write!(f, "corrupt journal: {reason}"),
            },
            SdJournalError::Transient { path, reason } => match path {
                Some(path) => write!(f, "transient journal state at {}: {reason}", path.display()),
                None => write!(f, "transient journal state: {reason}"),
            },
            SdJournalError::DecompressFailed { algo, reason } => {
                write!(f, "decompress failed ({algo}): {reason}")
            }
            SdJournalError::LimitExceeded { kind, limit } => {
                write!(f, "limit exceeded ({kind}): {limit}")
            }
            SdJournalError::NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for SdJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SdJournalError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn display_names_for_compression_algo_and_limit_kind_are_stable() {
        assert_eq!(CompressionAlgo::Xz.to_string(), "xz");
        assert_eq!(CompressionAlgo::Lz4.to_string(), "lz4");
        assert_eq!(CompressionAlgo::Zstd.to_string(), "zstd");

        assert_eq!(LimitKind::ObjectSizeBytes.to_string(), "object_size_bytes");
        assert_eq!(
            LimitKind::DecompressedBytes.to_string(),
            "decompressed_bytes"
        );
        assert_eq!(LimitKind::FieldNameLen.to_string(), "field_name_len");
        assert_eq!(LimitKind::FieldsPerEntry.to_string(), "fields_per_entry");
        assert_eq!(
            LimitKind::ObjectChainSteps.to_string(),
            "object_chain_steps"
        );
        assert_eq!(LimitKind::JournalFiles.to_string(), "journal_files");
        assert_eq!(LimitKind::QueryTerms.to_string(), "query_terms");
    }

    #[test]
    fn error_display_and_source_cover_structured_variants() {
        let io_source = std::io::Error::other("disk gone");
        let io_err = SdJournalError::io(
            "read_at",
            Some(PathBuf::from("/tmp/test.journal")),
            io_source,
        );
        assert_eq!(
            io_err.to_string(),
            "io error during read_at for /tmp/test.journal: disk gone"
        );
        assert_eq!(
            io_err
                .source()
                .expect("io variant should expose a source")
                .to_string(),
            "disk gone"
        );

        let corrupt = SdJournalError::Corrupt {
            path: Some(PathBuf::from("/tmp/test.journal")),
            offset: Some(64),
            reason: "bad header".to_string(),
        };
        assert_eq!(
            corrupt.to_string(),
            "corrupt journal at /tmp/test.journal (offset 64): bad header"
        );

        let limit = SdJournalError::LimitExceeded {
            kind: LimitKind::QueryTerms,
            limit: 64,
        };
        assert_eq!(limit.to_string(), "limit exceeded (query_terms): 64");
        assert!(limit.source().is_none());
    }
}
