use std::fmt;
use std::path::PathBuf;

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, SdJournalError>;

/// Compression algorithm used in journal DATA payloads.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgo {
    Xz,
    Lz4,
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
    ObjectSizeBytes,
    DecompressedBytes,
    FieldNameLen,
    FieldsPerEntry,
    ObjectChainSteps,
    JournalFiles,
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
    Io {
        op: &'static str,
        path: Option<PathBuf>,
        source: std::io::Error,
    },
    PermissionDenied {
        path: PathBuf,
    },
    InvalidQuery {
        reason: String,
    },
    Unsupported {
        reason: String,
    },
    Corrupt {
        path: Option<PathBuf>,
        offset: Option<u64>,
        reason: String,
    },
    Transient {
        path: Option<PathBuf>,
        reason: String,
    },
    DecompressFailed {
        algo: CompressionAlgo,
        reason: String,
    },
    LimitExceeded {
        kind: LimitKind,
        limit: u64,
    },
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
