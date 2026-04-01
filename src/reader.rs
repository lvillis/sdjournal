use crate::error::{Result, SdJournalError};
use crate::util::checked_add_u64;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "mmap")]
use memmap2::Mmap;
#[cfg(feature = "mmap")]
use std::path::Path;

/// A byte buffer returned by `RandomAccess`.
///
/// When mmap is enabled and safe to use, this may borrow from an mmap'd region.
/// Otherwise, this owns the bytes read from the underlying file.
#[derive(Debug, Clone)]
pub(crate) enum ByteBuf {
    #[cfg(feature = "mmap")]
    Mmap {
        map: Arc<Mmap>,
        range: std::ops::Range<usize>,
    },
    Owned(Arc<[u8]>),
}

impl ByteBuf {
    #[cfg(feature = "mmap")]
    pub(crate) fn from_mmap(
        map: Arc<Mmap>,
        range: std::ops::Range<usize>,
        path: &Path,
    ) -> Result<Self> {
        if map.get(range.clone()).is_none() {
            return Err(SdJournalError::Corrupt {
                path: Some(path.to_path_buf()),
                offset: None,
                reason: "mmap range out of bounds".to_string(),
            });
        }
        Ok(ByteBuf::Mmap { map, range })
    }

    pub(crate) fn from_vec(v: Vec<u8>) -> Self {
        ByteBuf::Owned(Arc::<[u8]>::from(v))
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            #[cfg(feature = "mmap")]
            ByteBuf::Mmap { map, range } => &map[range.clone()],
            ByteBuf::Owned(b) => b,
        }
    }
}

impl AsRef<[u8]> for ByteBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

pub(crate) trait RandomAccess: Send + Sync {
    fn len(&self) -> Result<u64>;
    fn read(&self, offset: u64, len: usize) -> Result<ByteBuf>;
}

#[derive(Clone)]
pub(crate) struct FileAccess {
    path: PathBuf,
    file: Arc<File>,
}

impl FileAccess {
    pub(crate) fn new(path: PathBuf, file: Arc<File>) -> Self {
        Self { path, file }
    }
}

impl RandomAccess for FileAccess {
    fn len(&self) -> Result<u64> {
        self.file
            .metadata()
            .map_err(|e| SdJournalError::io("metadata", Some(self.path.clone()), e))
            .map(|m| m.len())
    }

    fn read(&self, offset: u64, len: usize) -> Result<ByteBuf> {
        let end = checked_add_u64(offset, u64::try_from(len).unwrap_or(u64::MAX), "read range")?;
        let file_len = self.len()?;
        if end > file_len {
            return Err(SdJournalError::Transient {
                path: Some(self.path.clone()),
                reason: format!("read beyond end of file (file_len={file_len}, end={end})"),
            });
        }

        let mut buf = vec![0u8; len];
        read_exact_at(self.file.as_ref(), offset, &mut buf)
            .map_err(|e| SdJournalError::io("read_at", Some(self.path.clone()), e))?;
        Ok(ByteBuf::from_vec(buf))
    }
}

#[cfg(feature = "mmap")]
#[derive(Clone)]
pub(crate) struct MmapAccess {
    path: PathBuf,
    file: Arc<File>,
    map: Arc<Mmap>,
}

#[cfg(feature = "mmap")]
impl MmapAccess {
    pub(crate) fn new(path: PathBuf, file: Arc<File>, map: Arc<Mmap>) -> Self {
        Self { path, file, map }
    }

    pub(crate) fn file(&self) -> Arc<File> {
        self.file.clone()
    }
}

#[cfg(feature = "mmap")]
impl RandomAccess for MmapAccess {
    fn len(&self) -> Result<u64> {
        self.file
            .metadata()
            .map_err(|e| SdJournalError::io("metadata", Some(self.path.clone()), e))
            .map(|m| m.len())
    }

    fn read(&self, offset: u64, len: usize) -> Result<ByteBuf> {
        let end = checked_add_u64(offset, u64::try_from(len).unwrap_or(u64::MAX), "read range")?;
        let file_len = self.len()?;
        if end > file_len {
            return Err(SdJournalError::Transient {
                path: Some(self.path.clone()),
                reason: format!("mmap read beyond end of file (file_len={file_len}, end={end})"),
            });
        }

        let start = usize::try_from(offset).map_err(|_| SdJournalError::Corrupt {
            path: Some(self.path.clone()),
            offset: Some(offset),
            reason: "offset out of range".to_string(),
        })?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| SdJournalError::Corrupt {
                path: Some(self.path.clone()),
                offset: Some(offset),
                reason: "range overflow".to_string(),
            })?;

        ByteBuf::from_mmap(self.map.clone(), start..end, &self.path)
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt as _;
    while !buf.is_empty() {
        let n = file.read_at(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        offset = offset.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        buf = &mut buf[n..];
    }
    Ok(())
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt as _;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        offset = offset.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        buf = &mut buf[n..];
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(buf)
}
