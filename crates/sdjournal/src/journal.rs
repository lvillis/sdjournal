use crate::config::JournalConfig;
use crate::cursor::Cursor;
use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::JournalFile;
use crate::query::JournalQuery;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "tracing")]
use tracing::{debug, warn};

#[derive(Clone)]
pub struct Journal {
    pub(crate) inner: Arc<JournalInner>,
}

pub(crate) struct JournalInner {
    pub(crate) config: JournalConfig,
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) files: Vec<JournalFile>,
}

impl Journal {
    pub fn open_default() -> Result<Self> {
        Self::open_default_with_config(JournalConfig::default())
    }

    pub fn open_default_with_config(config: JournalConfig) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let paths = vec![
                PathBuf::from("/run/log/journal"),
                PathBuf::from("/var/log/journal"),
            ];
            Self::open_dirs_with_config(&paths, config)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            Err(SdJournalError::Unsupported {
                reason: "Journal::open_default is only supported on Linux".to_string(),
            })
        }
    }

    pub fn open_dir(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_dir_with_config(path, JournalConfig::default())
    }

    pub fn open_dir_with_config(path: impl AsRef<Path>, config: JournalConfig) -> Result<Self> {
        let paths = vec![path.as_ref().to_path_buf()];
        Self::open_dirs_with_config(&paths, config)
    }

    pub fn open_dirs(paths: &[PathBuf]) -> Result<Self> {
        Self::open_dirs_with_config(paths, JournalConfig::default())
    }

    pub fn open_dirs_with_config(paths: &[PathBuf], config: JournalConfig) -> Result<Self> {
        if paths.is_empty() {
            return Err(SdJournalError::InvalidQuery {
                reason: "open_dirs requires at least one path".to_string(),
            });
        }

        let mut roots = paths.to_vec();
        roots.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
        roots.dedup();

        let mut candidates: Vec<PathBuf> = Vec::new();
        let mut first_discover_error: Option<SdJournalError> = None;
        for p in paths {
            if let Err(e) = discover_journal_paths(p, &config, &mut candidates)
                && first_discover_error.is_none()
            {
                #[cfg(feature = "tracing")]
                warn!(path = %p.display(), error = %e, "journal discovery failed");
                first_discover_error = Some(e);
            }
        }

        if candidates.is_empty() {
            return Err(first_discover_error.unwrap_or(SdJournalError::NotFound));
        }

        candidates.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
        candidates.dedup();

        if candidates.len() > config.max_journal_files {
            return Err(SdJournalError::LimitExceeded {
                kind: LimitKind::JournalFiles,
                limit: u64::try_from(config.max_journal_files).unwrap_or(u64::MAX),
            });
        }

        let mut files = Vec::new();
        let mut errors = Vec::new();
        for path in candidates {
            match JournalFile::open(path, &config) {
                Ok(f) => {
                    #[cfg(feature = "tracing")]
                    debug!(path = %f.path().display(), "opened journal file");
                    files.push(f)
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    warn!(error = %e, "failed to open journal file");
                    errors.push(e)
                }
            }
        }

        if files.is_empty() {
            return Err(errors
                .into_iter()
                .next()
                .unwrap_or(SdJournalError::NotFound));
        }

        let mut seen: HashSet<[u8; 16]> = HashSet::new();
        files.retain(|f| seen.insert(f.file_id()));

        #[cfg(feature = "tracing")]
        debug!(n_files = files.len(), "journal opened");

        Ok(Self {
            inner: Arc::new(JournalInner {
                config,
                roots,
                files,
            }),
        })
    }

    pub fn query(&self) -> JournalQuery {
        JournalQuery::new(self.clone())
    }

    pub fn seek_cursor(&self, cursor: &Cursor) -> Result<JournalQuery> {
        let mut q = self.query();
        q.set_cursor_start(cursor.clone(), true)?;
        Ok(q)
    }

    /// Verify Forward Secure Sealing (TAG objects) for all opened journal files.
    ///
    /// This is available when the `verify-seal` feature is enabled.
    #[cfg(feature = "verify-seal")]
    pub fn verify_seal(&self, verification_key: &str) -> Result<()> {
        let key = crate::seal::parse_verification_key(verification_key)?;
        let params = crate::seal::FsprgParams::new(key.seed())?;

        for f in &self.inner.files {
            crate::seal::verify_file_seal(f, &key, &params)?;
        }
        Ok(())
    }
}

fn discover_journal_paths(
    dir: &Path,
    config: &JournalConfig,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    let rd = std::fs::read_dir(dir)
        .map_err(|e| SdJournalError::io("read_dir", Some(dir.to_path_buf()), e))?;

    let mut machine_id_dirs: Vec<PathBuf> = Vec::new();

    for entry in rd {
        let entry =
            entry.map_err(|e| SdJournalError::io("read_dir_entry", Some(dir.to_path_buf()), e))?;
        let ft = entry
            .file_type()
            .map_err(|e| SdJournalError::io("file_type", Some(entry.path()), e))?;

        if ft.is_symlink() {
            continue;
        }

        if ft.is_dir() {
            let name = entry.file_name();
            if is_machine_id_dir(&name) {
                machine_id_dirs.push(entry.path());
            }
            continue;
        }

        if !ft.is_file() {
            continue;
        }

        if is_journal_file(&entry.path(), config) {
            out.push(entry.path());
        }
    }

    for mid in machine_id_dirs {
        let rd = match std::fs::read_dir(&mid) {
            Ok(rd) => rd,
            Err(e) => return Err(SdJournalError::io("read_dir", Some(mid), e)),
        };
        for entry in rd {
            let entry = entry
                .map_err(|e| SdJournalError::io("read_dir_entry", Some(dir.to_path_buf()), e))?;
            let ft = entry
                .file_type()
                .map_err(|e| SdJournalError::io("file_type", Some(entry.path()), e))?;
            if ft.is_symlink() || !ft.is_file() {
                continue;
            }
            if is_journal_file(&entry.path(), config) {
                out.push(entry.path());
            }
        }
    }

    Ok(())
}

fn is_machine_id_dir(name: &OsStr) -> bool {
    let s = match name.to_str() {
        Some(s) => s,
        None => return false,
    };
    if s.len() != 32 {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_journal_file(path: &Path, config: &JournalConfig) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("journal") => true,
        Some("journal~") => config.include_journal_tilde,
        _ => false,
    }
}
