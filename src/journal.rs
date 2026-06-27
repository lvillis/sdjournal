use crate::config::JournalConfig;
use crate::cursor::Cursor;
use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::JournalFile;
use crate::live::LiveJournal;
use crate::query::JournalQuery;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "tracing")]
use tracing::{debug, warn};

/// An opened set of journal files.
///
/// Cloning a `Journal` is cheap; the underlying journal-file set is reference counted.
#[derive(Clone)]
pub struct Journal {
    pub(crate) inner: Arc<JournalInner>,
}

pub(crate) struct JournalInner {
    pub(crate) config: JournalConfig,
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) files: Vec<JournalFile>,
    pub(crate) file_paths: Vec<PathBuf>,
}

pub(crate) struct JournalDiscovery {
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) candidates: Vec<PathBuf>,
}

impl Journal {
    /// Open the default system journal roots on Linux.
    ///
    /// This scans `/run/log/journal` and `/var/log/journal`, opens any discovered journal files,
    /// and deduplicates them by journal file ID.
    ///
    /// On non-Linux targets this returns [`SdJournalError::Unsupported`].
    pub fn open_default() -> Result<Self> {
        Self::open_default_with_config(JournalConfig::default())
    }

    /// Open the default system journal roots with a custom [`JournalConfig`].
    ///
    /// See [`Journal::open_default`] for the scanned locations and platform behavior.
    pub fn open_default_with_config(config: JournalConfig) -> Result<Self> {
        core::cfg_select! {
            target_os = "linux" => {
                let paths = vec![
                    PathBuf::from("/run/log/journal"),
                    PathBuf::from("/var/log/journal"),
                ];
                Self::open_dirs_with_config(&paths, config)
            }
            _ => {
                let _ = config;
                Err(SdJournalError::Unsupported {
                    reason: "Journal::open_default is only supported on Linux".to_string(),
                })
            }
        }
    }

    /// Open journal files discovered under a single root directory.
    ///
    /// Discovery includes `*.journal` files in the directory itself and in immediate machine-ID
    /// subdirectories such as `/var/log/journal/<machine-id>/`.
    pub fn open_dir(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_dir_with_config(path, JournalConfig::default())
    }

    /// Open journal files discovered under a single root directory with a custom configuration.
    pub fn open_dir_with_config(path: impl AsRef<Path>, config: JournalConfig) -> Result<Self> {
        let paths = vec![path.as_ref().to_path_buf()];
        Self::open_dirs_with_config(&paths, config)
    }

    /// Open journal files discovered under multiple root directories.
    ///
    /// Roots are sorted and deduplicated before discovery.
    pub fn open_dirs(paths: &[PathBuf]) -> Result<Self> {
        Self::open_dirs_with_config(paths, JournalConfig::default())
    }

    /// Open journal files discovered under multiple root directories using a custom configuration.
    ///
    /// Discovery skips symlinks, only keeps files with supported journal extensions, and
    /// deduplicates opened files by journal file ID.
    ///
    /// When discovery finds more files than [`JournalConfig::max_open_files`], the returned
    /// [`Journal`] stores file paths and opens files on demand while queries perform a streaming
    /// merge. Combine this with [`crate::MmapPolicy::Never`] for strict virtual-memory limits.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`SdJournalError::InvalidQuery`] when `paths` is empty.
    /// - [`SdJournalError::NotFound`] when no usable journal files are found.
    /// - [`SdJournalError::LimitExceeded`] when discovery exceeds configured file limits.
    /// - An underlying file or parse error when all candidates fail to open.
    pub fn open_dirs_with_config(paths: &[PathBuf], config: JournalConfig) -> Result<Self> {
        validate_journal_config(&config)?;
        let discovery = discover_journal_candidates(paths, &config)?;
        let file_set = open_journal_file_set(discovery.candidates, &config)?;

        #[cfg(feature = "tracing")]
        debug!(
            n_files = file_set.file_paths.len(),
            lazy = file_set.files.is_empty(),
            "journal opened"
        );

        Ok(Self {
            inner: Arc::new(JournalInner {
                config,
                roots: discovery.roots,
                files: file_set.files,
                file_paths: file_set.file_paths,
            }),
        })
    }

    /// Start building a query over the currently opened journal files.
    pub fn query(&self) -> JournalQuery {
        JournalQuery::new(self.clone())
    }

    /// Create a shared live engine from this journal set.
    ///
    /// The returned [`LiveJournal`] shares one watcher and one live cursor across all registered
    /// subscriptions.
    pub fn live(&self) -> Result<LiveJournal> {
        LiveJournal::from_journal(self.clone())
    }

    /// Create a query positioned at `cursor`, inclusive.
    ///
    /// This is a convenience wrapper around [`Journal::query`] plus cursor positioning.
    pub fn seek_cursor(&self, cursor: &Cursor) -> Result<JournalQuery> {
        let mut q = self.query();
        q.set_cursor_start(cursor.clone(), true)?;
        Ok(q)
    }

    /// Verify Forward Secure Sealing (TAG objects) for all opened journal files.
    ///
    /// This validates TAG objects against a systemd verification key and returns an error if any
    /// opened file is sealed but fails verification.
    ///
    /// This is available when the `verify-seal` feature is enabled.
    #[cfg(feature = "verify-seal")]
    pub fn verify_seal(&self, verification_key: &str) -> Result<()> {
        let key = crate::seal::parse_verification_key(verification_key)?;
        let params = crate::seal::FsprgParams::new(key.seed())?;

        for idx in 0..self.inner.file_paths.len() {
            let f = self.inner.open_file_by_index(idx)?;
            crate::seal::verify_file_seal(&f, &params)?;
        }
        Ok(())
    }
}

pub(crate) struct JournalFileSet {
    pub(crate) files: Vec<JournalFile>,
    pub(crate) file_paths: Vec<PathBuf>,
}

impl JournalInner {
    pub(crate) fn is_lazy(&self) -> bool {
        self.files.is_empty() && !self.file_paths.is_empty()
    }

    pub(crate) fn open_file_by_index(&self, idx: usize) -> Result<JournalFile> {
        if let Some(file) = self.files.get(idx) {
            return Ok(file.clone());
        }
        let path = self.file_paths.get(idx).ok_or(SdJournalError::NotFound)?;
        JournalFile::open(path.clone(), &self.config)
    }
}

pub(crate) fn journal_from_file_paths(
    roots: Vec<PathBuf>,
    file_paths: Vec<PathBuf>,
    config: JournalConfig,
) -> Result<Journal> {
    validate_journal_config(&config)?;
    let file_set = open_journal_file_set(file_paths, &config)?;
    Ok(Journal {
        inner: Arc::new(JournalInner {
            config,
            roots,
            files: file_set.files,
            file_paths: file_set.file_paths,
        }),
    })
}

pub(crate) fn journal_from_open_files(config: JournalConfig, files: Vec<JournalFile>) -> Journal {
    let file_paths = files.iter().map(|file| file.path().to_path_buf()).collect();
    Journal {
        inner: Arc::new(JournalInner {
            config,
            roots: Vec::new(),
            files,
            file_paths,
        }),
    }
}

fn validate_journal_config(config: &JournalConfig) -> Result<()> {
    if config.max_open_files == 0 {
        return Err(SdJournalError::InvalidQuery {
            reason: "max_open_files must be greater than zero".to_string(),
        });
    }
    Ok(())
}

fn open_journal_file_set(paths: Vec<PathBuf>, config: &JournalConfig) -> Result<JournalFileSet> {
    if paths.len() <= config.max_open_files {
        open_eager_file_set(paths, config)
    } else {
        open_lazy_file_set(paths, config)
    }
}

fn open_eager_file_set(paths: Vec<PathBuf>, config: &JournalConfig) -> Result<JournalFileSet> {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for path in paths {
        match JournalFile::open(path, config) {
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
    let file_paths = files.iter().map(|file| file.path().to_path_buf()).collect();

    Ok(JournalFileSet { files, file_paths })
}

fn open_lazy_file_set(paths: Vec<PathBuf>, config: &JournalConfig) -> Result<JournalFileSet> {
    let mut file_paths = Vec::new();
    let mut errors = Vec::new();
    let mut seen: HashSet<[u8; 16]> = HashSet::new();

    for path in paths {
        match JournalFile::open(path.clone(), config) {
            Ok(file) => {
                if seen.insert(file.file_id()) {
                    file_paths.push(path);
                }
            }
            Err(e) => {
                #[cfg(feature = "tracing")]
                warn!(error = %e, "failed to validate journal file for lazy open");
                errors.push(e);
            }
        }
    }

    if file_paths.is_empty() {
        return Err(errors
            .into_iter()
            .next()
            .unwrap_or(SdJournalError::NotFound));
    }

    Ok(JournalFileSet {
        files: Vec::new(),
        file_paths,
    })
}

pub(crate) fn discover_journal_candidates(
    paths: &[PathBuf],
    config: &JournalConfig,
) -> Result<JournalDiscovery> {
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
        if let Err(e) = discover_journal_paths(p, config, &mut candidates)
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

    Ok(JournalDiscovery { roots, candidates })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use tempfile::tempdir;

    #[test]
    fn open_dirs_rejects_empty_path_list() {
        match Journal::open_dirs_with_config(&[], JournalConfig::default()) {
            Err(SdJournalError::InvalidQuery { reason }) => {
                assert_eq!(reason, "open_dirs requires at least one path");
            }
            Ok(_) => panic!("expected InvalidQuery"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn machine_id_dir_requires_exactly_32_hex_chars() {
        assert!(is_machine_id_dir(OsStr::new(
            "0123456789abcdef0123456789abcdef"
        )));
        assert!(!is_machine_id_dir(OsStr::new(
            "0123456789abcdef0123456789abcde"
        )));
        assert!(!is_machine_id_dir(OsStr::new(
            "0123456789abcdef0123456789abcdeg"
        )));
        assert!(!is_machine_id_dir(OsStr::new("not-a-machine-id")));
    }

    #[test]
    fn discover_journal_paths_finds_root_and_machine_id_files() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let machine_id = root.join("0123456789abcdef0123456789abcdef");
        let ignored_dir = root.join("not-machine-id");

        fs::create_dir(&machine_id).unwrap();
        fs::create_dir(&ignored_dir).unwrap();

        let root_journal = root.join("root.journal");
        let nested_journal = machine_id.join("nested.journal");
        let tilde_journal = root.join("temp.journal~");
        let ignored_journal = ignored_dir.join("ignored.journal");
        let not_journal = root.join("notes.log");

        File::create(&root_journal).unwrap();
        File::create(&nested_journal).unwrap();
        File::create(&tilde_journal).unwrap();
        File::create(&ignored_journal).unwrap();
        File::create(&not_journal).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&root_journal, root.join("link.journal")).unwrap();

        let mut out = Vec::new();
        discover_journal_paths(root, &JournalConfig::default(), &mut out).unwrap();
        out.sort();

        assert_eq!(out, vec![nested_journal.clone(), root_journal.clone()]);

        out.clear();
        discover_journal_paths(
            root,
            &JournalConfig {
                include_journal_tilde: true,
                ..Default::default()
            },
            &mut out,
        )
        .unwrap();
        out.sort();

        assert_eq!(out, vec![nested_journal, root_journal, tilde_journal]);
    }
}
