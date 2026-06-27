use crate::config::JournalConfig;
use crate::cursor::SdJournalEntryKey;
use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::{JournalFile, LiveFileState};
use crate::journal::{Journal, journal_from_file_paths};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::{compare_keys, is_skippable_live_file_error, warn_skipped_live_file};

pub(super) struct TrackedFile {
    pub(super) path: PathBuf,
    pub(super) file_id: [u8; 16],
    pub(super) live_state: LiveFileState,
    pub(super) tail: FileTailCursor,
}

pub(super) struct TrackedFiles {
    pub(super) files: Vec<TrackedFile>,
    pub(super) path_index: HashMap<PathBuf, usize>,
    pub(super) last_seen: Option<SdJournalEntryKey>,
}

pub(super) struct LiveSnapshot {
    pub(super) tracked: TrackedFiles,
    pub(super) journal: Journal,
}

pub(super) struct OffsetBatch {
    pub(super) offsets: Vec<u64>,
    pub(super) exhausted: bool,
}

pub(super) struct FallbackDirState {
    pub(super) path: PathBuf,
    pub(super) modified: Option<SystemTime>,
}

pub(super) struct FileTailCursor {
    current_array_offset: Option<u64>,
    next_item_idx: usize,
    last_entry_offset: Option<u64>,
}

impl FileTailCursor {
    fn at_end(file: &JournalFile) -> Result<Self> {
        let mut next = file.live_state().entry_array_offset;
        let mut current_array_offset = None;
        let mut next_item_idx = 0usize;
        let mut last_entry_offset = None;
        let mut steps = 0usize;

        while next != 0 {
            current_array_offset = Some(next);
            let items = file.read_entry_array_items(next)?;
            next_item_idx = items.len();
            last_entry_offset = items.last().copied();
            next = file.read_entry_array_next_offset(next)?;

            steps = steps.saturating_add(1);
            if steps > file.max_object_chain_steps() {
                return Err(SdJournalError::LimitExceeded {
                    kind: LimitKind::ObjectChainSteps,
                    limit: u64::try_from(file.max_object_chain_steps()).unwrap_or(u64::MAX),
                });
            }
        }

        Ok(Self {
            current_array_offset,
            next_item_idx,
            last_entry_offset,
        })
    }

    pub(super) fn drain_new_offsets(
        &mut self,
        file: &JournalFile,
        limit: usize,
    ) -> Result<OffsetBatch> {
        let mut out = Vec::new();
        let mut steps = 0usize;
        let mut current = match self.current_array_offset {
            Some(offset) => {
                let items = file.read_entry_array_items(offset)?;
                let mut item_idx = self.next_item_idx.min(items.len());
                while item_idx < items.len() {
                    let entry_offset = items[item_idx];
                    item_idx = item_idx.saturating_add(1);
                    if entry_offset != 0 {
                        out.push(entry_offset);
                        self.last_entry_offset = Some(entry_offset);
                    }
                    if out.len() >= limit {
                        self.next_item_idx = item_idx;
                        return Ok(OffsetBatch {
                            offsets: out,
                            exhausted: false,
                        });
                    }
                }
                self.next_item_idx = item_idx;
                file.read_entry_array_next_offset(offset)?
            }
            None => file.live_state().entry_array_offset,
        };

        while current != 0 {
            let items = file.read_entry_array_items(current)?;
            let mut item_idx = 0usize;
            while item_idx < items.len() {
                let entry_offset = items[item_idx];
                item_idx = item_idx.saturating_add(1);
                if entry_offset != 0 {
                    out.push(entry_offset);
                    self.last_entry_offset = Some(entry_offset);
                }
                if out.len() >= limit {
                    self.current_array_offset = Some(current);
                    self.next_item_idx = item_idx;
                    return Ok(OffsetBatch {
                        offsets: out,
                        exhausted: false,
                    });
                }
            }
            self.current_array_offset = Some(current);
            self.next_item_idx = item_idx;
            current = file.read_entry_array_next_offset(current)?;

            steps = steps.saturating_add(1);
            if steps > file.max_object_chain_steps() {
                return Err(SdJournalError::Transient {
                    path: Some(file.path().to_path_buf()),
                    reason: "entry array chain refresh exceeded expected growth".to_string(),
                });
            }
        }

        if self.current_array_offset.is_none() {
            self.next_item_idx = 0;
            self.last_entry_offset = None;
            return Ok(OffsetBatch {
                offsets: Vec::new(),
                exhausted: true,
            });
        }

        Ok(OffsetBatch {
            offsets: out,
            exhausted: true,
        })
    }
}

struct TrackedFileBuilder {
    tracked_files: Vec<TrackedFile>,
    path_index: HashMap<PathBuf, usize>,
    last_seen: Option<SdJournalEntryKey>,
    first_skipped_error: Option<SdJournalError>,
    seen: HashSet<[u8; 16]>,
}

impl TrackedFileBuilder {
    fn new(capacity: usize) -> Self {
        Self {
            tracked_files: Vec::with_capacity(capacity),
            path_index: HashMap::with_capacity(capacity),
            last_seen: None,
            first_skipped_error: None,
            seen: HashSet::new(),
        }
    }

    fn push(&mut self, file: &JournalFile) -> Result<bool> {
        let file_id = file.file_id();
        if self.seen.contains(&file_id) {
            return Ok(false);
        }

        match track_file(file) {
            Ok((tracked, key)) => {
                self.seen.insert(file_id);
                if key.as_ref().is_some_and(|key| {
                    self.last_seen
                        .as_ref()
                        .is_none_or(|last| compare_keys(key, last).is_gt())
                }) {
                    self.last_seen = key;
                }
                self.path_index
                    .insert(tracked.path.clone(), self.tracked_files.len());
                self.tracked_files.push(tracked);
                Ok(true)
            }
            Err(err) if is_skippable_live_file_error(&err) => {
                warn_skipped_live_file(file.path(), &err);
                if self.first_skipped_error.is_none() {
                    self.first_skipped_error = Some(err);
                }
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    fn skip_path(&mut self, path: &Path, err: SdJournalError) {
        warn_skipped_live_file(path, &err);
        if self.first_skipped_error.is_none() {
            self.first_skipped_error = Some(err);
        }
    }

    fn finish(self) -> Result<TrackedFiles> {
        finish_tracked_files(
            self.tracked_files,
            self.path_index,
            self.last_seen,
            self.first_skipped_error,
        )
    }
}

#[cfg(target_os = "linux")]
pub(super) fn collect_watch_paths(
    roots: &[PathBuf],
    tracked_files: &[TrackedFile],
) -> Vec<PathBuf> {
    let mut watch_paths: Vec<PathBuf> = roots.to_vec();
    for tracked in tracked_files {
        watch_paths.push(tracked.path.clone());
        if let Some(parent) = tracked.path.parent() {
            watch_paths.push(parent.to_path_buf());
        }
    }
    watch_paths.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    watch_paths.dedup();
    watch_paths
}

pub(super) fn collect_fallback_dirs(
    roots: &[PathBuf],
    tracked_files: &[TrackedFile],
) -> Vec<FallbackDirState> {
    let mut dirs: Vec<PathBuf> = roots.to_vec();
    for tracked in tracked_files {
        if let Some(parent) = tracked.path.parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    dirs.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    dirs.dedup();
    dirs.into_iter()
        .map(|path| FallbackDirState {
            modified: std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok(),
            path,
        })
        .collect()
}

pub(super) fn build_tracked_files_from_open_files(files: &[JournalFile]) -> Result<TrackedFiles> {
    let mut builder = TrackedFileBuilder::new(files.len());

    for file in files {
        builder.push(file)?;
    }

    builder.finish()
}

pub(super) fn build_tracked_files_from_paths(
    paths: &[PathBuf],
    config: &JournalConfig,
) -> Result<TrackedFiles> {
    let mut builder = TrackedFileBuilder::new(paths.len());

    for path in paths {
        let file = match JournalFile::open(path.clone(), config) {
            Ok(file) => file,
            Err(err) if is_skippable_live_file_error(&err) => {
                builder.skip_path(path, err);
                continue;
            }
            Err(err) => return Err(err),
        };
        builder.push(&file)?;
    }

    builder.finish()
}

pub(super) fn build_live_snapshot(
    paths: &[PathBuf],
    config: &JournalConfig,
) -> Result<LiveSnapshot> {
    let tracked = build_tracked_files_from_paths(paths, config)?;
    let file_paths = tracked
        .files
        .iter()
        .map(|tracked| tracked.path.clone())
        .collect();
    let journal = journal_from_file_paths(Vec::new(), file_paths, config.clone())?;

    Ok(LiveSnapshot { tracked, journal })
}

fn track_file(file: &JournalFile) -> Result<(TrackedFile, Option<SdJournalEntryKey>)> {
    let tail = FileTailCursor::at_end(file)?;
    let key = match tail.last_entry_offset {
        Some(offset) => {
            let meta = file.read_entry_meta(offset)?;
            Some(SdJournalEntryKey {
                file_id: meta.file_id,
                entry_offset: meta.entry_offset,
                seqnum: meta.seqnum,
                realtime_usec: meta.realtime_usec,
            })
        }
        None => None,
    };

    Ok((
        TrackedFile {
            path: file.path().to_path_buf(),
            file_id: file.file_id(),
            live_state: file.live_state(),
            tail,
        },
        key,
    ))
}

fn finish_tracked_files(
    tracked_files: Vec<TrackedFile>,
    path_index: HashMap<PathBuf, usize>,
    last_seen: Option<SdJournalEntryKey>,
    first_skipped_error: Option<SdJournalError>,
) -> Result<TrackedFiles> {
    if tracked_files.is_empty()
        && let Some(err) = first_skipped_error
    {
        return Err(err);
    }

    Ok(TrackedFiles {
        files: tracked_files,
        path_index,
        last_seen,
    })
}
