use super::JournalQuery;
use crate::error::{Result, SdJournalError};
use crate::file::EntryMeta;

pub(super) fn build_cursor_key(query: &JournalQuery) -> Result<Option<(EntryMeta, bool)>> {
    let (cursor, inclusive) = match &query.cursor_start {
        Some(v) => v,
        None => return Ok(None),
    };

    if let Some(k) = cursor.sdjournal_entry_key() {
        return Ok(Some((
            EntryMeta {
                file_id: k.file_id,
                entry_offset: k.entry_offset,
                seqnum: k.seqnum,
                realtime_usec: k.realtime_usec,
            },
            *inclusive,
        )));
    }

    if let Some((file_id, entry_offset)) = cursor.file_offset() {
        for idx in 0..query.journal.inner.file_paths.len() {
            let file = query.journal.inner.open_file_by_index(idx)?;
            if file.file_id() != file_id {
                continue;
            }
            let meta = file
                .read_entry_meta(entry_offset)
                .map_err(|_| SdJournalError::NotFound)?;
            return Ok(Some((meta, *inclusive)));
        }
        return Err(SdJournalError::NotFound);
    }

    if let Some(sys) = cursor.systemd() {
        let meta = resolve_systemd_cursor_key(query, sys)?;
        return Ok(Some((meta, *inclusive)));
    }

    Err(SdJournalError::InvalidQuery {
        reason: "unsupported cursor format".to_string(),
    })
}

fn resolve_systemd_cursor_key(
    query: &JournalQuery,
    sys: &crate::cursor::SystemdCursor,
) -> Result<EntryMeta> {
    match find_exact_systemd_cursor(query, sys) {
        Ok(Some(meta)) => return Ok(meta),
        Ok(None) => {}
        Err(e) => {
            if sys.realtime_usec.is_none() {
                return Err(e);
            }
        }
    }

    let realtime_usec = sys.realtime_usec.ok_or(SdJournalError::NotFound)?;
    Ok(EntryMeta {
        file_id: [0u8; 16],
        entry_offset: 0,
        seqnum: sys.seqnum.unwrap_or(0),
        realtime_usec,
    })
}

fn find_exact_systemd_cursor(
    query: &JournalQuery,
    sys: &crate::cursor::SystemdCursor,
) -> Result<Option<EntryMeta>> {
    let mut candidates: Vec<&crate::file::JournalFile> = Vec::new();
    if query.journal.inner.is_lazy() {
        return find_exact_systemd_cursor_lazy(query, sys);
    }

    if let Some(seqnum_id) = sys.seqnum_id {
        for f in &query.journal.inner.files {
            if f.seqnum_id() == seqnum_id {
                candidates.push(f);
            }
        }
        if candidates.is_empty() {
            candidates.extend(query.journal.inner.files.iter());
        }
    } else {
        candidates.extend(query.journal.inner.files.iter());
    }

    let mut first_error: Option<SdJournalError> = None;

    for file in candidates {
        match find_exact_systemd_cursor_in_file(file, sys) {
            Ok(Some(meta)) => return Ok(Some(meta)),
            Ok(None) => {}
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    match first_error {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

fn find_exact_systemd_cursor_lazy(
    query: &JournalQuery,
    sys: &crate::cursor::SystemdCursor,
) -> Result<Option<EntryMeta>> {
    let mut first_error: Option<SdJournalError> = None;
    let mut fallback_to_all = sys.seqnum_id.is_none();

    if let Some(seqnum_id) = sys.seqnum_id {
        let mut matched_seqnum_id = false;
        for idx in 0..query.journal.inner.file_paths.len() {
            let file = match query.journal.inner.open_file_by_index(idx) {
                Ok(file) => file,
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                    continue;
                }
            };
            if file.seqnum_id() != seqnum_id {
                continue;
            }
            matched_seqnum_id = true;
            match find_exact_systemd_cursor_in_file(&file, sys) {
                Ok(Some(meta)) => return Ok(Some(meta)),
                Ok(None) => {}
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
        fallback_to_all = !matched_seqnum_id;
    }

    if fallback_to_all {
        for idx in 0..query.journal.inner.file_paths.len() {
            let file = match query.journal.inner.open_file_by_index(idx) {
                Ok(file) => file,
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                    continue;
                }
            };
            match find_exact_systemd_cursor_in_file(&file, sys) {
                Ok(Some(meta)) => return Ok(Some(meta)),
                Ok(None) => {}
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
    }

    match first_error {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

fn find_exact_systemd_cursor_in_file(
    file: &crate::file::JournalFile,
    sys: &crate::cursor::SystemdCursor,
) -> Result<Option<EntryMeta>> {
    if let Some(seqnum_id) = sys.seqnum_id
        && file.seqnum_id() != seqnum_id
    {
        return Ok(None);
    }

    let iter = file.entry_iter_seek_realtime(false, sys.realtime_usec, None)?;
    for item in iter {
        let meta = item?;

        if let Some(want_realtime) = sys.realtime_usec
            && meta.realtime_usec != want_realtime
        {
            continue;
        }
        if let Some(want_seqnum) = sys.seqnum
            && meta.seqnum != want_seqnum
        {
            continue;
        }

        let fields = file.read_entry_cursor_fields(meta.entry_offset)?;

        if let Some(want_realtime) = sys.realtime_usec
            && fields.realtime_usec != want_realtime
        {
            continue;
        }
        if let Some(want_seqnum) = sys.seqnum
            && fields.seqnum != want_seqnum
        {
            continue;
        }
        if let Some(want_boot_id) = sys.boot_id
            && fields.boot_id != want_boot_id
        {
            continue;
        }
        if let Some(want_monotonic) = sys.monotonic_usec
            && fields.monotonic_usec != want_monotonic
        {
            continue;
        }
        if let Some(want_xor) = sys.xor_hash
            && fields.xor_hash != want_xor
        {
            continue;
        }

        return Ok(Some(meta));
    }

    Ok(None)
}
