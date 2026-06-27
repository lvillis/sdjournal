mod support;

#[cfg(not(target_os = "linux"))]
use sdjournal::SdJournalError;
use sdjournal::{Cursor, Journal, MmapPolicy};
use std::path::PathBuf;
use support::synthetic_journal::{
    SyntheticJournalFile, synthetic_message, write_synthetic_journal_file,
};

#[test]
fn user_supplied_journal_dir_supports_query_and_cursor_resume() {
    let units = ["alpha.service", "beta.service", "gamma.service"];
    let layout = SyntheticJournalFile::new(&units);
    layout.rewrite(&units);
    let journal = Journal::open_dir(layout.root()).expect("open synthetic journal directory");

    let all = journal
        .query()
        .collect_owned()
        .expect("collect all offline entries");
    assert_eq!(all.len(), 3);

    let mut alpha_query = journal.query();
    alpha_query.match_unit("alpha.service");
    let alpha_entries = alpha_query
        .collect_owned()
        .expect("query alpha entries from offline journal");
    assert_eq!(alpha_entries.len(), 1);
    assert_eq!(
        field(&alpha_entries[0], "MESSAGE"),
        synthetic_message(7, 0, "alpha.service")
    );

    let cursor_text = alpha_entries[0].cursor().expect("entry cursor").to_string();
    let cursor = Cursor::parse(&cursor_text).expect("parse cursor");

    let mut resumed = journal.query();
    resumed.after_cursor(cursor);
    let resumed_entries = resumed.collect_owned().expect("resume after stored cursor");

    assert_eq!(resumed_entries.len(), 2);
    assert_eq!(
        field(&resumed_entries[0], "MESSAGE"),
        synthetic_message(7, 1, "beta.service")
    );
    assert_eq!(
        field(&resumed_entries[1], "MESSAGE"),
        synthetic_message(7, 2, "gamma.service")
    );
}

#[test]
fn open_dirs_deduplicates_user_supplied_roots() {
    let layout = SyntheticJournalFile::new(&["alpha.service", "beta.service"]);
    let paths: Vec<PathBuf> = vec![layout.root().to_path_buf(), layout.root().to_path_buf()];

    let journal = Journal::open_dirs(&paths).expect("open duplicated roots");
    let entries = journal
        .query()
        .collect_owned()
        .expect("collect entries from deduplicated roots");

    assert_eq!(entries.len(), 2);
}

#[test]
fn exact_query_returns_all_entries_with_duplicate_data_payloads() {
    let layout = SyntheticJournalFile::new(&["alpha.service", "alpha.service", "alpha.service"]);
    let journal = Journal::open_dir(layout.root()).expect("open synthetic journal directory");

    let mut query = journal.query();
    query.match_unit("alpha.service");
    let entries = query
        .collect_owned()
        .expect("collect repeated alpha entries");

    assert_eq!(entries.len(), 3);
    for (idx, entry) in entries.iter().enumerate() {
        assert_eq!(
            field(entry, "MESSAGE"),
            synthetic_message(7, idx, "alpha.service")
        );
    }
}

#[test]
fn low_memory_query_merges_files_and_resumes_cursor() {
    let layout = SyntheticJournalFile::new(&["alpha.service"]);
    write_synthetic_journal_file(
        &layout.root().join("later.journal"),
        &["beta.service", "alpha.service"],
        9,
    );
    let cfg = sdjournal::JournalConfig {
        max_open_files: 1,
        mmap_policy: MmapPolicy::Never,
        ..Default::default()
    };
    let journal =
        Journal::open_dir_with_config(layout.root(), cfg).expect("open low-memory journal");

    let mut alpha = journal.query();
    alpha.match_unit("alpha.service");
    let entries = alpha
        .collect_owned()
        .expect("collect low-memory merged entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(
        field(&entries[0], "MESSAGE"),
        synthetic_message(7, 0, "alpha.service")
    );
    assert_eq!(
        field(&entries[1], "MESSAGE"),
        synthetic_message(9, 1, "alpha.service")
    );

    let cursor = Cursor::parse(&entries[0].cursor().expect("entry cursor").to_string())
        .expect("parse cursor");
    let mut resumed = journal.query();
    resumed.match_unit("alpha.service").after_cursor(cursor);
    let resumed_entries = resumed
        .collect_owned()
        .expect("resume low-memory query after cursor");
    assert_eq!(resumed_entries.len(), 1);
    assert_eq!(
        field(&resumed_entries[0], "MESSAGE"),
        synthetic_message(9, 1, "alpha.service")
    );

    let mut newest = journal.query();
    newest.match_unit("alpha.service").reverse(true);
    let newest_entries = newest.collect_owned().expect("reverse low-memory query");
    assert_eq!(newest_entries.len(), 2);
    assert_eq!(
        field(&newest_entries[0], "MESSAGE"),
        synthetic_message(9, 1, "alpha.service")
    );
}

#[test]
fn low_memory_query_honors_or_groups_limit_and_reverse_order() {
    let layout = SyntheticJournalFile::new(&["alpha.service", "beta.service"]);
    write_synthetic_journal_file(
        &layout.root().join("later.journal"),
        &["gamma.service", "alpha.service"],
        9,
    );
    let cfg = sdjournal::JournalConfig {
        max_open_files: 1,
        mmap_policy: MmapPolicy::Never,
        ..Default::default()
    };
    let journal =
        Journal::open_dir_with_config(layout.root(), cfg).expect("open low-memory journal");

    let mut forward = journal.query();
    forward
        .or_group(|group| {
            group.match_exact("_SYSTEMD_UNIT", b"alpha.service");
        })
        .or_group(|group| {
            group.match_exact("_SYSTEMD_UNIT", b"gamma.service");
        })
        .limit(2);
    let forward_entries = forward
        .collect_owned()
        .expect("collect limited low-memory OR query");
    assert_eq!(forward_entries.len(), 2);
    assert_eq!(
        field(&forward_entries[0], "MESSAGE"),
        synthetic_message(7, 0, "alpha.service")
    );
    assert_eq!(
        field(&forward_entries[1], "MESSAGE"),
        synthetic_message(9, 0, "gamma.service")
    );

    let mut reverse = journal.query();
    reverse
        .or_group(|group| {
            group.match_exact("_SYSTEMD_UNIT", b"alpha.service");
        })
        .or_group(|group| {
            group.match_exact("_SYSTEMD_UNIT", b"gamma.service");
        })
        .reverse(true)
        .limit(2);
    let reverse_entries = reverse
        .collect_owned()
        .expect("collect reverse low-memory OR query");
    assert_eq!(reverse_entries.len(), 2);
    assert_eq!(
        field(&reverse_entries[0], "MESSAGE"),
        synthetic_message(9, 1, "alpha.service")
    );
    assert_eq!(
        field(&reverse_entries[1], "MESSAGE"),
        synthetic_message(9, 0, "gamma.service")
    );
}

#[test]
fn open_rejects_zero_max_open_files() {
    let layout = SyntheticJournalFile::new(&["alpha.service"]);
    let cfg = sdjournal::JournalConfig {
        max_open_files: 0,
        ..Default::default()
    };

    match Journal::open_dir_with_config(layout.root(), cfg) {
        Err(sdjournal::SdJournalError::InvalidQuery { reason }) => {
            assert_eq!(reason, "max_open_files must be greater than zero");
        }
        Ok(_) => panic!("expected InvalidQuery"),
        Err(err) => panic!("unexpected error: {err}"),
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn open_default_is_explicitly_linux_only() {
    match Journal::open_default() {
        Err(SdJournalError::Unsupported { reason }) => {
            assert!(reason.contains("only supported on Linux"));
        }
        Ok(_) => panic!("expected Unsupported on non-Linux, got Ok"),
        Err(err) => panic!("expected Unsupported on non-Linux, got {err}"),
    }
}

fn field(entry: &sdjournal::EntryOwned, name: &str) -> String {
    String::from_utf8_lossy(entry.get(name).expect("entry field")).into_owned()
}
