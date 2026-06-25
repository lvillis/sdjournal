mod support;

#[cfg(not(target_os = "linux"))]
use sdjournal::SdJournalError;
use sdjournal::{Cursor, Journal};
use std::path::PathBuf;
use support::synthetic_journal::{SyntheticJournalFile, synthetic_message};

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
