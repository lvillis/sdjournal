use sdjournal::{EntryOwned, Journal};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn normalize_sdjournal_fields(entry: &EntryOwned) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in entry.iter_fields() {
        if out.contains_key(k) {
            continue;
        }
        out.insert(k.to_string(), String::from_utf8_lossy(v).into_owned());
    }
    out
}

#[test]
fn format_fixtures_are_parseable_and_stable() {
    let root = fixtures_root();
    if !root.is_dir() {
        eprintln!("skipping: fixtures directory not found: {}", root.display());
        return;
    }

    let mut fixtures = Vec::new();
    let rd = match std::fs::read_dir(&root) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!(
                "skipping: failed to read fixtures directory {}: {e}",
                root.display()
            );
            return;
        }
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            fixtures.push(p);
        }
    }

    if fixtures.is_empty() {
        eprintln!("skipping: no fixtures under {}", root.display());
        return;
    }

    for dir in fixtures {
        let journal_dir = dir.join("journal");
        let expected_path = dir.join("expected.json");

        if !journal_dir.is_dir() {
            eprintln!("skipping fixture (missing journal/): {}", dir.display());
            continue;
        }
        if !expected_path.is_file() {
            eprintln!(
                "skipping fixture (missing expected.json): {}",
                dir.display()
            );
            continue;
        }

        let expected_bytes =
            std::fs::read(&expected_path).expect("failed to read fixture expected.json");
        let expected: Vec<BTreeMap<String, String>> =
            serde_json::from_slice(&expected_bytes).expect("failed to parse fixture expected.json");

        let journal = match Journal::open_dir(&journal_dir) {
            Ok(j) => j,
            Err(e) => panic!(
                "failed to open fixture journal {}: {e}",
                journal_dir.display()
            ),
        };

        let got: Vec<BTreeMap<String, String>> = journal
            .query()
            .collect_owned()
            .expect("failed to read fixture journal entries")
            .into_iter()
            .map(|e| normalize_sdjournal_fields(&e))
            .collect();

        assert_eq!(
            got,
            expected,
            "fixture mismatch: {}",
            dir.file_name().unwrap_or_default().to_string_lossy()
        );
    }
}
