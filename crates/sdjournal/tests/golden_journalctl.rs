#![cfg(target_os = "linux")]

use sdjournal::{Cursor, Journal, JournalConfig};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn cmd_output(cmd: &str, args: &[&str]) -> std::io::Result<Output> {
    Command::new(cmd).args(args).output()
}

fn try_cmd_output(cmd: &str, args: &[&str]) -> Option<Output> {
    cmd_output(cmd, args).ok()
}

fn strict_mode() -> bool {
    matches!(
        std::env::var("SDJOURNAL_TEST_STRICT"),
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true")
    ) || matches!(
        std::env::var("CI"),
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true")
    )
}

fn use_sudo() -> bool {
    matches!(
        std::env::var("SDJOURNAL_TEST_USE_SUDO"),
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true")
    )
}

fn run_journalctl(args: &[&str]) -> Option<Output> {
    if let Some(out) = try_cmd_output("journalctl", args)
        && out.status.success()
    {
        return Some(out);
    }

    if !use_sudo() {
        return None;
    }

    let mut sudo_args = Vec::with_capacity(args.len().saturating_add(2));
    sudo_args.push("-n");
    sudo_args.push("journalctl");
    sudo_args.extend_from_slice(args);
    let out = try_cmd_output("sudo", &sudo_args)?;
    if out.status.success() {
        Some(out)
    } else {
        None
    }
}

fn run_logger(tag: &str, msg: &str) -> bool {
    let out = try_cmd_output("logger", &["-t", tag, msg]);
    matches!(out, Some(o) if o.status.success())
}

fn read_machine_id() -> Option<String> {
    let s = std::fs::read_to_string("/etc/machine-id").ok()?;
    let id = s.trim();
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(id.to_string())
}

fn journal_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mid = read_machine_id();

    for base in ["/run/log/journal", "/var/log/journal"] {
        let base_dir = PathBuf::from(base);
        if let Some(mid) = mid.as_deref() {
            let p = base_dir.join(mid);
            if p.is_dir() {
                dirs.push(p);
                continue;
            }
        }

        if base_dir.is_dir() {
            dirs.push(base_dir);
        }
    }

    dirs
}

fn parse_journalctl_json_lines(out: &Output) -> Vec<Value> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            entries.push(v);
        }
    }
    entries
}

fn read_entries_from_journalctl(tag: &str) -> Option<Vec<Value>> {
    let out = run_journalctl(&["-o", "json", "--no-pager", "-t", tag])?;
    Some(parse_journalctl_json_lines(&out))
}

fn get_realtime_usec(v: &Value) -> Option<u64> {
    v.get("__REALTIME_TIMESTAMP")?
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
}

fn get_monotonic_usec(v: &Value) -> Option<u64> {
    v.get("__MONOTONIC_TIMESTAMP")?
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
}

fn get_cursor(v: &Value) -> Option<String> {
    v.get("__CURSOR")?.as_str().map(|s| s.to_string())
}

fn get_message(v: &Value) -> Option<String> {
    v.get("MESSAGE")?.as_str().map(|s| s.to_string())
}

fn normalize_journalctl_fields(v: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let obj = match v.as_object() {
        Some(o) => o,
        None => return out,
    };

    for (k, v) in obj {
        if k.starts_with("__") {
            continue;
        }
        let s = match v.as_str() {
            Some(s) => s.to_string(),
            None => v.to_string(),
        };
        out.insert(k.to_string(), s);
    }

    out
}

fn normalize_sdjournal_fields(entry: &sdjournal::EntryOwned) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in entry.iter_fields() {
        if out.contains_key(k) {
            continue;
        }
        out.insert(k.to_string(), String::from_utf8_lossy(v).into_owned());
    }
    out
}

fn now_unique() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos()
}

#[test]
fn golden_match_and_time_filters_against_journalctl() {
    if try_cmd_output("journalctl", &["--version"]).is_none() {
        if strict_mode() {
            panic!("journalctl not available");
        }
        eprintln!("skipping: journalctl not available");
        return;
    };
    if try_cmd_output("logger", &["--version"]).is_none() {
        if strict_mode() {
            panic!("logger not available");
        }
        eprintln!("skipping: logger not available");
        return;
    };

    let dirs = journal_dirs();
    if dirs.is_empty() {
        if strict_mode() {
            panic!("journal directories not found");
        }
        eprintln!("skipping: journal directories not found");
        return;
    }

    let unique = now_unique();
    let tag = format!("sdjournal-test-{unique}");
    let msgs = [
        format!("msg-1-{unique}"),
        format!("msg-2-{unique}"),
        format!("msg-3-{unique}"),
    ];

    for m in &msgs {
        if !run_logger(&tag, m) {
            if strict_mode() {
                panic!("failed to write to journal");
            }
            eprintln!("skipping: failed to write to journal");
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }

    let start = SystemTime::now();
    let baseline = loop {
        if start.elapsed().unwrap_or(Duration::from_secs(0)) > Duration::from_secs(5) {
            if strict_mode() {
                panic!("journalctl did not return expected entries in time");
            }
            eprintln!("skipping: journalctl did not return expected entries in time");
            return;
        }
        let Some(entries) = read_entries_from_journalctl(&tag) else {
            if strict_mode() {
                panic!("cannot read journalctl output");
            }
            eprintln!("skipping: cannot read journalctl output");
            return;
        };
        if entries.len() >= msgs.len() {
            break entries;
        }
        thread::sleep(Duration::from_millis(100));
    };

    let unique_s = unique.to_string();
    let mut baseline_filtered: Vec<(u64, u64, String, String, BTreeMap<String, String>)> =
        Vec::new();
    for v in &baseline {
        let Some(ts) = get_realtime_usec(v) else {
            continue;
        };
        let Some(mono) = get_monotonic_usec(v) else {
            continue;
        };
        let Some(cur) = get_cursor(v) else {
            continue;
        };
        let Some(msg) = get_message(v) else {
            continue;
        };
        if msg.contains("msg-") && msg.contains(&unique_s) {
            baseline_filtered.push((ts, mono, cur, msg, normalize_journalctl_fields(v)));
        }
    }
    baseline_filtered.sort_by_key(|(ts, _, _, _, _)| *ts);
    if baseline_filtered.len() != msgs.len() {
        if strict_mode() {
            panic!("baseline did not contain expected messages");
        }
        eprintln!("skipping: baseline did not contain expected messages");
        return;
    }

    let cfg = JournalConfig::default();
    let journal = match Journal::open_dirs_with_config(&dirs, cfg) {
        Ok(j) => j,
        Err(e) => {
            if strict_mode() {
                panic!("cannot open journal files: {e}");
            }
            eprintln!("skipping: cannot open journal files: {e}");
            return;
        }
    };

    let mut q = journal.query();
    q.match_exact("SYSLOG_IDENTIFIER", tag.as_bytes());
    let got = match q.collect_owned() {
        Ok(v) => v,
        Err(e) => {
            if strict_mode() {
                panic!("query failed: {e}");
            }
            eprintln!("skipping: query failed: {e}");
            return;
        }
    };

    let mut got_filtered: Vec<(u64, u64, String, BTreeMap<String, String>)> = Vec::new();
    for e in got {
        let msg = e
            .get("MESSAGE")
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        if msg.contains("msg-") && msg.contains(&unique_s) {
            got_filtered.push((
                e.realtime_usec(),
                e.monotonic_usec(),
                msg,
                normalize_sdjournal_fields(&e),
            ));
        }
    }
    got_filtered.sort_by_key(|(ts, _, _, _)| *ts);

    assert_eq!(got_filtered.len(), msgs.len());
    for (
        i,
        ((ts_base, mono_base, _, msg_base, fields_base), (ts_got, mono_got, msg_got, fields_got)),
    ) in baseline_filtered
        .iter()
        .zip(got_filtered.iter())
        .enumerate()
    {
        assert_eq!(msg_got, msg_base, "message mismatch at index {i}");
        assert_eq!(*ts_got, *ts_base, "timestamp mismatch at index {i}");
        assert_eq!(*mono_got, *mono_base, "monotonic mismatch at index {i}");
        assert_eq!(fields_got, fields_base, "field diff at index {i}");
    }

    let t2 = baseline_filtered[1].0;
    let mut q2 = journal.query();
    q2.match_exact("SYSLOG_IDENTIFIER", tag.as_bytes());
    q2.since_realtime(t2).until_realtime(t2);
    let got_t2 = q2.collect_owned().expect("since/until query failed");
    assert!(!got_t2.is_empty(), "expected inclusive time window match");
    assert!(
        got_t2.iter().all(|e| e.realtime_usec() == t2),
        "since/until must constrain to the exact realtime_usec"
    );

    let cursor2 = Cursor::parse(&baseline_filtered[1].2).expect("failed to parse systemd cursor");

    let mut q3 = journal.seek_cursor(&cursor2).expect("seek_cursor failed");
    q3.match_exact("SYSLOG_IDENTIFIER", tag.as_bytes());
    let got_from_cursor = q3.collect_owned().expect("seek_cursor query failed");
    let first = got_from_cursor
        .first()
        .and_then(|e| e.get("MESSAGE"))
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    assert!(
        first == baseline_filtered[1].3,
        "seek_cursor did not start at expected entry"
    );

    let mut q4 = journal.query();
    q4.match_exact("SYSLOG_IDENTIFIER", tag.as_bytes());
    q4.after_cursor(cursor2);
    let got_after = q4.collect_owned().expect("after_cursor query failed");
    let first_after = got_after
        .first()
        .and_then(|e| e.get("MESSAGE"))
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    assert!(
        first_after == baseline_filtered[2].3,
        "after_cursor must be strictly-after"
    );
}

#[test]
fn follow_tails_and_emits_new_entries() {
    if try_cmd_output("logger", &["--version"]).is_none() {
        if strict_mode() {
            panic!("logger not available");
        }
        eprintln!("skipping: logger not available");
        return;
    };

    let dirs = journal_dirs();
    if dirs.is_empty() {
        if strict_mode() {
            panic!("journal directories not found");
        }
        eprintln!("skipping: journal directories not found");
        return;
    }

    let unique = now_unique();
    let tag = format!("sdjournal-follow-{unique}");
    let pre_msg = format!("preexisting-follow-msg-{unique}");
    let msg = format!("follow-msg-{unique}");

    let cfg = JournalConfig {
        poll_interval: Duration::from_millis(100),
        max_follow_backoff: Duration::from_millis(500),
        ..Default::default()
    };
    let journal = match Journal::open_dirs_with_config(&dirs, cfg) {
        Ok(j) => j,
        Err(e) => {
            if strict_mode() {
                panic!("cannot open journal files: {e}");
            }
            eprintln!("skipping: cannot open journal files: {e}");
            return;
        }
    };

    if !run_logger(&tag, &pre_msg) {
        if strict_mode() {
            panic!("failed to write to journal");
        }
        eprintln!("skipping: failed to write to journal");
        return;
    }
    thread::sleep(Duration::from_millis(100));

    let mut q = journal.query();
    q.match_exact("SYSLOG_IDENTIFIER", tag.as_bytes());
    let follow = match q.follow() {
        Ok(f) => f,
        Err(e) => {
            if strict_mode() {
                panic!("follow unsupported: {e}");
            }
            eprintln!("skipping: follow unsupported: {e}");
            return;
        }
    };

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut f = follow;
        let item = f.next();
        let _ = tx.send(item);
    });

    thread::sleep(Duration::from_millis(200));
    if !run_logger(&tag, &msg) {
        if strict_mode() {
            panic!("failed to write to journal");
        }
        eprintln!("skipping: failed to write to journal");
        return;
    }

    let item = rx.recv_timeout(Duration::from_secs(10)).expect("timeout");
    let entry = item.expect("missing follow item").expect("follow error");
    let got = entry
        .get("MESSAGE")
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    assert!(got.contains(&msg));
}
