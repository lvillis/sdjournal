mod support;

use sdjournal::{
    Journal, JournalConfig, LiveJournal, LiveQueueFullPolicy, LiveSubscription, MmapPolicy,
    SubscriptionOptions,
};
use std::fs;
use std::path::Path;
use std::sync::mpsc::TryRecvError;
use std::thread;
use std::time::Duration;
use support::synthetic_journal::{
    SyntheticJournalFile, synthetic_message, write_synthetic_journal_file,
};

#[test]
fn shared_live_engine_dispatches_appended_entries_to_matching_subscriptions() {
    let initial_units = ["alpha.service", "beta.service"];
    let layout = SyntheticJournalFile::new(&initial_units);
    let journal = Journal::open_dir_with_config(layout.root(), live_test_config())
        .expect("open synthetic journal");
    let mut live = journal.live().expect("create live engine");

    let alpha = subscribe_unit(&mut live, "alpha.service");
    let beta = subscribe_unit(&mut live, "beta.service");
    let alpha_by_message = subscribe_message(&mut live, &synthetic_message(7, 2, "alpha.service"));
    let absent = subscribe_unit(&mut live, "absent.service");

    assert_subscription_empty(&alpha);
    assert_subscription_empty(&beta);
    assert_subscription_empty(&alpha_by_message);
    assert_subscription_empty(&absent);

    let rewritten_units = [
        "alpha.service",
        "beta.service",
        "alpha.service",
        "beta.service",
        "gamma.service",
    ];
    layout.rewrite(&rewritten_units);

    let deliveries = poll_until_delivered(&mut live, 3);
    assert_eq!(deliveries, 3);

    let alpha_entry = recv_ready(&alpha);
    let beta_entry = recv_ready(&beta);
    let alpha_message_entry = recv_ready(&alpha_by_message);

    assert_entry(
        &alpha_entry,
        "alpha.service",
        &synthetic_message(7, 2, "alpha.service"),
    );
    assert_entry(
        &beta_entry,
        "beta.service",
        &synthetic_message(7, 3, "beta.service"),
    );
    assert_eq!(
        alpha_entry.cursor().expect("alpha cursor"),
        alpha_message_entry.cursor().expect("alpha message cursor"),
        "the same appended entry should fan out to both matching subscriptions"
    );

    assert_subscription_empty(&alpha);
    assert_subscription_empty(&beta);
    assert_subscription_empty(&alpha_by_message);
    assert_subscription_empty(&absent);
}

#[test]
fn direct_live_engine_open_dir_dispatches_appended_entries() {
    let layout = SyntheticJournalFile::new(&["alpha.service"]);
    let mut live = LiveJournal::open_dir_with_config(layout.root(), live_test_config())
        .expect("open live engine without historical journal");

    let alpha = subscribe_unit(&mut live, "alpha.service");
    assert_subscription_empty(&alpha);

    layout.rewrite(&["alpha.service", "alpha.service"]);

    let deliveries = poll_until_delivered(&mut live, 1);
    assert_eq!(deliveries, 1);

    let alpha_entry = recv_ready(&alpha);
    assert_entry(
        &alpha_entry,
        "alpha.service",
        &synthetic_message(7, 1, "alpha.service"),
    );
}

#[test]
fn live_engine_initial_recheck_does_not_replay_existing_entries() {
    let layout = SyntheticJournalFile::new(&["alpha.service"]);
    let mut live = LiveJournal::open_dir_with_config(layout.root(), live_test_config())
        .expect("open live engine");

    let alpha = subscribe_unit(&mut live, "alpha.service");

    assert_eq!(live.poll_once().expect("initial live recheck"), 0);
    assert_subscription_empty(&alpha);
}

#[test]
fn live_engine_drains_large_appends_across_bounded_batches() {
    let layout = SyntheticJournalFile::new(&["alpha.service"]);
    let mut live = LiveJournal::open_dir_with_config(
        layout.root(),
        live_test_config_with_live_limits(1, 1, LiveQueueFullPolicy::Block),
    )
    .expect("open live engine with tiny batches");

    let alpha = subscribe_unit(&mut live, "alpha.service");
    layout.rewrite(&["alpha.service", "alpha.service", "alpha.service"]);

    assert_eq!(live.poll_once().expect("first bounded poll"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 1, "alpha.service"),
    );

    assert_eq!(live.poll_once().expect("second bounded poll"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 2, "alpha.service"),
    );
}

#[test]
fn live_engine_disconnects_slow_subscription_when_queue_is_full() {
    let layout = SyntheticJournalFile::new(&["alpha.service"]);
    let mut live = LiveJournal::open_dir_with_config(
        layout.root(),
        live_test_config_with_live_limits(1, 2, LiveQueueFullPolicy::Disconnect),
    )
    .expect("open live engine with bounded disconnect policy");

    let alpha = subscribe_unit(&mut live, "alpha.service");
    layout.rewrite(&["alpha.service", "alpha.service", "alpha.service"]);

    assert_eq!(live.poll_once().expect("bounded poll"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 1, "alpha.service"),
    );
    match alpha.try_recv() {
        Err(TryRecvError::Disconnected) => {}
        other => panic!("expected disconnected slow subscription, got {other:?}"),
    }
}

#[test]
fn live_replay_is_delivered_in_bounded_batches() {
    let layout = SyntheticJournalFile::new(&["alpha.service", "alpha.service", "alpha.service"]);
    let mut live = LiveJournal::open_dir_with_config(
        layout.root(),
        live_test_config_with_live_limits(1, 1, LiveQueueFullPolicy::Block),
    )
    .expect("open live engine with bounded replay");

    let mut filter = live.filter();
    filter.match_unit("alpha.service");
    let mut options = SubscriptionOptions::new(filter);
    options.since_realtime(0);
    let alpha = live
        .subscribe_with_options(options)
        .expect("subscribe with replay");

    assert_eq!(live.poll_once().expect("first replay batch"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 0, "alpha.service"),
    );

    assert_eq!(live.poll_once().expect("second replay batch"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 1, "alpha.service"),
    );

    assert_eq!(live.poll_once().expect("third replay batch"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 2, "alpha.service"),
    );
}

#[test]
fn live_replay_has_no_default_total_entry_cap() {
    const ENTRIES: usize = 4097;

    let units = vec!["alpha.service"; ENTRIES];
    let layout = SyntheticJournalFile::new(&units);
    let mut live = LiveJournal::open_dir_with_config(
        layout.root(),
        live_test_config_with_live_limits(1024, 1024, LiveQueueFullPolicy::Block),
    )
    .expect("open live engine with unbounded replay");

    let mut filter = live.filter();
    filter.match_unit("alpha.service");
    let mut options = SubscriptionOptions::new(filter);
    options.since_realtime(0);
    let alpha = live
        .subscribe_with_options(options)
        .expect("subscribe with replay");

    let mut received = 0usize;
    while received < ENTRIES {
        let delivered = live.poll_once().expect("replay batch");
        assert_ne!(delivered, 0, "replay should continue until all entries");

        for _ in 0..delivered {
            let entry = recv_ready(&alpha);
            if received == 0 || received == ENTRIES - 1 {
                assert_entry(
                    &entry,
                    "alpha.service",
                    &synthetic_message(7, received, "alpha.service"),
                );
            }
            received = received.saturating_add(1);
        }
    }

    assert_eq!(received, ENTRIES);
}

#[test]
fn replay_subscription_does_not_advance_existing_live_tail() {
    let layout = SyntheticJournalFile::new(&["alpha.service"]);
    let mut live = LiveJournal::open_dir_with_config(layout.root(), live_test_config())
        .expect("open live engine");
    let alpha = subscribe_unit(&mut live, "alpha.service");

    layout.rewrite(&["alpha.service", "alpha.service"]);

    let mut replay_filter = live.filter();
    replay_filter.match_unit("absent.service");
    let mut options = SubscriptionOptions::new(replay_filter);
    options.since_realtime(0);
    let absent_replay = live
        .subscribe_with_options(options)
        .expect("subscribe replaying absent unit");

    let deliveries = poll_until_delivered(&mut live, 1);
    assert_eq!(deliveries, 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 1, "alpha.service"),
    );
    assert_subscription_empty(&absent_replay);
}

#[test]
fn replay_snapshot_switches_to_live_entries_created_after_subscription() {
    let layout = SyntheticJournalFile::new(&["alpha.service", "alpha.service"]);
    let mut cfg = live_test_config_with_live_limits(4, 1, LiveQueueFullPolicy::Block);
    cfg.max_live_replay_entries = Some(2);
    let mut live = LiveJournal::open_dir_with_config(layout.root(), cfg).expect("open live engine");

    let mut filter = live.filter();
    filter.match_unit("alpha.service");
    let mut options = SubscriptionOptions::new(filter);
    options.since_realtime(0);
    let alpha = live
        .subscribe_with_options(options)
        .expect("subscribe replay");

    write_synthetic_journal_file(&layout.root().join("later.journal"), &["alpha.service"], 9);

    assert_eq!(live.poll_once().expect("first replay batch"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 0, "alpha.service"),
    );

    assert_eq!(live.poll_once().expect("second replay batch"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 1, "alpha.service"),
    );

    let deliveries = poll_until_delivered(&mut live, 1);
    assert_eq!(deliveries, 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(9, 0, "alpha.service"),
    );
}

#[test]
fn live_only_subscription_is_not_blocked_by_another_subscription_replay() {
    let layout = SyntheticJournalFile::new(&["alpha.service", "alpha.service"]);
    let later = layout.root().join("later.journal");
    write_synthetic_journal_file(&later, &["gamma.service"], 9);
    let mut live = LiveJournal::open_dir_with_config(
        layout.root(),
        live_test_config_with_live_limits(4, 1, LiveQueueFullPolicy::Block),
    )
    .expect("open live engine");

    let mut replay_filter = live.filter();
    replay_filter.match_unit("alpha.service");
    let mut options = SubscriptionOptions::new(replay_filter);
    options.since_realtime(0);
    let alpha = live
        .subscribe_with_options(options)
        .expect("subscribe replaying alpha");
    let beta = subscribe_unit(&mut live, "beta.service");

    write_synthetic_journal_file(&later, &["gamma.service", "beta.service"], 9);

    assert_eq!(live.poll_once().expect("dispatch ready live entry"), 1);
    assert_entry(
        &recv_ready(&beta),
        "beta.service",
        &synthetic_message(9, 1, "beta.service"),
    );
    assert_subscription_empty(&alpha);

    assert_eq!(live.poll_once().expect("dispatch alpha replay"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 0, "alpha.service"),
    );
}

#[test]
fn replay_limit_counts_matching_entries_not_unrelated_entries() {
    let layout = SyntheticJournalFile::new(&["beta.service", "alpha.service"]);
    let mut cfg = live_test_config_with_live_limits(1, 1, LiveQueueFullPolicy::Block);
    cfg.max_live_replay_entries = Some(1);
    let mut live = LiveJournal::open_dir_with_config(layout.root(), cfg).expect("open live engine");

    let mut filter = live.filter();
    filter.match_unit("alpha.service");
    let mut options = SubscriptionOptions::new(filter);
    options.since_realtime(0);
    let alpha = live
        .subscribe_with_options(options)
        .expect("subscribe alpha replay");

    assert_eq!(live.poll_once().expect("single matching replay batch"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 1, "alpha.service"),
    );
}

#[test]
fn live_replay_configured_total_entry_cap_returns_limit_error() {
    let layout = SyntheticJournalFile::new(&["alpha.service", "alpha.service"]);
    let mut cfg = live_test_config_with_live_limits(1, 1, LiveQueueFullPolicy::Block);
    cfg.max_live_replay_entries = Some(1);
    let mut live = LiveJournal::open_dir_with_config(layout.root(), cfg).expect("open live engine");

    let mut filter = live.filter();
    filter.match_unit("alpha.service");
    let mut options = SubscriptionOptions::new(filter);
    options.since_realtime(0);
    let alpha = live
        .subscribe_with_options(options)
        .expect("subscribe capped replay");

    assert_eq!(live.poll_once().expect("first capped replay batch"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 0, "alpha.service"),
    );

    match live.poll_once() {
        Err(sdjournal::SdJournalError::LimitExceeded {
            kind: sdjournal::LimitKind::LiveReplayEntries,
            limit,
        }) => assert_eq!(limit, 1),
        Ok(value) => panic!("expected replay limit error, got Ok({value})"),
        Err(err) => panic!("expected replay limit error, got {err}"),
    }
}

#[test]
fn live_replay_works_with_low_memory_journal_snapshot() {
    let layout = SyntheticJournalFile::new(&["alpha.service"]);
    write_synthetic_journal_file(
        &layout.root().join("later.journal"),
        &["beta.service", "alpha.service"],
        9,
    );
    let mut cfg = live_test_config_with_live_limits(1, 1, LiveQueueFullPolicy::Block);
    cfg.max_open_files = 1;
    cfg.mmap_policy = MmapPolicy::Never;
    let mut live =
        LiveJournal::open_dir_with_config(layout.root(), cfg).expect("open low-memory live engine");

    let mut filter = live.filter();
    filter.match_unit("alpha.service");
    let mut options = SubscriptionOptions::new(filter);
    options.since_realtime(0);
    let alpha = live
        .subscribe_with_options(options)
        .expect("subscribe with low-memory replay");

    assert_eq!(live.poll_once().expect("first low-memory replay batch"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(7, 0, "alpha.service"),
    );

    assert_eq!(live.poll_once().expect("second low-memory replay batch"), 1);
    assert_entry(
        &recv_ready(&alpha),
        "alpha.service",
        &synthetic_message(9, 1, "alpha.service"),
    );
}

#[test]
fn live_engine_skips_corrupt_tilde_journal_and_tracks_healthy_files() {
    let initial_units = ["alpha.service"];
    let layout = SyntheticJournalFile::new(&initial_units);
    write_corrupt_tilde_journal(layout.root());

    let journal = Journal::open_dir_with_config(layout.root(), live_test_config_with_tilde())
        .expect("open journal set containing a corrupt tilde file");
    let mut live = journal
        .live()
        .expect("live engine should skip the corrupt tilde file");

    let alpha = subscribe_unit(&mut live, "alpha.service");
    assert_subscription_empty(&alpha);

    let rewritten_units = ["alpha.service", "alpha.service"];
    layout.rewrite(&rewritten_units);

    let deliveries = poll_until_delivered(&mut live, 1);
    assert_eq!(deliveries, 1);

    let alpha_entry = recv_ready(&alpha);
    assert_entry(
        &alpha_entry,
        "alpha.service",
        &synthetic_message(7, 1, "alpha.service"),
    );
}

#[test]
fn live_engine_fails_when_all_journal_files_are_untrackable() {
    let layout = SyntheticJournalFile::new(&["alpha.service"]);
    write_corrupt_tilde_journal(layout.root());
    fs::remove_file(layout.root().join("synthetic.journal")).expect("remove healthy journal");

    let journal = Journal::open_dir_with_config(layout.root(), live_test_config_with_tilde())
        .expect("open corrupt journal header");

    match journal.live() {
        Err(sdjournal::SdJournalError::Corrupt { .. }) => {}
        Err(sdjournal::SdJournalError::Transient { .. }) => {}
        Err(err) => panic!("unexpected live error: {err}"),
        Ok(_) => panic!("expected live engine to fail without any trackable journal files"),
    }
}

fn live_test_config() -> JournalConfig {
    JournalConfig {
        poll_interval: Duration::from_millis(10),
        ..JournalConfig::default()
    }
}

fn live_test_config_with_tilde() -> JournalConfig {
    JournalConfig {
        include_journal_tilde: true,
        ..live_test_config()
    }
}

fn live_test_config_with_live_limits(
    live_channel_capacity: usize,
    max_live_batch_entries: usize,
    live_queue_full_policy: LiveQueueFullPolicy,
) -> JournalConfig {
    JournalConfig {
        live_channel_capacity,
        max_live_batch_entries,
        live_queue_full_policy,
        ..live_test_config()
    }
}

fn write_corrupt_tilde_journal(root: &Path) {
    let mut bytes = fs::read(root.join("synthetic.journal")).expect("read synthetic journal");

    bytes[24] = bytes[24].wrapping_add(101);
    bytes[288] = 0;

    fs::write(root.join("corrupt.journal~"), bytes).expect("write corrupt tilde journal");
}

fn subscribe_unit(live: &mut LiveJournal, unit: &str) -> LiveSubscription {
    let mut filter = live.filter();
    filter.match_unit(unit);
    live.subscribe(filter).expect("subscribe unit")
}

fn subscribe_message(live: &mut LiveJournal, message: &str) -> LiveSubscription {
    let mut filter = live.filter();
    filter.match_exact("MESSAGE", message.as_bytes());
    live.subscribe(filter).expect("subscribe message")
}

fn poll_until_delivered(live: &mut LiveJournal, expected: usize) -> usize {
    let mut delivered = 0usize;
    for _ in 0..10 {
        delivered = delivered.saturating_add(live.poll_once().expect("poll live engine"));
        if delivered >= expected {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    delivered
}

fn recv_ready(subscription: &LiveSubscription) -> sdjournal::LiveEntry {
    subscription
        .try_recv()
        .expect("subscription should have one ready item")
        .expect("live entry should decode")
}

fn assert_entry(entry: &sdjournal::LiveEntry, unit: &str, message: &str) {
    assert_eq!(field(entry, "_SYSTEMD_UNIT"), unit);
    assert_eq!(field(entry, "MESSAGE"), message);
}

fn field(entry: &sdjournal::LiveEntry, name: &str) -> String {
    String::from_utf8_lossy(entry.get(name).expect("entry field")).into_owned()
}

fn assert_subscription_empty(subscription: &LiveSubscription) {
    match subscription.try_recv() {
        Err(TryRecvError::Empty) => {}
        Err(TryRecvError::Disconnected) => panic!("subscription disconnected"),
        Ok(Ok(entry)) => panic!(
            "subscription unexpectedly received MESSAGE={}",
            String::from_utf8_lossy(entry.get("MESSAGE").unwrap_or(b"<missing>"))
        ),
        Ok(Err(err)) => panic!("subscription unexpectedly received error: {err}"),
    }
}
