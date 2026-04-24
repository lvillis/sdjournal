mod support;

use sdjournal::{Journal, JournalConfig, LiveJournal, LiveSubscription};
use std::sync::mpsc::TryRecvError;
use std::thread;
use std::time::Duration;
use support::synthetic_journal::{SyntheticJournalFile, synthetic_message};

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

fn live_test_config() -> JournalConfig {
    JournalConfig {
        poll_interval: Duration::from_millis(10),
        ..JournalConfig::default()
    }
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
