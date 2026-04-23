use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use sdjournal::{Journal, JournalConfig, JournalQuery, LiveJournal, LiveSubscription};
use std::fs::{self, create_dir_all};
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

const HEADER_SIZE: usize = 272;
const DATA_HASH_TABLE_SIZE: usize = 16;
const REGULAR_DATA_OBJECT_HEADER_SIZE: usize = 64;
const ENTRY_ARRAY_OBJECT_HEADER_SIZE: usize = 24;
const ENTRY_OBJECT_HEADER_SIZE: usize = 64;
const ENTRY_ITEM_SIZE: usize = 16;
const MACHINE_ID_DIR: &str = "0123456789abcdef0123456789abcdef";
const FILES_PER_DIR: usize = 2;
const UNIT_FIELDS: [&str; 3] = ["_SYSTEMD_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT"];
const BENCH_UNITS: [&str; 8] = [
    "bench-a.service",
    "bench-b.service",
    "bench-c.service",
    "bench-d.service",
    "bench-e.service",
    "bench-f.service",
    "bench-g.service",
    "bench-h.service",
];

#[derive(Clone)]
struct EntryPlan {
    seqnum: u64,
    realtime_usec: u64,
    monotonic_usec: u64,
    boot_id: [u8; 16],
    field_indices: Vec<usize>,
}

#[derive(Clone)]
struct DataPlan {
    payload: Vec<u8>,
    hash: u64,
    owner_entry_idx: usize,
    offset: u64,
    size: u64,
    entry_offset: u64,
    next_hash_offset: u64,
}

struct SyntheticJournalLayout {
    root: TempDir,
    files_per_dir: usize,
}

impl SyntheticJournalLayout {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create synthetic journal root");
        let machine_dir = root.path().join(MACHINE_ID_DIR);
        create_dir_all(&machine_dir).expect("create machine-id dir");

        let mut seed = 1u8;
        for idx in 0..FILES_PER_DIR {
            write_synthetic_journal(
                &root.path().join(format!("root-{idx}.journal")),
                &BENCH_UNITS,
                seed,
            );
            seed = seed.wrapping_add(1);
        }
        for idx in 0..FILES_PER_DIR {
            write_synthetic_journal(
                &machine_dir.join(format!("nested-{idx}.journal")),
                &BENCH_UNITS,
                seed,
            );
            seed = seed.wrapping_add(1);
        }

        Self {
            root,
            files_per_dir: FILES_PER_DIR,
        }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn total_files(&self) -> usize {
        FILES_PER_DIR * 2
    }

    fn latest_file_path(&self) -> PathBuf {
        self.root
            .path()
            .join(MACHINE_ID_DIR)
            .join(format!("nested-{}.journal", self.files_per_dir - 1))
    }

    fn latest_file_seed(&self) -> u8 {
        u8::try_from(self.files_per_dir * 2).expect("latest file seed fits in u8")
    }
}

fn benchmark_config() -> JournalConfig {
    JournalConfig {
        poll_interval: Duration::ZERO,
        ..JournalConfig::default()
    }
}

fn open_layout(layout: &SyntheticJournalLayout) -> Journal {
    Journal::open_dir_with_config(layout.root(), benchmark_config())
        .expect("open synthetic journal layout")
}

fn build_match_unit_query(journal: &Journal, unit: &str) -> JournalQuery {
    let mut q = journal.query();
    q.match_unit(unit);
    q
}

fn build_match_exact_query(journal: &Journal, unit: &str) -> JournalQuery {
    let mut q = journal.query();
    q.match_exact("_SYSTEMD_UNIT", unit.as_bytes());
    q
}

fn build_multi_unit_exact_query(journal: &Journal, units: &[&str]) -> JournalQuery {
    let mut q = journal.query();
    for unit in units {
        for field in UNIT_FIELDS {
            q.or_group(|g| {
                g.match_exact(field, unit.as_bytes());
            });
        }
    }
    q
}

fn sanity_check(layout: &SyntheticJournalLayout) {
    let journal = open_layout(layout);
    let expected_per_unit = layout.total_files();
    let unit = BENCH_UNITS[0];

    let exact_count = build_match_exact_query(&journal, unit)
        .collect_owned()
        .expect("exact query should succeed")
        .len();
    assert_eq!(exact_count, expected_per_unit);

    let unit_count = build_match_unit_query(&journal, unit)
        .collect_owned()
        .expect("match_unit query should succeed")
        .len();
    assert_eq!(unit_count, expected_per_unit);

    let combined_count = build_multi_unit_exact_query(&journal, &BENCH_UNITS[..4])
        .collect_owned()
        .expect("combined query should succeed")
        .len();
    assert_eq!(combined_count, expected_per_unit * 4);
}

fn benchmark_query_perf(c: &mut Criterion) {
    let layout = SyntheticJournalLayout::new();
    sanity_check(&layout);
    let journal = open_layout(&layout);

    let mut group = c.benchmark_group("query_perf");
    group.sample_size(30);

    group.bench_function("open_dir_4_files_8_units", |b| {
        b.iter(|| black_box(open_layout(&layout)));
    });

    group.bench_function("single_unit_match_exact", |b| {
        b.iter(|| {
            let count = build_match_exact_query(&journal, BENCH_UNITS[0])
                .collect_owned()
                .expect("exact query should succeed")
                .len();
            black_box(count)
        });
    });

    group.bench_function("single_unit_match_unit", |b| {
        b.iter(|| {
            let count = build_match_unit_query(&journal, BENCH_UNITS[0])
                .collect_owned()
                .expect("match_unit query should succeed")
                .len();
            black_box(count)
        });
    });

    group.bench_function("multi_unit_independent_match_unit_queries_x4", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for unit in &BENCH_UNITS[..4] {
                count = count.saturating_add(
                    build_match_unit_query(&journal, unit)
                        .collect_owned()
                        .expect("independent match_unit query should succeed")
                        .len(),
                );
            }
            black_box(count)
        });
    });

    group.bench_function("multi_unit_combined_exact_query_x1", |b| {
        b.iter(|| {
            let count = build_multi_unit_exact_query(&journal, &BENCH_UNITS[..4])
                .collect_owned()
                .expect("combined unit query should succeed")
                .len();
            black_box(count)
        });
    });

    group.finish();
}

struct IndependentLiveSetup {
    engines: Vec<LiveJournal>,
    subscriptions: Vec<LiveSubscription>,
}

struct SharedLiveSetup {
    engine: LiveJournal,
    subscriptions: Vec<LiveSubscription>,
}

fn build_independent_live_setup(journal: &Journal, units: &[&str]) -> IndependentLiveSetup {
    let mut engines = Vec::with_capacity(units.len());
    let mut subscriptions = Vec::with_capacity(units.len());

    for unit in units {
        let mut live = journal
            .live()
            .expect("independent live engine should succeed");
        let mut filter = live.filter();
        filter.match_unit(unit);
        let subscription = live
            .subscribe(filter)
            .expect("independent live subscription should succeed");
        engines.push(live);
        subscriptions.push(subscription);
    }

    IndependentLiveSetup {
        engines,
        subscriptions,
    }
}

fn build_shared_live_setup(journal: &Journal, units: &[&str]) -> SharedLiveSetup {
    let mut engine = journal.live().expect("shared live engine should succeed");
    let mut subscriptions = Vec::with_capacity(units.len());

    for unit in units {
        let mut filter = engine.filter();
        filter.match_unit(unit);
        let subscription = engine
            .subscribe(filter)
            .expect("shared live subscription should succeed");
        subscriptions.push(subscription);
    }

    SharedLiveSetup {
        engine,
        subscriptions,
    }
}

fn drain_ready(subscription: &LiveSubscription) -> usize {
    let mut ready = 0usize;
    while let Ok(item) = subscription.try_recv() {
        item.expect("live delivery should succeed");
        ready = ready.saturating_add(1);
    }
    ready
}

fn benchmark_follow_perf(c: &mut Criterion) {
    let layout = SyntheticJournalLayout::new();
    sanity_check(&layout);
    let appended_units = appended_units_for_delivery();

    let mut group = c.benchmark_group("follow_perf");
    group.sample_size(20);

    group.bench_function("multi_unit_independent_live_engines_x4_setup", |b| {
        b.iter_batched(
            || open_layout(&layout),
            |journal| black_box(build_independent_live_setup(&journal, &BENCH_UNITS[..4])),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("shared_engine_multi_subscriptions_x4_setup", |b| {
        b.iter_batched(
            || open_layout(&layout),
            |journal| black_box(build_shared_live_setup(&journal, &BENCH_UNITS[..4])),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("multi_unit_independent_live_engines_x4_idle_poll", |b| {
        b.iter_batched(
            || build_independent_live_setup(&open_layout(&layout), &BENCH_UNITS[..4]),
            |mut setup| {
                let mut ready = 0usize;
                for engine in &mut setup.engines {
                    engine.poll_once().expect("idle live poll should succeed");
                }
                for subscription in &setup.subscriptions {
                    ready = ready.saturating_add(drain_ready(subscription));
                }
                black_box(ready)
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("shared_engine_multi_subscriptions_x4_idle_poll", |b| {
        b.iter_batched(
            || build_shared_live_setup(&open_layout(&layout), &BENCH_UNITS[..4]),
            |mut setup| {
                setup
                    .engine
                    .poll_once()
                    .expect("shared idle live poll should succeed");
                let mut ready = 0usize;
                for subscription in &setup.subscriptions {
                    ready = ready.saturating_add(drain_ready(subscription));
                }
                black_box(ready)
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("single_unit_live_engine_append_and_deliver", |b| {
        b.iter_batched(
            || {
                let layout = SyntheticJournalLayout::new();
                let journal = open_layout(&layout);
                let mut live = journal
                    .live()
                    .expect("single-unit live engine should succeed");
                let mut filter = live.filter();
                filter.match_unit(BENCH_UNITS[0]);
                let subscription = live
                    .subscribe(filter)
                    .expect("single-unit live subscription should succeed");
                (layout, live, subscription)
            },
            |(layout, mut live, subscription)| {
                rewrite_latest_file(&layout, &appended_units);
                let delivered = poll_until_ready(&mut live, &subscription, 3);
                black_box(delivered)
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function(
        "multi_unit_independent_live_engines_x4_append_and_deliver",
        |b| {
            b.iter_batched(
                || {
                    let layout = SyntheticJournalLayout::new();
                    let journal = open_layout(&layout);
                    let setup = build_independent_live_setup(&journal, &BENCH_UNITS[..4]);
                    (layout, setup)
                },
                |(layout, mut setup)| {
                    rewrite_latest_file(&layout, &appended_units);
                    let mut delivered = 0usize;
                    for (engine, subscription) in setup.engines.iter_mut().zip(&setup.subscriptions)
                    {
                        delivered =
                            delivered.saturating_add(poll_until_ready(engine, subscription, 3));
                    }
                    black_box(delivered)
                },
                BatchSize::SmallInput,
            );
        },
    );

    group.bench_function(
        "shared_engine_multi_subscriptions_x4_append_and_deliver",
        |b| {
            b.iter_batched(
                || {
                    let layout = SyntheticJournalLayout::new();
                    let journal = open_layout(&layout);
                    let setup = build_shared_live_setup(&journal, &BENCH_UNITS[..4]);
                    (layout, setup)
                },
                |(layout, mut setup)| {
                    rewrite_latest_file(&layout, &appended_units);
                    let delivered = poll_until_all_ready(
                        &mut setup.engine,
                        &setup.subscriptions,
                        setup.subscriptions.len(),
                        3,
                    );
                    black_box(delivered)
                },
                BatchSize::SmallInput,
            );
        },
    );

    group.finish();
}

fn appended_units_for_delivery() -> Vec<String> {
    let mut units = BENCH_UNITS
        .iter()
        .map(|unit| (*unit).to_string())
        .collect::<Vec<_>>();
    units.extend(
        BENCH_UNITS[..4]
            .iter()
            .map(|unit| (*unit).to_string())
            .collect::<Vec<_>>(),
    );
    units
}

fn rewrite_latest_file(layout: &SyntheticJournalLayout, units: &[String]) {
    let bytes = build_journal_bytes(units, layout.latest_file_seed());
    fs::write(layout.latest_file_path(), bytes).expect("rewrite latest synthetic journal");
}

fn poll_until_ready(
    engine: &mut LiveJournal,
    subscription: &LiveSubscription,
    max_attempts: usize,
) -> usize {
    for _ in 0..max_attempts {
        engine
            .poll_once()
            .expect("live poll for appended entry should succeed");
        let ready = drain_ready(subscription);
        if ready != 0 {
            return ready;
        }
    }
    0
}

fn poll_until_all_ready(
    engine: &mut LiveJournal,
    subscriptions: &[LiveSubscription],
    expected: usize,
    max_attempts: usize,
) -> usize {
    let mut total = 0usize;
    for _ in 0..max_attempts {
        engine
            .poll_once()
            .expect("shared live poll for appended entries should succeed");
        for subscription in subscriptions {
            total = total.saturating_add(drain_ready(subscription));
        }
        if total >= expected {
            return total;
        }
    }
    total
}

fn write_synthetic_journal<S: AsRef<str>>(path: &Path, units: &[S], seed: u8) {
    let bytes = build_journal_bytes(units, seed);
    fs::write(path, bytes).expect("write synthetic journal");
}

fn build_journal_bytes<S: AsRef<str>>(units: &[S], seed: u8) -> Vec<u8> {
    let file_id = fill_id(seed);
    let machine_id = fill_id(seed.wrapping_add(17));
    let boot_id = fill_id(seed.wrapping_add(34));
    let seqnum_id = fill_id(seed.wrapping_add(51));

    let mut entries = Vec::with_capacity(units.len());
    let mut data_plans = Vec::new();
    let mut current = align8(HEADER_SIZE + DATA_HASH_TABLE_SIZE);

    for (entry_idx, unit) in units.iter().enumerate() {
        let unit = unit.as_ref();
        let message = format!("MESSAGE=bench-message-{seed}-{entry_idx}").into_bytes();
        let priority = format!("PRIORITY={}", (entry_idx % 7) + 1).into_bytes();
        let identifier = format!("SYSLOG_IDENTIFIER=bench-{seed}").into_bytes();
        let payloads = vec![
            format!("_SYSTEMD_UNIT={unit}").into_bytes(),
            format!("UNIT={unit}").into_bytes(),
            format!("OBJECT_SYSTEMD_UNIT={unit}").into_bytes(),
            message,
            priority,
            identifier,
        ];

        let mut field_indices = Vec::with_capacity(payloads.len());
        for payload in payloads {
            let size = REGULAR_DATA_OBJECT_HEADER_SIZE + payload.len();
            data_plans.push(DataPlan {
                hash: jenkins_hash64(&payload),
                payload,
                owner_entry_idx: entry_idx,
                offset: u64::try_from(current).expect("data offset fits in u64"),
                size: u64::try_from(size).expect("data size fits in u64"),
                entry_offset: 0,
                next_hash_offset: 0,
            });
            field_indices.push(data_plans.len() - 1);
            current = align8(current + size);
        }

        let realtime_usec = 1_700_000_000_000_000u64
            .saturating_add(u64::from(seed) * 10_000)
            .saturating_add(u64::try_from(entry_idx).expect("entry index fits") * 100);
        entries.push(EntryPlan {
            seqnum: u64::try_from(entry_idx + 1).expect("entry seqnum fits"),
            realtime_usec,
            monotonic_usec: realtime_usec.saturating_sub(123),
            boot_id,
            field_indices,
        });
    }

    let entry_array_offset = current;
    let entry_array_size = ENTRY_ARRAY_OBJECT_HEADER_SIZE + (entries.len() * 8);
    current = align8(current + entry_array_size);

    let mut entry_offsets = Vec::with_capacity(entries.len());
    for entry in &entries {
        let size = ENTRY_OBJECT_HEADER_SIZE + (entry.field_indices.len() * ENTRY_ITEM_SIZE);
        entry_offsets.push(u64::try_from(current).expect("entry offset fits"));
        current = align8(current + size);
    }

    let next_offsets: Vec<u64> = data_plans
        .iter()
        .skip(1)
        .map(|plan| plan.offset)
        .chain(std::iter::once(0))
        .collect();

    for (idx, plan) in data_plans.iter_mut().enumerate() {
        plan.entry_offset = entry_offsets[plan.owner_entry_idx];
        plan.next_hash_offset = next_offsets[idx];
    }

    let mut bytes = vec![0u8; current];
    bytes[0..8].copy_from_slice(b"LPKSHHRH");
    put_u32(&mut bytes, 8, 0);
    put_u32(&mut bytes, 12, 0);
    bytes[16] = 2;
    bytes[24..40].copy_from_slice(&file_id);
    bytes[40..56].copy_from_slice(&machine_id);
    bytes[56..72].copy_from_slice(&boot_id);
    bytes[72..88].copy_from_slice(&seqnum_id);
    put_u64(&mut bytes, 88, HEADER_SIZE as u64);
    put_u64(
        &mut bytes,
        96,
        u64::try_from(current.saturating_sub(HEADER_SIZE)).expect("arena size fits"),
    );
    put_u64(&mut bytes, 104, HEADER_SIZE as u64);
    put_u64(&mut bytes, 112, DATA_HASH_TABLE_SIZE as u64);
    put_u64(&mut bytes, 120, 0);
    put_u64(&mut bytes, 128, 0);
    put_u64(
        &mut bytes,
        136,
        *entry_offsets
            .last()
            .unwrap_or(&u64::try_from(entry_array_offset).unwrap_or(0)),
    );
    put_u64(
        &mut bytes,
        152,
        u64::try_from(entries.len()).expect("entry count fits"),
    );
    put_u64(
        &mut bytes,
        176,
        u64::try_from(entry_array_offset).expect("entry array offset fits"),
    );

    let table_offset = HEADER_SIZE;
    put_u64(
        &mut bytes,
        table_offset,
        data_plans.first().map(|plan| plan.offset).unwrap_or(0),
    );
    put_u64(
        &mut bytes,
        table_offset + 8,
        data_plans.last().map(|plan| plan.offset).unwrap_or(0),
    );

    for plan in &data_plans {
        let offset = usize::try_from(plan.offset).expect("data offset fits usize");
        put_object_header(&mut bytes, offset, 1, 0, plan.size);
        put_u64(&mut bytes, offset + 16, plan.hash);
        put_u64(&mut bytes, offset + 24, plan.next_hash_offset);
        put_u64(&mut bytes, offset + 32, 0);
        put_u64(&mut bytes, offset + 40, plan.entry_offset);
        put_u64(&mut bytes, offset + 48, 0);
        put_u64(&mut bytes, offset + 56, 1);
        let payload_start = offset + REGULAR_DATA_OBJECT_HEADER_SIZE;
        let payload_end = payload_start + plan.payload.len();
        bytes[payload_start..payload_end].copy_from_slice(&plan.payload);
    }

    put_object_header(
        &mut bytes,
        entry_array_offset,
        6,
        0,
        u64::try_from(entry_array_size).expect("entry array size fits"),
    );
    put_u64(&mut bytes, entry_array_offset + 16, 0);
    for (idx, entry_offset) in entry_offsets.iter().enumerate() {
        put_u64(
            &mut bytes,
            entry_array_offset + ENTRY_ARRAY_OBJECT_HEADER_SIZE + (idx * 8),
            *entry_offset,
        );
    }

    for (entry_idx, entry) in entries.iter().enumerate() {
        let entry_offset = usize::try_from(entry_offsets[entry_idx]).expect("entry offset fits");
        let size = ENTRY_OBJECT_HEADER_SIZE + (entry.field_indices.len() * ENTRY_ITEM_SIZE);
        put_object_header(
            &mut bytes,
            entry_offset,
            3,
            0,
            u64::try_from(size).expect("entry size fits"),
        );
        put_u64(&mut bytes, entry_offset + 16, entry.seqnum);
        put_u64(&mut bytes, entry_offset + 24, entry.realtime_usec);
        put_u64(&mut bytes, entry_offset + 32, entry.monotonic_usec);
        bytes[entry_offset + 40..entry_offset + 56].copy_from_slice(&entry.boot_id);
        put_u64(&mut bytes, entry_offset + 56, 0);

        for (item_idx, plan_idx) in entry.field_indices.iter().copied().enumerate() {
            let plan = &data_plans[plan_idx];
            let item_offset =
                entry_offset + ENTRY_OBJECT_HEADER_SIZE + (item_idx * ENTRY_ITEM_SIZE);
            put_u64(&mut bytes, item_offset, plan.offset);
            put_u64(&mut bytes, item_offset + 8, plan.hash);
        }
    }

    bytes
}

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

fn fill_id(seed: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add(u8::try_from(idx).expect("id index fits"));
    }
    out
}

fn put_object_header(bytes: &mut [u8], offset: usize, object_type: u8, flags: u8, size: u64) {
    bytes[offset] = object_type;
    bytes[offset + 1] = flags;
    put_u64(bytes, offset + 8, size);
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn jenkins_hash64(data: &[u8]) -> u64 {
    let (pc, pb) = jenkins_hashlittle2(data, 0, 0);
    ((u64::from(pc)) << 32) | u64::from(pb)
}

fn jenkins_hashlittle2(key: &[u8], init_pc: u32, init_pb: u32) -> (u32, u32) {
    let mut a = 0xdeadbeefu32
        .wrapping_add(u32::try_from(key.len()).unwrap_or(u32::MAX))
        .wrapping_add(init_pc);
    let mut b = a;
    let mut c = a.wrapping_add(init_pb);

    fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
        *a = a.wrapping_sub(*c);
        *a ^= c.rotate_left(4);
        *c = c.wrapping_add(*b);

        *b = b.wrapping_sub(*a);
        *b ^= a.rotate_left(6);
        *a = a.wrapping_add(*c);

        *c = c.wrapping_sub(*b);
        *c ^= b.rotate_left(8);
        *b = b.wrapping_add(*a);

        *a = a.wrapping_sub(*c);
        *a ^= c.rotate_left(16);
        *c = c.wrapping_add(*b);

        *b = b.wrapping_sub(*a);
        *b ^= a.rotate_left(19);
        *a = a.wrapping_add(*c);

        *c = c.wrapping_sub(*b);
        *c ^= b.rotate_left(4);
        *b = b.wrapping_add(*a);
    }

    fn final_(a: &mut u32, b: &mut u32, c: &mut u32) {
        *c ^= *b;
        *c = c.wrapping_sub(b.rotate_left(14));

        *a ^= *c;
        *a = a.wrapping_sub(c.rotate_left(11));

        *b ^= *a;
        *b = b.wrapping_sub(a.rotate_left(25));

        *c ^= *b;
        *c = c.wrapping_sub(b.rotate_left(16));

        *a ^= *c;
        *a = a.wrapping_sub(c.rotate_left(4));

        *b ^= *a;
        *b = b.wrapping_sub(a.rotate_left(14));

        *c ^= *b;
        *c = c.wrapping_sub(b.rotate_left(24));
    }

    let mut i = 0usize;
    while key.len().saturating_sub(i) > 12 {
        let a_part = u32::from_le_bytes([key[i], key[i + 1], key[i + 2], key[i + 3]]);
        let b_part = u32::from_le_bytes([key[i + 4], key[i + 5], key[i + 6], key[i + 7]]);
        let c_part = u32::from_le_bytes([key[i + 8], key[i + 9], key[i + 10], key[i + 11]]);

        a = a.wrapping_add(a_part);
        b = b.wrapping_add(b_part);
        c = c.wrapping_add(c_part);
        mix(&mut a, &mut b, &mut c);

        i += 12;
    }

    let tail = &key[i..];
    if tail.is_empty() {
        return (c, b);
    }

    let n = tail.len();
    if n >= 12 {
        c = c.wrapping_add((u32::from(tail[11])) << 24);
    }
    if n >= 11 {
        c = c.wrapping_add((u32::from(tail[10])) << 16);
    }
    if n >= 10 {
        c = c.wrapping_add((u32::from(tail[9])) << 8);
    }
    if n >= 9 {
        c = c.wrapping_add(u32::from(tail[8]));
    }
    if n >= 8 {
        b = b.wrapping_add((u32::from(tail[7])) << 24);
    }
    if n >= 7 {
        b = b.wrapping_add((u32::from(tail[6])) << 16);
    }
    if n >= 6 {
        b = b.wrapping_add((u32::from(tail[5])) << 8);
    }
    if n >= 5 {
        b = b.wrapping_add(u32::from(tail[4]));
    }
    if n >= 4 {
        a = a.wrapping_add((u32::from(tail[3])) << 24);
    }
    if n >= 3 {
        a = a.wrapping_add((u32::from(tail[2])) << 16);
    }
    if n >= 2 {
        a = a.wrapping_add((u32::from(tail[1])) << 8);
    }
    if n >= 1 {
        a = a.wrapping_add(u32::from(tail[0]));
    }

    final_(&mut a, &mut b, &mut c);
    (c, b)
}

criterion_group!(benches, benchmark_query_perf, benchmark_follow_perf);
criterion_main!(benches);
