use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const HEADER_SIZE: usize = 272;
const DATA_HASH_TABLE_SIZE: usize = 16;
const REGULAR_DATA_OBJECT_HEADER_SIZE: usize = 64;
const ENTRY_ARRAY_OBJECT_HEADER_SIZE: usize = 24;
const ENTRY_OBJECT_HEADER_SIZE: usize = 64;
const ENTRY_ITEM_SIZE: usize = 16;
const DEFAULT_ENTRY_ARRAY_CAPACITY: usize = 64;

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

pub struct SyntheticJournalFile {
    root: TempDir,
    path: PathBuf,
    seed: u8,
    entry_array_capacity: usize,
}

impl SyntheticJournalFile {
    pub fn new<S: AsRef<str>>(units: &[S]) -> Self {
        let root = tempfile::tempdir().expect("create synthetic journal root");
        let path = root.path().join("synthetic.journal");
        let seed = 7;
        let entry_array_capacity = DEFAULT_ENTRY_ARRAY_CAPACITY.max(units.len());
        write_synthetic_journal(&path, units, seed, entry_array_capacity);

        Self {
            root,
            path,
            seed,
            entry_array_capacity,
        }
    }

    pub fn root(&self) -> &Path {
        self.root.path()
    }

    pub fn rewrite<S: AsRef<str>>(&self, units: &[S]) {
        assert!(
            units.len() <= self.entry_array_capacity,
            "synthetic journal entry capacity exceeded"
        );
        write_synthetic_journal(&self.path, units, self.seed, self.entry_array_capacity);
    }
}

pub fn synthetic_message(seed: u8, entry_idx: usize, unit: &str) -> String {
    format!("synthetic-message-{seed}-{entry_idx}-{unit}")
}

fn write_synthetic_journal<S: AsRef<str>>(
    path: &Path,
    units: &[S],
    seed: u8,
    entry_array_capacity: usize,
) {
    let bytes = build_journal_bytes(units, seed, entry_array_capacity);
    fs::write(path, bytes).expect("write synthetic journal");
}

fn build_journal_bytes<S: AsRef<str>>(
    units: &[S],
    seed: u8,
    entry_array_capacity: usize,
) -> Vec<u8> {
    let file_id = fill_id(seed);
    let machine_id = fill_id(seed.wrapping_add(17));
    let boot_id = fill_id(seed.wrapping_add(34));
    let seqnum_id = fill_id(seed.wrapping_add(51));

    let entry_array_offset = align8(HEADER_SIZE + DATA_HASH_TABLE_SIZE);
    let entry_array_size = ENTRY_ARRAY_OBJECT_HEADER_SIZE + (entry_array_capacity * 8);
    let mut current = align8(entry_array_offset + entry_array_size);

    let mut entries = Vec::with_capacity(units.len());
    let mut data_plans = Vec::new();

    for (entry_idx, unit) in units.iter().enumerate() {
        let unit = unit.as_ref();
        let message = format!("MESSAGE={}", synthetic_message(seed, entry_idx, unit)).into_bytes();
        let priority = format!("PRIORITY={}", (entry_idx % 7) + 1).into_bytes();
        let identifier = format!("SYSLOG_IDENTIFIER=synthetic-{seed}").into_bytes();
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
    bytes[16] = 1;
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

    put_object_header(
        &mut bytes,
        entry_array_offset,
        6,
        0,
        u64::try_from(entry_array_size).expect("entry array size fits"),
    );
    put_u64(&mut bytes, entry_array_offset + 16, 0);
    for idx in 0..entry_array_capacity {
        let entry_offset = entry_offsets.get(idx).copied().unwrap_or(0);
        put_u64(
            &mut bytes,
            entry_array_offset + ENTRY_ARRAY_OBJECT_HEADER_SIZE + (idx * 8),
            entry_offset,
        );
    }

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
