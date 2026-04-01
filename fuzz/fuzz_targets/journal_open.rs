#![no_main]

use libfuzzer_sys::fuzz_target;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const MAX_INPUT_SIZE: usize = 2 * 1024 * 1024;
const HEADER_SIZE: usize = 272;
const ENTRY_ARRAY_OFFSET: usize = HEADER_SIZE;
const OBJECT_ENTRY: u8 = 3;
const OBJECT_ENTRY_ARRAY: u8 = 6;
const HEADER_INCOMPATIBLE_COMPACT: u32 = 1 << 4;
const MACHINE_ID_DIR: &str = "0123456789abcdef0123456789abcdef";

struct ReusableJournalLayout {
    root: PathBuf,
    machine_dir: PathBuf,
    root_file: Mutex<File>,
    machine_file: Mutex<File>,
    tilde_file: Mutex<File>,
}

impl ReusableJournalLayout {
    fn new() -> Option<Self> {
        let root =
            std::env::temp_dir().join(format!("sdjournal-fuzz-journal-open-{}", std::process::id()));
        create_dir_all(&root).ok()?;

        let machine_dir = root.join(MACHINE_ID_DIR);
        create_dir_all(&machine_dir).ok()?;

        let root_file = open_rw(root.join("root.journal"))?;
        let machine_file = open_rw(machine_dir.join("nested.journal"))?;
        let tilde_file = open_rw(root.join("temp.journal~"))?;

        Some(Self {
            root,
            machine_dir,
            root_file: Mutex::new(root_file),
            machine_file: Mutex::new(machine_file),
            tilde_file: Mutex::new(tilde_file),
        })
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn machine_dir(&self) -> &Path {
        &self.machine_dir
    }

    fn rewrite_all(&self, root_bytes: &[u8], machine_bytes: &[u8], tilde_bytes: &[u8]) -> bool {
        rewrite_locked_file(&self.root_file, root_bytes)
            && rewrite_locked_file(&self.machine_file, machine_bytes)
            && rewrite_locked_file(&self.tilde_file, tilde_bytes)
    }
}

fn open_rw(path: PathBuf) -> Option<File> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(path)
        .ok()
}

fn rewrite_locked_file(file: &Mutex<File>, bytes: &[u8]) -> bool {
    let mut file = match file.lock() {
        Ok(file) => file,
        Err(_) => return false,
    };

    if file.rewind().is_err() {
        return false;
    }
    if file.set_len(0).is_err() {
        return false;
    }
    if file.write_all(bytes).is_err() {
        return false;
    }
    let final_len = match u64::try_from(bytes.len()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if file.set_len(final_len).is_err() {
        return false;
    }

    true
}

fn reusable_journal_layout() -> Option<&'static ReusableJournalLayout> {
    static SLOT: OnceLock<Option<ReusableJournalLayout>> = OnceLock::new();
    SLOT.get_or_init(ReusableJournalLayout::new).as_ref()
}

fn write_le_u32(dst: &mut [u8], offset: usize, v: u32) {
    if let Some(b) = dst.get_mut(offset..offset + 4) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

fn write_le_u64(dst: &mut [u8], offset: usize, v: u64) {
    if let Some(b) = dst.get_mut(offset..offset + 8) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

fn fill_bytes(dst: &mut [u8], src: &[u8], start: usize, fallback: u8) {
    if src.is_empty() {
        dst.fill(fallback);
        return;
    }

    for (idx, byte) in dst.iter_mut().enumerate() {
        *byte = src
            .get(start.saturating_add(idx))
            .copied()
            .unwrap_or_else(|| src[idx % src.len()]);
    }
}

fn load_u64(src: &[u8], start: usize, fallback: u64) -> u64 {
    let Some(bytes) = src.get(start..start.saturating_add(8)) else {
        return fallback;
    };
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    u64::from_le_bytes(out)
}

fn variant_bytes(data: &[u8], salt: u8) -> Vec<u8> {
    if data.is_empty() {
        return vec![salt];
    }

    let mut out = data.to_vec();
    let len = out.len();
    let rotate = usize::from(salt) % len;
    out.rotate_left(rotate);
    out[0] ^= salt;
    out.push(salt);
    out
}

fn minimal_journal_bytes(data: &[u8]) -> Vec<u8> {
    let compact = data.first().copied().unwrap_or(0) & 1 != 0;
    let entry_array_size = if compact { 28usize } else { 32usize };
    let entry_offset = ENTRY_ARRAY_OFFSET.saturating_add(entry_array_size);
    let used_size = entry_offset.saturating_add(64);

    let mut bytes = data.to_vec();
    if bytes.len() < used_size {
        bytes.resize(used_size, 0);
    }

    bytes[0..8].copy_from_slice(b"LPKSHHRH");

    let mut incompatible =
        u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) & 0x1f;
    if compact {
        incompatible |= HEADER_INCOMPATIBLE_COMPACT;
    } else {
        incompatible &= !HEADER_INCOMPATIBLE_COMPACT;
    }
    write_le_u32(&mut bytes, 12, incompatible);
    bytes[16] = data.get(1).copied().unwrap_or(0) % 3;

    fill_bytes(&mut bytes[24..40], data, 24, 0x11);
    fill_bytes(&mut bytes[40..56], data, 40, 0x22);
    fill_bytes(&mut bytes[56..72], data, 56, 0x33);
    fill_bytes(&mut bytes[72..88], data, 72, 0x44);

    write_le_u64(&mut bytes, 88, HEADER_SIZE as u64);
    write_le_u64(&mut bytes, 96, (used_size - HEADER_SIZE) as u64);
    write_le_u64(&mut bytes, 104, 0);
    write_le_u64(&mut bytes, 112, 0);
    write_le_u64(&mut bytes, 120, 0);
    write_le_u64(&mut bytes, 128, 0);
    write_le_u64(&mut bytes, 136, entry_offset as u64);
    write_le_u64(&mut bytes, 152, 1);
    write_le_u64(&mut bytes, 176, ENTRY_ARRAY_OFFSET as u64);

    bytes[ENTRY_ARRAY_OFFSET] = OBJECT_ENTRY_ARRAY;
    bytes[ENTRY_ARRAY_OFFSET + 1] = 0;
    write_le_u64(&mut bytes, ENTRY_ARRAY_OFFSET + 8, entry_array_size as u64);
    write_le_u64(&mut bytes, ENTRY_ARRAY_OFFSET + 16, 0);
    if compact {
        write_le_u32(&mut bytes, ENTRY_ARRAY_OFFSET + 24, entry_offset as u32);
    } else {
        write_le_u64(&mut bytes, ENTRY_ARRAY_OFFSET + 24, entry_offset as u64);
    }

    bytes[entry_offset] = OBJECT_ENTRY;
    bytes[entry_offset + 1] = 0;
    write_le_u64(&mut bytes, entry_offset + 8, 64);
    write_le_u64(&mut bytes, entry_offset + 16, load_u64(data, 96, 1));
    write_le_u64(&mut bytes, entry_offset + 24, load_u64(data, 104, 1));
    write_le_u64(&mut bytes, entry_offset + 32, load_u64(data, 112, 1));
    fill_bytes(&mut bytes[entry_offset + 40..entry_offset + 56], data, 120, 0x55);
    write_le_u64(&mut bytes, entry_offset + 56, load_u64(data, 136, 0));

    bytes
}

fn exercise_queries(journal: &sdjournal::Journal) {
    let _ = journal.query().limit(8).collect_owned();

    let mut head = journal.query();
    head.seek_head().limit(4);
    let _ = head.collect_owned();

    let mut tail = journal.query();
    tail.seek_tail().limit(8);
    let tail_entries = tail.collect_owned().unwrap_or_default();

    let mut bounded = journal.query();
    bounded.since_realtime(0).until_realtime(u64::MAX).limit(4);
    let _ = bounded.collect_owned();

    let mut present = journal.query();
    present.match_present("MESSAGE").limit(4);
    let _ = present.collect_owned();

    let mut exact = journal.query();
    exact.match_exact("MESSAGE", b"hello").limit(4);
    let _ = exact.collect_owned();

    let mut unit = journal.query();
    unit.match_unit("sshd.service").limit(4);
    let _ = unit.collect_owned();

    let mut or_units = journal.query();
    or_units.or_group(|g| {
        g.match_exact("_SYSTEMD_UNIT", b"sshd.service");
    });
    or_units.or_group(|g| {
        g.match_exact("_SYSTEMD_UNIT", b"systemd-journald.service");
    });
    or_units.limit(4);
    let _ = or_units.collect_owned();

    if let Some(first) = tail_entries.first()
        && let Ok(cursor) = first.cursor()
    {
        let _ = journal.seek_cursor(&cursor).and_then(|mut q| {
            q.limit(2);
            q.collect_owned()
        });

        let mut after = journal.query();
        after.after_cursor(cursor).limit(2);
        let _ = after.collect_owned();
    }
}

fn exercise_open_paths(layout: &ReusableJournalLayout, include_journal_tilde: bool) {
    let cfg = sdjournal::JournalConfig {
        include_journal_tilde,
        max_object_size_bytes: 4 * 1024 * 1024,
        max_decompressed_bytes: 1024 * 1024,
        ..Default::default()
    };

    if let Ok(journal) = sdjournal::Journal::open_dir_with_config(layout.root(), cfg.clone()) {
        exercise_queries(&journal);
    }
    if let Ok(journal) = sdjournal::Journal::open_dir_with_config(layout.machine_dir(), cfg.clone())
    {
        exercise_queries(&journal);
    }

    let duplicate_roots = vec![layout.root().to_path_buf(), layout.root().to_path_buf()];
    if let Ok(journal) = sdjournal::Journal::open_dirs_with_config(&duplicate_roots, cfg.clone()) {
        exercise_queries(&journal);
    }

    let merged_roots = vec![
        layout.root().to_path_buf(),
        layout.machine_dir().to_path_buf(),
    ];
    if let Ok(journal) = sdjournal::Journal::open_dirs_with_config(&merged_roots, cfg) {
        exercise_queries(&journal);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let layout = match reusable_journal_layout() {
        Some(layout) => layout,
        None => return,
    };

    let root_bytes = minimal_journal_bytes(data);
    let machine_bytes = minimal_journal_bytes(&variant_bytes(data, 0x5a));
    let tilde_bytes = minimal_journal_bytes(&variant_bytes(data, 0xa5));

    if !layout.rewrite_all(&root_bytes, &machine_bytes, &tilde_bytes) {
        return;
    }

    exercise_open_paths(layout, false);
    exercise_open_paths(layout, true);
});
