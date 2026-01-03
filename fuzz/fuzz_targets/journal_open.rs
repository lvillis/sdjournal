#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write as _;

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

fuzz_target!(|data: &[u8]| {
    if data.len() > 2 * 1024 * 1024 {
        return;
    }

    let mut bytes = data.to_vec();
    if bytes.len() < 272 {
        bytes.resize(272, 0);
    }

    // Force a plausible journal header so we exercise more parsing code paths.
    bytes[0..8].copy_from_slice(b"LPKSHHRH");

    // Keep incompatible_flags within the set that sdjournal understands.
    let incompatible = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) & 0x1f;
    write_le_u32(&mut bytes, 12, incompatible);

    // header_size and arena_size must be consistent with file length.
    let header_size = 272u64;
    let arena_size = (bytes.len() as u64).saturating_sub(header_size);
    write_le_u64(&mut bytes, 88, header_size);
    write_le_u64(&mut bytes, 96, arena_size);

    // Create a temp directory with a single *.journal file.
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let path = dir.path().join("fuzz.journal");
    let mut f = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    if f.write_all(&bytes).is_err() {
        return;
    }

    let cfg = sdjournal::JournalConfig {
        max_object_size_bytes: 4 * 1024 * 1024,
        max_decompressed_bytes: 1024 * 1024,
        ..Default::default()
    };

    let journal = match sdjournal::Journal::open_dir_with_config(dir.path(), cfg) {
        Ok(j) => j,
        Err(_) => return,
    };

    let _ = journal.query().limit(8).collect_owned();

    let mut q = journal.query();
    q.reverse(true);
    q.limit(8);
    let _ = q.collect_owned();
});

