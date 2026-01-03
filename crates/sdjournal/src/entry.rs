use crate::cursor::Cursor;
use crate::error::Result;
use crate::reader::ByteBuf;

/// An owned journal entry, suitable for caching, cross-thread use, or async contexts.
#[derive(Debug, Clone)]
pub struct EntryOwned {
    pub(crate) file_id: [u8; 16],
    pub(crate) entry_offset: u64,
    seqnum: u64,
    realtime_usec: u64,
    monotonic_usec: u64,
    boot_id: [u8; 16],
    fields_in_order: Vec<(String, Vec<u8>)>,
}

impl EntryOwned {
    pub(crate) fn new(
        file_id: [u8; 16],
        entry_offset: u64,
        seqnum: u64,
        realtime_usec: u64,
        monotonic_usec: u64,
        boot_id: [u8; 16],
        fields_in_order: Vec<(String, Vec<u8>)>,
    ) -> Self {
        Self {
            file_id,
            entry_offset,
            seqnum,
            realtime_usec,
            monotonic_usec,
            boot_id,
            fields_in_order,
        }
    }

    /// Return the entry cursor.
    pub fn cursor(&self) -> Result<Cursor> {
        Ok(Cursor::new_entry_key(
            self.file_id,
            self.entry_offset,
            self.seqnum,
            self.realtime_usec,
        ))
    }

    /// Get the first occurrence of a field.
    pub fn get(&self, field: &str) -> Option<&[u8]> {
        self.fields_in_order
            .iter()
            .find(|(k, _)| k == field)
            .map(|(_, v)| v.as_slice())
    }

    /// Iterate over all fields (including duplicates) in entry order.
    pub fn iter_fields(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.fields_in_order
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// Realtime timestamp, microseconds since UNIX epoch.
    pub fn realtime_usec(&self) -> u64 {
        self.realtime_usec
    }

    /// Monotonic timestamp, microseconds since boot.
    pub fn monotonic_usec(&self) -> u64 {
        self.monotonic_usec
    }

    /// Boot ID for this entry.
    pub fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }

    /// Sequence number for this entry.
    pub fn seqnum(&self) -> u64 {
        self.seqnum
    }
}

#[derive(Debug, Clone)]
struct FieldRef {
    name: String,
    payload: ByteBuf,
    eq_pos: usize,
}

impl FieldRef {
    fn value(&self) -> &[u8] {
        let payload = self.payload.as_slice();
        payload.get(self.eq_pos.saturating_add(1)..).unwrap_or(&[])
    }
}

/// A zero-copy entry view, backed by journal file storage (mmap) when possible.
#[derive(Debug, Clone)]
pub struct EntryRef {
    file_id: [u8; 16],
    entry_offset: u64,
    seqnum: u64,
    realtime_usec: u64,
    monotonic_usec: u64,
    boot_id: [u8; 16],
    fields_in_order: Vec<FieldRef>,
}

impl EntryRef {
    pub(crate) fn new_parsed(
        file_id: [u8; 16],
        entry_offset: u64,
        seqnum: u64,
        realtime_usec: u64,
        monotonic_usec: u64,
        boot_id: [u8; 16],
        fields_in_order: Vec<(String, ByteBuf, usize)>,
    ) -> Self {
        let fields_in_order = fields_in_order
            .into_iter()
            .map(|(name, payload, eq_pos)| FieldRef {
                name,
                payload,
                eq_pos,
            })
            .collect();

        Self {
            file_id,
            entry_offset,
            seqnum,
            realtime_usec,
            monotonic_usec,
            boot_id,
            fields_in_order,
        }
    }

    /// Convert this entry to an owned representation.
    pub fn to_owned(&self) -> EntryOwned {
        let mut fields = Vec::with_capacity(self.fields_in_order.len());
        for f in &self.fields_in_order {
            fields.push((f.name.clone(), f.value().to_vec()));
        }

        EntryOwned::new(
            self.file_id,
            self.entry_offset,
            self.seqnum,
            self.realtime_usec,
            self.monotonic_usec,
            self.boot_id,
            fields,
        )
    }

    /// Return the entry cursor.
    pub fn cursor(&self) -> Result<Cursor> {
        Ok(Cursor::new_entry_key(
            self.file_id,
            self.entry_offset,
            self.seqnum,
            self.realtime_usec,
        ))
    }

    /// Get the first occurrence of a field.
    pub fn get(&self, field: &str) -> Option<&[u8]> {
        self.fields_in_order
            .iter()
            .find(|f| f.name == field)
            .map(|f| f.value())
    }

    /// Iterate over all fields (including duplicates) in entry order.
    pub fn iter_fields(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.fields_in_order
            .iter()
            .map(|f| (f.name.as_str(), f.value()))
    }

    /// Realtime timestamp, microseconds since UNIX epoch.
    pub fn realtime_usec(&self) -> u64 {
        self.realtime_usec
    }

    /// Monotonic timestamp, microseconds since boot.
    pub fn monotonic_usec(&self) -> u64 {
        self.monotonic_usec
    }

    /// Boot ID for this entry.
    pub fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }

    /// Sequence number for this entry.
    pub fn seqnum(&self) -> u64 {
        self.seqnum
    }
}
