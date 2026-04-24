use crate::cursor::Cursor;
use crate::error::Result;
use crate::reader::ByteBuf;
use std::ops::Deref;
use std::sync::Arc;

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

/// A shared live entry delivered by [`crate::LiveSubscription`].
///
/// This wraps an [`EntryRef`] in reference counting so one decoded journal entry can be dispatched
/// to multiple live subscribers without duplicating all field storage.
#[derive(Debug, Clone)]
pub struct LiveEntry(Arc<EntryRef>);

impl LiveEntry {
    pub(crate) fn new(entry: EntryRef) -> Self {
        Self(Arc::new(entry))
    }

    /// Convert this shared live entry into an owned entry.
    pub fn into_owned(self) -> EntryOwned {
        self.0.as_ref().to_owned()
    }
}

impl Deref for LiveEntry {
    type Target = EntryRef;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl AsRef<EntryRef> for LiveEntry {
    fn as_ref(&self) -> &EntryRef {
        self.0.as_ref()
    }
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

    pub(crate) fn entry_offset_raw(&self) -> u64 {
        self.entry_offset
    }

    pub(crate) fn file_id_raw(&self) -> [u8; 16] {
        self.file_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_owned_get_prefers_first_duplicate_and_iter_preserves_order() {
        let entry = EntryOwned::new(
            [0x11; 16],
            7,
            9,
            11,
            13,
            [0x22; 16],
            vec![
                ("MESSAGE".to_string(), b"first".to_vec()),
                ("PRIORITY".to_string(), b"6".to_vec()),
                ("MESSAGE".to_string(), b"second".to_vec()),
            ],
        );

        assert_eq!(entry.get("MESSAGE"), Some(&b"first"[..]));
        let fields: Vec<(&str, &[u8])> = entry.iter_fields().collect();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0], ("MESSAGE", &b"first"[..]));
        assert_eq!(fields[1], ("PRIORITY", &b"6"[..]));
        assert_eq!(fields[2], ("MESSAGE", &b"second"[..]));
        assert_eq!(entry.realtime_usec(), 11);
        assert_eq!(entry.monotonic_usec(), 13);
        assert_eq!(entry.seqnum(), 9);
        assert_eq!(entry.boot_id(), [0x22; 16]);
    }

    #[test]
    fn entry_ref_to_owned_preserves_visible_fields_and_cursor() {
        let entry = EntryRef::new_parsed(
            [0x33; 16],
            17,
            19,
            23,
            29,
            [0x44; 16],
            vec![
                (
                    "MESSAGE".to_string(),
                    ByteBuf::from_vec(b"MESSAGE=hello".to_vec()),
                    7,
                ),
                (
                    "PRIORITY".to_string(),
                    ByteBuf::from_vec(b"PRIORITY=5".to_vec()),
                    8,
                ),
            ],
        );

        let owned = entry.to_owned();
        assert_eq!(entry.get("MESSAGE"), Some(&b"hello"[..]));
        assert_eq!(owned.get("MESSAGE"), Some(&b"hello"[..]));
        assert_eq!(owned.get("PRIORITY"), Some(&b"5"[..]));
        assert_eq!(
            entry.cursor().unwrap().to_string(),
            owned.cursor().unwrap().to_string()
        );
        assert_eq!(owned.realtime_usec(), 23);
        assert_eq!(owned.monotonic_usec(), 29);
        assert_eq!(owned.seqnum(), 19);
        assert_eq!(owned.boot_id(), [0x44; 16]);
    }
}
