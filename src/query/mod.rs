mod cursor;
mod execute;

use crate::cursor::Cursor;
use crate::entry::{EntryOwned, EntryRef};
use crate::error::{LimitKind, Result, SdJournalError};
use crate::follow::Follow;
use crate::journal::Journal;
use crate::util::is_ascii_field_name;

use self::execute::JournalIter;

#[derive(Debug, Clone)]
enum MatchTerm {
    Exact {
        field: String,
        value: Vec<u8>,
        payload: Vec<u8>,
    },
    Present {
        field: String,
    },
}

/// A query builder for reading entries from a [`Journal`].
///
/// `JournalQuery` is mutable and chainable: each builder method updates the query in place and
/// returns `&mut Self`.
///
/// Validation for field names and query-term limits is intentionally deferred. Builder methods
/// record validation failures internally, and terminal methods such as [`JournalQuery::iter`],
/// [`JournalQuery::collect_owned`], and [`JournalQuery::follow`] surface them as
/// [`SdJournalError`] values.
#[derive(Clone)]
pub struct JournalQuery {
    journal: Journal,

    global_terms: Vec<MatchTerm>,
    or_groups: Vec<Vec<MatchTerm>>,

    since_realtime: Option<u64>,
    until_realtime: Option<u64>,
    cursor_start: Option<(Cursor, bool)>, // (cursor, inclusive)
    reverse: bool,
    limit: Option<usize>,
    invalid_reason: Option<String>,
    too_many_terms: bool,
}

impl JournalQuery {
    pub(crate) fn new(journal: Journal) -> Self {
        Self {
            journal,
            global_terms: Vec::new(),
            or_groups: Vec::new(),
            since_realtime: None,
            until_realtime: None,
            cursor_start: None,
            reverse: false,
            limit: None,
            invalid_reason: None,
            too_many_terms: false,
        }
    }

    /// Match entries whose field equals `value` byte-for-byte.
    ///
    /// Field-name validation is deferred until a terminal method is called.
    pub fn match_exact(&mut self, field: &str, value: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.journal.inner.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.count_terms() >= self.journal.inner.config.max_query_terms {
            self.too_many_terms = true;
            return self;
        }

        let mut payload =
            Vec::with_capacity(field.len().saturating_add(1).saturating_add(value.len()));
        payload.extend_from_slice(field.as_bytes());
        payload.push(b'=');
        payload.extend_from_slice(value);

        self.global_terms.push(MatchTerm::Exact {
            field: field.to_string(),
            value: value.to_vec(),
            payload,
        });
        self
    }

    /// Match entries that contain `field`, regardless of its value.
    ///
    /// Field-name validation is deferred until a terminal method is called.
    pub fn match_present(&mut self, field: &str) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.journal.inner.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.count_terms() >= self.journal.inner.config.max_query_terms {
            self.too_many_terms = true;
            return self;
        }

        self.global_terms.push(MatchTerm::Present {
            field: field.to_string(),
        });
        self
    }

    /// Match entries for a specific systemd unit.
    ///
    /// This expands to an OR over common unit fields:
    /// `(_SYSTEMD_UNIT=unit) OR (UNIT=unit) OR (OBJECT_SYSTEMD_UNIT=unit)`.
    ///
    /// The resulting unit filter is AND-ed with any existing query terms.
    pub fn match_unit(&mut self, unit: &str) -> &mut Self {
        self.match_unit_bytes(unit.as_bytes())
    }

    /// Same as [`JournalQuery::match_unit`], but accepts the unit name as raw bytes.
    pub fn match_unit_bytes(&mut self, unit: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }

        let max_terms = self.journal.inner.config.max_query_terms;
        let global_len = self.global_terms.len();
        let new_total_terms = if self.or_groups.is_empty() {
            global_len.saturating_add(3)
        } else {
            let mut old_groups_terms = 0usize;
            for g in &self.or_groups {
                old_groups_terms = old_groups_terms.saturating_add(g.len());
            }
            let old_groups = self.or_groups.len();

            // Distribute a 3-way OR across existing OR branches:
            // (G1 OR G2 OR ...) AND (U1 OR U2 OR U3)
            // => (G1+U1) OR (G1+U2) OR (G1+U3) OR (G2+U1) ...
            global_len
                .saturating_add(old_groups_terms.saturating_mul(3))
                .saturating_add(old_groups.saturating_mul(3))
        };

        if new_total_terms > max_terms {
            self.too_many_terms = true;
            return self;
        }

        fn unit_term(field: &str, unit: &[u8]) -> MatchTerm {
            let mut payload =
                Vec::with_capacity(field.len().saturating_add(1).saturating_add(unit.len()));
            payload.extend_from_slice(field.as_bytes());
            payload.push(b'=');
            payload.extend_from_slice(unit);
            MatchTerm::Exact {
                field: field.to_string(),
                value: unit.to_vec(),
                payload,
            }
        }

        let unit_terms = ["_SYSTEMD_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT"];

        if self.or_groups.is_empty() {
            self.or_groups = unit_terms
                .iter()
                .map(|f| vec![unit_term(f, unit)])
                .collect();
            return self;
        }

        let mut next = Vec::with_capacity(self.or_groups.len().saturating_mul(3));
        for group in &self.or_groups {
            for field in unit_terms {
                let mut g = group.clone();
                g.push(unit_term(field, unit));
                next.push(g);
            }
        }
        self.or_groups = next;
        self
    }

    /// Add an OR-group to the query.
    ///
    /// Terms added inside the closure are OR-ed together, then AND-ed with the rest of the query.
    /// Empty groups are ignored.
    ///
    /// This is useful for queries such as:
    ///
    /// `(_PID=1 OR _UID=0) AND _SYSTEMD_UNIT=sshd.service`
    pub fn or_group<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut OrGroupBuilder),
    {
        if self.invalid_reason.is_some() {
            return self;
        }
        let remaining = self
            .journal
            .inner
            .config
            .max_query_terms
            .saturating_sub(self.count_terms());
        let mut b = OrGroupBuilder {
            terms: Vec::new(),
            config: self.journal.inner.config.clone(),
            invalid_reason: None,
            too_many_terms: false,
            remaining,
        };
        f(&mut b);
        if let Some(r) = b.invalid_reason {
            self.invalid_reason = Some(r);
            return self;
        }
        if b.too_many_terms {
            self.too_many_terms = true;
            return self;
        }
        if !b.terms.is_empty() {
            self.or_groups.push(b.terms);
        }
        self
    }

    /// Set an inclusive lower realtime bound in microseconds since the Unix epoch.
    pub fn since_realtime(&mut self, usec: u64) -> &mut Self {
        self.since_realtime = Some(usec);
        self
    }

    /// Set an inclusive upper realtime bound in microseconds since the Unix epoch.
    pub fn until_realtime(&mut self, usec: u64) -> &mut Self {
        self.until_realtime = Some(usec);
        self
    }

    /// Resume strictly after `cursor`.
    ///
    /// Unlike [`Journal::seek_cursor`], this excludes the entry identified by `cursor`.
    pub fn after_cursor(&mut self, cursor: Cursor) -> &mut Self {
        self.cursor_start = Some((cursor, false));
        self
    }

    /// Seek to the start of the journal (oldest entries).
    ///
    /// This clears any cursor-based starting position and disables `reverse`.
    pub fn seek_head(&mut self) -> &mut Self {
        self.cursor_start = None;
        self.reverse = false;
        self
    }

    /// Seek to the end of the journal (newest entries).
    ///
    /// This clears any cursor-based starting position and enables `reverse`.
    pub fn seek_tail(&mut self) -> &mut Self {
        self.cursor_start = None;
        self.reverse = true;
        self
    }

    /// Control whether results are returned newest-first instead of oldest-first.
    ///
    /// `false` is the default.
    pub fn reverse(&mut self, reverse: bool) -> &mut Self {
        self.reverse = reverse;
        self
    }

    /// Limit the number of returned entries.
    ///
    /// Passing `0` produces an empty iterator.
    pub fn limit(&mut self, n: usize) -> &mut Self {
        self.limit = Some(n);
        self
    }

    /// Validate the query and create a streaming iterator of matching entries.
    ///
    /// The iterator yields [`EntryRef`] values, which borrow or share underlying journal storage
    /// when possible.
    pub fn iter(&self) -> Result<impl Iterator<Item = Result<EntryRef>> + use<>> {
        self.validate()?;
        JournalIter::new(self.clone())
    }

    /// Collect all matching entries into owned values.
    ///
    /// This is a convenience wrapper around [`JournalQuery::iter`] plus
    /// [`EntryRef::to_owned`](crate::EntryRef::to_owned).
    pub fn collect_owned(&self) -> Result<Vec<EntryOwned>> {
        let mut out = Vec::new();
        for item in self.iter()? {
            let entry = item?;
            out.push(entry.to_owned());
        }
        Ok(out)
    }

    /// Create a blocking follow iterator.
    ///
    /// `follow()` first drains any matching backlog, then reopens the journal roots and waits for
    /// newly appended matching entries.
    ///
    /// # Errors
    ///
    /// Returns [`SdJournalError::InvalidQuery`] if the query uses unsupported follow-only states,
    /// such as `reverse=true` or `until_realtime`.
    pub fn follow(&self) -> Result<Follow> {
        self.validate()?;
        self.validate_follow()?;

        let roots = self.journal.inner.roots.clone();
        let config = self.journal.inner.config.clone();

        let live_journal = Journal::open_dirs_with_config(&roots, config.clone())?;
        let mut template = self.with_journal(live_journal.clone());
        template.limit = None;

        let mut catchup_query = self.with_journal(live_journal);
        let mut last_cursor: Option<Cursor> = None;

        let has_lower_bound = self.cursor_start.is_some() || self.since_realtime.is_some();
        if !has_lower_bound {
            let mut tail_probe = template.clone();
            tail_probe.reverse(true);
            tail_probe.limit(1);

            for item in tail_probe.iter()? {
                match item {
                    Ok(entry) => {
                        let c = entry.cursor()?;
                        catchup_query.set_cursor_start(c.clone(), false)?;
                        last_cursor = Some(c);
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }

        let catchup_iter: Box<dyn Iterator<Item = Result<EntryRef>> + Send> =
            Box::new(catchup_query.iter()?);
        Ok(Follow::new(
            roots,
            config,
            template,
            catchup_iter,
            last_cursor,
        ))
    }

    /// Create an async follow adapter for Tokio.
    ///
    /// This spawns a background thread that drives [`JournalQuery::follow`] and forwards owned
    /// entries through a Tokio channel.
    #[cfg(feature = "tokio")]
    pub fn follow_tokio(&self) -> Result<crate::follow::TokioFollow> {
        Ok(crate::follow::TokioFollow::spawn(self.follow()?))
    }

    pub(crate) fn set_cursor_start(&mut self, cursor: Cursor, inclusive: bool) -> Result<()> {
        self.cursor_start = Some((cursor, inclusive));
        Ok(())
    }

    pub(crate) fn with_journal(&self, journal: Journal) -> Self {
        let mut q = self.clone();
        q.journal = journal;
        q
    }

    fn validate(&self) -> Result<()> {
        if let Some(reason) = &self.invalid_reason {
            return Err(SdJournalError::InvalidQuery {
                reason: reason.clone(),
            });
        }
        if self.too_many_terms {
            return Err(SdJournalError::LimitExceeded {
                kind: LimitKind::QueryTerms,
                limit: u64::try_from(self.journal.inner.config.max_query_terms).unwrap_or(u64::MAX),
            });
        }

        if let (Some(since), Some(until)) = (self.since_realtime, self.until_realtime)
            && since > until
        {
            return Err(SdJournalError::InvalidQuery {
                reason: "since_realtime must be <= until_realtime".to_string(),
            });
        }

        Ok(())
    }

    fn validate_follow(&self) -> Result<()> {
        if self.reverse {
            return Err(SdJournalError::InvalidQuery {
                reason: "follow() requires reverse=false".to_string(),
            });
        }
        if self.until_realtime.is_some() {
            return Err(SdJournalError::InvalidQuery {
                reason: "follow() does not allow until_realtime".to_string(),
            });
        }
        Ok(())
    }

    fn count_terms(&self) -> usize {
        let mut n = self.global_terms.len();
        for g in &self.or_groups {
            n = n.saturating_add(g.len());
        }
        n
    }
}

/// Builder used inside [`JournalQuery::or_group`].
///
/// This type is usually used only from the closure passed to [`JournalQuery::or_group`].
pub struct OrGroupBuilder {
    terms: Vec<MatchTerm>,
    config: crate::config::JournalConfig,
    invalid_reason: Option<String>,
    too_many_terms: bool,
    remaining: usize,
}

impl OrGroupBuilder {
    /// Add an exact field match to this OR-group.
    pub fn match_exact(&mut self, field: &str, value: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.terms.len() >= self.remaining {
            self.too_many_terms = true;
            return self;
        }
        let mut payload =
            Vec::with_capacity(field.len().saturating_add(1).saturating_add(value.len()));
        payload.extend_from_slice(field.as_bytes());
        payload.push(b'=');
        payload.extend_from_slice(value);

        self.terms.push(MatchTerm::Exact {
            field: field.to_string(),
            value: value.to_vec(),
            payload,
        });
        self
    }

    /// Add a field-presence match to this OR-group.
    pub fn match_present(&mut self, field: &str) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.terms.len() >= self.remaining {
            self.too_many_terms = true;
            return self;
        }
        self.terms.push(MatchTerm::Present {
            field: field.to_string(),
        });
        self
    }
}

fn validate_field_name(field: &str, config: &crate::config::JournalConfig) -> Result<()> {
    if field.len() > config.max_field_name_len {
        return Err(SdJournalError::InvalidQuery {
            reason: "field name too long".to_string(),
        });
    }
    if !is_ascii_field_name(field.as_bytes()) {
        return Err(SdJournalError::InvalidQuery {
            reason: "field name must be ASCII and must not contain '='".to_string(),
        });
    }
    Ok(())
}

fn build_branches(query: &JournalQuery) -> Vec<Vec<MatchTerm>> {
    if query.or_groups.is_empty() {
        return vec![query.global_terms.clone()];
    }

    let mut out = Vec::with_capacity(query.or_groups.len());
    for group in &query.or_groups {
        let mut terms = query.global_terms.clone();
        terms.extend_from_slice(group);
        out.push(terms);
    }
    out
}

fn term_matches(entry: &EntryOwned, term: &MatchTerm) -> bool {
    match term {
        MatchTerm::Exact { field, value, .. } => entry
            .iter_fields()
            .any(|(k, v)| k == field.as_str() && v == value.as_slice()),
        MatchTerm::Present { field } => entry.get(field).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JournalConfig;
    use crate::journal::JournalInner;
    use std::sync::Arc;

    fn empty_journal_with_config(config: JournalConfig) -> Journal {
        Journal {
            inner: Arc::new(JournalInner {
                config,
                roots: Vec::new(),
                files: Vec::new(),
            }),
        }
    }

    #[test]
    fn invalid_field_name_rejected_on_iter() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.match_exact("BAD=FIELD", b"x");
        match q.iter() {
            Ok(_) => panic!("expected InvalidQuery"),
            Err(err) => assert!(matches!(err, SdJournalError::InvalidQuery { .. })),
        }
    }

    #[test]
    fn too_many_terms_rejected_on_iter() {
        let cfg = JournalConfig {
            max_query_terms: 1,
            ..Default::default()
        };
        let journal = empty_journal_with_config(cfg);
        let mut q = JournalQuery::new(journal);
        q.match_present("A");
        q.match_present("B");
        match q.iter() {
            Ok(_) => panic!("expected QueryTerms limit error"),
            Err(err) => assert!(matches!(
                err,
                SdJournalError::LimitExceeded {
                    kind: LimitKind::QueryTerms,
                    ..
                }
            )),
        }
    }

    #[test]
    fn match_unit_builds_three_or_branches() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.match_present("PRIORITY");
        q.match_unit("sshd.service");

        assert_eq!(q.or_groups.len(), 3);
        let branches = build_branches(&q);
        assert_eq!(branches.len(), 3);
        for b in &branches {
            assert_eq!(b.len(), 2);
            assert!(matches!(&b[0], MatchTerm::Present { field } if field == "PRIORITY"));
        }

        let unit_fields: std::collections::BTreeSet<&str> = branches
            .iter()
            .map(|b| match &b[1] {
                MatchTerm::Exact {
                    field,
                    value,
                    payload,
                } => {
                    assert_eq!(value, b"sshd.service");
                    let expected = [field.as_bytes(), b"=", value.as_slice()].concat();
                    assert_eq!(payload, &expected);
                    field.as_str()
                }
                _ => panic!("expected exact unit match term"),
            })
            .collect();
        assert_eq!(
            unit_fields,
            std::collections::BTreeSet::from(["_SYSTEMD_UNIT", "OBJECT_SYSTEMD_UNIT", "UNIT"])
        );
    }

    #[test]
    fn match_unit_distributes_over_existing_or_groups() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.or_group(|g| {
            g.match_present("A");
        });
        q.or_group(|g| {
            g.match_present("B");
        });
        q.match_unit("foo.service");

        assert_eq!(q.or_groups.len(), 6);
        for g in &q.or_groups {
            assert_eq!(g.len(), 2);
            assert!(matches!(&g[0], MatchTerm::Present { .. }));
            assert!(matches!(&g[1], MatchTerm::Exact { .. }));
        }

        let mut a = 0usize;
        let mut b = 0usize;
        for g in &q.or_groups {
            match &g[0] {
                MatchTerm::Present { field } if field == "A" => a += 1,
                MatchTerm::Present { field } if field == "B" => b += 1,
                _ => panic!("unexpected first term"),
            }
        }
        assert_eq!(a, 3);
        assert_eq!(b, 3);
    }

    #[test]
    fn match_unit_respects_max_query_terms() {
        let cfg = JournalConfig {
            max_query_terms: 2,
            ..Default::default()
        };
        let journal = empty_journal_with_config(cfg);
        let mut q = JournalQuery::new(journal);
        q.match_unit("sshd.service");

        assert!(q.too_many_terms);
        assert!(q.or_groups.is_empty());
    }

    #[test]
    fn since_realtime_must_not_exceed_until_realtime() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.since_realtime(20);
        q.until_realtime(10);

        match q.iter() {
            Ok(_) => panic!("expected InvalidQuery"),
            Err(err) => assert!(matches!(err, SdJournalError::InvalidQuery { .. })),
        }
    }

    #[test]
    fn follow_rejects_reverse_queries() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.reverse(true);

        match q.follow() {
            Ok(_) => panic!("expected InvalidQuery"),
            Err(err) => assert!(matches!(err, SdJournalError::InvalidQuery { .. })),
        }
    }

    #[test]
    fn follow_rejects_until_realtime_queries() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.until_realtime(42);

        match q.follow() {
            Ok(_) => panic!("expected InvalidQuery"),
            Err(err) => assert!(matches!(err, SdJournalError::InvalidQuery { .. })),
        }
    }

    #[test]
    fn seek_head_clears_cursor_start_and_disables_reverse() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.after_cursor(Cursor::parse("t=42").unwrap());
        q.reverse(true);

        q.seek_head();

        assert!(q.cursor_start.is_none());
        assert!(!q.reverse);
    }

    #[test]
    fn seek_tail_clears_cursor_start_and_enables_reverse() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.after_cursor(Cursor::parse("t=42").unwrap());

        q.seek_tail();

        assert!(q.cursor_start.is_none());
        assert!(q.reverse);
    }

    #[test]
    fn limit_zero_produces_empty_iterator() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.limit(0);

        let mut it = q.iter().expect("iter should succeed");
        assert!(it.next().is_none());
    }

    #[test]
    fn or_group_invalid_field_name_rejected_on_iter() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.or_group(|g| {
            g.match_exact("BAD=FIELD", b"x");
        });

        match q.iter() {
            Ok(_) => panic!("expected InvalidQuery"),
            Err(err) => assert!(matches!(err, SdJournalError::InvalidQuery { .. })),
        }
    }

    #[test]
    fn or_group_respects_remaining_term_budget() {
        let cfg = JournalConfig {
            max_query_terms: 1,
            ..Default::default()
        };
        let journal = empty_journal_with_config(cfg);
        let mut q = JournalQuery::new(journal);
        q.match_present("A");
        q.or_group(|g| {
            g.match_present("B");
        });

        match q.iter() {
            Ok(_) => panic!("expected QueryTerms limit error"),
            Err(err) => assert!(matches!(
                err,
                SdJournalError::LimitExceeded {
                    kind: LimitKind::QueryTerms,
                    ..
                }
            )),
        }
    }

    #[test]
    fn empty_or_group_is_ignored() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);

        q.or_group(|_| {});

        assert!(q.or_groups.is_empty());
        assert!(q.global_terms.is_empty());
    }

    #[test]
    fn after_cursor_sets_exclusive_start() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        let cursor = Cursor::parse("t=42").unwrap();

        q.after_cursor(cursor.clone());

        match &q.cursor_start {
            Some((saved, inclusive)) => {
                assert_eq!(saved.to_string(), cursor.to_string());
                assert!(!inclusive);
            }
            None => panic!("expected cursor_start to be set"),
        }
    }

    #[test]
    fn build_branches_without_or_groups_uses_global_terms_only() {
        let journal = empty_journal_with_config(JournalConfig::default());
        let mut q = JournalQuery::new(journal);
        q.match_present("PRIORITY");

        let branches = build_branches(&q);
        assert_eq!(branches.len(), 1);
        assert!(matches!(
            &branches[0][0],
            MatchTerm::Present { field } if field == "PRIORITY"
        ));
    }

    #[test]
    fn term_matches_handles_exact_and_present_terms() {
        let entry = EntryOwned::new(
            [0x11; 16],
            7,
            9,
            11,
            13,
            [0x22; 16],
            vec![
                ("MESSAGE".to_string(), b"hello".to_vec()),
                ("PRIORITY".to_string(), b"6".to_vec()),
            ],
        );

        assert!(term_matches(
            &entry,
            &MatchTerm::Exact {
                field: "MESSAGE".to_string(),
                value: b"hello".to_vec(),
                payload: b"MESSAGE=hello".to_vec(),
            }
        ));
        assert!(!term_matches(
            &entry,
            &MatchTerm::Exact {
                field: "MESSAGE".to_string(),
                value: b"nope".to_vec(),
                payload: b"MESSAGE=nope".to_vec(),
            }
        ));
        assert!(term_matches(
            &entry,
            &MatchTerm::Present {
                field: "PRIORITY".to_string(),
            }
        ));
        assert!(!term_matches(
            &entry,
            &MatchTerm::Present {
                field: "SYSLOG_IDENTIFIER".to_string(),
            }
        ));
    }

    #[test]
    fn field_name_length_limit_is_inclusive() {
        let cfg = JournalConfig {
            max_field_name_len: 3,
            ..Default::default()
        };
        let journal = empty_journal_with_config(cfg);
        let mut q = JournalQuery::new(journal);

        q.match_present("ABC");
        assert!(q.invalid_reason.is_none());

        q.match_present("ABCD");
        assert_eq!(
            q.invalid_reason.as_deref(),
            Some("invalid query: field name too long")
        );
    }
}
