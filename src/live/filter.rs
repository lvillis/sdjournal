use crate::config::JournalConfig;
use crate::entry::{EntryOwned, EntryRef};
use crate::error::{LimitKind, Result, SdJournalError};
use crate::util::is_ascii_field_name;

#[derive(Debug, Clone)]
pub(super) enum MatchTerm {
    Exact { field: String, value: Vec<u8> },
    Present { field: String },
}

#[derive(Debug, Clone)]
pub(super) struct CompiledFilter {
    pub(super) branches: Vec<Vec<MatchTerm>>,
}

impl CompiledFilter {
    pub(super) fn matches<E: MatchableEntry>(&self, entry: &E) -> bool {
        self.branches
            .iter()
            .any(|branch| branch.iter().all(|term| term_matches(entry, term)))
    }
}

pub(super) trait MatchableEntry {
    fn get_field(&self, field: &str) -> Option<&[u8]>;
    fn any_field_equals(&self, field: &str, value: &[u8]) -> bool;
}

impl MatchableEntry for EntryOwned {
    fn get_field(&self, field: &str) -> Option<&[u8]> {
        self.get(field)
    }

    fn any_field_equals(&self, field: &str, value: &[u8]) -> bool {
        self.iter_fields()
            .any(|(name, field_value)| name == field && field_value == value)
    }
}

impl MatchableEntry for EntryRef {
    fn get_field(&self, field: &str) -> Option<&[u8]> {
        self.get(field)
    }

    fn any_field_equals(&self, field: &str, value: &[u8]) -> bool {
        self.iter_fields()
            .any(|(name, field_value)| name == field && field_value == value)
    }
}

/// In-memory filter builder for live subscriptions.
///
/// The filter DSL mirrors the historical query builder, but it only describes live matching
/// predicates. Time bounds and cursor resumes are configured through
/// [`crate::SubscriptionOptions`].
///
/// Direct terms are AND-ed together. Each [`LiveFilter::or_group`] call adds one alternative
/// branch whose terms are also AND-ed together.
#[derive(Clone)]
pub struct LiveFilter {
    config: JournalConfig,
    global_terms: Vec<MatchTerm>,
    or_groups: Vec<Vec<MatchTerm>>,
    invalid_reason: Option<String>,
    too_many_terms: bool,
}

impl LiveFilter {
    pub(crate) fn new(config: JournalConfig) -> Self {
        Self {
            config,
            global_terms: Vec::new(),
            or_groups: Vec::new(),
            invalid_reason: None,
            too_many_terms: false,
        }
    }

    /// Match entries whose field equals `value` byte-for-byte.
    ///
    /// Multiple terms added directly to a filter are AND-ed together. Validation is deferred until
    /// the filter is registered with [`crate::LiveJournal::subscribe`] or
    /// [`crate::LiveJournal::subscribe_with_options`].
    pub fn match_exact(&mut self, field: &str, value: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.count_terms() >= self.config.max_query_terms {
            self.too_many_terms = true;
            return self;
        }

        self.global_terms.push(MatchTerm::Exact {
            field: field.to_string(),
            value: value.to_vec(),
        });
        self
    }

    /// Match entries that contain `field`, regardless of its value.
    ///
    /// Multiple terms added directly to a filter are AND-ed together. Validation is deferred until
    /// the filter is registered with [`crate::LiveJournal::subscribe`] or
    /// [`crate::LiveJournal::subscribe_with_options`].
    pub fn match_present(&mut self, field: &str) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }
        if let Err(e) = validate_field_name(field, &self.config) {
            self.invalid_reason = Some(e.to_string());
            return self;
        }
        if self.count_terms() >= self.config.max_query_terms {
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
    /// This expands to an OR over `_SYSTEMD_UNIT`, `UNIT`, and `OBJECT_SYSTEMD_UNIT`.
    pub fn match_unit(&mut self, unit: &str) -> &mut Self {
        self.match_unit_bytes(unit.as_bytes())
    }

    /// Same as [`LiveFilter::match_unit`], but accepts raw unit bytes.
    pub fn match_unit_bytes(&mut self, unit: &[u8]) -> &mut Self {
        if self.invalid_reason.is_some() {
            return self;
        }

        let max_terms = self.config.max_query_terms;
        let global_len = self.global_terms.len();
        let new_total_terms = if self.or_groups.is_empty() {
            global_len.saturating_add(3)
        } else {
            let old_group_terms = self.or_groups.iter().map(Vec::len).sum::<usize>();
            let old_groups = self.or_groups.len();
            global_len
                .saturating_add(old_group_terms.saturating_mul(3))
                .saturating_add(old_groups.saturating_mul(3))
        };

        if new_total_terms > max_terms {
            self.too_many_terms = true;
            return self;
        }

        fn unit_term(field: &str, unit: &[u8]) -> MatchTerm {
            MatchTerm::Exact {
                field: field.to_string(),
                value: unit.to_vec(),
            }
        }

        let unit_fields = ["_SYSTEMD_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT"];

        if self.or_groups.is_empty() {
            self.or_groups = unit_fields
                .iter()
                .map(|field| vec![unit_term(field, unit)])
                .collect();
            return self;
        }

        let mut next = Vec::with_capacity(self.or_groups.len().saturating_mul(3));
        for group in &self.or_groups {
            for field in unit_fields {
                let mut branch = group.clone();
                branch.push(unit_term(field, unit));
                next.push(branch);
            }
        }
        self.or_groups = next;
        self
    }

    /// Add an OR-group to the filter.
    ///
    /// Each call creates one OR branch. Terms added inside the closure are AND-ed together within
    /// that branch. Empty groups are ignored.
    ///
    /// ```no_run
    /// # use sdjournal::LiveJournal;
    /// let mut live = LiveJournal::open_default()?;
    /// let mut filter = live.filter();
    /// filter
    ///     .match_present("MESSAGE")
    ///     .or_group(|g| {
    ///         g.match_exact("_SYSTEMD_UNIT", b"sshd.service");
    ///     })
    ///     .or_group(|g| {
    ///         g.match_exact("_SYSTEMD_UNIT", b"systemd.service");
    ///     });
    /// let _subscription = live.subscribe(filter)?;
    /// # Ok::<(), sdjournal::SdJournalError>(())
    /// ```
    pub fn or_group<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut LiveOrGroupBuilder),
    {
        if self.invalid_reason.is_some() {
            return self;
        }

        let remaining = self
            .config
            .max_query_terms
            .saturating_sub(self.count_terms());
        let mut builder = LiveOrGroupBuilder {
            terms: Vec::new(),
            config: self.config.clone(),
            invalid_reason: None,
            too_many_terms: false,
            remaining,
        };
        f(&mut builder);
        if let Some(reason) = builder.invalid_reason {
            self.invalid_reason = Some(reason);
            return self;
        }
        if builder.too_many_terms {
            self.too_many_terms = true;
            return self;
        }
        if !builder.terms.is_empty() {
            self.or_groups.push(builder.terms);
        }
        self
    }

    pub(super) fn compile(&self) -> Result<CompiledFilter> {
        self.validate()?;
        Ok(CompiledFilter {
            branches: build_branches(self),
        })
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
                limit: u64::try_from(self.config.max_query_terms).unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }

    fn count_terms(&self) -> usize {
        let mut n = self.global_terms.len();
        for group in &self.or_groups {
            n = n.saturating_add(group.len());
        }
        n
    }
}

/// Builder used inside [`LiveFilter::or_group`].
///
/// Multiple terms added to the same builder are AND-ed together.
pub struct LiveOrGroupBuilder {
    terms: Vec<MatchTerm>,
    config: JournalConfig,
    invalid_reason: Option<String>,
    too_many_terms: bool,
    remaining: usize,
}

impl LiveOrGroupBuilder {
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

        self.terms.push(MatchTerm::Exact {
            field: field.to_string(),
            value: value.to_vec(),
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

fn validate_field_name(field: &str, config: &JournalConfig) -> Result<()> {
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

fn build_branches(filter: &LiveFilter) -> Vec<Vec<MatchTerm>> {
    if filter.or_groups.is_empty() {
        return vec![filter.global_terms.clone()];
    }

    let mut out = Vec::with_capacity(filter.or_groups.len());
    for group in &filter.or_groups {
        let mut branch = filter.global_terms.clone();
        branch.extend_from_slice(group);
        out.push(branch);
    }
    out
}

fn term_matches<E: MatchableEntry>(entry: &E, term: &MatchTerm) -> bool {
    match term {
        MatchTerm::Exact { field, value } => entry.any_field_equals(field, value.as_slice()),
        MatchTerm::Present { field } => entry.get_field(field).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> EntryOwned {
        EntryOwned::new(
            [0x11; 16],
            7,
            9,
            11,
            13,
            [0x22; 16],
            vec![
                ("MESSAGE".to_string(), b"hello".to_vec()),
                ("_SYSTEMD_UNIT".to_string(), b"sshd.service".to_vec()),
                ("UNIT".to_string(), b"sshd.service".to_vec()),
            ],
        )
    }

    #[test]
    fn live_filter_match_unit_matches_common_unit_fields() {
        let mut filter = LiveFilter::new(JournalConfig::default());
        filter.match_unit("sshd.service");
        let compiled = filter.compile().expect("filter should compile");

        assert!(compiled.matches(&sample_entry()));
    }

    #[test]
    fn live_filter_or_group_matches_existing_branch_style() {
        let mut filter = LiveFilter::new(JournalConfig::default());
        filter.match_present("MESSAGE");
        filter.or_group(|group| {
            group.match_exact("PRIORITY", b"3");
        });
        filter.or_group(|group| {
            group.match_exact("_SYSTEMD_UNIT", b"sshd.service");
        });
        let compiled = filter.compile().expect("filter should compile");

        assert!(compiled.matches(&sample_entry()));
    }

    #[test]
    fn term_matches_handles_exact_and_present_terms() {
        let entry = sample_entry();

        assert!(term_matches(
            &entry,
            &MatchTerm::Exact {
                field: "MESSAGE".to_string(),
                value: b"hello".to_vec(),
            }
        ));
        assert!(term_matches(
            &entry,
            &MatchTerm::Present {
                field: "_SYSTEMD_UNIT".to_string(),
            }
        ));
        assert!(!term_matches(
            &entry,
            &MatchTerm::Exact {
                field: "MESSAGE".to_string(),
                value: b"missing".to_vec(),
            }
        ));
    }
}
