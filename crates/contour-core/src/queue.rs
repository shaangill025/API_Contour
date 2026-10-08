//! Single-owner sanitized retention and frozen ownership. Snapshots remain caller authority.
use crate::admission::validate_record;
use crate::{AdmissionError, AdmissionInputs, CheckedRecord, RecordDraft, Timestamp};
use std::{
    collections::VecDeque,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};
use time::{Duration, OffsetDateTime};
mod frozen;
pub use frozen::{Acknowledgement, DeliveryBinding, DeliveryReservation, FrozenView};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    Limits,
    Identity,
    Revision,
    Revoked,
    Clock,
    Full,
    Record,
    Ownership,
    Receipt,
    Admission(AdmissionError),
}
impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QueueError {}
#[derive(Clone, Copy, Debug)]
pub struct QueueLimits {
    records: usize,
    bytes: usize,
}
impl QueueLimits {
    pub fn new(records: usize, bytes: usize) -> Result<Self, QueueError> {
        if !(1..=500).contains(&records) || !(1..=268_435_456).contains(&bytes) {
            return Err(QueueError::Limits);
        }
        Ok(Self { records, bytes })
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueStats {
    pub records: usize,
    /// Three per-record wire allowances, reserved up front for retained records,
    /// frozen serialization and one transport copy. Not resident memory usage.
    pub bytes: usize,
    pub dropped: u64,
    /// Pending records individually exceeding an explicit pre-send wire bound.
    pub oversized: u64,
    pub expired: u64,
    pub purged: u64,
    pub rejected: u64,
    pub acknowledged: u64,
}
struct Entry {
    record: CheckedRecord,
    // Base C bounds this record's wire contribution including envelope slack.
    base_allowance: usize,
    // Admission reserves checked 3C before retaining records or future copies.
    charge: usize,
}
/// Not enrollment, online freshness, persistent anti-rollback or authenticated I/O.
pub struct MemoryQueue {
    identity: [String; 2],
    limits: QueueLimits,
    entries: VecDeque<Entry>,
    stats: QueueStats,
    high_water: Option<(u64, [u8; 32])>,
    revoked: bool,
    frozen: Option<frozen::Frozen>,
    instance: u64,
    generation: u64,
}
impl fmt::Debug for MemoryQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryQueue")
    }
}
impl MemoryQueue {
    pub fn new(identity: [&str; 2], limits: QueueLimits) -> Result<Self, QueueError> {
        if identity.iter().any(|id| !crate::policy::uuid(id)) {
            return Err(QueueError::Identity);
        }
        Ok(Self {
            identity: identity.map(str::to_owned),
            limits,
            entries: VecDeque::new(),
            stats: QueueStats::default(),
            high_water: None,
            revoked: false,
            frozen: None,
            instance: frozen::next_instance()?,
            generation: 0,
        })
    }
    pub fn stats(&self) -> QueueStats {
        self.stats
    }
    /// Borrow checked IDs and original retention timestamps in FIFO order:
    /// frozen records first, then pending, each exactly once (at most 500).
    /// Inspection neither reconciles authority/expiry nor grants capture or send.
    pub fn retained_record_times(&self) -> impl Iterator<Item = (&str, &Timestamp, &Timestamp)> {
        self.frozen
            .iter()
            .flat_map(|frozen| frozen.entries.iter())
            .chain(self.entries.iter())
            .map(|entry| {
                (
                    entry.record.record.record_id(),
                    entry.record.queued_at(),
                    entry.record.expires_at(),
                )
            })
    }
    /// Irreversible for this object. No transfer or reactivation API exists.
    pub fn revoke(&mut self) {
        self.revoked = true;
        self.purge();
    }
    pub fn reconcile(&mut self, inputs: &AdmissionInputs<'_>) -> Result<(), QueueError> {
        let now = self.now()?;
        self.reconcile_at(inputs, now)
    }
    /// Only drafts are accepted. Declared queue timestamps cannot enter this API.
    pub fn admit(
        &mut self,
        draft: RecordDraft,
        inputs: &AdmissionInputs<'_>,
    ) -> Result<(), QueueError> {
        self.admit_with(draft, inputs, wall_clock)
    }
    fn now(&mut self) -> Result<OffsetDateTime, QueueError> {
        self.clock_result(wall_clock())
    }
    fn clock_result(
        &mut self,
        result: Result<OffsetDateTime, QueueError>,
    ) -> Result<OffsetDateTime, QueueError> {
        result.map_err(|error| {
            self.purge();
            self.reject(error)
        })
    }
    fn reject(&mut self, error: QueueError) -> QueueError {
        self.stats.rejected = self.stats.rejected.saturating_add(1);
        error
    }
    fn purge(&mut self) {
        self.stats.purged = self.stats.purged.saturating_add(self.stats.records as u64);
        self.entries.clear();
        self.frozen = None;
        self.stats.records = 0;
        self.stats.bytes = 0;
    }
    /// Delete expired retained records without granting capture/send authority.
    /// Useful while paused for authorized renewal; does not renew timestamps,
    /// alter identity/high-water evidence, or make a revoked queue usable.
    pub fn expire_retained(&mut self) -> Result<(), QueueError> {
        let now = self.now()?;
        self.expire_retained_at(now);
        Ok(())
    }
    fn expire_retained_at(&mut self, now: OffsetDateTime) {
        if self.frozen.as_ref().is_some_and(|batch| {
            batch
                .entries
                .iter()
                .any(|entry| entry.record.expires_at().instant() <= now)
        }) {
            self.cancel_frozen(now);
        }
        self.entries.retain(|entry| {
            if entry.record.expires_at().instant() <= now {
                self.stats.expired = self.stats.expired.saturating_add(1);
                false
            } else {
                true
            }
        });
        self.recount();
    }
    fn reconcile_at(
        &mut self,
        inputs: &AdmissionInputs<'_>,
        now: OffsetDateTime,
    ) -> Result<(), QueueError> {
        let gate = self.guard(inputs, now);
        if let Err(error) = gate {
            self.purge();
            return Err(self.reject(error));
        }
        self.reconcile_frozen(inputs, now);
        let mut kept = VecDeque::new();
        while let Some(entry) = self.entries.pop_front() {
            if entry.record.expires_at().instant() <= now {
                self.stats.expired = self.stats.expired.saturating_add(1);
            } else if validate_record(
                &entry.record.record,
                inputs,
                entry.record.queued_at().instant(),
                entry.record.expires_at().instant(),
                now,
            )
            .is_err()
            {
                self.stats.purged = self.stats.purged.saturating_add(1);
            } else {
                kept.push_back(entry);
            }
        }
        self.entries = kept;
        let bytes = self.limits.bytes.min(inputs.current.queue_bytes() as usize);
        self.recount();
        if self.stats.bytes > bytes && self.frozen.is_some() {
            self.cancel_frozen(now);
            self.recount();
        }
        while self.stats.bytes > bytes {
            let entry = self.entries.pop_front().expect("nonempty charged queue");
            self.stats.bytes -= entry.charge;
            self.stats.purged = self.stats.purged.saturating_add(1);
        }
        self.recount();
        Ok(())
    }
    fn guard(
        &mut self,
        inputs: &AdmissionInputs<'_>,
        now: OffsetDateTime,
    ) -> Result<(), QueueError> {
        if self.revoked {
            return Err(QueueError::Revoked);
        }
        if inputs
            .identity
            .iter()
            .copied()
            .ne(self.identity.iter().map(String::as_str))
        {
            return Err(QueueError::Identity);
        }
        let revision = inputs.current.revision();
        let content = inputs.current.content_digest();
        if let Some((previous, digest)) = self.high_water {
            if revision < previous || revision == previous && digest != content {
                return Err(QueueError::Revision);
            }
        }
        // Preserve this even when the signed update is disabled or has since expired.
        self.high_water = Some((revision, content));
        inputs
            .current
            .validate_capture_at(now)
            .map_err(|_| QueueError::Admission(AdmissionError::Time))
    }
    fn admit_with(
        &mut self,
        draft: RecordDraft,
        inputs: &AdmissionInputs<'_>,
        mut clock: impl FnMut() -> Result<OffsetDateTime, QueueError>,
    ) -> Result<(), QueueError> {
        let initial = self.clock_result(clock())?;
        self.reconcile_at(inputs, initial)?;
        if draft.record.policy_revision.get() != inputs.current.revision() {
            return Err(self.reject(QueueError::Revision));
        }
        let lifetime = Duration::seconds(inputs.current.ttl() as i64);
        let expiry = initial
            .checked_add(lifetime)
            .ok_or_else(|| self.reject(QueueError::Clock))?;
        validate_record(&draft.record, inputs, initial, expiry, initial)
            .map_err(|error| self.reject(QueueError::Admission(error)))?;
        if self
            .entries
            .iter()
            .chain(self.frozen.iter().flat_map(|frozen| frozen.entries.iter()))
            .any(|entry| entry.record.record.record_id() == draft.record.record_id())
        {
            return Err(self.reject(QueueError::Record));
        }
        let base_allowance = draft
            .retention_charge()
            .map_err(|_| self.reject(QueueError::Record))?;
        let charge = base_allowance
            .checked_mul(3)
            .ok_or_else(|| self.reject(QueueError::Limits))?;
        let bytes = self.limits.bytes.min(inputs.current.queue_bytes() as usize);
        if self.stats.records >= self.limits.records
            || self
                .stats
                .bytes
                .checked_add(charge)
                .is_none_or(|total| total > bytes)
        {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Err(QueueError::Full);
        }
        // Capacity is reserved by this exclusive borrow; no other owner can consume it.
        let queued = self.clock_result(clock())?;
        if queued < initial {
            self.purge();
            return Err(self.reject(QueueError::Clock));
        }
        // Time may have advanced across bounded validation/serialization work.
        // Reconcile again so known current expiry cannot leave old data retained.
        self.reconcile_at(inputs, queued)?;
        let expiry = queued
            .checked_add(lifetime)
            .ok_or_else(|| self.reject(QueueError::Clock))?;
        validate_record(&draft.record, inputs, queued, expiry, queued)
            .map_err(|error| self.reject(QueueError::Admission(error)))?;
        let queued = Timestamp::from_instant(queued).map_err(|_| self.reject(QueueError::Clock))?;
        let expires =
            Timestamp::from_instant(expiry).map_err(|_| self.reject(QueueError::Clock))?;
        let record = draft
            .declare_queue_times(queued, expires)
            .map_err(|_| self.reject(QueueError::Record))?;
        self.entries.push_back(Entry {
            record,
            base_allowance,
            charge,
        });
        self.recount();
        Ok(())
    }
}
fn wall_clock() -> Result<OffsetDateTime, QueueError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| QueueError::Clock)?;
    let nanos = i128::try_from(elapsed.as_nanos()).map_err(|_| QueueError::Clock)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| QueueError::Clock)
}
#[cfg(test)]
#[path = "../tests/queue/mod.rs"]
mod tests;
