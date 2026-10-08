//! Queue-owned payloads and local callback routing, not transport authentication.
use super::*;
use crate::batch::BorrowedBatch;
use std::sync::atomic::{AtomicU64, Ordering};
static INSTANCES: AtomicU64 = AtomicU64::new(1);
pub(super) fn next_instance() -> Result<u64, QueueError> {
    INSTANCES
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| QueueError::Ownership)
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeliveryBinding {
    instance: u64,
    generation: u64,
}
impl fmt::Debug for DeliveryBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliveryBinding")
    }
}
pub(super) struct Frozen {
    pub(super) entries: Vec<Entry>,
    wire: Vec<u8>,
    pub(super) digest: [u8; 32],
    id: String,
    created: Timestamp,
    deadline: OffsetDateTime,
    pub(super) binding: DeliveryBinding,
    in_flight: bool,
}
/// Immutable borrowed data. Freshness is checked when issued, not during later I/O.
pub struct FrozenView<'a> {
    frozen: &'a Frozen,
}
impl fmt::Debug for FrozenView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FrozenView")
    }
}
impl FrozenView<'_> {
    pub fn batch_id(&self) -> &str {
        &self.frozen.id
    }
    pub fn wire(&self) -> &[u8] {
        &self.frozen.wire
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.frozen.digest
    }
    pub fn deadline(&self) -> OffsetDateTime {
        self.frozen.deadline
    }
    pub fn created_at(&self) -> &Timestamp {
        &self.frozen.created
    }
    pub fn record_count(&self) -> usize {
        self.frozen.entries.len()
    }
    pub fn binding(&self) -> DeliveryBinding {
        self.frozen.binding
    }
}
/// Parsed receipt plus request routing evidence supplied by trusted transport.
/// Syntax/binding checks are not authentication or proof of server commitment.
pub struct Acknowledgement<'a> {
    binding: DeliveryBinding,
    identity: [&'a str; 2],
    batch_id: &'a str,
    digest: &'a [u8; 32],
    receipt_id: &'a str,
    accepted_at: &'a Timestamp,
}
impl fmt::Debug for Acknowledgement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Acknowledgement")
    }
}
impl<'a> Acknowledgement<'a> {
    pub fn from_transport(
        binding: DeliveryBinding,
        identity: [&'a str; 2],
        batch_id: &'a str,
        digest: &'a [u8; 32],
        receipt_id: &'a str,
        accepted_at: &'a Timestamp,
    ) -> Result<Self, QueueError> {
        if identity
            .iter()
            .chain([batch_id, receipt_id].iter())
            .any(|id| !crate::policy::uuid(id))
        {
            return Err(QueueError::Receipt);
        }
        Ok(Self {
            binding,
            identity,
            batch_id,
            digest,
            receipt_id,
            accepted_at,
        })
    }
}
impl MemoryQueue {
    /// Freeze a FIFO prefix without releasing record charges. Supplied IDs must
    /// be unique for different content; syntax checks do not generate random IDs.
    pub fn freeze(
        &mut self,
        batch_id: &str,
        maximum_records: usize,
        inputs: &AdmissionInputs<'_>,
    ) -> Result<Option<FrozenView<'_>>, QueueError> {
        let now = self.now()?;
        self.freeze_at(batch_id, maximum_records, inputs, now)?;
        let now = self.now()?;
        self.reconcile_at(inputs, now)?;
        Ok(self.frozen.as_ref().map(|frozen| FrozenView { frozen }))
    }
    /// Prepare/retry the exact owned payload. In-flight data remains fully charged.
    /// The caller must authenticate transport and cancel actual I/O on invalidation.
    pub fn delivery_view(
        &mut self,
        inputs: &AdmissionInputs<'_>,
    ) -> Result<Option<FrozenView<'_>>, QueueError> {
        let now = self.now()?;
        self.delivery_at(inputs, now)
    }
    pub fn acknowledge(&mut self, receipt: Acknowledgement<'_>) -> Result<(), QueueError> {
        let frozen = self.frozen.as_ref().ok_or(QueueError::Ownership)?;
        if !frozen.in_flight
            || frozen.binding != receipt.binding
            || frozen.id != receipt.batch_id
            || frozen.digest != *receipt.digest
            || receipt
                .identity
                .iter()
                .copied()
                .ne(self.identity.iter().map(String::as_str))
        {
            return Err(QueueError::Receipt);
        }
        // These are checked receipt metadata, not an authenticated Boolean shortcut.
        if !crate::policy::uuid(receipt.receipt_id)
            || Timestamp::parse(receipt.accepted_at.as_str()).is_err()
        {
            return Err(QueueError::Receipt);
        }
        self.stats.acknowledged = self
            .stats
            .acknowledged
            .saturating_add(frozen.entries.len() as u64);
        self.frozen = None;
        self.recount();
        Ok(())
    }
    pub fn discard_frozen(&mut self, binding: DeliveryBinding) -> Result<(), QueueError> {
        if self
            .frozen
            .as_ref()
            .is_none_or(|frozen| frozen.binding != binding)
        {
            return Err(QueueError::Ownership);
        }
        let frozen = self.frozen.take().ok_or(QueueError::Ownership)?;
        self.stats.purged = self
            .stats
            .purged
            .saturating_add(frozen.entries.len() as u64);
        self.recount();
        Ok(())
    }
    pub(super) fn freeze_at(
        &mut self,
        batch_id: &str,
        maximum_records: usize,
        inputs: &AdmissionInputs<'_>,
        now: OffsetDateTime,
    ) -> Result<(), QueueError> {
        if !crate::policy::uuid(batch_id) || !(1..=500).contains(&maximum_records) {
            return Err(QueueError::Limits);
        }
        if self.frozen.is_some() {
            return Err(QueueError::Ownership);
        }
        self.reconcile_at(inputs, now)?;
        if self.entries.is_empty() {
            return Ok(());
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(QueueError::Ownership)?;
        let count = maximum_records.min(self.entries.len());
        let created = Timestamp::from_instant(now).map_err(|_| QueueError::Clock)?;
        let records = self
            .entries
            .iter()
            .take(count)
            .map(|entry| &entry.record.record)
            .collect::<Vec<_>>();
        let batch = BorrowedBatch::new(
            batch_id,
            [&self.identity[0], &self.identity[1]],
            &created,
            &records,
        )
        .map_err(|_| QueueError::Record)?;
        let length = batch.length().map_err(|_| QueueError::Record)?;
        let quota = self.limits.bytes.min(inputs.current.queue_bytes() as usize);
        if self
            .stats
            .bytes
            .checked_add(length)
            .is_none_or(|total| total > quota)
        {
            return Err(QueueError::Full);
        }
        // Exclusive ownership reserves this exact additional retained buffer first.
        let digest = batch.digest().map_err(|_| QueueError::Record)?;
        let wire = batch.encode().map_err(|_| QueueError::Record)?;
        if wire.len() != length {
            return Err(QueueError::Record);
        }
        let entries = self.entries.drain(..count).collect::<Vec<_>>();
        let deadline = entries
            .iter()
            .map(|entry| entry.record.expires_at().instant())
            .min()
            .ok_or(QueueError::Record)?;
        self.generation = generation;
        self.frozen = Some(Frozen {
            entries,
            wire,
            digest,
            id: batch_id.to_owned(),
            created,
            deadline,
            binding: DeliveryBinding {
                instance: self.instance,
                generation,
            },
            in_flight: false,
        });
        self.recount();
        Ok(())
    }
    pub(super) fn delivery_at(
        &mut self,
        inputs: &AdmissionInputs<'_>,
        now: OffsetDateTime,
    ) -> Result<Option<FrozenView<'_>>, QueueError> {
        self.reconcile_at(inputs, now)?;
        if let Some(frozen) = &mut self.frozen {
            frozen.in_flight = true;
        }
        Ok(self.frozen.as_ref().map(|frozen| FrozenView { frozen }))
    }
    pub(super) fn recount(&mut self) {
        let retained = self
            .entries
            .iter()
            .chain(self.frozen.iter().flat_map(|frozen| frozen.entries.iter()));
        self.stats.records = self.entries.len()
            + self
                .frozen
                .as_ref()
                .map_or(0, |frozen| frozen.entries.len());
        self.stats.bytes = retained.map(|entry| entry.charge).sum::<usize>()
            + self.frozen.as_ref().map_or(0, |frozen| frozen.wire.len());
    }
    pub(super) fn cancel_frozen(&mut self, now: OffsetDateTime) {
        if let Some(frozen) = self.frozen.take() {
            for entry in frozen.entries {
                if entry.record.expires_at().instant() <= now {
                    self.stats.expired = self.stats.expired.saturating_add(1);
                } else {
                    self.stats.purged = self.stats.purged.saturating_add(1);
                }
            }
        }
    }
    pub(super) fn reconcile_frozen(&mut self, inputs: &AdmissionInputs<'_>, now: OffsetDateTime) {
        if self.frozen.as_ref().is_some_and(|frozen| {
            now < frozen.created.instant() - Duration::minutes(5)
                || frozen.entries.iter().any(|entry| {
                    validate_record(
                        &entry.record.record,
                        inputs,
                        entry.record.queued_at().instant(),
                        entry.record.expires_at().instant(),
                        now,
                    )
                    .is_err()
                })
        }) {
            self.cancel_frozen(now);
        }
    }
}
