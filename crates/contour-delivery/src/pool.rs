//! Fixed-owner pool. It never transfers authority or waits in capture callbacks.
use super::{CaptureId, CollectorOwner, OwnerError, SendOutcome};
use contour_core::{AdmissionInputs, CaptureScope, RecordMetadata};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{
        Arc, Mutex as Gate,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
};
use tokio::sync::{Mutex, Notify};

#[derive(Clone, Copy, Debug)]
pub struct PoolCapture {
    slot: usize,
    epoch: u64,
    id: CaptureId,
}

#[cfg(test)]
mod tests {
    use super::super::capture_tests::{make_owner, scope};
    use super::*;

    #[test]
    fn active_capture_is_not_displaced_by_send_or_another_stream() {
        let pool = CollectorPool::new(vec![make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let token = pool.try_begin(&scope()).unwrap();
        assert!(pool.try_begin(&scope()).is_err());
        pool.try_fragment(token, br#"{"id":1}"#).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(runtime.block_on(pool.send(0)).is_err());
        assert!(
            pool.try_freeze(0, "00000000-0000-4000-8000-000000000001", 1, 10000)
                .is_err()
        );
        pool.try_cancel(token);
        assert!(pool.try_begin(&scope()).is_ok());
    }

    #[test]
    fn observed_expiry_pauses_pool_and_clears_all_raw_streams() {
        let pool = CollectorPool::new(vec![make_owner(), make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let first = pool.try_begin(&scope()).unwrap();
        let second = pool.try_begin(&scope()).unwrap();
        pool.try_fragment(first, b"secret").unwrap();
        pool.try_fragment(second, b"secret").unwrap();
        pool.slots[1]
            .try_lock()
            .unwrap()
            .live
            .as_mut()
            .unwrap()
            .deadline = tokio::time::Instant::now();
        assert!(pool.try_fragment(first, b"more").is_err());
        assert!(!pool.enabled.load(Ordering::Acquire));
        assert!(
            pool.slots
                .iter()
                .all(|slot| slot.try_lock().unwrap().streams.is_empty())
        );
    }

    #[test]
    fn finish_rejects_metadata_that_does_not_match_captured_scope() {
        let pool = CollectorPool::new(vec![make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let token = pool.try_begin(&scope()).unwrap();
        pool.try_fragment(token, br#"{"id":1}"#).unwrap();
        let now = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
        let s = scope();
        let metadata = RecordMetadata {
            record_id: s.source_id,
            source_id: s.source_id,
            workload: s.workload,
            protocol: "http",
            direction: "request",
            visibility: "application",
            operation: s.operation,
            route_template: "/other",
            route_uncertain: false,
            parser_profile: s.parser_profile,
            policy_revision: 1,
            count: 1,
            first_seen: now.clone(),
            last_seen: now,
            sample_numerator: 1,
            sample_denominator: 1,
            status_code: None,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        };
        assert!(pool.try_finish(token, metadata).is_err());
        assert_eq!(pool.slots[0].try_lock().unwrap().stats().records, 0);
    }
}
/// The pool owns all slots; no owner handle escapes to the forwarding adapter.
pub struct CollectorPool {
    slots: Vec<Mutex<CollectorOwner>>,
    enabled: AtomicBool,
    epoch: AtomicU64,
    sync: Mutex<()>,
    cancel: Notify,
    gate: Gate<()>,
    losses: AtomicU64,
}
impl CollectorPool {
    pub fn new(owners: Vec<CollectorOwner>) -> Result<Arc<Self>, OwnerError> {
        if owners.is_empty() || owners.len() > 8 {
            return Err(OwnerError::Paused);
        }
        let first = &owners[0];
        if owners
            .iter()
            .any(|o| o.client.identity != first.client.identity || o.source_ids != first.source_ids)
        {
            return Err(OwnerError::Paused);
        }
        Ok(Arc::new(Self {
            slots: owners.into_iter().map(Mutex::new).collect(),
            enabled: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            sync: Mutex::new(()),
            cancel: Notify::new(),
            gate: Gate::new(()),
            losses: AtomicU64::new(0),
        }))
    }
    pub fn losses(&self) -> u64 {
        self.losses.load(Ordering::Relaxed)
    }
    /// Reclaim raw streams after an idle lease expires. A runtime must call
    /// this periodically in addition to the checks on capture operations.
    pub fn poll_authority(&self) -> Result<(), OwnerError> {
        let _gate = self.gate.try_lock().map_err(|_| OwnerError::Paused)?;
        if !self.enabled.load(Ordering::Acquire) {
            return Err(OwnerError::Paused);
        }
        self.check_live()
    }
    fn lose(&self) {
        self.losses.fetch_add(1, Ordering::Relaxed);
    }
    fn current(&self, epoch: u64) -> bool {
        self.enabled.load(Ordering::Acquire) && self.epoch.load(Ordering::Acquire) == epoch
    }
    // Called with the coordinator gate held. A slot held by send has no raw
    // stream; every other slot can be examined and reclaimed without waiting.
    fn check_live(&self) -> Result<(), OwnerError> {
        let expired = self
            .slots
            .iter()
            .any(|slot| slot.try_lock().is_ok_and(|owner| !owner.is_live()));
        if !expired {
            return Ok(());
        }
        self.enabled.store(false, Ordering::Release);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        for slot in &self.slots {
            if let Ok(mut owner) = slot.try_lock() {
                owner.streams.clear();
            }
        }
        self.cancel.notify_waiters();
        Err(OwnerError::Paused)
    }
    /// Stop capture immediately, interrupt active owned send futures, await every
    /// owner lock, then obtain common live signed authority and aggregate quota.
    pub async fn synchronize(&self) -> Result<(), OwnerError> {
        let epoch = {
            let _gate = self.gate.lock().map_err(|_| OwnerError::Paused)?;
            self.enabled.store(false, Ordering::Release);
            let epoch = self
                .epoch
                .fetch_add(1, Ordering::AcqRel)
                .checked_add(1)
                .ok_or(OwnerError::Paused)?;
            // A busy owner can only be an in-flight send, which never holds raw captures.
            for slot in &self.slots {
                if let Ok(mut owner) = slot.try_lock() {
                    owner.streams.clear();
                }
            }
            epoch
        };
        self.cancel.notify_waiters();
        let _sync = self.sync.lock().await;
        let mut guards = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            guards.push(slot.lock().await);
        }
        for owner in &mut guards {
            owner.streams.clear();
            owner.refresh().await?;
        }
        let first = guards.first().ok_or(OwnerError::Paused)?;
        let policy = &first.policies.last().ok_or(OwnerError::Paused)?.policy;
        let total = guards
            .iter()
            .try_fold(0usize, |sum, owner| {
                sum.checked_add(owner.configured_queue_bytes)
            })
            .ok_or(OwnerError::Paused)?;
        if total as u64 > policy.queue_bytes() {
            return Err(OwnerError::Paused);
        }
        for owner in &guards {
            let current = &owner.policies.last().ok_or(OwnerError::Paused)?.policy;
            if !owner.is_live()
                || current.revision() != policy.revision()
                || total as u64 > current.queue_bytes()
                || AdmissionInputs::new(
                    first.client.identity.each_ref().map(String::as_str),
                    current,
                    &[policy],
                    &[],
                )
                .is_err()
            {
                return Err(OwnerError::Paused);
            }
        }
        if self.epoch.load(Ordering::Acquire) != epoch {
            return Err(OwnerError::Paused);
        }
        let _gate = self.gate.lock().map_err(|_| OwnerError::Paused)?;
        if self.epoch.load(Ordering::Acquire) != epoch {
            return Err(OwnerError::Paused);
        }
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }
    pub fn try_begin(&self, scope: &CaptureScope<'_>) -> Result<PoolCapture, OwnerError> {
        let _gate = self.gate.try_lock().map_err(|_| {
            self.lose();
            OwnerError::Paused
        })?;
        let epoch = self.epoch.load(Ordering::Acquire);
        if !self.current(epoch) {
            self.lose();
            return Err(OwnerError::Paused);
        }
        self.check_live()?;
        for (slot, mutex) in self.slots.iter().enumerate() {
            if let Ok(mut owner) = mutex.try_lock() {
                if !self.current(epoch) {
                    self.lose();
                    return Err(OwnerError::Paused);
                }
                // Reserve one owner per stream so a busy request cannot monopolize
                // all capture slots or be displaced by a background send.
                if !owner.streams.is_empty() {
                    continue;
                }
                if let Ok(id) = owner.begin_capture(scope) {
                    return Ok(PoolCapture { slot, epoch, id });
                }
            }
        }
        self.lose();
        Err(OwnerError::Paused)
    }
    pub fn try_fragment(&self, token: PoolCapture, bytes: &[u8]) -> Result<(), OwnerError> {
        let _gate = self.gate.try_lock().map_err(|_| {
            self.lose();
            OwnerError::Paused
        })?;
        if !self.current(token.epoch) {
            self.lose();
            return Err(OwnerError::Paused);
        }
        self.check_live()?;
        let Some(slot) = self.slots.get(token.slot) else {
            self.lose();
            return Err(OwnerError::Paused);
        };
        let Ok(mut owner) = slot.try_lock() else {
            self.lose();
            return Err(OwnerError::Paused);
        };
        if !self.current(token.epoch) {
            owner.cancel_capture(token.id);
            self.lose();
            return Err(OwnerError::Paused);
        }
        let result = owner.capture_fragment(token.id, bytes).map_err(|e| {
            self.lose();
            e
        });
        drop(owner);
        self.check_live()?;
        result
    }
    pub fn try_finish(
        &self,
        token: PoolCapture,
        metadata: RecordMetadata<'_>,
    ) -> Result<(), OwnerError> {
        let _gate = self.gate.try_lock().map_err(|_| {
            self.lose();
            OwnerError::Paused
        })?;
        if !self.current(token.epoch) {
            self.lose();
            return Err(OwnerError::Paused);
        }
        self.check_live()?;
        let Some(slot) = self.slots.get(token.slot) else {
            self.lose();
            return Err(OwnerError::Paused);
        };
        let Ok(mut owner) = slot.try_lock() else {
            self.lose();
            return Err(OwnerError::Paused);
        };
        if !self.current(token.epoch) {
            owner.cancel_capture(token.id);
            self.lose();
            return Err(OwnerError::Paused);
        }
        let result = owner.finish_and_admit(token.id, metadata);
        drop(owner);
        self.check_live()?;
        result.map_err(|e| {
            self.lose();
            e
        })
    }
    pub fn try_cancel(&self, token: PoolCapture) {
        let Ok(_gate) = self.gate.try_lock() else {
            self.lose();
            return;
        };
        if let Some(slot) = self.slots.get(token.slot) {
            if let Ok(mut owner) = slot.try_lock() {
                owner.cancel_capture(token.id);
            }
        }
    }
    pub fn try_freeze(
        &self,
        slot: usize,
        batch_id: &str,
        maximum_records: usize,
        maximum_wire_bytes: usize,
    ) -> Result<bool, OwnerError> {
        let _gate = self.gate.try_lock().map_err(|_| OwnerError::Paused)?;
        let epoch = self.epoch.load(Ordering::Acquire);
        if !self.current(epoch) {
            return Err(OwnerError::Paused);
        }
        let mut owner = self
            .slots
            .get(slot)
            .ok_or(OwnerError::Paused)?
            .try_lock()
            .map_err(|_| OwnerError::Paused)?;
        if !owner.streams.is_empty() {
            return Err(OwnerError::Paused);
        }
        owner.freeze(batch_id, maximum_records, maximum_wire_bytes)
    }
    /// Background only: owner remains in its mutex if cancellation drops the
    /// send future, preserving frozen IDs and releasing transport owners first.
    pub async fn send(&self, slot: usize) -> Result<SendOutcome, OwnerError> {
        let epoch = self.epoch.load(Ordering::Acquire);
        if !self.current(epoch) {
            return Err(OwnerError::Paused);
        }
        let mut owner = {
            let _gate = self.gate.try_lock().map_err(|_| OwnerError::Paused)?;
            let owner = self
                .slots
                .get(slot)
                .ok_or(OwnerError::Paused)?
                .try_lock()
                .map_err(|_| OwnerError::Paused)?;
            if !self.current(epoch) || !owner.streams.is_empty() {
                return Err(OwnerError::Paused);
            }
            owner
        };
        let notify = self.cancel.notified();
        let mut notify = pin!(notify);
        let send = owner.send_once();
        let mut send = pin!(send);
        poll_fn(|cx| {
            if !self.current(epoch) || notify.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(OwnerError::Paused));
            }
            send.as_mut().poll(cx)
        })
        .await
    }
    /// Advance the existing retry controller without losing the frozen owner.
    /// Cancellation releases this borrow and leaves the same payload retained.
    pub async fn wait_retry(&self, slot: usize) -> Result<crate::WaitOutcome, OwnerError> {
        let epoch = self.epoch.load(Ordering::Acquire);
        if !self.current(epoch) {
            return Err(OwnerError::Paused);
        }
        let mut owner = {
            let _gate = self.gate.try_lock().map_err(|_| OwnerError::Paused)?;
            let owner = self
                .slots
                .get(slot)
                .ok_or(OwnerError::Paused)?
                .try_lock()
                .map_err(|_| OwnerError::Paused)?;
            if !self.current(epoch) || !owner.streams.is_empty() {
                return Err(OwnerError::Paused);
            }
            owner
        };
        let notify = self.cancel.notified();
        let mut notify = pin!(notify);
        let cancel = poll_fn(|cx| {
            if !self.current(epoch) || notify.as_mut().poll(cx).is_ready() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });
        let result = owner.wait_retry(cancel).await;
        if !self.current(epoch) {
            return Err(OwnerError::Paused);
        }
        result
    }
}
