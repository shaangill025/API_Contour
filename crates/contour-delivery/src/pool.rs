//! Fixed-owner pool. It never transfers authority or waits in capture callbacks.
use super::{CaptureId, CollectorOwner, OwnerError, SendOutcome};
use contour_core::{AdmissionInputs, CaptureScope, OriginWitness, QueueStats, RecordMetadata};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{
        Arc, Mutex as Gate, MutexGuard,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::Poll,
};
use tokio::sync::{Mutex, Notify, Semaphore, SemaphorePermit};

#[derive(Clone, Copy, Debug)]
pub struct PoolCapture {
    pool: u64,
    slot: usize,
    epoch: u64,
    id: CaptureId,
}

/// The pool owns all slots; no owner handle escapes to the forwarding adapter.
pub struct CollectorPool {
    instance: u64,
    origin_v2: bool,
    slots: Vec<Mutex<CollectorOwner>>,
    enabled: AtomicBool,
    epoch: AtomicU64,
    sync: Mutex<()>,
    background: Semaphore,
    cancel: Notify,
    gate: Gate<()>,
    losses: AtomicU64,
    cancelled: Vec<AtomicU64>,
    next_slot: AtomicUsize,
    #[cfg(test)]
    blocked_sends: AtomicUsize,
}

// Cancellation stays durable even when forwarding cannot acquire the gate.
// Every gate holder drains it before releasing the last synchronous raw owner.
struct PoolGate<'a> {
    pool: &'a CollectorPool,
    _guard: MutexGuard<'a, ()>,
}
impl Drop for PoolGate<'_> {
    fn drop(&mut self) {
        self.pool.drain_cancelled();
    }
}
impl CollectorPool {
    pub fn new(owners: Vec<CollectorOwner>) -> Result<Arc<Self>, OwnerError> {
        if owners.is_empty() || owners.len() > 8 {
            return Err(OwnerError::Paused);
        }
        let first = &owners[0];
        if owners.iter().any(|o| {
            o.client.identity != first.client.identity
                || o.source_ids != first.source_ids
                || o.client.wire_mode != first.client.wire_mode
        }) {
            return Err(OwnerError::Paused);
        }
        static NEXT_POOL: AtomicU64 = AtomicU64::new(1);
        let instance = NEXT_POOL
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| OwnerError::Paused)?;
        let origin_v2 = first.client.wire_mode == super::WireMode::V2;
        let cancelled = (0..owners.len()).map(|_| AtomicU64::new(0)).collect();
        Ok(Arc::new(Self {
            instance,
            origin_v2,
            cancelled,
            slots: owners.into_iter().map(Mutex::new).collect(),
            enabled: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            sync: Mutex::new(()),
            background: Semaphore::new(1),
            cancel: Notify::new(),
            gate: Gate::new(()),
            losses: AtomicU64::new(0),
            next_slot: AtomicUsize::new(0),
            #[cfg(test)]
            blocked_sends: AtomicUsize::new(0),
        }))
    }
    /// The immutable wire profile shared by every owner in this pool.
    pub fn is_origin_v2(&self) -> bool {
        self.origin_v2
    }
    fn try_gate(&self) -> Result<PoolGate<'_>, OwnerError> {
        let guard = self.gate.try_lock().map_err(|_| OwnerError::Paused)?;
        self.drain_cancelled();
        Ok(PoolGate {
            pool: self,
            _guard: guard,
        })
    }
    fn lock_gate(&self) -> Result<PoolGate<'_>, OwnerError> {
        let guard = self.gate.lock().map_err(|_| OwnerError::Paused)?;
        self.drain_cancelled();
        Ok(PoolGate {
            pool: self,
            _guard: guard,
        })
    }
    fn drain_cancelled(&self) {
        for (slot, cancelled) in self.slots.iter().zip(&self.cancelled) {
            if let Ok(mut owner) = slot.try_lock() {
                owner
                    .streams
                    .cancel_through(cancelled.load(Ordering::Acquire));
            }
        }
    }
    fn advance_epoch(&self) -> Result<u64, OwnerError> {
        self.epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .map(|previous| previous + 1)
            .map_err(|_| OwnerError::Paused)
    }
    pub fn losses(&self) -> u64 {
        self.losses.load(Ordering::Relaxed)
    }
    /// Copy one owner's counters without waiting or changing owner state.
    /// Returns None when the slot does not exist or its owner is busy.
    pub fn try_queue_stats(&self, slot: usize) -> Option<QueueStats> {
        self.slots
            .get(slot)?
            .try_lock()
            .ok()
            .map(|owner| owner.stats())
    }
    /// Reclaim raw streams after an idle lease expires. A runtime must call
    /// this periodically in addition to the checks on capture operations.
    pub fn poll_authority(&self) -> Result<(), OwnerError> {
        let _gate = self.try_gate().map_err(|_| OwnerError::Paused)?;
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
    // Wait outside every owner/raw lock. Tokio's semaphore queues waiters fairly;
    // cancellation must also wake an old waiter before it can use a new grant.
    async fn background_permit(&self, epoch: u64) -> Result<SemaphorePermit<'_>, OwnerError> {
        let acquire = self.background.acquire();
        let mut acquire = pin!(acquire);
        let notify = self.cancel.notified();
        let mut notify = pin!(notify);
        poll_fn(|cx| {
            if !self.current(epoch) || notify.as_mut().poll(cx).is_ready() || !self.current(epoch) {
                return Poll::Ready(Err(OwnerError::Paused));
            }
            match acquire.as_mut().poll(cx) {
                Poll::Ready(Ok(permit)) if self.current(epoch) => Poll::Ready(Ok(permit)),
                Poll::Ready(_) => Poll::Ready(Err(OwnerError::Paused)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
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
        let _ = self.advance_epoch();
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
            let _gate = self.lock_gate().map_err(|_| OwnerError::Paused)?;
            self.enabled.store(false, Ordering::Release);
            let epoch = self.advance_epoch()?;
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
        Self::validate_common(&guards)?;
        if self.epoch.load(Ordering::Acquire) != epoch {
            return Err(OwnerError::Paused);
        }
        let _gate = self.lock_gate().map_err(|_| OwnerError::Paused)?;
        if self.epoch.load(Ordering::Acquire) != epoch {
            return Err(OwnerError::Paused);
        }
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }
    fn validate_common(
        guards: &[tokio::sync::MutexGuard<'_, CollectorOwner>],
    ) -> Result<(), OwnerError> {
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
        for owner in guards {
            let current = &owner.policies.last().ok_or(OwnerError::Paused)?.policy;
            if !owner.is_live()
                || owner.live.as_ref().ok_or(OwnerError::Paused)?.sources
                    != first.live.as_ref().ok_or(OwnerError::Paused)?.sources
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
        Ok(())
    }
    pub fn try_begin(&self, scope: &CaptureScope<'_>) -> Result<PoolCapture, OwnerError> {
        self.try_begin_version(scope, None)
    }
    /// Begin a V2 stream with a data-only origin witness.
    pub fn try_begin_v2(
        &self,
        scope: &CaptureScope<'_>,
        witness: &OriginWitness,
    ) -> Result<PoolCapture, OwnerError> {
        self.try_begin_version(scope, Some(witness))
    }
    fn try_begin_version(
        &self,
        scope: &CaptureScope<'_>,
        witness: Option<&OriginWitness>,
    ) -> Result<PoolCapture, OwnerError> {
        let _gate = self.try_gate().map_err(|_| {
            self.lose();
            OwnerError::Paused
        })?;
        let epoch = self.epoch.load(Ordering::Acquire);
        if !self.current(epoch) {
            self.lose();
            return Err(OwnerError::Paused);
        }
        self.check_live()?;
        // The gate serializes this bounded scheduling cursor; it is not an
        // authority generation and advances only after a reservation succeeds.
        let start = self.next_slot.load(Ordering::Relaxed);
        let mut tried = 0u8;
        loop {
            let mut chosen: Option<(usize, tokio::sync::MutexGuard<'_, CollectorOwner>)> = None;
            let mut full = 0;
            for offset in 0..self.slots.len() {
                let slot = (start + offset) % self.slots.len();
                if tried & (1 << slot) != 0 {
                    continue;
                }
                let Ok(mut owner) = self.slots[slot].try_lock() else {
                    continue;
                };
                if !self.current(epoch) {
                    self.lose();
                    return Err(OwnerError::Paused);
                }
                // Reserve one owner per stream so a busy request cannot monopolize
                // all capture slots or be displaced by a background send.
                if !owner.streams.is_empty() {
                    continue;
                }
                // Expired retained entries must not make a live owner appear
                // permanently full. Maintenance only deletes; it grants no
                // authority and errors cannot fall through to another slot.
                owner.expire_retained().inspect_err(|_| self.lose())?;
                if owner.guard().is_err() {
                    drop(owner);
                    let _ = self.check_live();
                    self.lose();
                    return Err(OwnerError::Paused);
                }
                let stats = owner.stats();
                if stats.records >= owner.configured_queue_records
                    || stats.bytes >= owner.configured_queue_bytes
                {
                    full += 1;
                    continue;
                }
                // Compare charged fractions without rounding; iteration order
                // provides the rotating tie-breaker. The next charge is unknown.
                let replace = chosen.as_ref().is_none_or(|(_, best)| {
                    (stats.bytes as u128) * (best.configured_queue_bytes as u128)
                        < (best.stats().bytes as u128) * (owner.configured_queue_bytes as u128)
                });
                if replace {
                    chosen = Some((slot, owner));
                }
            }
            let Some((slot, mut owner)) = chosen else {
                self.lose();
                return if full == self.slots.len() {
                    Err(OwnerError::Queue(contour_core::QueueError::Full))
                } else {
                    Err(OwnerError::Paused)
                };
            };
            if let Ok(id) = match witness {
                Some(w) => owner.begin_capture_v2(scope, w),
                None => owner.begin_capture(scope),
            } {
                self.next_slot
                    .store((slot + 1) % self.slots.len(), Ordering::Relaxed);
                return Ok(PoolCapture {
                    pool: self.instance,
                    slot,
                    epoch,
                    id,
                });
            }
            tried |= 1 << slot;
        }
    }
    pub fn try_fragment(&self, token: PoolCapture, bytes: &[u8]) -> Result<(), OwnerError> {
        if token.pool != self.instance {
            return Err(OwnerError::Paused);
        }
        let _gate = self.try_gate().map_err(|_| {
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
        let result = owner.capture_fragment(token.id, bytes).inspect_err(|_| {
            self.lose();
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
        if token.pool != self.instance {
            return Err(OwnerError::Paused);
        }
        let _gate = self.try_gate().map_err(|_| {
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
        result.inspect_err(|_| {
            self.lose();
        })
    }
    pub fn try_cancel(&self, token: PoolCapture) {
        if token.pool != self.instance {
            return;
        }
        if let Some(cancelled) = self.cancelled.get(token.slot) {
            cancelled.fetch_max(token.id.sequence(), Ordering::AcqRel);
        }
        let Ok(_gate) = self.try_gate() else {
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
        let _gate = self.try_gate().map_err(|_| OwnerError::Paused)?;
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
        let _permit = self.background_permit(epoch).await?;
        let mut owner = {
            let _gate = self.try_gate().map_err(|_| OwnerError::Paused)?;
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
        #[cfg(test)]
        let send = async {
            if self.blocked_sends.load(Ordering::Acquire) != 0 {
                self.blocked_sends.fetch_add(1, Ordering::AcqRel);
                std::future::pending().await
            } else {
                owner.send_once().await
            }
        };
        #[cfg(not(test))]
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
        let _permit = self.background_permit(epoch).await?;
        let mut owner = {
            let _gate = self.try_gate().map_err(|_| OwnerError::Paused)?;
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

#[cfg(test)]
mod tests {
    use super::super::capture_tests::{
        make_owner, make_owner_at, make_owner_at_with_ttl, make_owner_v2, scope,
    };
    use super::*;

    #[test]
    fn pending_background_sends_leave_capture_owner_available() {
        let now = time::OffsetDateTime::now_utc();
        let mut owners = vec![make_owner_at(now), make_owner_at(now)];
        for owner in &mut owners {
            let limits = contour_core::QueueLimits::new(2, 4000).unwrap();
            owner.queue = contour_core::MemoryQueue::new(
                owner.client.identity.each_ref().map(String::as_str),
                limits,
            )
            .unwrap();
            owner.configured_queue_bytes = limits.byte_limit();
            owner.configured_queue_records = limits.record_limit();
        }
        let pool = CollectorPool::new(owners).unwrap();
        {
            let guards = pool
                .slots
                .iter()
                .map(|slot| slot.try_lock().unwrap())
                .collect::<Vec<_>>();
            assert!(CollectorPool::validate_common(&guards).is_ok());
        }
        pool.enabled.store(true, Ordering::Release);
        pool.blocked_sends.store(1, Ordering::Release);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut first = pin!(pool.send(0));
                let mut second = pin!(pool.send(1));
                poll_fn(|cx| {
                    assert!(first.as_mut().poll(cx).is_pending());
                    assert!(second.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert!(
                    pool.blocked_sends.load(Ordering::Acquire) > 1,
                    "a transport is actually pending while holding an owner"
                );
                let s = scope();
                let capture = pool
                    .try_begin(&s)
                    .expect("background network waits must leave another owner available");
                pool.try_fragment(capture, br#"{"id":1}"#).unwrap();
                let timestamp = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
                pool.try_finish(
                    capture,
                    RecordMetadata {
                        record_id: "00000000-0000-4000-8000-000000000002",
                        source_id: s.source_id,
                        workload: s.workload,
                        protocol: "http",
                        direction: "request",
                        visibility: "structure",
                        operation: s.operation,
                        route_template: s.route_template,
                        route_uncertain: false,
                        parser_profile: s.parser_profile,
                        policy_revision: 1,
                        count: 1,
                        first_seen: timestamp.clone(),
                        last_seen: timestamp,
                        sample_numerator: 1,
                        sample_denominator: 1,
                        status_code: None,
                        request_header_names: &[],
                        response_header_names: &[],
                        query_parameter_names: &[],
                    },
                )
                .expect("reserved owner must admit the actual captured record");
                assert_eq!(pool.losses(), 0);
            });
    }

    #[test]
    fn synchronize_cancels_permit_waiter_and_inflight_send_clears_raw() {
        let pool = CollectorPool::new(vec![make_owner(), make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        pool.blocked_sends.store(1, Ordering::Release);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let sync_lock = pool.sync.lock().await;
                let mut sending = pin!(pool.send(0));
                let mut waiting = pin!(pool.send(1));
                poll_fn(|cx| {
                    assert!(sending.as_mut().poll(cx).is_pending());
                    assert!(waiting.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                let capture = pool.try_begin(&scope()).unwrap();
                assert_eq!(capture.slot, 1);
                pool.try_fragment(capture, b"private raw bytes").unwrap();
                let mut sync = Box::pin(pool.synchronize());
                poll_fn(|cx| {
                    assert!(sync.as_mut().poll(cx).is_pending());
                    assert!(!pool.enabled.load(Ordering::Acquire));
                    assert!(pool.slots[1].try_lock().unwrap().streams.is_empty());
                    assert!(matches!(
                        waiting.as_mut().poll(cx),
                        Poll::Ready(Err(OwnerError::Paused))
                    ));
                    // The waiter returned without acquiring a permit or owner;
                    // the active transport remains owned until its future polls cancellation.
                    assert!(pool.slots[0].try_lock().is_err());
                    assert!(matches!(
                        sending.as_mut().poll(cx),
                        Poll::Ready(Err(OwnerError::Paused))
                    ));
                    Poll::Ready(())
                })
                .await;
                assert!(pool.slots[0].try_lock().is_ok());
                assert_eq!(pool.blocked_sends.load(Ordering::Acquire), 2);
                drop(sync);
                drop(sync_lock);
            });
    }

    #[test]
    fn waiter_cannot_use_authority_from_a_later_epoch() {
        let pool = CollectorPool::new(vec![make_owner(), make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        pool.blocked_sends.store(1, Ordering::Release);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut sending = pin!(pool.send(0));
                let mut waiting = pin!(pool.wait_retry(1));
                poll_fn(|cx| {
                    assert!(sending.as_mut().poll(cx).is_pending());
                    assert!(waiting.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                // Model an authority generation being replaced while the old
                // future is queued; it must not use the later live generation.
                pool.enabled.store(false, Ordering::Release);
                pool.advance_epoch().unwrap();
                pool.enabled.store(true, Ordering::Release);
                pool.cancel.notify_waiters();
                poll_fn(|cx| {
                    assert!(matches!(
                        waiting.as_mut().poll(cx),
                        Poll::Ready(Err(OwnerError::Paused))
                    ));
                    assert!(matches!(
                        sending.as_mut().poll(cx),
                        Poll::Ready(Err(OwnerError::Paused))
                    ));
                    Poll::Ready(())
                })
                .await;
                assert_eq!(pool.blocked_sends.load(Ordering::Acquire), 2);
                assert!(pool.slots[1].try_lock().unwrap().streams.is_empty());
            });
    }

    #[test]
    fn expired_retention_is_reclaimed_before_full_queue_selection() {
        let owner = make_owner_at_with_ttl(time::OffsetDateTime::now_utc(), 1);
        let pool = CollectorPool::new(vec![owner]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let s = scope();
        let timestamp = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
        let metadata = |record_id| RecordMetadata {
            record_id,
            source_id: s.source_id,
            workload: s.workload,
            protocol: "http",
            direction: "request",
            visibility: "structure",
            operation: s.operation,
            route_template: s.route_template,
            route_uncertain: false,
            parser_profile: s.parser_profile,
            policy_revision: 1,
            count: 1,
            first_seen: timestamp.clone(),
            last_seen: timestamp.clone(),
            sample_numerator: 1,
            sample_denominator: 1,
            status_code: None,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        };
        let first = pool.try_begin(&s).unwrap();
        pool.try_fragment(first, br#"{"id":1}"#).unwrap();
        pool.try_finish(first, metadata("00000000-0000-4000-8000-000000000002"))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1200));
        {
            let owner = pool.slots[0].try_lock().unwrap();
            assert!(
                owner.is_live(),
                "authority must remain live after retention expires"
            );
            assert_eq!(owner.stats().records, 1, "no external maintenance occurred");
        }
        let next = pool
            .try_begin(&s)
            .expect("expired retention must not block a live capture");
        pool.try_fragment(next, br#"{"id":1}"#).unwrap();
        pool.try_finish(next, metadata("00000000-0000-4000-8000-000000000003"))
            .unwrap();
        let stats = pool.slots[0].try_lock().unwrap().stats();
        assert_eq!(stats.expired, 1);
        assert_eq!(stats.records, 1);
    }

    #[test]
    fn failed_reservation_does_not_advance_rotation() {
        let now = time::OffsetDateTime::now_utc();
        let pool = CollectorPool::new(vec![make_owner_at(now), make_owner_at(now)]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let first = pool.try_begin(&scope()).unwrap();
        let second = pool.try_begin(&scope()).unwrap();
        assert_eq!((first.slot, second.slot), (0, 1));
        assert!(pool.try_begin(&scope()).is_err());
        assert_eq!(pool.next_slot.load(Ordering::Relaxed), 0);
        pool.try_cancel(first);
        let next = pool.try_begin(&scope()).unwrap();
        assert_eq!(next.slot, 0);
        pool.try_cancel(next);
        pool.try_cancel(second);
    }

    #[test]
    fn chooses_lower_fraction_of_charged_queue_budget() {
        let now = time::OffsetDateTime::now_utc();
        let mut owners = vec![make_owner_at(now), make_owner_at(now)];
        for (owner, bytes) in owners.iter_mut().zip([4000, 6000]) {
            let limits = contour_core::QueueLimits::new(2, bytes).unwrap();
            owner.queue = contour_core::MemoryQueue::new(
                owner.client.identity.each_ref().map(String::as_str),
                limits,
            )
            .unwrap();
            owner.configured_queue_bytes = limits.byte_limit();
            owner.configured_queue_records = limits.record_limit();
            let s = scope();
            let timestamp = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
            let token = owner.begin_capture(&s).unwrap();
            owner.capture_fragment(token, br#"{"id":1}"#).unwrap();
            owner
                .finish_and_admit(
                    token,
                    RecordMetadata {
                        record_id: "00000000-0000-4000-8000-000000000002",
                        source_id: s.source_id,
                        workload: s.workload,
                        protocol: "http",
                        direction: "request",
                        visibility: "structure",
                        operation: s.operation,
                        route_template: s.route_template,
                        route_uncertain: false,
                        parser_profile: s.parser_profile,
                        policy_revision: 1,
                        count: 1,
                        first_seen: timestamp.clone(),
                        last_seen: timestamp,
                        sample_numerator: 1,
                        sample_denominator: 1,
                        status_code: None,
                        request_header_names: &[],
                        response_header_names: &[],
                        query_parameter_names: &[],
                    },
                )
                .unwrap();
        }
        let pool = CollectorPool::new(owners).unwrap();
        {
            let guards = pool
                .slots
                .iter()
                .map(|slot| slot.try_lock().unwrap())
                .collect::<Vec<_>>();
            assert!(CollectorPool::validate_common(&guards).is_ok());
            assert_eq!(guards[0].stats().bytes, guards[1].stats().bytes);
        }
        pool.enabled.store(true, Ordering::Release);
        let token = pool.try_begin(&scope()).unwrap();
        assert_eq!(token.slot, 1);
        pool.try_cancel(token);
    }

    #[test]
    fn rotating_capture_reservations_use_both_record_and_byte_capacity() {
        for (record_limit, byte_limit) in [(1, 5000), (16, 5000), (16, 3936)] {
            let now = time::OffsetDateTime::now_utc();
            let mut owners = vec![make_owner_at(now), make_owner_at(now)];
            for owner in &mut owners {
                let limits = contour_core::QueueLimits::new(record_limit, byte_limit).unwrap();
                owner.queue = contour_core::MemoryQueue::new(
                    owner.client.identity.each_ref().map(String::as_str),
                    limits,
                )
                .unwrap();
                owner.configured_queue_bytes = limits.byte_limit();
                owner.configured_queue_records = limits.record_limit();
                assert!(owner.is_live());
            }
            let pool = CollectorPool::new(owners).unwrap();
            {
                let guards = pool
                    .slots
                    .iter()
                    .map(|slot| slot.try_lock().unwrap())
                    .collect::<Vec<_>>();
                assert!(CollectorPool::validate_common(&guards).is_ok());
            }
            pool.enabled.store(true, Ordering::Release);
            let metadata = |record_id| {
                let s = scope();
                let timestamp = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
                RecordMetadata {
                    record_id,
                    source_id: s.source_id,
                    workload: s.workload,
                    protocol: "http",
                    direction: "request",
                    visibility: "structure",
                    operation: s.operation,
                    route_template: s.route_template,
                    route_uncertain: false,
                    parser_profile: s.parser_profile,
                    policy_revision: 1,
                    count: 1,
                    first_seen: timestamp.clone(),
                    last_seen: timestamp,
                    sample_numerator: 1,
                    sample_denominator: 1,
                    status_code: None,
                    request_header_names: &[],
                    response_header_names: &[],
                    query_parameter_names: &[],
                }
            };
            for (expected_slot, id) in [
                (0, "00000000-0000-4000-8000-000000000002"),
                (1, "00000000-0000-4000-8000-000000000003"),
            ] {
                let token = pool.try_begin(&scope()).unwrap();
                assert_eq!(token.slot, expected_slot);
                pool.try_fragment(token, br#"{"id":1}"#).unwrap();
                pool.try_finish(token, metadata(id)).unwrap();
            }
            for slot in &pool.slots {
                let stats = slot.try_lock().unwrap().stats();
                assert_eq!(stats.records, 1);
                assert!(stats.bytes > 2500 && stats.bytes <= byte_limit, "{stats:?}");
            }
            let before = pool.losses();
            if record_limit == 1 || byte_limit == 3936 {
                assert!(matches!(
                    pool.try_begin(&scope()),
                    Err(OwnerError::Queue(contour_core::QueueError::Full))
                ));
            } else {
                let token = pool.try_begin(&scope()).unwrap();
                pool.try_fragment(token, br#"{"id":1}"#).unwrap();
                assert!(matches!(
                    pool.try_finish(token, metadata("00000000-0000-4000-8000-000000000004")),
                    Err(OwnerError::Queue(contour_core::QueueError::Full))
                ));
            }
            assert_eq!(pool.losses(), before + 1);
            for slot in &pool.slots {
                let owner = slot.try_lock().unwrap();
                assert_eq!(owner.stats().records, 1);
                assert!(owner.streams.is_empty());
            }
        }
    }

    #[test]
    fn capture_uses_available_owner_when_first_owner_queue_is_full() {
        for record_limit in [1, 16] {
            let now = time::OffsetDateTime::now_utc();
            let mut owners = vec![make_owner_at(now), make_owner_at(now)];
            for owner in &mut owners {
                let limits = contour_core::QueueLimits::new(record_limit, 5000).unwrap();
                owner.queue = contour_core::MemoryQueue::new(
                    owner.client.identity.each_ref().map(String::as_str),
                    limits,
                )
                .unwrap();
                owner.configured_queue_bytes = limits.byte_limit();
                owner.configured_queue_records = limits.record_limit();
                assert!(owner.is_live());
            }
            let pool = CollectorPool::new(owners).unwrap();
            {
                let guards = pool
                    .slots
                    .iter()
                    .map(|slot| slot.try_lock().unwrap())
                    .collect::<Vec<_>>();
                assert!(CollectorPool::validate_common(&guards).is_ok());
            }
            pool.enabled.store(true, Ordering::Release);
            let metadata = |record_id| {
                let s = scope();
                let timestamp = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
                RecordMetadata {
                    record_id,
                    source_id: s.source_id,
                    workload: s.workload,
                    protocol: "http",
                    direction: "request",
                    visibility: "structure",
                    operation: s.operation,
                    route_template: s.route_template,
                    route_uncertain: false,
                    parser_profile: s.parser_profile,
                    policy_revision: 1,
                    count: 1,
                    first_seen: timestamp.clone(),
                    last_seen: timestamp,
                    sample_numerator: 1,
                    sample_denominator: 1,
                    status_code: None,
                    request_header_names: &[],
                    response_header_names: &[],
                    query_parameter_names: &[],
                }
            };
            {
                let mut first = pool.slots[0].try_lock().unwrap();
                let token = first.begin_capture(&scope()).unwrap();
                first.capture_fragment(token, br#"{"id":1}"#).unwrap();
                first
                    .finish_and_admit(token, metadata("00000000-0000-4000-8000-000000000002"))
                    .unwrap();
            }
            assert_eq!(pool.slots[0].try_lock().unwrap().stats().records, 1);
            assert_eq!(pool.slots[1].try_lock().unwrap().stats().records, 0);
            let token = pool.try_begin(&scope()).unwrap();
            pool.try_fragment(token, br#"{"id":1}"#).unwrap();
            let result = pool.try_finish(token, metadata("00000000-0000-4000-8000-000000000003"));
            if result.is_err() {
                let mut other = pool.slots[1].try_lock().unwrap();
                let available = other.begin_capture(&scope()).unwrap();
                other.capture_fragment(available, br#"{"id":1}"#).unwrap();
                other
                    .finish_and_admit(available, metadata("00000000-0000-4000-8000-000000000004"))
                    .expect("other owner must have actual capacity");
            }
            assert!(
                result.is_ok(),
                "available owner should accept capture: {result:?}"
            );
        }
    }

    #[test]
    fn v2_pool_rejects_mixed_modes_foreign_tokens_and_stale_epochs() {
        assert!(CollectorPool::new(vec![make_owner(), make_owner_v2()]).is_err());
        assert!(
            !CollectorPool::new(vec![make_owner()])
                .unwrap()
                .is_origin_v2()
        );
        let a = CollectorPool::new(vec![make_owner_v2()]).unwrap();
        let b = CollectorPool::new(vec![make_owner_v2()]).unwrap();
        assert!(a.is_origin_v2());
        a.enabled.store(true, Ordering::Release);
        b.enabled.store(true, Ordering::Release);
        assert!(a.try_begin(&scope()).is_err());
        let foreign = a
            .try_begin_v2(&scope(), &OriginWitness::Unattributed)
            .unwrap();
        let own = b
            .try_begin_v2(&scope(), &OriginWitness::Unattributed)
            .unwrap();
        assert!(b.try_fragment(foreign, b"foreign").is_err());
        b.try_cancel(foreign);
        b.try_fragment(own, b"private").unwrap();
        b.advance_epoch().unwrap();
        assert!(b.try_fragment(own, b"late").is_err());
        b.try_cancel(own);
        assert!(b.slots[0].try_lock().unwrap().streams.is_empty());
        assert!(a.try_fragment(foreign, br#"{"id":1}"#).is_ok());
        a.try_cancel(foreign);
    }
    #[test]
    fn queue_stats_snapshot_is_nonblocking_and_read_only() {
        let pool = CollectorPool::new(vec![make_owner(), make_owner()]).unwrap();
        let expected = pool.slots[0].try_lock().unwrap().stats();
        let losses = pool.losses();
        assert_eq!(pool.try_queue_stats(0), Some(expected));
        assert_eq!(pool.try_queue_stats(0), Some(expected));
        assert!(pool.try_queue_stats(2).is_none());
        let guard = pool.slots[0].try_lock().unwrap();
        assert!(pool.try_queue_stats(0).is_none());
        assert_eq!(
            pool.try_queue_stats(1),
            Some(pool.slots[1].try_lock().unwrap().stats())
        );
        assert_eq!(guard.stats(), expected);
        drop(guard);
        assert_eq!(pool.try_queue_stats(0), Some(expected));
        assert_eq!(pool.losses(), losses);
    }

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
    fn cancellation_during_a_busy_gate_is_reclaimed_by_the_gate_owner() {
        let pool = CollectorPool::new(vec![make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let token = pool.try_begin(&scope()).unwrap();
        pool.try_fragment(token, b"private raw bytes").unwrap();
        let gate = pool.try_gate().unwrap();
        pool.try_cancel(token);
        assert!(!pool.slots[0].try_lock().unwrap().streams.is_empty());
        drop(gate);
        assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
        let next = pool.try_begin(&scope()).unwrap();
        pool.try_cancel(token);
        pool.try_fragment(next, br#"{"id":1}"#).unwrap();
        assert!(!pool.slots[0].try_lock().unwrap().streams.is_empty());
    }
    #[test]
    fn common_policy_cannot_resume_with_different_source_authorizations() {
        let now = time::OffsetDateTime::now_utc();
        let a = make_owner_at(now);
        let b = make_owner_at(now);
        let pool = CollectorPool::new(vec![a, b]).unwrap();
        let mut guards = pool
            .slots
            .iter()
            .map(|slot| slot.try_lock().unwrap())
            .collect::<Vec<_>>();
        for owner in &mut guards {
            owner.configured_queue_bytes = 5000;
        }
        assert!(CollectorPool::validate_common(&guards).is_ok());
        let id = scope().source_id;
        guards[1].live.as_mut().unwrap().sources = vec![
            contour_core::SourceAssignment::new(id, [id; 6], "runtime", &["http_text_v1"]).unwrap(),
        ];
        assert!(CollectorPool::validate_common(&guards).is_err());
    }
    #[test]
    fn common_policy_rejects_same_revision_different_signed_content() {
        let now = time::OffsetDateTime::now_utc();
        let a = make_owner_at(now - time::Duration::seconds(1));
        let b = make_owner_at(now);
        let pool = CollectorPool::new(vec![a, b]).unwrap();
        let mut guards = pool
            .slots
            .iter()
            .map(|slot| slot.try_lock().unwrap())
            .collect::<Vec<_>>();
        for owner in &mut guards {
            owner.configured_queue_bytes = 5000;
            assert!(owner.is_live());
        }
        assert_eq!(
            guards[0].policies.last().unwrap().policy.revision(),
            guards[1].policies.last().unwrap().policy.revision()
        );
        assert_ne!(
            guards[0].policies.last().unwrap().policy.expires_at(),
            guards[1].policies.last().unwrap().policy.expires_at()
        );
        assert!(CollectorPool::validate_common(&guards).is_err());
    }
    #[test]
    fn tokens_cannot_cross_pool_ownership() {
        let a = CollectorPool::new(vec![make_owner()]).unwrap();
        let b = CollectorPool::new(vec![make_owner()]).unwrap();
        a.enabled.store(true, Ordering::Release);
        b.enabled.store(true, Ordering::Release);
        let foreign = a.try_begin(&scope()).unwrap();
        let own = b.try_begin(&scope()).unwrap();
        assert!(b.try_fragment(foreign, b"foreign").is_err());
        b.try_cancel(foreign);
        b.try_fragment(own, br#"{"id":1}"#).unwrap();
        assert!(!b.slots[0].try_lock().unwrap().streams.is_empty());
    }
    #[test]
    fn epoch_exhaustion_does_not_wrap_or_revive_old_tokens() {
        let pool = CollectorPool::new(vec![make_owner()]).unwrap();
        pool.epoch.store(u64::MAX, Ordering::Release);
        assert!(pool.advance_epoch().is_err());
        assert_eq!(pool.epoch.load(Ordering::Acquire), u64::MAX);
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
