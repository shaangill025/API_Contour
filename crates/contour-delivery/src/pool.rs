//! Fixed-owner pool. It never transfers authority or waits in capture callbacks.
use super::{CaptureId, CollectorOwner, OwnerError, SendOutcome};
use crate::adapter::StructuralAdapter;
use crate::authority::Refresh;
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
use tokio::time::Instant;

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
    renewal: Vec<RenewalConfig>,
    enabled: AtomicBool,
    epoch: AtomicU64,
    failed_epoch: AtomicU64,
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

struct RenewalConfig {
    client: crate::DeliveryClient,
    keys: Arc<contour_core::PolicyKeys>,
    source_ids: Vec<String>,
}

impl RenewalConfig {
    fn duplicate(&self) -> Self {
        Self {
            client: self.client.duplicate(),
            keys: self.keys.clone(),
            source_ids: self.source_ids.clone(),
        }
    }
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
struct RenewalFence<'a> {
    pool: &'a CollectorPool,
    epoch: u64,
    armed: bool,
    guards: Vec<tokio::sync::MutexGuard<'a, CollectorOwner>>,
    permit: Option<SemaphorePermit<'a>>,
}
impl Drop for RenewalFence<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Publish the failure before waiting for a callback's gate. A
            // callback in progress must see this before retaining its result.
            if let Some(marker) = self.epoch.checked_add(1) {
                self.pool.failed_epoch.fetch_max(marker, Ordering::SeqCst);
            }
            self.pool.cancel.notify_waiters();
            for owner in &mut self.guards {
                owner.streams.clear();
            }
            self.guards.clear();
            if let Ok(_gate) = self.pool.lock_gate() {
                self.pool.invalidate_epoch(self.epoch);
            }
        }
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
        let renewal = owners
            .iter()
            .map(|owner| RenewalConfig {
                client: owner.client.duplicate(),
                keys: owner.keys.clone(),
                source_ids: owner.source_ids.clone(),
            })
            .collect();
        Ok(Arc::new(Self {
            instance,
            origin_v2,
            cancelled,
            slots: owners.into_iter().map(Mutex::new).collect(),
            renewal,
            enabled: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            failed_epoch: AtomicU64::new(0),
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
        let epoch = self.epoch.load(Ordering::Acquire);
        if !self.current(epoch) {
            return Err(OwnerError::Paused);
        }
        self.check_live()?;
        for slot in &self.slots {
            if let Ok(mut owner) = slot.try_lock() {
                owner.streams.expire();
            }
        }
        Ok(())
    }
    fn lose(&self) {
        self.losses.fetch_add(1, Ordering::Relaxed);
    }
    fn current(&self, epoch: u64) -> bool {
        self.enabled.load(Ordering::Acquire)
            && self.epoch.load(Ordering::Acquire) == epoch
            && epoch
                .checked_add(1)
                .is_some_and(|marker| self.failed_epoch.load(Ordering::SeqCst) < marker)
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
    /// Renew equivalent authority without interrupting live streams while the
    /// independently owned transport is pending. Real changes use full sync.
    pub async fn renew(&self) -> Result<(), OwnerError> {
        let configs = &self.renewal;
        self.renew_with(|index| {
            let mut config = configs[index].duplicate();
            async move {
                config
                    .client
                    .refresh_authority(&config.source_ids, &config.keys)
                    .await
                    .map_err(OwnerError::from)
            }
        })
        .await
    }

    async fn renew_with<F, Fut>(&self, mut fetch: F) -> Result<(), OwnerError>
    where
        F: FnMut(usize) -> Fut,
        Fut: Future<Output = Result<Refresh, OwnerError>>,
    {
        // Full synchronize invalidates before waiting on this mutex. Thus an
        // older renewal can never install after a stop or newer full sync.
        let _sync = self.sync.lock().await;
        let epoch = {
            let _gate = self.lock_gate()?;
            let epoch = self.epoch.load(Ordering::Acquire);
            if !self.current(epoch) {
                return Err(OwnerError::Paused);
            }
            self.check_live()?;
            epoch
        };
        let mut fence = RenewalFence {
            pool: self,
            epoch,
            armed: true,
            guards: Vec::with_capacity(self.slots.len()),
            permit: None,
        };
        let mut candidates = Vec::with_capacity(self.slots.len());
        for index in 0..self.slots.len() {
            let notify = self.cancel.notified();
            let mut notify = pin!(notify);
            let future = fetch(index);
            let mut future = pin!(future);
            let candidate = poll_fn(|cx| {
                if !self.current(epoch) || notify.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(OwnerError::Paused));
                }
                future.as_mut().poll(cx)
            })
            .await?;
            candidates.push(candidate);
        }
        // Drain the single background transport before taking any owner lock,
        // so a deferred send cannot hold previously acquired raw owners idle.
        fence.permit = Some(self.background_permit(epoch).await?);
        // Await owner locks without the coordinator gate. Capture operations
        // never wait on these locks and their contention losses are counted.
        for slot in &self.slots {
            let notify = self.cancel.notified();
            let mut notify = pin!(notify);
            let lock = slot.lock();
            let mut lock = pin!(lock);
            let guard = poll_fn(|cx| {
                if !self.current(epoch) || notify.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(OwnerError::Paused));
                }
                match lock.as_mut().poll(cx) {
                    Poll::Ready(guard) => Poll::Ready(Ok(guard)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            fence.guards.push(guard);
        }
        let _gate = self.lock_gate()?;
        let checked = (|| -> Result<(), OwnerError> {
            if !self.current(epoch) || fence.guards.iter().any(|owner| !owner.is_live()) {
                return Err(OwnerError::Paused);
            }
            let total = fence
                .guards
                .iter()
                .try_fold(0usize, |sum, owner| {
                    sum.checked_add(owner.configured_queue_bytes)
                })
                .ok_or(OwnerError::Paused)?;
            let first = candidates.first().ok_or(OwnerError::Paused)?;
            let equivalent = fence
                .guards
                .iter()
                .zip(&candidates)
                .all(|(owner, candidate)| {
                    let Some(current) = owner.policies.last().map(|p| &p.policy) else {
                        return false;
                    };
                    let Some(live) = owner.live.as_ref() else {
                        return false;
                    };
                    candidate.live.sources == live.sources
                        && candidate.live.sources == first.live.sources
                        && candidate.policy.revision() == current.revision()
                        && total as u64 <= candidate.policy.queue_bytes()
                        && Instant::now() < candidate.live.deadline
                        && candidate
                            .policy
                            .validate_capture_at(time::OffsetDateTime::now_utc())
                            .is_ok()
                        && AdmissionInputs::new(
                            owner.client.identity.each_ref().map(String::as_str),
                            &candidate.policy,
                            &[current],
                            &candidate.live.sources,
                        )
                        .is_ok()
                        && AdmissionInputs::new(
                            owner.client.identity.each_ref().map(String::as_str),
                            &candidate.policy,
                            &[&first.policy],
                            &candidate.live.sources,
                        )
                        .is_ok()
                });
            if !equivalent {
                return Err(OwnerError::Paused);
            }
            // All candidate checks precede reconciliation; no partial installation
            // can be observed while every owner and the coordinator gate are held.
            for (owner, candidate) in fence.guards.iter_mut().zip(&candidates) {
                let owner = &mut **owner;
                let refs = owner.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
                let inputs = AdmissionInputs::new(
                    owner.client.identity.each_ref().map(String::as_str),
                    &candidate.policy,
                    &refs,
                    &candidate.live.sources,
                )
                .map_err(|e| OwnerError::Queue(crate::QueueError::Admission(e)))?;
                owner.queue.reconcile(&inputs)?;
            }
            if !self.current(epoch)
                || fence.guards.iter().any(|owner| !owner.is_live())
                || candidates.iter().any(|c| {
                    Instant::now() >= c.live.deadline
                        || c.policy
                            .validate_capture_at(time::OffsetDateTime::now_utc())
                            .is_err()
                })
            {
                return Err(OwnerError::Paused);
            }
            Ok(())
        })();
        if let Err(error) = checked {
            // Failed reconciliation or drift is visible before the gate and
            // owners are released, including already-held raw streams.
            for owner in &mut fence.guards {
                owner.streams.clear();
            }
            self.invalidate_epoch(epoch);
            fence.armed = false;
            return Err(error);
        }
        for (owner, candidate) in fence.guards.iter_mut().zip(candidates) {
            owner.live = Some(candidate.live);
            if owner
                .retry
                .as_ref()
                .is_some_and(|r| r.directive == crate::RetryDirective::RenewAuthorizedEnrollment)
            {
                owner.retry = None;
            }
        }
        fence.armed = false;
        Ok(())
    }

    // Caller holds the coordinator gate; invalidation is conditional so a
    // dropped stale renewal cannot disable a newer generation.
    fn invalidate_epoch(&self, epoch: u64) {
        if self.enabled.load(Ordering::Acquire) && self.epoch.load(Ordering::Acquire) == epoch {
            self.enabled.store(false, Ordering::Release);
            let _ = self.advance_epoch();
            for slot in &self.slots {
                if let Ok(mut owner) = slot.try_lock() {
                    owner.streams.clear();
                }
            }
            self.cancel.notify_waiters();
        }
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
        self.try_begin_version(scope, None, None)
    }
    /// Begin a V2 stream with a data-only origin witness.
    pub fn try_begin_v2(
        &self,
        scope: &CaptureScope<'_>,
        witness: &OriginWitness,
    ) -> Result<PoolCapture, OwnerError> {
        self.try_begin_version(scope, Some(witness), None)
    }
    pub(crate) fn adapter_begin(
        &self,
        adapter: &StructuralAdapter,
        scope: &CaptureScope<'_>,
        witness: Option<&OriginWitness>,
    ) -> Result<PoolCapture, OwnerError> {
        self.try_begin_version(scope, witness, Some(adapter))
    }
    fn try_begin_version(
        &self,
        scope: &CaptureScope<'_>,
        witness: Option<&OriginWitness>,
        adapter: Option<&StructuralAdapter>,
    ) -> Result<PoolCapture, OwnerError> {
        let _gate = self.try_gate().map_err(|_| {
            self.lose();
            OwnerError::Paused
        })?;
        if adapter.is_some_and(|a| !a.active.load(Ordering::SeqCst)) {
            return Err(OwnerError::Paused);
        }
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
                if let Some(a) = adapter {
                    // The total order pairs this reservation with detach's
                    // revoke-then-snapshot: one side observes the other.
                    a.sequences[slot].store(id.sequence(), Ordering::SeqCst);
                    if !a.active.load(Ordering::SeqCst) {
                        owner.cancel_capture(id);
                        return Err(OwnerError::Paused);
                    }
                }
                if !self.current(epoch) {
                    owner.cancel_capture(id);
                    self.lose();
                    return Err(OwnerError::Paused);
                }
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
        self.fragment_version(token, bytes, None)
    }
    pub(crate) fn adapter_fragment(
        &self,
        adapter: &StructuralAdapter,
        token: PoolCapture,
        bytes: &[u8],
    ) -> Result<(), OwnerError> {
        self.fragment_version(token, bytes, Some(adapter))
    }
    fn fragment_version(
        &self,
        token: PoolCapture,
        bytes: &[u8],
        adapter: Option<&StructuralAdapter>,
    ) -> Result<(), OwnerError> {
        if token.pool != self.instance {
            return Err(OwnerError::Paused);
        }
        let _gate = self.try_gate().map_err(|_| {
            self.lose();
            OwnerError::Paused
        })?;
        if adapter.is_some_and(|a| !a.active.load(Ordering::SeqCst)) {
            return Err(OwnerError::Paused);
        }
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
        let mut result = owner
            .capture_fragment_checked(token.id, bytes, || self.current(token.epoch))
            .inspect_err(|_| {
                self.lose();
            });
        if !self.current(token.epoch) {
            owner.cancel_capture(token.id);
            self.lose();
            result = Err(OwnerError::Paused);
        }
        drop(owner);
        self.check_live()?;
        result
    }
    pub fn try_finish(
        &self,
        token: PoolCapture,
        metadata: RecordMetadata<'_>,
    ) -> Result<(), OwnerError> {
        self.finish_version(token, metadata, None)
    }
    pub(crate) fn adapter_finish(
        &self,
        adapter: &StructuralAdapter,
        token: PoolCapture,
        metadata: RecordMetadata<'_>,
    ) -> Result<(), OwnerError> {
        self.finish_version(token, metadata, Some(adapter))
    }
    fn finish_version(
        &self,
        token: PoolCapture,
        metadata: RecordMetadata<'_>,
        adapter: Option<&StructuralAdapter>,
    ) -> Result<(), OwnerError> {
        if token.pool != self.instance {
            return Err(OwnerError::Paused);
        }
        let _gate = self.try_gate().map_err(|_| {
            self.lose();
            OwnerError::Paused
        })?;
        if adapter.is_some_and(|a| !a.active.load(Ordering::SeqCst)) {
            return Err(OwnerError::Paused);
        }
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
        let result =
            owner.finish_and_admit_checked(token.id, metadata, || self.current(token.epoch));
        drop(owner);
        self.check_live()?;
        result.inspect_err(|_| {
            self.lose();
        })
    }
    pub(crate) fn detach_adapter(&self, adapter: &StructuralAdapter) -> Result<(), OwnerError> {
        adapter.active.store(false, Ordering::SeqCst);
        for (slot, sequence) in adapter.sequences.iter().enumerate().take(self.slots.len()) {
            self.cancelled[slot].fetch_max(sequence.load(Ordering::SeqCst), Ordering::AcqRel);
        }
        let _gate = self.try_gate()?;
        Ok(())
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
        let result = owner.freeze(batch_id, maximum_records, maximum_wire_bytes);
        if !self.current(epoch) {
            return Err(OwnerError::Paused);
        }
        result
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
            match send.as_mut().poll(cx) {
                Poll::Ready(result) if self.current(epoch) => Poll::Ready(result),
                Poll::Ready(_) => Poll::Ready(Err(OwnerError::Paused)),
                Poll::Pending => Poll::Pending,
            }
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
        make_owner, make_owner_at, make_owner_at_with_ttl, make_owner_mode_at, make_owner_v2, scope,
    };
    use super::*;

    #[test]
    fn drop_after_last_drain_requires_maintenance_to_reclaim_raw() {
        let pool = CollectorPool::new(vec![make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let adapter = StructuralAdapter::attach(pool.clone()).unwrap();
        let token = adapter.try_begin(&scope(), None).unwrap();
        adapter.try_fragment(token, b"private").unwrap();
        // Reproduce the exact interval between PoolGate's final drain and
        // release of its underlying mutex, without timing-dependent threads.
        let guard = pool.gate.lock().unwrap();
        pool.drain_cancelled();
        drop(adapter);
        drop(guard);
        assert!(!pool.slots[0].try_lock().unwrap().streams.is_empty());
        pool.poll_authority().unwrap();
        assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
    }

    #[test]
    fn pending_detach_retries_with_maintenance_and_never_accepts_fragments() {
        let pool = CollectorPool::new(vec![make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let adapter = StructuralAdapter::attach(pool.clone()).unwrap();
        let token = adapter.try_begin(&scope(), None).unwrap();
        adapter.try_fragment(token, b"before").unwrap();
        let gate = pool.gate.lock().unwrap();
        pool.drain_cancelled();
        assert!(adapter.detach().is_err());
        assert!(pool.poll_authority().is_err());
        assert!(adapter.detach().is_err());
        assert!(adapter.try_fragment(token, b"after").is_err());
        let s = scope();
        let now = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
        let metadata = RecordMetadata {
            record_id: s.source_id,
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
            first_seen: now.clone(),
            last_seen: now,
            sample_numerator: 1,
            sample_denominator: 1,
            status_code: None,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        };
        assert!(adapter.try_finish(token, metadata).is_err());
        assert_eq!(pool.slots[0].try_lock().unwrap().stats().records, 0);
        drop(gate);
        assert!(adapter.try_fragment(token, b"late").is_err());
        assert!(pool.poll_authority().is_ok());
        assert!(adapter.detach().is_ok());
        assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
        assert_eq!(pool.slots[0].try_lock().unwrap().stats().records, 0);
    }

    #[test]
    fn adapter_detach_cancels_only_its_stream_and_old_tokens_stay_dead() {
        let pool = CollectorPool::new(vec![make_owner(), make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let a = StructuralAdapter::attach(pool.clone()).unwrap();
        let b = StructuralAdapter::attach(pool.clone()).unwrap();
        assert_eq!(a.descriptor().version, 1);
        let old = a.try_begin(&scope(), None).unwrap();
        let other = b.try_begin(&scope(), None).unwrap();
        a.try_fragment(old, b"private").unwrap();
        b.try_fragment(other, b"independent").unwrap();
        assert!(b.try_fragment(old, b"foreign").is_err());
        b.try_cancel(old);
        a.detach().unwrap();
        assert!(a.try_fragment(old, b"late").is_err());
        assert!(a.try_begin(&scope(), None).is_err());
        let s = scope();
        let now = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
        let metadata = RecordMetadata {
            record_id: s.source_id,
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
            first_seen: now.clone(),
            last_seen: now,
            sample_numerator: 1,
            sample_denominator: 1,
            status_code: None,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        };
        assert!(a.try_finish(old, metadata).is_err());
        b.try_fragment(other, b"still live").unwrap();
        let next = StructuralAdapter::attach(pool.clone()).unwrap();
        assert!(next.try_fragment(old, b"stale").is_err());
        let fresh = next.try_begin(&scope(), None).unwrap();
        a.try_cancel(old);
        next.try_fragment(fresh, b"new").unwrap();
        b.try_cancel(other);
        next.try_cancel(fresh);
        assert!(
            pool.slots
                .iter()
                .all(|s| s.try_lock().unwrap().streams.is_empty())
        );
    }

    #[test]
    fn adapter_detach_serializes_with_busy_gate_and_reclaims_capture() {
        let pool = CollectorPool::new(vec![make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let adapter = StructuralAdapter::attach(pool.clone()).unwrap();
        let token = adapter.try_begin(&scope(), None).unwrap();
        adapter.try_fragment(token, b"private").unwrap();
        let gate = pool.try_gate().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let worker = adapter.clone();
        let thread = std::thread::spawn(move || {
            sent.send(worker.detach().is_err()).unwrap();
        });
        assert!(adapter.try_fragment(token, b"busy").is_err());
        assert!(
            received
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap()
        );
        drop(gate);
        thread.join().unwrap();
        adapter.detach().unwrap();
        assert!(adapter.try_fragment(token, b"late").is_err());
        assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
    }

    #[test]
    fn adapters_reject_cross_pool_and_support_v2_witness() {
        let a = CollectorPool::new(vec![make_owner_v2()]).unwrap();
        let b = CollectorPool::new(vec![make_owner_v2()]).unwrap();
        a.enabled.store(true, Ordering::Release);
        b.enabled.store(true, Ordering::Release);
        let left = StructuralAdapter::attach(a).unwrap();
        let right = StructuralAdapter::attach(b).unwrap();
        assert!(left.descriptor().origin_v2);
        let token = left
            .try_begin(&scope(), Some(&OriginWitness::Unattributed))
            .unwrap();
        assert!(right.try_fragment(token, b"foreign").is_err());
        right.try_cancel(token);
        left.try_fragment(token, b"live").unwrap();
        left.try_cancel(token);
    }

    #[test]
    fn dropping_busy_attachment_durably_cancels_its_capture() {
        let pool = CollectorPool::new(vec![make_owner()]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let adapter = StructuralAdapter::attach(pool.clone()).unwrap();
        let token = adapter.try_begin(&scope(), None).unwrap();
        adapter.try_fragment(token, b"private").unwrap();
        let gate = pool.try_gate().unwrap();
        drop(adapter);
        assert!(!pool.slots[0].try_lock().unwrap().streams.is_empty());
        drop(gate);
        assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
    }

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
    fn pending_equivalent_renewal_preserves_stream() {
        let now = time::OffsetDateTime::now_utc();
        let pool = CollectorPool::new(vec![make_owner_at(now)]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let mut candidate_owner = make_owner_at(now);
        let candidate = Refresh {
            live: candidate_owner.live.take().unwrap(),
            policy: candidate_owner.policies.pop().unwrap().policy,
            envelope_bytes: 0,
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let token = pool.try_begin(&scope()).unwrap();
                pool.try_fragment(token, br#"{"id":"#).unwrap();
                let (tx, rx) = tokio::sync::oneshot::channel();
                let mut rx = Some(rx);
                let mut renewal = Box::pin(pool.renew_with(|_| {
                    let rx = rx.take().unwrap();
                    async move { rx.await.map_err(|_| OwnerError::Paused) }
                }));
                poll_fn(|cx| {
                    assert!(renewal.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert!(
                    pool.slots[0].try_lock().is_ok(),
                    "fetch holds no owner lock"
                );
                pool.try_fragment(token, b"1}")
                    .expect("pending fetch preserves raw stream");
                tx.send(candidate).ok().unwrap();
                renewal.await.unwrap();
                let s = scope();
                let timestamp = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
                pool.try_finish(
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
                assert_eq!(pool.try_queue_stats(0).unwrap().records, 1);
                assert_eq!(pool.losses(), 0);
            });
    }

    fn candidate_at(now: time::OffsetDateTime) -> Refresh {
        let mut owner = make_owner_at(now);
        Refresh {
            live: owner.live.take().unwrap(),
            policy: owner.policies.pop().unwrap().policy,
            envelope_bytes: 0,
        }
    }

    #[test]
    fn v2_witness_survives_equivalent_renewal() {
        let now = time::OffsetDateTime::now_utc();
        let owner = make_owner_mode_at(super::super::WireMode::V2, now, 60);
        let pool = CollectorPool::new(vec![owner]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let mut candidate = Some(candidate_at(now));
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let witness = OriginWitness::DownstreamMtlsLeafSha256V1 {
                    leaf_sha256: "a".repeat(64),
                };
                let token = pool.try_begin_v2(&scope(), &witness).unwrap();
                pool.try_fragment(token, br#"{"id":"#).unwrap();
                pool.renew_with(|_| {
                    let candidate = candidate.take().unwrap();
                    async move { Ok(candidate) }
                })
                .await
                .unwrap();
                pool.try_fragment(token, b"1}").unwrap();
                let s = scope();
                let timestamp = contour_core::Timestamp::parse("2026-10-30T12:00:00Z").unwrap();
                pool.try_finish(
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
                let mut owner = pool.slots[0].try_lock().unwrap();
                assert!(
                    owner
                        .freeze("00000000-0000-4000-8000-000000000001", 1, 10000)
                        .unwrap()
                );
                let owner = &mut *owner;
                let refs = owner.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
                let inputs = AdmissionInputs::new(
                    owner.client.identity.each_ref().map(String::as_str),
                    refs.last().unwrap(),
                    &refs,
                    &owner.live.as_ref().unwrap().sources,
                )
                .unwrap();
                let mut attempt = owner.queue.reserve_delivery(&inputs).unwrap().unwrap();
                let value: serde_json::Value =
                    serde_json::from_slice(attempt.view().wire()).unwrap();
                assert_eq!(
                    value["records"][0]["origin_witness"]["leaf_sha256"],
                    "a".repeat(64)
                );
            });
    }

    #[test]
    fn renewal_failure_and_dropped_future_fence_capture() {
        for cancel in [false, true] {
            let now = time::OffsetDateTime::now_utc();
            let pool = CollectorPool::new(vec![make_owner_at(now)]).unwrap();
            pool.enabled.store(true, Ordering::Release);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let token = pool.try_begin(&scope()).unwrap();
                    pool.try_fragment(token, b"private").unwrap();
                    if cancel {
                        let mut renewal = Box::pin(pool.renew_with(|_| async {
                            std::future::pending::<Result<Refresh, OwnerError>>().await
                        }));
                        poll_fn(|cx| {
                            assert!(renewal.as_mut().poll(cx).is_pending());
                            Poll::Ready(())
                        })
                        .await;
                        drop(renewal);
                    } else {
                        assert!(
                            pool.renew_with(|_| async {
                                Err(OwnerError::Transport(crate::DeliveryError::Transport))
                            })
                            .await
                            .is_err()
                        );
                    }
                    assert!(!pool.enabled.load(Ordering::Acquire));
                    assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
                    assert!(pool.try_fragment(token, b"late").is_err());
                });
        }
    }

    #[test]
    fn stale_renewal_cannot_disable_or_reactivate_new_epoch() {
        let now = time::OffsetDateTime::now_utc();
        let pool = CollectorPool::new(vec![make_owner_at(now)]).unwrap();
        pool.enabled.store(true, Ordering::Release);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let mut rx = Some(rx);
                let mut renewal = Box::pin(pool.renew_with(|_| {
                    let rx = rx.take().unwrap();
                    async move { rx.await.map_err(|_| OwnerError::Paused) }
                }));
                poll_fn(|cx| {
                    assert!(renewal.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                let mut stop = Box::pin(pool.synchronize());
                poll_fn(|cx| {
                    assert!(stop.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert!(!pool.enabled.load(Ordering::Acquire));
                let new_epoch = pool.epoch.load(Ordering::Acquire);
                // Model a newer successfully enabled generation while the old
                // transport is still pending; its late response must not affect that one.
                pool.enabled.store(true, Ordering::Release);
                tx.send(candidate_at(now)).ok().unwrap();
                assert!(renewal.await.is_err());
                assert!(pool.current(new_epoch));
                drop(stop);
            });
    }

    #[test]
    fn changed_content_or_source_never_commits_as_equivalent() {
        for source_drift in [false, true] {
            let now = time::OffsetDateTime::now_utc();
            let pool = CollectorPool::new(vec![make_owner_at(now)]).unwrap();
            pool.enabled.store(true, Ordering::Release);
            let mut candidate = if source_drift {
                candidate_at(now)
            } else {
                candidate_at(now + time::Duration::seconds(1))
            };
            if source_drift {
                candidate.live.sources.clear();
            }
            let mut candidate = Some(candidate);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let token = pool.try_begin(&scope()).unwrap();
                    pool.try_fragment(token, b"private").unwrap();
                    assert!(
                        pool.renew_with(|_| {
                            let c = candidate.take().unwrap();
                            async move { Ok(c) }
                        })
                        .await
                        .is_err()
                    );
                    assert!(!pool.enabled.load(Ordering::Acquire));
                    assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
                    assert!(pool.try_fragment(token, b"late").is_err());
                });
        }
    }

    #[test]
    fn denied_malformed_and_expired_candidates_disable_capture() {
        for failure in 0..4 {
            let now = time::OffsetDateTime::now_utc();
            let pool = CollectorPool::new(vec![make_owner_at(now)]).unwrap();
            pool.enabled.store(true, Ordering::Release);
            let mut candidate = candidate_at(now);
            candidate.live.deadline = Instant::now();
            let mut candidate = Some(candidate);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let token = pool.try_begin(&scope()).unwrap();
                    pool.try_fragment(token, b"private").unwrap();
                    let result = pool
                        .renew_with(|_| {
                            let candidate = candidate.take().unwrap();
                            async move {
                                match failure {
                                    0 => {
                                        Err(OwnerError::Transport(crate::DeliveryError::Rejected {
                                            status: 403,
                                            retry_after: None,
                                        }))
                                    }
                                    1 => Err(OwnerError::Transport(crate::DeliveryError::Receipt)),
                                    2 => {
                                        Err(OwnerError::Transport(crate::DeliveryError::Transport))
                                    }
                                    _ => Ok(candidate),
                                }
                            }
                        })
                        .await;
                    assert!(result.is_err());
                    assert!(!pool.enabled.load(Ordering::Acquire));
                    assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
                    assert!(pool.try_fragment(token, b"late").is_err());
                });
        }
    }

    #[test]
    fn aggregate_quota_drift_invalidates_without_install() {
        let now = time::OffsetDateTime::now_utc();
        let mut owners = vec![make_owner_at(now), make_owner_at(now)];
        for owner in &mut owners {
            owner.configured_queue_bytes = 6000;
        }
        let pool = CollectorPool::new(owners).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let mut candidates = [Some(candidate_at(now)), Some(candidate_at(now))];
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let token = pool.try_begin(&scope()).unwrap();
                pool.try_fragment(token, b"private").unwrap();
                let original = pool.slots[0]
                    .try_lock()
                    .unwrap()
                    .live
                    .as_ref()
                    .unwrap()
                    .deadline;
                assert!(
                    pool.renew_with(|i| {
                        let c = candidates[i].take().unwrap();
                        async move { Ok(c) }
                    })
                    .await
                    .is_err()
                );
                assert!(!pool.enabled.load(Ordering::Acquire));
                assert_eq!(
                    pool.slots[0]
                        .try_lock()
                        .unwrap()
                        .live
                        .as_ref()
                        .unwrap()
                        .deadline,
                    original
                );
                assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
            });
    }

    #[test]
    fn commit_owner_contention_counts_capture_loss() {
        let now = time::OffsetDateTime::now_utc();
        let mut owners = vec![make_owner_at(now), make_owner_at(now)];
        for owner in &mut owners {
            owner.configured_queue_bytes = 4000;
        }
        let pool = CollectorPool::new(owners).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let mut candidates = [Some(candidate_at(now)), Some(candidate_at(now))];
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let token = pool.try_begin(&scope()).unwrap();
                assert_eq!(token.slot, 0);
                pool.try_fragment(token, b"prefix").unwrap();
                let busy = pool.slots[1].lock().await;
                let mut renewal = Box::pin(pool.renew_with(|i| {
                    let c = candidates[i].take().unwrap();
                    async move { Ok(c) }
                }));
                poll_fn(|cx| {
                    assert!(renewal.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert!(pool.try_fragment(token, b"suffix").is_err());
                assert_eq!(pool.losses(), 1);
                drop(renewal);
                assert!(pool.slots[0].try_lock().unwrap().streams.is_empty());
                drop(busy);
            });
    }

    #[test]
    fn pending_send_does_not_block_fetch_and_renewal_cancel_interrupts_send() {
        let now = time::OffsetDateTime::now_utc();
        let mut owners = vec![make_owner_at(now), make_owner_at(now)];
        for owner in &mut owners {
            owner.configured_queue_bytes = 4000;
        }
        let pool = CollectorPool::new(owners).unwrap();
        pool.enabled.store(true, Ordering::Release);
        pool.blocked_sends.store(1, Ordering::Release);
        let mut candidates = [Some(candidate_at(now)), Some(candidate_at(now))];
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut send = Box::pin(pool.send(0));
                poll_fn(|cx| {
                    assert!(send.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                let token = pool.try_begin(&scope()).unwrap();
                assert_eq!(token.slot, 1);
                pool.try_fragment(token, b"before").unwrap();
                let mut renewal = Box::pin(pool.renew_with(|i| {
                    let candidate = candidates[i].take().unwrap();
                    async move { Ok(candidate) }
                }));
                poll_fn(|cx| {
                    assert!(renewal.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                pool.try_fragment(token, b"after").unwrap();
                drop(renewal);
                assert!(!pool.enabled.load(Ordering::Acquire));
                assert!(pool.slots[1].try_lock().unwrap().streams.is_empty());
                poll_fn(|cx| {
                    assert!(matches!(
                        send.as_mut().poll(cx),
                        Poll::Ready(Err(OwnerError::Paused))
                    ));
                    Poll::Ready(())
                })
                .await;
            });
    }

    #[test]
    fn partial_pool_failure_invalidates_all_slots_without_install() {
        let now = time::OffsetDateTime::now_utc();
        let mut owners = vec![make_owner_at(now), make_owner_at(now)];
        for owner in &mut owners {
            owner.configured_queue_bytes = 4000;
        }
        let pool = CollectorPool::new(owners).unwrap();
        pool.enabled.store(true, Ordering::Release);
        let mut candidate = Some(candidate_at(now));
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let token = pool.try_begin(&scope()).unwrap();
                pool.try_fragment(token, b"private").unwrap();
                let original = pool.slots[0]
                    .try_lock()
                    .unwrap()
                    .live
                    .as_ref()
                    .unwrap()
                    .deadline;
                let result = pool
                    .renew_with(|index| {
                        let candidate = if index == 0 { candidate.take() } else { None };
                        async move { candidate.ok_or(OwnerError::Paused) }
                    })
                    .await;
                assert!(result.is_err());
                assert!(!pool.enabled.load(Ordering::Acquire));
                assert!(
                    pool.slots
                        .iter()
                        .all(|slot| slot.try_lock().unwrap().streams.is_empty())
                );
                assert_eq!(
                    pool.slots[0]
                        .try_lock()
                        .unwrap()
                        .live
                        .as_ref()
                        .unwrap()
                        .deadline,
                    original
                );
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
