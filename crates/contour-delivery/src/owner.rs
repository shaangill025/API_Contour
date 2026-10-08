//! Caller-driven exclusive collector ownership; online refresh is the only grant.
use crate::{
    authority::{HISTORY_BYTES, LiveAuthority},
    *,
};
use contour_core::{
    AdmissionInputs, MemoryQueue, PolicyKeys, QueueLimits, QueueStats, RecordDraft, VerifiedPolicy,
};
use std::collections::BTreeSet;

#[derive(Debug)]
pub enum OwnerError {
    Paused,
    HistoryLimit,
    Queue(QueueError),
    Transport(DeliveryError),
    Retry(RetryError),
}
impl fmt::Display for OwnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for OwnerError {}
impl From<QueueError> for OwnerError {
    fn from(e: QueueError) -> Self {
        Self::Queue(e)
    }
}
impl From<DeliveryError> for OwnerError {
    fn from(e: DeliveryError) -> Self {
        Self::Transport(e)
    }
}
impl From<RetryError> for OwnerError {
    fn from(e: RetryError) -> Self {
        Self::Retry(e)
    }
}
#[derive(Debug)]
pub enum SendOutcome {
    Empty,
    Acknowledged {
        receipt_id: String,
        status: ReceiptStatus,
    },
    Deferred(RetryDirective),
}
struct PolicyEntry {
    policy: VerifiedPolicy,
    bytes: usize,
}
struct RetryState {
    controller: RetryController,
    directive: RetryDirective,
    ready: bool,
}
/// No cache bootstrap, shared queue handles, policy setters or exposed authority.
/// Dropping refresh/send futures releases transport and leaves this owner paused.
/// Callers must service expire_retained while paused; this is not a scheduler.
pub struct CollectorOwner {
    client: DeliveryClient,
    keys: PolicyKeys,
    source_ids: Vec<String>,
    queue: MemoryQueue,
    policies: Vec<PolicyEntry>,
    live: Option<LiveAuthority>,
    retry: Option<RetryState>,
}
impl CollectorOwner {
    pub fn new(
        client: DeliveryClient,
        keys: PolicyKeys,
        source_ids: &[&str],
        limits: QueueLimits,
    ) -> Result<Self, OwnerError> {
        if source_ids.is_empty()
            || source_ids.len() > 500
            || source_ids.iter().any(|s| !uuid(s))
            || source_ids.iter().copied().collect::<BTreeSet<_>>().len() != source_ids.len()
        {
            return Err(DeliveryError::Configuration.into());
        }
        let queue = MemoryQueue::new(client.identity.each_ref().map(String::as_str), limits)?;
        Ok(Self {
            client,
            keys,
            source_ids: source_ids.iter().map(|s| (*s).to_owned()).collect(),
            queue,
            policies: Vec::new(),
            live: None,
            retry: None,
        })
    }
    pub fn stats(&self) -> QueueStats {
        self.queue.stats()
    }
    pub fn is_live(&self) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| Instant::now() < live.deadline)
            && self.policies.last().is_some_and(|p| {
                p.policy
                    .validate_capture_at(OffsetDateTime::now_utc())
                    .is_ok()
            })
    }
    fn guard(&mut self) -> Result<(), OwnerError> {
        if !self.is_live() {
            self.live = None;
            return Err(OwnerError::Paused);
        }
        Ok(())
    }
    fn prune_history(&mut self) {
        let retained = self
            .queue
            .retained_policy_revisions()
            .collect::<BTreeSet<_>>();
        let current = self.policies.last().map(|p| p.policy.revision());
        self.policies.retain(|p| {
            Some(p.policy.revision()) == current || retained.contains(&p.policy.revision())
        });
    }
    pub fn expire_retained(&mut self) -> Result<(), OwnerError> {
        self.queue.expire_retained()?;
        self.prune_history();
        if self.queue.stats().records == 0 {
            self.retry = None;
        }
        if !self.is_live() {
            self.live = None;
        }
        Ok(())
    }
    /// Failure/cancellation cannot extend the old lease. HTTP403 is a pause, not
    /// irreversible queue revocation. History is bounded without forgetting records.
    pub async fn refresh(&mut self) -> Result<(), OwnerError> {
        self.live = None;
        self.expire_retained()?;
        let fresh = self
            .client
            .refresh_authority(&self.source_ids, &self.keys)
            .await?;
        let same_revision = self
            .policies
            .last()
            .is_some_and(|p| p.policy.revision() == fresh.policy.revision());
        let retained = self
            .queue
            .retained_policy_revisions()
            .collect::<BTreeSet<_>>();
        let needed = |p: &&PolicyEntry| same_revision || retained.contains(&p.policy.revision());
        let bytes: usize = self.policies.iter().filter(needed).map(|p| p.bytes).sum();
        let count = self.policies.iter().filter(needed).count();
        if !same_revision
            && (count >= 500
                || bytes
                    .checked_add(fresh.envelope_bytes)
                    .is_none_or(|n| n > HISTORY_BYTES))
        {
            return Err(OwnerError::HistoryLimit);
        }
        let mut refs = self
            .policies
            .iter()
            .filter(needed)
            .map(|p| &p.policy)
            .collect::<Vec<_>>();
        if !same_revision {
            refs.push(&fresh.policy);
        }
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            &fresh.policy,
            &refs,
            &fresh.live.sources,
        )
        .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        // Existing highwater/content checks run even for an otherwise valid reply.
        self.queue.reconcile(&inputs)?;
        if !same_revision {
            self.policies
                .retain(|p| retained.contains(&p.policy.revision()));
            self.policies.push(PolicyEntry {
                policy: fresh.policy,
                bytes: fresh.envelope_bytes,
            });
        }
        self.prune_history();
        if Instant::now() >= fresh.live.deadline {
            return Err(DeliveryError::Deadline.into());
        }
        if self
            .retry
            .as_ref()
            .is_some_and(|r| r.directive == RetryDirective::RenewAuthorizedEnrollment)
        {
            self.retry = None;
        }
        self.live = Some(fresh.live);
        self.guard()
    }
    pub fn admit(&mut self, draft: RecordDraft) -> Result<(), OwnerError> {
        self.guard()?;
        let live = self.live.as_ref().ok_or(OwnerError::Paused)?;
        let refs = self.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            refs.last().ok_or(OwnerError::Paused)?,
            &refs,
            &live.sources,
        )
        .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        self.queue.admit(draft, &inputs)?;
        self.guard()
    }
    pub fn freeze(&mut self, batch_id: &str, maximum_records: usize) -> Result<bool, OwnerError> {
        self.guard()?;
        let live = self.live.as_ref().ok_or(OwnerError::Paused)?;
        let refs = self.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            refs.last().ok_or(OwnerError::Paused)?,
            &refs,
            &live.sources,
        )
        .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        let frozen = self
            .queue
            .freeze(batch_id, maximum_records, &inputs)?
            .is_some();
        self.guard()?;
        if frozen {
            self.retry = None;
        }
        Ok(frozen)
    }
    /// Outer monotonic authority cap applies in addition to send_once's local
    /// wallclock/attempt deadline. On cancellation all I/O and reservations drop.
    pub async fn send_once(&mut self) -> Result<SendOutcome, OwnerError> {
        self.guard()?;
        if let Some(retry) = &self.retry {
            if !retry.ready {
                return Ok(SendOutcome::Deferred(retry.directive));
            }
        }
        let live = self.live.take().ok_or(OwnerError::Paused)?;
        let refs = self.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            refs.last().ok_or(OwnerError::Paused)?,
            &refs,
            &live.sources,
        )
        .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        let Some(mut attempt) = self.queue.reserve_delivery(&inputs)? else {
            self.retry = None;
            self.live = Some(live);
            return Ok(SendOutcome::Empty);
        };
        let binding = attempt.view().binding();
        let mut controller = match self.retry.take() {
            Some(retry) if retry.controller.binding() == binding => retry.controller,
            _ => RetryController::for_attempt(&mut attempt),
        };
        let result = timeout_at(live.deadline, self.client.send_once(&mut attempt))
            .await
            .unwrap_or(Err(DeliveryError::Deadline));
        let result = if Instant::now() >= live.deadline
            || self.policies.last().is_none_or(|p| {
                p.policy
                    .validate_capture_at(OffsetDateTime::now_utc())
                    .is_err()
            }) {
            Err(DeliveryError::Deadline)
        } else {
            result
        };
        match result {
            Ok(receipt) => {
                let outcome = SendOutcome::Acknowledged {
                    receipt_id: receipt.receipt_id().to_owned(),
                    status: receipt.status(),
                };
                receipt.acknowledge(attempt)?;
                self.live = Some(live);
                self.prune_history();
                Ok(outcome)
            }
            Err(error) => {
                drop(attempt); // I/O already dropped; release queue before decisions.
                let directive = controller.on_failure(binding, error)?;
                if directive == RetryDirective::DiscardInvalid {
                    self.queue.discard_frozen(binding)?;
                } else {
                    self.retry = Some(RetryState {
                        controller,
                        directive,
                        ready: false,
                    });
                }
                if directive != RetryDirective::RenewAuthorizedEnrollment
                    && Instant::now() < live.deadline
                {
                    self.live = Some(live);
                }
                self.expire_retained()?;
                Ok(SendOutcome::Deferred(directive))
            }
        }
    }
    pub async fn wait_retry(
        &mut self,
        cancel: impl Future<Output = ()>,
    ) -> Result<WaitOutcome, OwnerError> {
        let state = self
            .retry
            .as_mut()
            .ok_or(OwnerError::Retry(RetryError::Stopped))?;
        let outcome = state.controller.wait(cancel).await?;
        state.ready = outcome == WaitOutcome::Ready;
        if outcome == WaitOutcome::Cancelled {
            self.live = None;
        }
        self.expire_retained()?;
        Ok(outcome)
    }
}
