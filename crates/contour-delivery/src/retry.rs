//! Metadata-only caller-driven decisions. No queue, payload or enrollment grant.
use crate::DeliveryError;
use contour_core::{DeliveryBinding, DeliveryReservation};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};
use time::OffsetDateTime;
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryDirective {
    Retry { after: Duration },
    DiscardInvalid,
    RenewAuthorizedEnrollment,
    StopConflict,
    RequireSplit,
    StopRejected(u16),
    StopConfiguration,
    Expired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryError {
    Binding,
    Stopped,
    Entropy,
    Clock,
}
impl std::fmt::Display for RetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RetryError {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    Ready,
    Expired,
    Cancelled,
}
/// One frozen binding, not a scheduler. Terminal states have no resume shortcut:
/// authorized enrollment/renewal must be implemented by a separate trust boundary.
/// After every wait, obtain fresh trusted inputs and reserve again before I/O.
pub struct RetryController {
    binding: DeliveryBinding,
    expires: OffsetDateTime,
    ceiling: u64,
    directive: Option<RetryDirective>,
    due: Option<(Instant, Instant)>,
    random: SystemRandom,
}
impl std::fmt::Debug for RetryController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetryController")
    }
}
impl RetryController {
    pub fn for_attempt(attempt: &mut DeliveryReservation<'_>) -> Self {
        let view = attempt.view();
        Self {
            binding: view.binding(),
            expires: view.deadline(),
            ceiling: 1,
            directive: None,
            due: None,
            random: SystemRandom::new(),
        }
    }
    pub fn binding(&self) -> DeliveryBinding {
        self.binding
    }
    /// Owner must schedule deletion-only maintenance at this TTL while paused.
    pub fn retained_until(&self) -> OffsetDateTime {
        self.expires
    }
    /// Nonretryable decisions are terminal. Apply DiscardInvalid using the queue's
    /// binding-checked discard_frozen; its safe loss counter remains queue-owned.
    pub fn on_failure(
        &mut self,
        binding: DeliveryBinding,
        error: DeliveryError,
    ) -> Result<RetryDirective, RetryError> {
        if binding != self.binding {
            return Err(RetryError::Binding);
        }
        if self
            .directive
            .is_some_and(|d| !matches!(d, RetryDirective::Retry { .. }))
        {
            return Err(RetryError::Stopped);
        }
        let (terminal, retry_after) = match error {
            DeliveryError::Rejected {
                status,
                retry_after,
            } => (
                match status {
                    400 | 422 => Some(RetryDirective::DiscardInvalid),
                    401 | 403 => Some(RetryDirective::RenewAuthorizedEnrollment),
                    409 => Some(RetryDirective::StopConflict),
                    413 => Some(RetryDirective::RequireSplit),
                    429 | 500..=599 => None,
                    _ => Some(RetryDirective::StopRejected(status)),
                },
                retry_after,
            ),
            DeliveryError::Configuration => (Some(RetryDirective::StopConfiguration), None),
            _ => (None, None),
        };
        if let Some(directive) = terminal {
            self.directive = Some(directive);
            self.due = None;
            return Ok(directive);
        }
        let started = Instant::now();
        // Lease/capture authority is deliberately not renewed by a retry wait.
        // Record TTL conversion depends on the same operator-trusted wall clock.
        let remaining = self.expires - OffsetDateTime::now_utc();
        if remaining <= time::Duration::ZERO {
            self.directive = Some(RetryDirective::Expired);
            self.due = None;
            return Ok(RetryDirective::Expired);
        }
        let lifetime = Duration::try_from(remaining).map_err(|_| RetryError::Stopped)?;
        let jitter = self.jitter().inspect_err(|_| {
            self.directive = Some(RetryDirective::StopConfiguration);
            self.due = None;
        })?;
        let after = jitter
            .max(
                retry_after
                    .unwrap_or(Duration::ZERO)
                    .min(Duration::from_secs(300)),
            )
            .min(lifetime);
        self.ceiling = (self.ceiling * 2).min(60);
        let expiry = started.checked_add(lifetime).ok_or_else(|| {
            self.directive = Some(RetryDirective::StopConfiguration);
            self.due = None;
            RetryError::Clock
        })?;
        let due = started.checked_add(after).ok_or_else(|| {
            self.directive = Some(RetryDirective::StopConfiguration);
            self.due = None;
            RetryError::Clock
        })?;
        self.due = Some((due, expiry));
        let directive = RetryDirective::Retry { after };
        self.directive = Some(directive);
        Ok(directive)
    }
    /// Owns only a timer and caller's cancellation future; no reservation/body.
    /// Drop this wait on trusted policy updates, expire/reconcile the queue, then
    /// re-reserve with fresh inputs. This does not service a capture channel.
    pub async fn wait(&self, cancel: impl Future<Output = ()>) -> Result<WaitOutcome, RetryError> {
        let (due, expiry) = self.due.ok_or(RetryError::Stopped)?;
        let mut timer = std::pin::pin!(tokio::time::sleep_until(due));
        let mut cancel = std::pin::pin!(cancel);
        Ok(poll_fn(|cx| {
            if cancel.as_mut().poll(cx).is_ready() {
                return Poll::Ready(WaitOutcome::Cancelled);
            }
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(if Instant::now() >= expiry {
                    WaitOutcome::Expired
                } else {
                    WaitOutcome::Ready
                });
            }
            Poll::Pending
        })
        .await)
    }
    fn jitter(&self) -> Result<Duration, RetryError> {
        // Uniform millisecond samples in [0, nominal ceiling], with rejection
        // rather than modulo bias. Bounded entropy attempts; fail closed on error.
        let width = u32::try_from(self.ceiling * 1000 + 1).map_err(|_| RetryError::Entropy)?;
        let limit = u32::MAX - u32::MAX % width;
        for _ in 0..4 {
            let mut bytes = [0; 4];
            self.random
                .fill(&mut bytes)
                .map_err(|_| RetryError::Entropy)?;
            let value = u32::from_le_bytes(bytes);
            if value < limit {
                return Ok(Duration::from_millis(u64::from(value % width)));
            }
        }
        Err(RetryError::Entropy)
    }
}
