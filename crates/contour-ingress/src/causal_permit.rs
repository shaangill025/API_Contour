//! Dormant, single-generation private channel; the trusted launcher owns both ends.
use crate::{CausalIssueOwner, CausalJournalError};
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::{CausalError, CausalIssuer, CausalMarkerBinder, CausalSession};
use std::{os::unix::net::UnixStream as StdStream, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{Instant, sleep, timeout, timeout_at},
};

const REQUEST: usize = 108;
const MAX_LEASE_MS: u128 = 1000;
const REFRESH_BUDGET: Duration = Duration::from_millis(500);
pub(crate) const STARTUP_BUDGET: Duration = Duration::from_secs(2);
const BACKOFF_MS: [u64; 5] = [10, 20, 40, 80, 80];

pub(crate) struct RetryWindow {
    pub(crate) deadline: Instant,
    pub(crate) epoch: Option<u64>,
    pub(crate) ceiling: Option<Instant>,
}
impl RetryWindow {
    pub(crate) fn retain(&mut self, session: &CausalSession) -> Result<(), CausalError> {
        let anchor = Instant::now();
        self.retain_values(session.epoch(), session.verified_remaining(), anchor)
    }
    fn retain_values(
        &mut self,
        epoch: u64,
        remaining: Duration,
        now: Instant,
    ) -> Result<(), CausalError> {
        if self.epoch.is_some_and(|old| old != epoch) {
            return Err(CausalError::Scope);
        }
        let current = now.checked_add(remaining).ok_or(CausalError::Expired)?;
        let ceiling = self.ceiling.map_or(current, |old| old.min(current));
        if ceiling <= now {
            return Err(CausalError::Expired);
        }
        self.epoch = Some(epoch);
        self.ceiling = Some(ceiling);
        Ok(())
    }
    pub(crate) fn remaining_deadline(&self) -> Instant {
        self.ceiling
            .map_or(self.deadline, |ceiling| ceiling.min(self.deadline))
    }
    fn delay(&self, error: CausalError, attempt: usize, now: Instant) -> Option<Duration> {
        if error != CausalError::Busy {
            return None;
        }
        let wait = Duration::from_millis(*BACKOFF_MS.get(attempt)?);
        (now.checked_add(wait)? < self.remaining_deadline()).then_some(wait)
    }
}

trait RefreshAttempt {
    type Output;
    fn attempt<'a>(
        &'a mut self,
        window: &'a mut RetryWindow,
    ) -> impl std::future::Future<Output = Result<Self::Output, CausalError>> + Send + 'a;
}
struct DatabaseAttempt<'a> {
    owner: &'a mut CausalIssueOwner,
    issuer: &'a mut CausalIssuer,
    generation: &'a [u8; 32],
    peer: &'a [u8; 32],
    grant: &'a CausalGrantKeys,
    policy: &'a PolicyKeys,
}
impl RefreshAttempt for DatabaseAttempt<'_> {
    type Output = CausalSession;
    async fn attempt(&mut self, window: &mut RetryWindow) -> Result<CausalSession, CausalError> {
        let mut session = self
            .owner
            .issue_until(
                self.issuer,
                self.peer,
                self.grant,
                self.policy,
                window.remaining_deadline(),
            )
            .await?;
        window.retain(&session)?;
        self.issuer
            .claim_generation_until(
                &mut session,
                self.generation,
                self.peer,
                self.grant,
                self.policy,
                window.remaining_deadline(),
            )
            .await?;
        window.retain(&session)?;
        Ok(session)
    }
}
async fn retry_checked<A: RefreshAttempt>(
    operation: &mut A,
    window: &mut RetryWindow,
) -> Result<A::Output, CausalError> {
    for attempt in 0..=BACKOFF_MS.len() {
        if Instant::now() >= window.remaining_deadline() {
            return Err(CausalError::Deadline);
        }
        match operation.attempt(window).await {
            Ok(session) if Instant::now() < window.remaining_deadline() => return Ok(session),
            Ok(_) => return Err(CausalError::Deadline),
            Err(error) => match window.delay(error, attempt, Instant::now()) {
                Some(wait) => sleep(wait).await,
                None => return Err(error),
            },
        }
    }
    Err(CausalError::Database)
}
pub(crate) async fn checked_refresh(
    owner: &mut CausalIssueOwner,
    issuer: &mut CausalIssuer,
    generation: &[u8; 32],
    peer: &[u8; 32],
    grant: &CausalGrantKeys,
    policy: &PolicyKeys,
    window: &mut RetryWindow,
) -> Result<CausalSession, CausalError> {
    retry_checked(
        &mut DatabaseAttempt {
            owner,
            issuer,
            generation,
            peer,
            grant,
            policy,
        },
        window,
    )
    .await
}
fn valid_request(
    r: &[u8; REQUEST],
    generation: &[u8; 32],
    identity: &[u8; 32],
    next: u64,
    previous: &[u8; 32],
) -> bool {
    &r[..4] == b"CQP1"
        && r[4..36] == *generation
        && r[36..68] == *identity
        && u64::from_be_bytes(r[68..76].try_into().unwrap()) == next
        && r[76..] != [0; 32]
        && r[76..] != *previous
}

#[derive(PartialEq, Eq)]
struct SelectedScope {
    tenant: String,
    runtime: String,
    nonce: String,
    epoch: u64,
}
pub(crate) struct SelectedBinding {
    pub(crate) product_credential: String,
    pub(crate) product_leaf: [u8; 32],
    pub(crate) marker_public: [u8; 32],
    pub(crate) peer: [u8; 32],
    scope: Option<SelectedScope>,
}
impl SelectedBinding {
    pub(crate) fn new(
        product_credential: String,
        product_leaf: [u8; 32],
        marker_public: [u8; 32],
        peer: [u8; 32],
    ) -> Self {
        Self {
            product_credential,
            product_leaf,
            marker_public,
            peer,
            scope: None,
        }
    }
    fn observe(&mut self, session: &CausalSession) -> Result<(), CausalError> {
        if !session.matches_peer(&self.peer) {
            return Err(CausalError::Identity);
        }
        let v = session.wire_profile_503().ok_or(CausalError::Identity)?;
        let current = SelectedScope {
            tenant: v.tenant_id().into(),
            runtime: v.runtime_id().into(),
            nonce: v.nonce().into(),
            epoch: v.epoch(),
        };
        match &self.scope {
            Some(original) if *original != current => Err(CausalError::Scope),
            Some(_) => Ok(()),
            None => {
                self.scope = Some(current);
                Ok(())
            }
        }
    }
}
trait MarkerCheck {
    type Session;
    async fn check(
        &mut self,
        session: &mut Self::Session,
        deadline: Instant,
    ) -> Result<(), CausalError>;
}
struct DatabaseMarkerCheck<'a> {
    binder: &'a mut CausalMarkerBinder,
    selected: &'a SelectedBinding,
    generation: &'a [u8; 32],
    grant: &'a CausalGrantKeys,
    policy: &'a PolicyKeys,
}
impl MarkerCheck for DatabaseMarkerCheck<'_> {
    type Session = CausalSession;
    async fn check(
        &mut self,
        session: &mut CausalSession,
        deadline: Instant,
    ) -> Result<(), CausalError> {
        let receipt = self
            .binder
            .bind_until(
                session,
                self.generation,
                &self.selected.product_credential,
                &self.selected.product_leaf,
                &self.selected.marker_public,
                &self.selected.peer,
                self.grant,
                self.policy,
                deadline,
            )
            .await?;
        if receipt.public_key() != self.selected.marker_public {
            return Err(CausalError::Identity);
        }
        Ok(())
    }
}
async fn require_marker<C: MarkerCheck>(
    check: &mut C,
    session: &mut C::Session,
    deadline: Instant,
) -> Result<(), CausalError> {
    if Instant::now() >= deadline {
        return Err(CausalError::Deadline);
    }
    // If the outer timer wins, cancellation may race a COMMIT. Preserve the
    // uncertainty rather than reporting a definitely pre-commit deadline.
    let result = timeout_at(deadline, check.check(session, deadline))
        .await
        .map_err(|_| CausalError::OutcomeUnknown)?;
    result?;
    if Instant::now() >= deadline {
        return Err(CausalError::Deadline);
    }
    Ok(())
}

pub(crate) struct BoundDatabaseAttempt<'a> {
    pub(crate) owner: &'a mut CausalIssueOwner,
    pub(crate) issuer: &'a mut CausalIssuer,
    pub(crate) binder: &'a mut CausalMarkerBinder,
    pub(crate) generation: &'a [u8; 32],
    pub(crate) selected: &'a mut SelectedBinding,
    pub(crate) grant: &'a CausalGrantKeys,
    pub(crate) policy: &'a PolicyKeys,
}
impl RefreshAttempt for BoundDatabaseAttempt<'_> {
    type Output = CausalSession;
    async fn attempt(&mut self, window: &mut RetryWindow) -> Result<CausalSession, CausalError> {
        let peer = self.selected.peer;
        let mut session = DatabaseAttempt {
            owner: self.owner,
            issuer: self.issuer,
            generation: self.generation,
            peer: &peer,
            grant: self.grant,
            policy: self.policy,
        }
        .attempt(window)
        .await?;
        self.selected.observe(&session)?;
        let mut check = DatabaseMarkerCheck {
            binder: self.binder,
            selected: self.selected,
            generation: self.generation,
            grant: self.grant,
            policy: self.policy,
        };
        require_marker(&mut check, &mut session, window.remaining_deadline()).await?;
        window.retain(&session)?;
        self.selected.observe(&session)?;
        Ok(session)
    }
}
pub(crate) async fn checked_bound_refresh(
    attempt: &mut BoundDatabaseAttempt<'_>,
    window: &mut RetryWindow,
) -> Result<CausalSession, CausalError> {
    retry_checked(attempt, window).await
}

/// Claim is durable before the child is launched. Never reuse an old owner for a
/// replacement; an uncertain claim remains consumed and requires a new issue.
pub struct CausalPermitOwner {
    owner: CausalIssueOwner,
    stream: UnixStream,
    generation: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
    ceiling: tokio::time::Instant,
    bound_session: Option<CausalSession>,
    selected: Option<SelectedBinding>,
}
impl CausalPermitOwner {
    pub(crate) fn from_bound(proof: crate::causal_launch_bound::BoundPermitProof) -> Self {
        let (owner, stream, generation, identity, epoch, ceiling, session, selected) =
            proof.into_parts();
        Self {
            owner,
            stream,
            generation,
            identity,
            epoch,
            ceiling,
            bound_session: Some(session),
            selected: Some(selected),
        }
    }
    pub(crate) fn bound_fresh(&self) -> bool {
        self.bound_session.as_ref().is_some_and(|session| {
            session.wire_profile_503().is_some()
                && session.epoch() == self.epoch
                && Instant::now() < self.ceiling
        })
    }
    /// `identity` is the trusted launcher's commitment to the entire selected
    /// configuration, including all three separate key identities and endpoints.
    /// Both the descriptor and this commitment must be passed privately to only
    /// the intended child. This API does not attest the child or its source.
    pub async fn claim(
        mut owner: CausalIssueOwner,
        stream: StdStream,
        identity: [u8; 32],
        issuer: &mut CausalIssuer,
        peer: &[u8; 32],
        grant: &CausalGrantKeys,
        policy: &PolicyKeys,
    ) -> Result<Self, CausalJournalError> {
        if identity == [0; 32] {
            return Err(CausalJournalError::Unsafe);
        }
        stream
            .set_nonblocking(true)
            .map_err(|_| CausalJournalError::Io)?;
        let stream = UnixStream::from_std(stream).map_err(|_| CausalJournalError::Io)?;
        let generation = owner.claim_generation()?;
        let mut window = RetryWindow {
            deadline: Instant::now() + STARTUP_BUDGET,
            epoch: None,
            ceiling: None,
        };
        let session = checked_refresh(
            &mut owner,
            issuer,
            &generation,
            peer,
            grant,
            policy,
            &mut window,
        )
        .await
        .map_err(|_| CausalJournalError::Io)?;
        if !session.is_legacy_intent_profile() {
            return Err(CausalJournalError::Mismatch);
        }
        owner.consume_launch()?;
        let anchor = tokio::time::Instant::now();
        let remaining = session.verified_remaining();
        if remaining.is_zero() {
            return Err(CausalJournalError::Io);
        }
        Ok(Self {
            owner,
            stream,
            generation,
            identity,
            epoch: session.epoch(),
            ceiling: window
                .ceiling
                .ok_or(CausalJournalError::Io)?
                .min(anchor + remaining),
            bound_session: None,
            selected: None,
        })
    }
    /// Only pass to the one selected child over its inherited private launch path.
    pub fn generation(&self) -> [u8; 32] {
        self.generation
    }
    /// Every response requires a fresh checked issuer transaction. Any error or
    /// channel closure terminates this generation; only confirmed gate contention
    /// retries the complete check within the original response budget.
    pub async fn serve(
        self,
        issuer: &mut CausalIssuer,
        peer: &[u8; 32],
        grant: &CausalGrantKeys,
        policy: &PolicyKeys,
    ) {
        if self.selected.is_some() || self.bound_session.is_some() {
            return;
        }
        self.serve_inner(issuer, None, peer, grant, policy).await;
    }
    /// Bound sessions require an independent SQL23 recheck of the exact selected
    /// credential and marker before every permit. Any failure closes the stream.
    pub async fn serve_bound(
        self,
        issuer: &mut CausalIssuer,
        binder: &mut CausalMarkerBinder,
        peer: &[u8; 32],
        grant: &CausalGrantKeys,
        policy: &PolicyKeys,
    ) {
        if !self.bound_fresh() || self.selected.as_ref().is_none_or(|s| &s.peer != peer) {
            return;
        }
        self.serve_inner(issuer, Some(binder), peer, grant, policy)
            .await;
    }
    async fn serve_inner(
        mut self,
        issuer: &mut CausalIssuer,
        mut binder: Option<&mut CausalMarkerBinder>,
        peer: &[u8; 32],
        grant: &CausalGrantKeys,
        policy: &PolicyKeys,
    ) {
        let mut count = 0u64;
        let mut last_challenge = [0u8; 32];
        let mut ceiling = self.ceiling;
        loop {
            if self.bound_session.is_some() && !self.bound_fresh() {
                return;
            }
            let mut request = [0u8; REQUEST];
            if !matches!(
                timeout(Duration::from_secs(2), self.stream.read_exact(&mut request)).await,
                Ok(Ok(_))
            ) {
                return;
            }
            let counter = u64::from_be_bytes(request[68..76].try_into().unwrap());
            let Some(next) = count.checked_add(1) else {
                return;
            };
            if !valid_request(
                &request,
                &self.generation,
                &self.identity,
                next,
                &last_challenge,
            ) {
                return;
            }
            last_challenge.copy_from_slice(&request[76..]);
            let mut window = RetryWindow {
                deadline: Instant::now() + REFRESH_BUDGET,
                epoch: Some(self.epoch),
                ceiling: Some(ceiling),
            };
            let session = if let Some(selected) = self.selected.as_mut() {
                if &selected.peer != peer {
                    return;
                }
                let Some(binder) = binder.as_deref_mut() else {
                    return;
                };
                let mut attempt = BoundDatabaseAttempt {
                    owner: &mut self.owner,
                    issuer,
                    binder,
                    generation: &self.generation,
                    selected,
                    grant,
                    policy,
                };
                match checked_bound_refresh(&mut attempt, &mut window).await {
                    Ok(session) => session,
                    Err(_) => return,
                }
            } else {
                match checked_refresh(
                    &mut self.owner,
                    issuer,
                    &self.generation,
                    peer,
                    grant,
                    policy,
                    &mut window,
                )
                .await
                {
                    Ok(session) if session.is_legacy_intent_profile() => session,
                    _ => return,
                }
            };
            if self.bound_session.is_some() && !self.bound_fresh() {
                return;
            }
            let now = tokio::time::Instant::now();
            let checked = match now.checked_add(session.verified_remaining()) {
                Some(v) => v,
                None => return,
            };
            let limit = ceiling.min(checked).min(window.ceiling.unwrap_or(ceiling));
            ceiling = limit;
            let millis = limit
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .min(MAX_LEASE_MS) as u32;
            if millis == 0 {
                return;
            }
            let mut response = Vec::with_capacity(120);
            response.extend_from_slice(b"CRP1");
            response.extend_from_slice(&request[4..]);
            response.extend_from_slice(&session.epoch().to_be_bytes());
            response.extend_from_slice(&millis.to_be_bytes());
            if !matches!(
                timeout_at(
                    window.remaining_deadline(),
                    self.stream.write_all(&response)
                )
                .await,
                Ok(Ok(()))
            ) {
                return;
            }
            count = counter;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn retry_restarts_full_attempt_only_for_confirmed_busy() {
        use std::collections::VecDeque;
        struct Script {
            steps: VecDeque<(bool, Option<CausalError>)>,
            issues: usize,
            claims: usize,
        }
        impl RefreshAttempt for Script {
            type Output = ();
            async fn attempt(&mut self, window: &mut RetryWindow) -> Result<(), CausalError> {
                self.issues += 1;
                let (issue_succeeds, error) = self.steps.pop_front().unwrap();
                if !issue_succeeds {
                    return Err(error.unwrap());
                }
                window.retain_values(7, Duration::from_secs(1), Instant::now())?;
                self.claims += 1;
                if let Some(error) = error {
                    return Err(error);
                }
                Ok(())
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (steps, expected, issues, claims) in [
            (
                vec![(false, Some(CausalError::Busy)), (true, None)],
                Ok(()),
                2,
                1,
            ),
            (
                vec![(true, Some(CausalError::Busy)), (true, None)],
                Ok(()),
                2,
                2,
            ),
            (
                vec![(true, Some(CausalError::OutcomeUnknown))],
                Err(CausalError::OutcomeUnknown),
                1,
                1,
            ),
            (
                vec![(false, Some(CausalError::Database))],
                Err(CausalError::Database),
                1,
                0,
            ),
            (
                vec![(true, Some(CausalError::Scope))],
                Err(CausalError::Scope),
                1,
                1,
            ),
        ] {
            let mut script = Script {
                steps: steps.into(),
                issues: 0,
                claims: 0,
            };
            let mut window = RetryWindow {
                deadline: Instant::now() + Duration::from_secs(1),
                epoch: Some(7),
                ceiling: None,
            };
            assert_eq!(
                rt.block_on(retry_checked(&mut script, &mut window)),
                expected
            );
            assert_eq!((script.issues, script.claims), (issues, claims));
        }
        let mut script = Script {
            steps: vec![(false, Some(CausalError::Busy)); 6].into(),
            issues: 0,
            claims: 0,
        };
        let mut window = RetryWindow {
            deadline: Instant::now() + Duration::from_secs(1),
            epoch: None,
            ceiling: None,
        };
        assert_eq!(
            rt.block_on(retry_checked(&mut script, &mut window)),
            Err(CausalError::Busy)
        );
        assert_eq!(script.issues, 6);
        struct Slow;
        impl RefreshAttempt for Slow {
            type Output = ();
            async fn attempt(&mut self, _: &mut RetryWindow) -> Result<(), CausalError> {
                sleep(Duration::from_millis(20)).await;
                Ok(())
            }
        }
        let mut window = RetryWindow {
            deadline: Instant::now() + Duration::from_millis(10),
            epoch: None,
            ceiling: None,
        };
        assert_eq!(
            rt.block_on(retry_checked(&mut Slow, &mut window)),
            Err(CausalError::Deadline)
        );
    }
    #[test]
    fn retry_window_only_retries_busy_and_never_extends_ceiling_or_epoch() {
        let now = Instant::now();
        let mut window = RetryWindow {
            deadline: now + Duration::from_millis(500),
            epoch: None,
            ceiling: None,
        };
        window
            .retain_values(7, Duration::from_millis(300), now)
            .unwrap();
        assert_eq!(window.ceiling, Some(now + Duration::from_millis(300)));
        window
            .retain_values(7, Duration::from_secs(1), now)
            .unwrap();
        assert_eq!(window.ceiling, Some(now + Duration::from_millis(300)));
        assert_eq!(
            window.retain_values(8, Duration::from_secs(1), now),
            Err(CausalError::Scope)
        );
        for (i, ms) in BACKOFF_MS.iter().enumerate() {
            assert_eq!(
                window.delay(CausalError::Busy, i, now),
                Some(Duration::from_millis(*ms))
            );
        }
        assert_eq!(window.delay(CausalError::Busy, 5, now), None);
        for error in [
            CausalError::Database,
            CausalError::Deadline,
            CausalError::OutcomeUnknown,
            CausalError::Scope,
        ] {
            assert_eq!(window.delay(error, 0, now), None);
        }
        assert_eq!(
            window.delay(CausalError::Busy, 0, now + Duration::from_millis(290)),
            None
        );
    }
    #[test]
    fn socketpair_frames_bind_generation_identity_counter_and_challenge() {
        let (mut a, mut b) = StdStream::pair().unwrap();
        let mut r = [0u8; REQUEST];
        r[..4].copy_from_slice(b"CQP1");
        r[4..36].fill(1);
        r[36..68].fill(2);
        r[68..76].copy_from_slice(&1u64.to_be_bytes());
        r[76..].fill(3);
        a.write_all(&r).unwrap();
        let mut got = [0; REQUEST];
        b.read_exact(&mut got).unwrap();
        assert!(valid_request(&got, &[1; 32], &[2; 32], 1, &[0; 32]));
        assert!(!valid_request(&got, &[9; 32], &[2; 32], 1, &[0; 32]));
        assert!(!valid_request(&got, &[1; 32], &[9; 32], 1, &[0; 32]));
        assert!(!valid_request(&got, &[1; 32], &[2; 32], 2, &[0; 32]));
        assert!(!valid_request(&got, &[1; 32], &[2; 32], 1, &[3; 32]));
        got[76..].fill(0);
        assert!(!valid_request(&got, &[1; 32], &[2; 32], 1, &[0; 32]));
    }
    #[test]
    fn marker_recheck_failure_or_timeout_never_reaches_permit_write() {
        struct Fake {
            result: Result<(), CausalError>,
            calls: usize,
            seen: Option<Instant>,
            delay: Duration,
        }
        impl MarkerCheck for Fake {
            type Session = ();
            async fn check(&mut self, _: &mut (), deadline: Instant) -> Result<(), CausalError> {
                self.calls += 1;
                self.seen = Some(deadline);
                sleep(self.delay).await;
                self.result
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for error in [
            CausalError::Scope,
            CausalError::Identity,
            CausalError::Database,
            CausalError::OutcomeUnknown,
            CausalError::Deadline,
        ] {
            let mut check = Fake {
                result: Err(error),
                calls: 0,
                seen: None,
                delay: Duration::ZERO,
            };
            let deadline = Instant::now() + Duration::from_millis(500);
            let mut writes = 0;
            rt.block_on(async {
                if require_marker(&mut check, &mut (), deadline).await.is_ok() {
                    writes += 1;
                }
            });
            assert_eq!(check.calls, 1);
            assert_eq!(check.seen, Some(deadline));
            assert_eq!(writes, 0);
        }
        let mut slow = Fake {
            result: Ok(()),
            calls: 0,
            seen: None,
            delay: Duration::from_millis(50),
        };
        let deadline = Instant::now() + Duration::from_millis(10);
        assert_eq!(
            rt.block_on(require_marker(&mut slow, &mut (), deadline)),
            Err(CausalError::OutcomeUnknown)
        );
        assert_eq!(slow.calls, 1);
        let mut good = Fake {
            result: Ok(()),
            calls: 0,
            seen: None,
            delay: Duration::ZERO,
        };
        assert_eq!(
            rt.block_on(require_marker(
                &mut good,
                &mut (),
                Instant::now() + Duration::from_millis(500)
            )),
            Ok(())
        );
        assert_eq!(good.calls, 1);
    }
    #[test]
    fn cancelling_marker_recheck_drops_inflight_work() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct Guard(Arc<AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        struct Pending(Arc<AtomicBool>);
        impl MarkerCheck for Pending {
            type Session = ();
            async fn check(&mut self, _: &mut (), _: Instant) -> Result<(), CausalError> {
                let _guard = Guard(self.0.clone());
                std::future::pending().await
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let mut check = Pending(dropped.clone());
        rt.block_on(async {
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    require_marker(
                        &mut check,
                        &mut (),
                        Instant::now() + Duration::from_millis(500)
                    )
                )
                .await
                .is_err()
            );
        });
        assert!(dropped.load(Ordering::SeqCst));
    }
    #[test]
    fn bound_busy_restarts_entire_issue_claim_bind_once_per_attempt() {
        use std::collections::VecDeque;
        #[derive(Clone, Copy)]
        enum Stage {
            Issue,
            Claim,
            Bind,
            Success,
        }
        struct Script {
            stages: VecDeque<(Stage, CausalError)>,
            seen: Vec<Stage>,
            current_epoch: u64,
        }
        impl RefreshAttempt for Script {
            type Output = ();
            async fn attempt(&mut self, window: &mut RetryWindow) -> Result<(), CausalError> {
                let (stage, error) = self.stages.pop_front().unwrap();
                self.seen.push(Stage::Issue);
                if matches!(stage, Stage::Issue) {
                    return Err(error);
                }
                window.retain_values(
                    self.current_epoch,
                    Duration::from_millis(250),
                    Instant::now(),
                )?;
                self.seen.push(Stage::Claim);
                if matches!(stage, Stage::Claim) {
                    return Err(error);
                }
                self.seen.push(Stage::Bind);
                if matches!(stage, Stage::Bind) {
                    return Err(error);
                }
                Ok(())
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut script = Script {
            stages: VecDeque::from([
                (Stage::Issue, CausalError::Busy),
                (Stage::Claim, CausalError::Busy),
                (Stage::Bind, CausalError::Busy),
                (Stage::Success, CausalError::Busy),
            ]),
            seen: vec![],
            current_epoch: 7,
        };
        let start = Instant::now();
        let mut window = RetryWindow {
            deadline: start + Duration::from_millis(500),
            epoch: Some(7),
            ceiling: Some(start + Duration::from_millis(200)),
        };
        assert_eq!(rt.block_on(retry_checked(&mut script, &mut window)), Ok(()));
        assert_eq!(script.seen.len(), 9);
        assert_eq!(window.epoch, Some(7));
        assert!(window.ceiling.unwrap() <= start + Duration::from_millis(200));
        for terminal in [
            CausalError::Database,
            CausalError::Deadline,
            CausalError::OutcomeUnknown,
            CausalError::Scope,
        ] {
            let mut script = Script {
                stages: VecDeque::from([(Stage::Bind, terminal)]),
                seen: vec![],
                current_epoch: 7,
            };
            let mut window = RetryWindow {
                deadline: Instant::now() + Duration::from_millis(500),
                epoch: Some(7),
                ceiling: None,
            };
            assert_eq!(
                rt.block_on(retry_checked(&mut script, &mut window)),
                Err(terminal)
            );
            assert_eq!(script.seen.len(), 3);
        }
        let mut wrong_epoch = Script {
            stages: VecDeque::from([(Stage::Success, CausalError::Busy)]),
            seen: vec![],
            current_epoch: 8,
        };
        let mut window = RetryWindow {
            deadline: Instant::now() + Duration::from_millis(500),
            epoch: Some(7),
            ceiling: None,
        };
        assert_eq!(
            rt.block_on(retry_checked(&mut wrong_epoch, &mut window)),
            Err(CausalError::Scope)
        );
        assert_eq!(wrong_epoch.seen.len(), 1);
    }
}
