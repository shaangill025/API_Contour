//! Dormant, single-generation private channel; the trusted launcher owns both ends.
use crate::{CausalIssueOwner, CausalJournalError};
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::{CausalError, CausalIssuer, CausalSession};
use std::{os::unix::net::UnixStream as StdStream, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{Instant, sleep, timeout, timeout_at},
};

const REQUEST: usize = 108;
const MAX_LEASE_MS: u128 = 1000;
const REFRESH_BUDGET: Duration = Duration::from_millis(500);
const STARTUP_BUDGET: Duration = Duration::from_secs(2);
const BACKOFF_MS: [u64; 5] = [10, 20, 40, 80, 80];

struct RetryWindow {
    deadline: Instant,
    epoch: Option<u64>,
    ceiling: Option<Instant>,
}
impl RetryWindow {
    fn retain(&mut self, session: &CausalSession) -> Result<(), CausalError> {
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
    fn remaining_deadline(&self) -> Instant {
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
async fn checked_refresh(
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

/// Claim is durable before the child is launched. Never reuse an old owner for a
/// replacement; an uncertain claim remains consumed and requires a new issue.
pub struct CausalPermitOwner {
    owner: CausalIssueOwner,
    stream: UnixStream,
    generation: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
    ceiling: tokio::time::Instant,
}
impl CausalPermitOwner {
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
        if session.verified_remaining().is_zero() {
            return Err(CausalJournalError::Io);
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
        mut self,
        issuer: &mut CausalIssuer,
        peer: &[u8; 32],
        grant: &CausalGrantKeys,
        policy: &PolicyKeys,
    ) {
        let mut count = 0u64;
        let mut last_challenge = [0u8; 32];
        let mut ceiling = self.ceiling;
        loop {
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
            let session = match checked_refresh(
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
                Ok(session) => session,
                Err(_) => return,
            };
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
}
