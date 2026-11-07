//! Dormant, single-generation private channel; the trusted launcher owns both ends.
use crate::{CausalIssueOwner, CausalJournalError};
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::CausalIssuer;
use std::{os::unix::net::UnixStream as StdStream, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const REQUEST: usize = 108;
const MAX_LEASE_MS: u128 = 1000;
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
        let mut session = owner
            .issue(issuer, peer, grant, policy)
            .await
            .map_err(|_| CausalJournalError::Io)?;
        issuer
            .claim_generation(&mut session, &generation, peer, grant, policy)
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
            ceiling: anchor + remaining,
        })
    }
    /// Only pass to the one selected child over its inherited private launch path.
    pub fn generation(&self) -> [u8; 32] {
        self.generation
    }
    /// Every response requires a fresh checked issuer transaction. Any error or
    /// channel closure terminates this generation; no retry or replacement occurs.
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
            let mut session = match timeout(
                Duration::from_secs(2),
                self.owner.issue(issuer, peer, grant, policy),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => return,
            };
            if self.epoch != session.epoch() {
                return;
            }
            if !matches!(
                timeout(
                    Duration::from_secs(2),
                    issuer.claim_generation(&mut session, &self.generation, peer, grant, policy)
                )
                .await,
                Ok(Ok(()))
            ) {
                return;
            }
            let now = tokio::time::Instant::now();
            let checked = match now.checked_add(session.verified_remaining()) {
                Some(v) => v,
                None => return,
            };
            let limit = ceiling.min(checked);
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
                timeout(Duration::from_secs(2), self.stream.write_all(&response)).await,
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
