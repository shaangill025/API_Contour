//! Candidate 503 bound transition. The input is intentionally unconstructible
//! outside this module until an owned Docker observer and attach path exist.
//! This is not runtime qualification, producer attestation, or TLS peer proof.
use crate::causal_owner::BoundLaunchRecord;
use crate::causal_permit::{
    BoundDatabaseAttempt, RetryWindow, STARTUP_BUDGET, SelectedBinding, checked_bound_refresh,
};
use crate::{
    CausalIssueOwner, CausalJournalError, CausalPermitOwner, FileSnapshot, InspectedDeployment,
    MetadataInputs, RelayCodec, RelayEvent, canonical_metadata, check_material,
};
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::{CausalError, CausalIssuer, CausalMarkerBinder};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::{os::unix::net::UnixStream as StdStream, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{Instant, timeout_at},
};

const TRANSFER_BUDGET: Duration = Duration::from_secs(15);
const PATHS: [&str; 7] = [
    "/run/apicontour/live/ca.pem",
    "/run/apicontour/live/export.key",
    "/run/apicontour/live/export.pem",
    "/run/apicontour/live/product.key",
    "/run/apicontour/live/product.pem",
    "/run/apicontour/live/server.key",
    "/run/apicontour/live/server.pem",
];

/// Sealed prerequisites. No public or crate-visible constructor exists. A future
/// reviewed adapter must establish the real observation and private owned attach;
/// caller JSON, a digest, or a boolean cannot construct this value.
/// ```compile_fail
/// use contour_ingress::BoundLaunchInputs;
/// let _input = BoundLaunchInputs {};
/// ```
pub struct BoundLaunchInputs {
    deployment: InspectedDeployment,
    target: crate::causal_launch_docker::RunningTarget,
    observation: Vec<u8>,
    setup_deadline: Instant,
    progress: crate::BindProgress,
    snapshots: [FileSnapshot; 7],
    permit_stream: StdStream,
    attach: UnixStream,
    product_credential: String,
    export_credential: String,
    batch_bytes: u32,
    batch_events: u32,
    queue_bytes: u32,
    queue_ttl_ms: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundLaunchError {
    Journal(CausalJournalError),
    Database(CausalError),
    Invalid,
    Expired,
    Transfer,
}
impl From<CausalJournalError> for BoundLaunchError {
    fn from(e: CausalJournalError) -> Self {
        Self::Journal(e)
    }
}
impl From<CausalError> for BoundLaunchError {
    fn from(e: CausalError) -> Self {
        Self::Database(e)
    }
}

struct Secret([u8; 32]);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
struct SecretFrame(Vec<u8>);
impl Drop for SecretFrame {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
fn random() -> Result<[u8; 32], BoundLaunchError> {
    let mut v = [0; 32];
    SystemRandom::new()
        .fill(&mut v)
        .map_err(|_| BoundLaunchError::Invalid)?;
    if v == [0; 32] {
        return Err(BoundLaunchError::Invalid);
    }
    Ok(v)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
struct ValidatedPeer([u8; 32]);
fn validate_export_peer(
    material: &crate::MaterialIdentity,
    peer: &[u8; 32],
) -> Result<ValidatedPeer, BoundLaunchError> {
    let leaf = material.export_leaf();
    if leaf != *peer {
        return Err(BoundLaunchError::Invalid);
    }
    Ok(ValidatedPeer(leaf))
}
fn begin_generation(
    owner: &mut CausalIssueOwner,
    _peer: &ValidatedPeer,
) -> Result<[u8; 32], BoundLaunchError> {
    owner.claim_generation().map_err(BoundLaunchError::Journal)
}
fn fresh(
    session: &contour_postgres::CausalSession,
    deadline: Instant,
) -> Result<(), BoundLaunchError> {
    if Instant::now() >= deadline || session.verified_remaining().is_zero() {
        Err(BoundLaunchError::Expired)
    } else {
        Ok(())
    }
}
pub(crate) struct BoundInputParts {
    pub(crate) deployment: InspectedDeployment,
    pub(crate) target: crate::causal_launch_docker::RunningTarget,
    pub(crate) observation: Vec<u8>,
    pub(crate) setup_deadline: Instant,
    pub(crate) progress: crate::BindProgress,
    pub(crate) snapshots: [FileSnapshot; 7],
    pub(crate) permit_stream: StdStream,
    pub(crate) attach: UnixStream,
    pub(crate) config: crate::causal_launch_docker::LaunchConfig,
}
impl BoundLaunchInputs {
    pub(crate) fn from_running(parts: BoundInputParts) -> Self {
        Self {
            deployment: parts.deployment,
            target: parts.target,
            observation: parts.observation,
            setup_deadline: parts.setup_deadline,
            progress: parts.progress,
            snapshots: parts.snapshots,
            permit_stream: parts.permit_stream,
            attach: parts.attach,
            product_credential: parts.config.product_credential,
            export_credential: parts.config.export_credential,
            batch_bytes: parts.config.batch_bytes,
            batch_events: parts.config.batch_events,
            queue_bytes: parts.config.queue_bytes,
            queue_ttl_ms: parts.config.queue_ttl_ms,
        }
    }
    fn validate_mounts(&self) -> Result<(), BoundLaunchError> {
        let pairs: Vec<_> = PATHS
            .iter()
            .zip(self.snapshots.iter())
            .map(|(p, s)| (*p, s))
            .collect();
        self.deployment
            .revalidate(&self.observation, &pairs)
            .map_err(|_| BoundLaunchError::Invalid)?;
        self.deployment
            .validate_candidate_sources()
            .map_err(|_| BoundLaunchError::Invalid)
    }
    /// This transition is dormant because the input has no constructor. It
    /// never invokes the legacy COL1 claim, and never exposes the seed before
    /// the one-shot COL2 record and its directory have both synced.
    pub async fn claim(
        self,
        mut owner: CausalIssueOwner,
        issuer: &mut CausalIssuer,
        binder: &mut CausalMarkerBinder,
        peer: &[u8; 32],
        grants: &CausalGrantKeys,
        policies: &PolicyKeys,
    ) -> Result<BoundTransfer, BoundLaunchError> {
        let setup_deadline = self.setup_deadline;
        let now = Instant::now();
        if setup_deadline <= now || setup_deadline.duration_since(now) > Duration::from_secs(600) {
            return Err(BoundLaunchError::Expired);
        }
        self.permit_stream
            .set_nonblocking(true)
            .map_err(|_| BoundLaunchError::Invalid)?;
        let seed = Secret(random()?);
        let slot = random()?;
        self.progress.set(crate::BindStage::MountsBefore);
        self.validate_mounts()?;
        self.progress.set(crate::BindStage::TargetBefore);
        self.target
            .revalidate_observed(&self.deployment, setup_deadline, Some(&self.progress))
            .await
            .map_err(|_| BoundLaunchError::Invalid)?;
        if Instant::now() >= setup_deadline {
            return Err(BoundLaunchError::Expired);
        }
        self.progress.set(crate::BindStage::Material);
        let material = check_material(
            &seed.0,
            self.snapshots[4].as_bytes(),
            self.snapshots[3].as_bytes(),
            self.snapshots[2].as_bytes(),
            self.snapshots[1].as_bytes(),
            self.snapshots[6].as_bytes(),
            self.snapshots[5].as_bytes(),
            self.snapshots[0].as_bytes(),
        )
        .map_err(|_| BoundLaunchError::Invalid)?;
        if Instant::now() >= setup_deadline {
            return Err(BoundLaunchError::Expired);
        }
        self.progress.set(crate::BindStage::Peer);
        let verified_peer = validate_export_peer(&material, peer)?;
        let record = self
            .deployment
            .canonical_record()
            .map_err(|_| BoundLaunchError::Invalid)?;
        let mut digest = Sha256::new();
        digest.update(b"apicontour/causal-launcher/1\n");
        digest.update(&record);
        let launcher: [u8; 32] = digest.finalize().into();
        if Instant::now() >= setup_deadline {
            return Err(BoundLaunchError::Expired);
        }
        let deadline = (Instant::now() + STARTUP_BUDGET).min(setup_deadline);
        self.progress.set(crate::BindStage::Generation);
        let generation = begin_generation(&mut owner, &verified_peer)?;
        if Instant::now() >= deadline {
            return Err(BoundLaunchError::Expired);
        }
        let mut window = RetryWindow {
            deadline,
            epoch: None,
            ceiling: None,
        };
        let mut selected = SelectedBinding::new(
            self.product_credential.clone(),
            material.product_leaf(),
            material.marker_public(),
            verified_peer.0,
        );
        let mut attempt = BoundDatabaseAttempt {
            owner: &mut owner,
            issuer,
            binder,
            generation: &generation,
            selected: &mut selected,
            grant: grants,
            policy: policies,
        };
        self.progress.set(crate::BindStage::Database);
        let session = checked_bound_refresh(&mut attempt, &mut window).await?;
        self.progress.set(crate::BindStage::Session);
        let (tenant, runtime, nonce, epoch, manifest) = {
            let v = session
                .wire_profile_503()
                .ok_or(BoundLaunchError::Invalid)?;
            (
                v.tenant_id().to_owned(),
                v.runtime_id().to_owned(),
                v.nonce().to_owned(),
                v.epoch(),
                v.profile_sha256(),
            )
        };
        fresh(&session, window.remaining_deadline())?;
        {
            let v = session
                .wire_profile_503()
                .ok_or(BoundLaunchError::Invalid)?;
            if v.tenant_id() != tenant
                || v.runtime_id() != runtime
                || v.nonce() != nonce
                || v.epoch() != epoch
                || v.profile_sha256() != manifest
            {
                return Err(BoundLaunchError::Invalid);
            }
        }
        fresh(&session, window.remaining_deadline())?;
        self.progress.set(crate::BindStage::MountsAfter);
        self.validate_mounts()?;
        self.progress.set(crate::BindStage::TargetAfter);
        self.target
            .revalidate_observed(
                &self.deployment,
                window.remaining_deadline(),
                Some(&self.progress),
            )
            .await
            .map_err(|_| BoundLaunchError::Invalid)?;
        fresh(&session, window.remaining_deadline())?;
        self.progress.set(crate::BindStage::Metadata);
        let ca = hex(&material.ca_sha256());
        let export = hex(&material.export_leaf());
        let product = hex(&material.product_leaf());
        let server = hex(&material.server_leaf());
        let marker = hex(&material.marker_public());
        let generation_hex = hex(&generation);
        let slot_hex = hex(&slot);
        let launcher_hex = hex(&launcher);
        let (metadata, identity) = canonical_metadata(&MetadataInputs {
            batch_bytes: self.batch_bytes,
            batch_events: self.batch_events,
            ca_sha256: &ca,
            epoch,
            export_credential: &self.export_credential,
            export_leaf: &export,
            generation: &generation_hex,
            launch_slot: &slot_hex,
            launcher_sha256: &launcher_hex,
            manifest_sha256: manifest,
            marker_public: &marker,
            nonce: &nonce,
            product_credential: &self.product_credential,
            product_leaf: &product,
            queue_bytes: self.queue_bytes,
            queue_ttl_ms: self.queue_ttl_ms,
            runtime: &runtime,
            server_leaf: &server,
            tenant: &tenant,
        })
        .map_err(|_| BoundLaunchError::Invalid)?;
        fresh(&session, window.remaining_deadline())?;
        self.progress.set(crate::BindStage::UnixStream);
        let permit_stream =
            UnixStream::from_std(self.permit_stream).map_err(|_| BoundLaunchError::Invalid)?;
        fresh(&session, window.remaining_deadline())?;
        self.progress.set(crate::BindStage::LaunchJournal);
        owner.consume_bound_launch(&BoundLaunchRecord::checked(
            slot, launcher, identity, record,
        ))?;
        fresh(&session, window.remaining_deadline())?;
        let ceiling = window.ceiling.ok_or(BoundLaunchError::Expired)?.min(
            session
                .wire_profile_503()
                .ok_or(BoundLaunchError::Expired)?
                .verified_until(),
        );
        let proof = BoundPermitProof {
            owner,
            stream: permit_stream,
            generation,
            identity,
            epoch,
            ceiling,
            session,
            selected,
        };
        let permit = CausalPermitOwner::from_bound(proof);
        self.progress.set(crate::BindStage::Complete);
        Ok(BoundTransfer {
            deployment: self.deployment,
            target: self.target,
            snapshots: self.snapshots,
            observation: self.observation,
            seed,
            metadata,
            permit: Some(permit),
            attach: Some(self.attach),
            ceiling,
            setup_deadline,
            generation,
            identity,
            epoch,
        })
    }
}
/// Constructed only in this module after successful COL2 sync.
pub(crate) struct BoundPermitProof {
    owner: CausalIssueOwner,
    stream: UnixStream,
    generation: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
    ceiling: Instant,
    session: contour_postgres::CausalSession,
    selected: SelectedBinding,
}
impl BoundPermitProof {
    pub(crate) fn into_parts(
        self,
    ) -> (
        CausalIssueOwner,
        UnixStream,
        [u8; 32],
        [u8; 32],
        u64,
        Instant,
        contour_postgres::CausalSession,
        SelectedBinding,
    ) {
        (
            self.owner,
            self.stream,
            self.generation,
            self.identity,
            self.epoch,
            self.ceiling,
            self.session,
            self.selected,
        )
    }
}
/// One-use seed transfer state. Drop clears owned seed bytes best effort; this
/// is not a guarantee of memory erasure. A failed/partial transfer is terminal.
pub struct BoundTransfer {
    deployment: InspectedDeployment,
    target: crate::causal_launch_docker::RunningTarget,
    snapshots: [FileSnapshot; 7],
    observation: Vec<u8>,
    seed: Secret,
    metadata: Vec<u8>,
    permit: Option<CausalPermitOwner>,
    attach: Option<UnixStream>,
    ceiling: Instant,
    setup_deadline: Instant,
    generation: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
}
impl BoundTransfer {
    pub(crate) fn local_cleanup(&self) -> crate::LocalCleanup {
        self.target.local_cleanup()
    }
    /// Write once to the sealed owned attach. On cancellation or partial write,
    /// this consumed state and permit are dropped; no remote process is killed.
    pub(crate) async fn transfer(
        mut self,
    ) -> Result<
        (
            CausalPermitOwner,
            UnixStream,
            RelayCodec,
            crate::causal_launch_docker::RunningTarget,
            Instant,
        ),
        BoundLaunchError,
    > {
        if !self
            .permit
            .as_ref()
            .is_some_and(CausalPermitOwner::bound_fresh)
        {
            return Err(BoundLaunchError::Expired);
        }
        let deadline = (Instant::now() + TRANSFER_BUDGET)
            .min(self.ceiling)
            .min(self.setup_deadline);
        if Instant::now() >= deadline {
            return Err(BoundLaunchError::Expired);
        }
        self.target
            .revalidate(&self.deployment, deadline)
            .await
            .map_err(|_| BoundLaunchError::Invalid)?;
        let attach = self.attach.as_mut().ok_or(BoundLaunchError::Invalid)?;
        let permit = self.permit.as_ref().ok_or(BoundLaunchError::Invalid)?;
        let gate = RunningGate {
            target: &self.target,
            deployment: &self.deployment,
            snapshots: &self.snapshots,
            observation: &self.observation,
            permit,
        };
        let codec = guarded_bootstrap(
            attach,
            &self.metadata,
            &self.seed.0,
            (self.generation, self.identity, self.epoch),
            deadline,
            &gate,
        )
        .await?;
        if !self
            .permit
            .as_ref()
            .is_some_and(CausalPermitOwner::bound_fresh)
        {
            return Err(BoundLaunchError::Expired);
        }
        Ok((
            self.permit.take().ok_or(BoundLaunchError::Invalid)?,
            self.attach.take().ok_or(BoundLaunchError::Invalid)?,
            codec,
            self.target,
            deadline,
        ))
    }
}
trait ProxyGate {
    async fn verify(&self, pid: u32, start: u64, deadline: Instant)
    -> Result<(), BoundLaunchError>;
}
struct RunningGate<'a> {
    target: &'a crate::causal_launch_docker::RunningTarget,
    deployment: &'a InspectedDeployment,
    snapshots: &'a [FileSnapshot; 7],
    observation: &'a [u8],
    permit: &'a CausalPermitOwner,
}
impl ProxyGate for RunningGate<'_> {
    async fn verify(
        &self,
        pid: u32,
        start: u64,
        deadline: Instant,
    ) -> Result<(), BoundLaunchError> {
        self.target
            .verify_proxy(self.deployment, pid, start, deadline)
            .await
            .map_err(|_| BoundLaunchError::Invalid)?;
        let pairs: Vec<_> = PATHS
            .iter()
            .zip(self.snapshots.iter())
            .map(|(p, s)| (*p, s))
            .collect();
        self.deployment
            .revalidate(self.observation, &pairs)
            .map_err(|_| BoundLaunchError::Invalid)?;
        self.deployment
            .validate_candidate_sources()
            .map_err(|_| BoundLaunchError::Invalid)?;
        self.target
            .revalidate(self.deployment, deadline)
            .await
            .map_err(|_| BoundLaunchError::Invalid)?;
        if !self.permit.bound_fresh() || Instant::now() >= deadline {
            return Err(BoundLaunchError::Expired);
        }
        Ok(())
    }
}
async fn guarded_bootstrap<G: ProxyGate>(
    attach: &mut UnixStream,
    metadata: &[u8],
    seed: &[u8; 32],
    identity: ([u8; 32], [u8; 32], u64),
    deadline: Instant,
    gate: &G,
) -> Result<RelayCodec, BoundLaunchError> {
    let (mut codec, pid, start) =
        perform_hello(attach, identity.0, identity.1, identity.2, deadline).await?;
    gate.verify(pid, start, deadline).await?;
    write_bootstrap(attach, metadata, seed, &mut codec, deadline).await?;
    Ok(codec)
}
async fn perform_hello(
    attach: &mut UnixStream,
    generation: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
    deadline: Instant,
) -> Result<(RelayCodec, u32, u64), BoundLaunchError> {
    if Instant::now() >= deadline {
        return Err(BoundLaunchError::Expired);
    }
    let mut codec = RelayCodec::new(random()?, generation, identity, epoch)
        .map_err(|_| BoundLaunchError::Invalid)?;
    let initial = codec
        .initial_frame()
        .map_err(|_| BoundLaunchError::Invalid)?;
    timeout_at(deadline, attach.write_all(&initial))
        .await
        .map_err(|_| BoundLaunchError::Transfer)?
        .map_err(|_| BoundLaunchError::Transfer)?;
    let mut hello = [0u8; 53];
    timeout_at(deadline, attach.read_exact(&mut hello))
        .await
        .map_err(|_| BoundLaunchError::Transfer)?
        .map_err(|_| BoundLaunchError::Transfer)?;
    let events = codec.push(&hello).map_err(|_| BoundLaunchError::Transfer)?;
    let (pid, start) = match events.as_slice() {
        [RelayEvent::Hello { pid, start }] => (*pid, *start),
        _ => return Err(BoundLaunchError::Transfer),
    };
    let mut extra = [0u8; 1];
    match attach.try_read(&mut extra) {
        Ok(_) => return Err(BoundLaunchError::Transfer),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(_) => return Err(BoundLaunchError::Transfer),
    }
    Ok((codec, pid, start))
}
async fn write_bootstrap(
    attach: &mut UnixStream,
    metadata: &[u8],
    seed: &[u8; 32],
    codec: &mut RelayCodec,
    deadline: Instant,
) -> Result<(), BoundLaunchError> {
    if Instant::now() >= deadline || metadata.is_empty() || metadata.len() > 16384 {
        return Err(BoundLaunchError::Expired);
    }
    let mut frame = SecretFrame(Vec::with_capacity(9 + 8 + metadata.len() + 32));
    frame.0.extend_from_slice(b"CBP1B");
    frame
        .0
        .extend_from_slice(&((8 + metadata.len() + 32) as u32).to_be_bytes());
    frame.0.extend_from_slice(b"CLB1");
    frame
        .0
        .extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    frame.0.extend_from_slice(metadata);
    frame.0.extend_from_slice(seed);
    timeout_at(deadline, attach.write_all(&frame.0))
        .await
        .map_err(|_| BoundLaunchError::Transfer)?
        .map_err(|_| BoundLaunchError::Transfer)?;
    if Instant::now() >= deadline {
        return Err(BoundLaunchError::Transfer);
    }
    codec
        .bootstrap_transferred()
        .map_err(|_| BoundLaunchError::Transfer)?;
    Ok(())
}
#[cfg(test)]
async fn transfer_with_deadlines(
    attach: &mut UnixStream,
    metadata: &[u8],
    seed: &[u8; 32],
    generation: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
    deadlines: (Instant, Instant),
) -> Result<RelayCodec, BoundLaunchError> {
    let deadline = (Instant::now() + TRANSFER_BUDGET)
        .min(deadlines.0)
        .min(deadlines.1);
    transfer_frame(
        attach, metadata, seed, generation, identity, epoch, deadline,
    )
    .await
}
#[cfg(test)]
async fn transfer_frame(
    attach: &mut UnixStream,
    metadata: &[u8],
    seed: &[u8; 32],
    generation: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
    deadline: Instant,
) -> Result<RelayCodec, BoundLaunchError> {
    let (mut codec, _, _) = perform_hello(attach, generation, identity, epoch, deadline).await?;
    write_bootstrap(attach, metadata, seed, &mut codec, deadline).await?;
    Ok(codec)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
    fn hello(initial: &[u8; 41]) -> [u8; 53] {
        let mut out = [0u8; 53];
        out[..5].copy_from_slice(b"CBP1H");
        out[5..9].copy_from_slice(&44u32.to_be_bytes());
        out[9..41].copy_from_slice(&initial[9..41]);
        out[44] = 1;
        out[52] = 2;
        out
    }
    #[test]
    fn only_sends_seed_after_matching_hello_and_complete_one_shot_frame() {
        runtime().block_on(async {
            let (mut host,mut peer)=UnixStream::pair().unwrap();
            let peer_task=tokio::spawn(async move {
                let mut initial=[0;41]; peer.read_exact(&mut initial).await.unwrap();
                assert_eq!(&initial[..5],b"CBP1I");
                assert!(matches!(peer.try_read(&mut [0u8;1]),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
                peer.write_all(&hello(&initial)).await.unwrap();
                let mut header=[0;9]; peer.read_exact(&mut header).await.unwrap(); assert_eq!(&header[..5],b"CBP1B");
                let len=u32::from_be_bytes(header[5..9].try_into().unwrap()) as usize;
                let mut body=vec![0;len]; peer.read_exact(&mut body).await.unwrap();
                assert_eq!(&body[..8],b"CLB1\0\0\0\x02"); assert_eq!(&body[8..10],b"{}"); assert_eq!(&body[10..],&[7;32]);
            });
            let result=transfer_frame(&mut host,b"{}",&[7;32],[1;32],[2;32],1,Instant::now()+Duration::from_secs(1)).await;
            assert!(result.is_ok()); peer_task.await.unwrap();
        });
    }
    #[test]
    fn bad_or_missing_hello_never_sends_seed() {
        runtime().block_on(async {
            for bad in [true,false] {
                let (mut host,mut peer)=UnixStream::pair().unwrap();
                let peer_task=tokio::spawn(async move {
                    let mut initial=[0;41]; peer.read_exact(&mut initial).await.unwrap();
                    if bad { let mut h=hello(&initial); h[9]^=1; peer.write_all(&h).await.unwrap(); }
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    assert!(matches!(peer.try_read(&mut [0u8;1]),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
                });
                let result=transfer_frame(&mut host,b"{}",&[7;32],[1;32],[2;32],1,Instant::now()+Duration::from_millis(30)).await;
                assert!(matches!(result,Err(BoundLaunchError::Transfer)));
                peer_task.await.unwrap();
            }
        });
    }
    #[test]
    fn expired_or_invalid_input_never_writes() {
        runtime().block_on(async {
            let (mut host,peer)=UnixStream::pair().unwrap();
            assert!(matches!(transfer_frame(&mut host,b"{}",&[7;32],[1;32],[2;32],1,Instant::now()).await,Err(BoundLaunchError::Expired)));
            assert!(matches!(peer.try_read(&mut [0u8;1]),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        });
    }
    #[test]
    fn partial_bootstrap_timeout_is_terminal() {
        use std::os::fd::AsRawFd;
        runtime().block_on(async {
            let (mut host, mut peer) = UnixStream::pair().unwrap();
            let size: libc::c_int = 1024;
            // SAFETY: valid local socket and a valid integer option buffer.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        host.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        &size as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&size) as libc::socklen_t,
                    )
                },
                0
            );
            let peer_task = tokio::spawn(async move {
                let mut initial = [0; 41];
                peer.read_exact(&mut initial).await.unwrap();
                peer.write_all(&hello(&initial)).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut received = vec![0; 16433];
                let n = peer.try_read(&mut received).unwrap();
                assert!(n > 0 && n < 16433);
            });
            let metadata = vec![b'x'; 16384];
            let result = transfer_frame(
                &mut host,
                &metadata,
                &[7; 32],
                [1; 32],
                [2; 32],
                1,
                Instant::now() + Duration::from_millis(50),
            )
            .await;
            assert!(matches!(result, Err(BoundLaunchError::Transfer)));
            peer_task.await.unwrap();
        });
    }
    #[test]
    fn mismatched_checked_export_leaf_refuses_before_generation() {
        use contour_postgres::{CausalBinding, CausalIssue};
        use std::os::unix::fs::PermissionsExt;
        let material = check_material(
            &[7; 32],
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/product.pem"),
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/product.key"),
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/export.pem"),
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/export.key"),
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/server.pem"),
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/server.key"),
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/ca.pem"),
        )
        .unwrap();
        let mut different = material.export_leaf();
        different[0] ^= 1;
        let id = "00000000-0000-4000-8000-000000000001";
        let issue = CausalIssue::new(
            CausalBinding::new([id; 10], different).unwrap(),
            id,
            Duration::from_secs(1),
            b"grant",
            b"policy",
        )
        .unwrap();
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("contour-peer-{}", hex(&random().unwrap())));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut owner = CausalIssueOwner::prepare(&path, issue, [1; 32], [2; 32]).unwrap();
        if let Ok(peer) = validate_export_peer(&material, &different) {
            let _ = begin_generation(&mut owner, &peer);
            panic!("mismatched peer authorized");
        }
        assert!(!path.join("generation").exists());
        let checked = validate_export_peer(&material, &material.export_leaf()).unwrap();
        assert_ne!(begin_generation(&mut owner, &checked).unwrap(), [0; 32]);
        drop(owner);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn expired_original_setup_deadline_sends_no_initial_frame() {
        runtime().block_on(async {
            let (mut host,peer)=UnixStream::pair().unwrap();
            let result=transfer_with_deadlines(&mut host,b"{}",&[7;32],[1;32],[2;32],1,(Instant::now()+Duration::from_secs(1),Instant::now())).await;
            assert!(matches!(result,Err(BoundLaunchError::Expired)));
            assert!(matches!(peer.try_read(&mut [0u8;1]),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        });
    }
    #[test]
    fn hello_returns_before_any_bootstrap_is_written() {
        runtime().block_on(async {
            let (mut host,mut peer)=UnixStream::pair().unwrap();
            let task=tokio::spawn(async move {
                let mut initial=[0;41];peer.read_exact(&mut initial).await.unwrap();
                peer.write_all(&hello(&initial)).await.unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
                assert!(matches!(peer.try_read(&mut [0u8;1]),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
            });
            let (_,pid,start)=perform_hello(&mut host,[1;32],[2;32],1,Instant::now()+Duration::from_secs(1)).await.unwrap();
            assert_eq!((pid,start),(1,2)); task.await.unwrap();
        });
    }
    #[test]
    fn wrong_namespace_pid_proof_never_sends_bootstrap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Gate(AtomicUsize);
        impl ProxyGate for Gate {
            async fn verify(
                &self,
                pid: u32,
                start: u64,
                _: Instant,
            ) -> Result<(), BoundLaunchError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                if (pid, start) != (99, 2) {
                    return Err(BoundLaunchError::Invalid);
                }
                Ok(())
            }
        }
        runtime().block_on(async {
            let (mut host,mut peer)=UnixStream::pair().unwrap();
            let task=tokio::spawn(async move {
                let mut initial=[0;41];peer.read_exact(&mut initial).await.unwrap();peer.write_all(&hello(&initial)).await.unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
                assert!(matches!(peer.try_read(&mut [0u8;1]),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
            });
            let gate=Gate(AtomicUsize::new(0));
            let result=guarded_bootstrap(&mut host,b"{}",&[7;32],([1;32],[2;32],1),Instant::now()+Duration::from_secs(1),&gate).await;
            assert!(matches!(result,Err(BoundLaunchError::Invalid)));assert_eq!(gate.0.load(Ordering::SeqCst),1);task.await.unwrap();
        });
    }
}
