//! Checked candidate-503 inert deployment. Signature preflight is only a local
//! filter for inert Docker setup; it does not issue a session or authorize seed.
//! A separate operator supervisor must enforce the whole 600-second setup wall
//! clock: synchronous filesystem and OS process operations cannot be preempted
//! by these cooperative deadline checks.
//!
//! The operator must control the retained source files and their ancestor
//! namespace throughout launch and use, as well as the Docker CLI and daemon.
//! Path, digest and timestamp rechecks detect observed drift; they do not attest
//! immutable Docker-mounted inodes or protect against concurrent hostile host
//! writers substituting an ancestor during mount resolution.
use crate::CausalIssueOwner;
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::CausalError;
use tokio::time::{Duration, Instant};

const SETUP_MAX: Duration = Duration::from_secs(600);
/// Owns the original issue lock and immutable key references. It is not Clone,
/// cannot be deserialized, and has no public fields or raw constructor.
pub struct Prelaunch503<'a> {
    owner: CausalIssueOwner,
    peer: [u8; 32],
    grants: &'a CausalGrantKeys,
    policies: &'a PolicyKeys,
    original: [u8; 32],
    deadline: Instant,
}
impl<'a> Prelaunch503<'a> {
    /// Verify the exact signed original request for candidate 503, using local
    /// time only as an inert preflight. The later DB issue remains mandatory.
    pub fn prepare(
        owner: CausalIssueOwner,
        peer: [u8; 32],
        grants: &'a CausalGrantKeys,
        policies: &'a PolicyKeys,
    ) -> Result<Self, CausalError> {
        let deadline = Instant::now() + SETUP_MAX;
        owner.signature_preflight_503(&peer, grants, policies)?;
        if Instant::now() >= deadline {
            return Err(CausalError::Deadline);
        }
        let original = owner.original_commitment();
        Ok(Self {
            owner,
            peer,
            grants,
            policies,
            original,
            deadline,
        })
    }
    /// Reverify immediately before any future inert mutation; no raw JSON or
    /// caller assertion is accepted as evidence.
    pub fn revalidate(&self) -> Result<(), CausalError> {
        if Instant::now() >= self.deadline || self.original != self.owner.original_commitment() {
            return Err(CausalError::Deadline);
        }
        self.owner
            .signature_preflight_503(&self.peer, self.grants, self.policies)?;
        if Instant::now() >= self.deadline {
            return Err(CausalError::Deadline);
        }
        Ok(())
    }
}

use crate::causal_launch_process::{ActualDockerObservation, DockerInspect};
use crate::{DockerPolicy, ProcessError};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchObserveError {
    Preflight(CausalError),
    Process(ProcessError),
    MutationUnknown,
    Invalid,
}
/// Actual fixed-image observation; data only. It neither starts a container nor
/// grants producer authority. The fields are private and cannot be deserialized.
pub struct VerifiedImage {
    id: [u8; 32],
    policy: [u8; 32],
    labels: std::collections::BTreeMap<String, String>,
}

// Preserve numbers and reject duplicate keys recursively. Input size is already
// bounded by the fixed CLI worker; serde_json enforces its nesting limit.
struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(UniqueVisitor)
    }
}
struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = UniqueJson;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unique-key JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(v)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(v.into())))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(v.into())))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
        Number::from_f64(v)
            .map(|n| UniqueJson(Value::Number(n)))
            .ok_or_else(|| E::custom("number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(v.to_owned())))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(v)))
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element::<UniqueJson>()? {
            out.push(v.0);
        }
        Ok(UniqueJson(Value::Array(out)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate"));
            }
            let value = map.next_value::<UniqueJson>()?;
            out.insert(key, value.0);
        }
        Ok(UniqueJson(Value::Object(out)))
    }
}
fn image_id(bytes: &[u8]) -> Result<[u8; 32], LaunchObserveError> {
    const REPOS: [&str; 2] = [
        "nodered/node-red@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963",
        "docker.io/nodered/node-red@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963",
    ];
    if bytes.is_empty() || bytes.len() > 262144 {
        return Err(LaunchObserveError::Invalid);
    }
    let value: UniqueJson =
        serde_json::from_slice(bytes).map_err(|_| LaunchObserveError::Invalid)?;
    let items = value.0.as_array().ok_or(LaunchObserveError::Invalid)?;
    if items.len() != 1 {
        return Err(LaunchObserveError::Invalid);
    }
    let item = items[0].as_object().ok_or(LaunchObserveError::Invalid)?;
    let raw = item
        .get("Id")
        .and_then(Value::as_str)
        .and_then(|v| v.strip_prefix("sha256:"))
        .ok_or(LaunchObserveError::Invalid)?;
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(LaunchObserveError::Invalid);
    }
    let digests = item
        .get("RepoDigests")
        .and_then(Value::as_array)
        .ok_or(LaunchObserveError::Invalid)?;
    if digests.is_empty()
        || !digests.iter().all(|v| v.as_str().is_some())
        || !digests
            .iter()
            .any(|v| v.as_str().is_some_and(|s| REPOS.contains(&s)))
    {
        return Err(LaunchObserveError::Invalid);
    }
    let mut out = [0u8; 32];
    for (i, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        out[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    if out == [0; 32] {
        return Err(LaunchObserveError::Invalid);
    }
    Ok(out)
}
fn verified_image(
    observation: ActualDockerObservation,
    expected: [u8; 32],
) -> Result<VerifiedImage, LaunchObserveError> {
    if observation.recipe() != DockerInspect::Image || expected == [0; 32] {
        return Err(LaunchObserveError::Invalid);
    }
    let id = image_id(observation.bytes())?;
    if id != expected {
        return Err(LaunchObserveError::Invalid);
    }
    Ok(VerifiedImage {
        id,
        policy: observation.policy_digest(),
        labels: image_labels(observation.bytes())?,
    })
}
fn image_labels(
    bytes: &[u8],
) -> Result<std::collections::BTreeMap<String, String>, LaunchObserveError> {
    let item = one_object(bytes)?;
    let labels = item
        .get("Config")
        .and_then(|v| v.get("Labels"))
        .ok_or(LaunchObserveError::Invalid)?;
    if labels.is_null() {
        return Ok(Default::default());
    }
    let labels = labels.as_object().ok_or(LaunchObserveError::Invalid)?;
    if labels.len() > 64 {
        return Err(LaunchObserveError::Invalid);
    }
    let mut result = std::collections::BTreeMap::new();
    let mut total = 0usize;
    for (key, value) in labels {
        let value = value.as_str().ok_or(LaunchObserveError::Invalid)?;
        if key.is_empty()
            || key.len() > 256
            || value.len() > 4096
            || key.starts_with("org.apicontour.")
        {
            return Err(LaunchObserveError::Invalid);
        }
        total = total
            .checked_add(key.len() + value.len())
            .ok_or(LaunchObserveError::Invalid)?;
        if total > 16384 {
            return Err(LaunchObserveError::Invalid);
        }
        result.insert(key.clone(), value.to_owned());
    }
    Ok(result)
}
impl Prelaunch503<'_> {
    /// Recheck signed preflight around an actual fixed image inspection.
    pub async fn inspect_image(
        &self,
        policy: &DockerPolicy,
        expected_id: [u8; 32],
    ) -> Result<VerifiedImage, LaunchObserveError> {
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        let observation = policy
            .observe(DockerInspect::Image, self.deadline.into())
            .await
            .map_err(LaunchObserveError::Process)?;
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        verified_image(observation, expected_id)
    }
}

/// Closed ownership-label families used by the approved causal deployment and
/// its isolated qualification network. Tokens are operator configuration.
#[derive(Clone, Copy)]
pub enum OwnerLabel {
    Causal,
    Fixture,
}
impl OwnerLabel {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Causal => "org.apicontour.causal.owner",
            Self::Fixture => "org.apicontour.fixture-owner",
        }
    }
}
/// Evidence for one independently inspected peer; not producer authority.
pub struct VerifiedPeer {
    id: [u8; 32],
    policy: [u8; 32],
    image: [u8; 32],
    label: OwnerLabel,
    owner: [u8; 32],
}
/// Evidence for one exact internal network and its independently checked peers.
pub struct VerifiedNetwork {
    id: [u8; 32],
    name: String,
    policy: [u8; 32],
    members: Vec<PeerIdentity>,
    label: OwnerLabel,
    owner: [u8; 32],
}
struct PeerIdentity {
    id: [u8; 32],
    image: [u8; 32],
    label: OwnerLabel,
    owner: [u8; 32],
}
fn lower_hex(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn one_object(bytes: &[u8]) -> Result<Map<String, Value>, LaunchObserveError> {
    if bytes.is_empty() || bytes.len() > 262144 {
        return Err(LaunchObserveError::Invalid);
    }
    let value: UniqueJson =
        serde_json::from_slice(bytes).map_err(|_| LaunchObserveError::Invalid)?;
    let Value::Array(mut items) = value.0 else {
        return Err(LaunchObserveError::Invalid);
    };
    if items.len() != 1 {
        return Err(LaunchObserveError::Invalid);
    }
    match items.pop() {
        Some(Value::Object(map)) => Ok(map),
        _ => Err(LaunchObserveError::Invalid),
    }
}
pub(crate) fn peer_metadata(
    bytes: &[u8],
    id: [u8; 32],
    image: [u8; 32],
    label: OwnerLabel,
    owner: [u8; 32],
) -> Result<(), LaunchObserveError> {
    let item = one_object(bytes)?;
    let labels = item
        .get("Config")
        .and_then(|v| v.get("Labels"))
        .and_then(Value::as_object)
        .ok_or(LaunchObserveError::Invalid)?;
    if item.get("Id").and_then(Value::as_str) != Some(lower_hex(&id).as_str())
        || item.get("Image").and_then(Value::as_str)
            != Some(format!("sha256:{}", lower_hex(&image)).as_str())
        || labels.get(label.key()).and_then(Value::as_str) != Some(lower_hex(&owner).as_str())
    {
        return Err(LaunchObserveError::Invalid);
    }
    Ok(())
}
pub(crate) fn network_metadata(
    bytes: &[u8],
    id: [u8; 32],
    name: &str,
    label: OwnerLabel,
    owner: [u8; 32],
    members: &[[u8; 32]],
) -> Result<(), LaunchObserveError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(LaunchObserveError::Invalid);
    }
    let item = one_object(bytes)?;
    let labels = item
        .get("Labels")
        .and_then(Value::as_object)
        .ok_or(LaunchObserveError::Invalid)?;
    if item.get("Id").and_then(Value::as_str) != Some(lower_hex(&id).as_str())
        || item.get("Name").and_then(Value::as_str) != Some(name)
        || item.get("Internal").and_then(Value::as_bool) != Some(true)
        || labels.get(label.key()).and_then(Value::as_str) != Some(lower_hex(&owner).as_str())
    {
        return Err(LaunchObserveError::Invalid);
    }
    let actual = item
        .get("Containers")
        .and_then(Value::as_object)
        .ok_or(LaunchObserveError::Invalid)?;
    let expected: std::collections::BTreeSet<_> = members.iter().map(|m| lower_hex(m)).collect();
    if expected.len() != members.len()
        || actual.len() != expected.len()
        || actual.keys().any(|x| !expected.contains(x))
    {
        return Err(LaunchObserveError::Invalid);
    }
    Ok(())
}
impl Prelaunch503<'_> {
    /// Observe an existing peer by exact CID, image and trusted owner label.
    pub async fn inspect_peer(
        &self,
        policy: &DockerPolicy,
        id: [u8; 32],
        image: [u8; 32],
        label: OwnerLabel,
        owner: [u8; 32],
    ) -> Result<VerifiedPeer, LaunchObserveError> {
        if [id, image, owner].contains(&[0; 32]) {
            return Err(LaunchObserveError::Invalid);
        }
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        let observed = policy
            .observe(DockerInspect::Container(id), self.deadline.into())
            .await
            .map_err(LaunchObserveError::Process)?;
        if observed.recipe() != DockerInspect::Container(id) {
            return Err(LaunchObserveError::Invalid);
        }
        peer_metadata(observed.bytes(), id, image, label, owner)?;
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        Ok(VerifiedPeer {
            id,
            policy: observed.policy_digest(),
            image,
            label,
            owner,
        })
    }
    /// Observe an internal network with exactly the independently observed peers.
    pub async fn inspect_network(
        &self,
        policy: &DockerPolicy,
        id: [u8; 32],
        name: &str,
        label: OwnerLabel,
        owner: [u8; 32],
        peers: &[VerifiedPeer],
    ) -> Result<VerifiedNetwork, LaunchObserveError> {
        if [id, owner].contains(&[0; 32]) || peers.len() > 31 {
            return Err(LaunchObserveError::Invalid);
        }
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        let observed = policy
            .observe(DockerInspect::Network(id), self.deadline.into())
            .await
            .map_err(LaunchObserveError::Process)?;
        if observed.recipe() != DockerInspect::Network(id)
            || peers.iter().any(|p| p.policy != observed.policy_digest())
        {
            return Err(LaunchObserveError::Invalid);
        }
        let members: Vec<_> = peers.iter().map(|p| p.id).collect();
        network_metadata(observed.bytes(), id, name, label, owner, &members)?;
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        Ok(VerifiedNetwork {
            id,
            name: name.into(),
            policy: observed.policy_digest(),
            members: peers
                .iter()
                .map(|p| PeerIdentity {
                    id: p.id,
                    image: p.image,
                    label: p.label,
                    owner: p.owner,
                })
                .collect(),
            label,
            owner,
        })
    }
}

use crate::CandidateSources;
use crate::causal_launch_process::{FixedCreateSpec, OwnedCreateIntent};
use sha2::{Digest, Sha256};
use std::path::Path;

/// An exact CID whose intent and CID receipt were durably persisted. The
/// container is not yet authorized for a seed, and no automatic adoption or
/// cleanup is performed if later inspection or start has an uncertain outcome.
pub struct InertCreated<'a> {
    prelaunch: Prelaunch503<'a>,
    intent: OwnedCreateIntent,
    image: VerifiedImage,
    network: VerifiedNetwork,
    sources: CandidateSources,
    cid: [u8; 32],
}
pub(crate) fn parse_cid(bytes: &[u8]) -> Result<[u8; 32], LaunchObserveError> {
    if bytes.len() != 65
        || bytes[64] != b'\n'
        || !bytes[..64]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(LaunchObserveError::MutationUnknown);
    }
    let mut id = [0; 32];
    for (i, pair) in bytes[..64].chunks_exact(2).enumerate() {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        id[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    if id == [0; 32] {
        return Err(LaunchObserveError::MutationUnknown);
    }
    Ok(id)
}
impl Prelaunch503<'_> {
    async fn revalidate_network(
        &self,
        policy: &DockerPolicy,
        network: &VerifiedNetwork,
    ) -> Result<(), LaunchObserveError> {
        if policy.policy_digest() != network.policy {
            return Err(LaunchObserveError::Invalid);
        }
        let mut peers = Vec::with_capacity(network.members.len());
        for p in &network.members {
            peers.push(
                self.inspect_peer(policy, p.id, p.image, p.label, p.owner)
                    .await?,
            );
        }
        let observed = self
            .inspect_network(
                policy,
                network.id,
                &network.name,
                network.label,
                network.owner,
                &peers,
            )
            .await?;
        if observed.id != network.id
            || observed.policy != network.policy
            || observed.name != network.name
        {
            return Err(LaunchObserveError::Invalid);
        }
        Ok(())
    }
    /// Create only the fixed inert proxy after a durable no-clobber intent.
    /// Errors after launching the CLI are outcome-unknown and never trigger
    /// adoption, retry, removal, or a replacement container.
    pub async fn create<'a>(
        mut self,
        policy: &DockerPolicy,
        journal_dir: &Path,
        image: VerifiedImage,
        network: VerifiedNetwork,
        sources: CandidateSources,
    ) -> Result<InertCreated<'a>, LaunchObserveError>
    where
        Self: 'a,
    {
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        if policy.policy_digest() != image.policy || policy.policy_digest() != network.policy {
            return Err(LaunchObserveError::Invalid);
        }
        let observed = self.inspect_image(policy, image.id).await?;
        if observed.id != image.id
            || observed.policy != image.policy
            || observed.labels != image.labels
        {
            return Err(LaunchObserveError::Invalid);
        }
        self.revalidate_network(policy, &network).await?;
        let source_commitment = sources
            .commitment()
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        let mut digest = Sha256::new();
        digest.update(b"apicontour/inert-create-plan/1\n");
        digest.update(self.original);
        digest.update(image.id);
        digest.update(network.id);
        digest.update((network.name.len() as u64).to_be_bytes());
        digest.update(network.name.as_bytes());
        digest.update(network.owner);
        digest.update(network.label.key().as_bytes());
        digest.update(source_commitment);
        digest.update(policy.policy_digest());
        for peer in &network.members {
            digest.update(peer.id);
            digest.update(peer.image);
            digest.update(peer.owner);
            digest.update(peer.label.key().as_bytes());
        }
        let plan_digest: [u8; 32] = digest.finalize().into();
        let intent =
            OwnedCreateIntent::prepare(journal_dir, image.id, network.id, plan_digest, policy)
                .map_err(LaunchObserveError::Process)?;
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        sources
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.owner
            .consume_inert_create(intent.token(), plan_digest)
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.revalidate_network(policy, &network).await?;
        let observed = self.inspect_image(policy, image.id).await?;
        if observed.id != image.id
            || observed.policy != image.policy
            || observed.labels != image.labels
        {
            return Err(LaunchObserveError::Invalid);
        }
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        sources
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        sources
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        let spec = FixedCreateSpec {
            network: &network.name,
            owner: intent.token(),
            mounts: sources.mount_pairs(),
        };
        let process = policy
            .create_inert(&spec, self.deadline.into())
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let output = process
            .wait()
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let cid = parse_cid(&output)?;
        intent
            .record_cid(cid)
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        if Instant::now() >= self.deadline {
            return Err(LaunchObserveError::MutationUnknown);
        }
        Ok(InertCreated {
            prelaunch: self,
            intent,
            image,
            network,
            sources,
            cid,
        })
    }
}

impl InertCreated<'_> {
    /// Reinspect the exact newly created CID and its approved network before
    /// any start. A failed inspection never deletes or adopts a container.
    pub async fn verify_created(&self, policy: &DockerPolicy) -> Result<(), LaunchObserveError> {
        use crate::causal_launch_inspect::{
            ActualExpected, ActualState, validate_actual_container,
        };
        self.prelaunch
            .revalidate()
            .map_err(LaunchObserveError::Preflight)?;
        if policy.policy_digest() != self.image.policy
            || policy.policy_digest() != self.network.policy
        {
            return Err(LaunchObserveError::Invalid);
        }
        self.sources
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.prelaunch
            .revalidate_network(policy, &self.network)
            .await?;
        let image = self.prelaunch.inspect_image(policy, self.image.id).await?;
        if image.id != self.image.id
            || image.policy != self.image.policy
            || image.labels != self.image.labels
        {
            return Err(LaunchObserveError::Invalid);
        }
        let container = policy
            .observe(
                DockerInspect::Container(self.cid),
                self.prelaunch.deadline.into(),
            )
            .await
            .map_err(LaunchObserveError::Process)?;
        let network = policy
            .observe(
                DockerInspect::Network(self.network.id),
                self.prelaunch.deadline.into(),
            )
            .await
            .map_err(LaunchObserveError::Process)?;
        let expected = ActualExpected {
            cid: self.cid,
            image: self.image.id,
            image_labels: &self.image.labels,
            owner: self.intent.token(),
            network_id: self.network.id,
            network_name: &self.network.name,
            network_owner: self.network.owner,
            network_label: self.network.label.key(),
            peers: self.network.members.iter().map(|p| p.id).collect(),
            daemon: policy.daemon_endpoint(),
            policy_digest: policy.policy_digest(),
        };
        validate_actual_container(
            &container,
            &network,
            &self.sources,
            &expected,
            ActualState::Created,
        )
        .map_err(|_| LaunchObserveError::Invalid)?;
        self.prelaunch
            .revalidate()
            .map_err(LaunchObserveError::Preflight)?;
        Ok(())
    }
}

use crate::causal_launch_inspect::{
    ActualExpected, ActualState, ValidatedActual, validate_actual_container,
};
use crate::causal_launch_process::LocalAttached;
use std::sync::Arc;

/// Read-only bind progress; it conveys no authority or target data.
/// ```compile_fail
/// use contour_ingress::{BindProgress, BindStage};
/// fn change(p: &BindProgress) { p.set(BindStage::Complete); }
/// ```
#[derive(Clone)]
pub struct BindProgress(Arc<BindProgressState>);
struct BindProgressState {
    stage: std::sync::atomic::AtomicU8,
    process_failure: std::sync::atomic::AtomicU8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BindStage {
    NotStarted,
    Preflight,
    Sources,
    Seal,
    MountsBefore,
    TargetBefore,
    TargetStart,
    TargetSourcesBefore,
    TargetImage,
    TargetPeer,
    TargetFirst,
    TargetNetwork,
    TargetSecond,
    TargetActual,
    TargetSourcesAfter,
    TargetFinish,
    Material,
    Peer,
    Generation,
    Database,
    Session,
    MountsAfter,
    TargetAfter,
    Metadata,
    UnixStream,
    LaunchJournal,
    Complete,
}
impl BindProgress {
    fn new() -> Self {
        Self(Arc::new(BindProgressState {
            stage: std::sync::atomic::AtomicU8::new(0),
            process_failure: std::sync::atomic::AtomicU8::new(0),
        }))
    }
    pub fn stage(&self) -> BindStage {
        match self.0.stage.load(std::sync::atomic::Ordering::Acquire) {
            0 => BindStage::NotStarted,
            1 => BindStage::Preflight,
            2 => BindStage::Sources,
            3 => BindStage::Seal,
            4 => BindStage::MountsBefore,
            5 => BindStage::TargetBefore,
            6 => BindStage::TargetStart,
            7 => BindStage::TargetSourcesBefore,
            8 => BindStage::TargetImage,
            9 => BindStage::TargetPeer,
            10 => BindStage::TargetFirst,
            11 => BindStage::TargetNetwork,
            12 => BindStage::TargetSecond,
            13 => BindStage::TargetActual,
            14 => BindStage::TargetSourcesAfter,
            15 => BindStage::TargetFinish,
            16 => BindStage::Material,
            17 => BindStage::Peer,
            18 => BindStage::Generation,
            19 => BindStage::Database,
            20 => BindStage::Session,
            21 => BindStage::MountsAfter,
            22 => BindStage::TargetAfter,
            23 => BindStage::Metadata,
            24 => BindStage::UnixStream,
            25 => BindStage::LaunchJournal,
            26 => BindStage::Complete,
            _ => unreachable!("only internal fixed stages are stored"),
        }
    }
    /// The fixed process error and whether the deadline had been reached when
    /// that error was observed. The boolean does not establish its cause.
    pub fn process_failure(&self) -> Option<(ProcessError, bool)> {
        let value = self
            .0
            .process_failure
            .load(std::sync::atomic::Ordering::Acquire);
        if value == 0 {
            return None;
        }
        let error = match (value - 1) % 8 {
            0 => ProcessError::Unsafe,
            1 => ProcessError::Busy,
            2 => ProcessError::Existing,
            3 => ProcessError::Io,
            4 => ProcessError::Timeout,
            5 => ProcessError::OutputLimit,
            6 => ProcessError::Exit,
            7 => ProcessError::CleanupUnknown,
            _ => unreachable!(),
        };
        Some((error, value > 8))
    }
    fn record_process_failure(&self, error: ProcessError, deadline_reached: bool) {
        let value = match error {
            ProcessError::Unsafe => 1,
            ProcessError::Busy => 2,
            ProcessError::Existing => 3,
            ProcessError::Io => 4,
            ProcessError::Timeout => 5,
            ProcessError::OutputLimit => 6,
            ProcessError::Exit => 7,
            ProcessError::CleanupUnknown => 8,
        } + if deadline_reached { 8 } else { 0 };
        self.0
            .process_failure
            .store(value, std::sync::atomic::Ordering::Release);
    }
    pub(crate) fn set(&self, stage: BindStage) {
        self.0
            .stage
            .store(stage as u8, std::sync::atomic::Ordering::Release);
    }
}

/// An owned attach whose exact container and network were inspected as running.
/// It still cannot transfer a seed or authorize a producer.
pub struct InertStarted<'a> {
    created: InertCreated<'a>,
    progress: BindProgress,
    policy: Arc<DockerPolicy>,
    attached: LocalAttached,
    stream: Option<tokio::net::UnixStream>,
    actual: Option<ValidatedActual>,
    pid: u64,
    started_at: String,
}
fn observed_state(
    bytes: &[u8],
    cid: [u8; 32],
    image: [u8; 32],
) -> Result<String, LaunchObserveError> {
    let item = one_object(bytes)?;
    if item.get("Id").and_then(Value::as_str) != Some(lower_hex(&cid).as_str())
        || item.get("Image").and_then(Value::as_str)
            != Some(format!("sha256:{}", lower_hex(&image)).as_str())
    {
        return Err(LaunchObserveError::Invalid);
    }
    item.get("State")
        .and_then(|v| v.get("Status"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(LaunchObserveError::Invalid)
}
impl<'a> InertCreated<'a> {
    /// One start attempt only. Its durable start marker is written before the
    /// local CLI is started; a lost acknowledgement stays outcome-unknown.
    pub async fn start(
        self,
        policy: Arc<DockerPolicy>,
    ) -> Result<InertStarted<'a>, LaunchObserveError> {
        self.verify_created(&policy).await?;
        self.prelaunch
            .revalidate()
            .map_err(LaunchObserveError::Preflight)?;
        self.sources
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.intent
            .record_start(self.cid)
            .map_err(LaunchObserveError::Process)?;
        self.prelaunch
            .revalidate()
            .map_err(LaunchObserveError::Preflight)?;
        let mut attached = policy
            .start_attached(self.cid, self.prelaunch.deadline.into())
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let stream = attached
            .take_stream()
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let actual = loop {
            if Instant::now() >= self.prelaunch.deadline || attached.cleanup().result().is_some() {
                return Err(LaunchObserveError::MutationUnknown);
            }
            self.prelaunch
                .revalidate()
                .map_err(|_| LaunchObserveError::MutationUnknown)?;
            let container = policy
                .observe(
                    DockerInspect::Container(self.cid),
                    self.prelaunch.deadline.into(),
                )
                .await
                .map_err(|_| LaunchObserveError::MutationUnknown)?;
            match observed_state(container.bytes(), self.cid, self.image.id)
                .map_err(|_| LaunchObserveError::MutationUnknown)?
                .as_str()
            {
                "created" => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    continue;
                }
                "running" => {}
                _ => return Err(LaunchObserveError::MutationUnknown),
            }
            for peer in &self.network.members {
                self.prelaunch
                    .inspect_peer(&policy, peer.id, peer.image, peer.label, peer.owner)
                    .await
                    .map_err(|_| LaunchObserveError::MutationUnknown)?;
            }
            let network = policy
                .observe(
                    DockerInspect::Network(self.network.id),
                    self.prelaunch.deadline.into(),
                )
                .await
                .map_err(|_| LaunchObserveError::MutationUnknown)?;
            let expected = ActualExpected {
                cid: self.cid,
                image: self.image.id,
                image_labels: &self.image.labels,
                owner: self.intent.token(),
                network_id: self.network.id,
                network_name: &self.network.name,
                network_owner: self.network.owner,
                network_label: self.network.label.key(),
                peers: self.network.members.iter().map(|p| p.id).collect(),
                daemon: policy.daemon_endpoint(),
                policy_digest: policy.policy_digest(),
            };
            let actual = validate_actual_container(
                &container,
                &network,
                &self.sources,
                &expected,
                ActualState::Running,
            )
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
            self.prelaunch
                .revalidate()
                .map_err(|_| LaunchObserveError::MutationUnknown)?;
            break actual;
        };
        let (pid, started_at) = actual.identity();
        let started_at = started_at.to_owned();
        Ok(InertStarted {
            created: self,
            progress: BindProgress::new(),
            policy,
            attached,
            stream: Some(stream),
            actual: Some(actual),
            pid,
            started_at,
        })
    }
}

impl InertStarted<'_> {
    /// Read-only, cloneable progress for this bind attempt.
    pub fn bind_progress(&self) -> BindProgress {
        self.progress.clone()
    }
    /// Observe cleanup of the owned local attach process group after it is dropped.
    /// This does not report the state of the remote container or business child.
    pub fn local_cleanup(&self) -> crate::LocalCleanup {
        self.attached.cleanup()
    }
}

/// Private running target, including the local attach owner and durable create
/// journal. It can only be assembled from the sealed start transition above.
pub(crate) struct RunningTarget {
    policy: Arc<DockerPolicy>,
    _intent: OwnedCreateIntent,
    image: VerifiedImage,
    network: VerifiedNetwork,
    sources: CandidateSources,
    cid: [u8; 32],
    owner: [u8; 32],
    pid: u64,
    started_at: String,
    setup_deadline: Instant,
    attached: LocalAttached,
}
impl RunningTarget {
    pub(crate) fn local_cleanup(&self) -> crate::LocalCleanup {
        self.attached.cleanup()
    }
    pub(crate) async fn verify_proxy(
        &self,
        deployment: &crate::InspectedDeployment,
        pid: u32,
        start: u64,
        deadline: Instant,
    ) -> Result<(), LaunchObserveError> {
        self.revalidate(deployment, deadline).await?;
        self.policy
            .verify_proxy_process(self.cid, pid, start, deadline.into())
            .await
            .map_err(LaunchObserveError::Process)?;
        self.revalidate(deployment, deadline).await
    }
    pub(crate) async fn revalidate(
        &self,
        deployment: &crate::InspectedDeployment,
        deadline: Instant,
    ) -> Result<(), LaunchObserveError> {
        self.revalidate_observed(deployment, deadline, None).await
    }
    pub(crate) async fn revalidate_observed(
        &self,
        deployment: &crate::InspectedDeployment,
        deadline: Instant,
        progress: Option<&BindProgress>,
    ) -> Result<(), LaunchObserveError> {
        let mark = |stage| {
            if let Some(p) = progress {
                p.set(stage);
            }
        };
        let deadline = deadline.min(self.setup_deadline);
        let observe_error = |error| {
            if let Some(p) = progress {
                p.record_process_failure(error, Instant::now() >= deadline);
            }
            LaunchObserveError::Process(error)
        };
        mark(BindStage::TargetStart);
        if Instant::now() >= deadline || self.attached.cleanup().result().is_some() {
            return Err(LaunchObserveError::MutationUnknown);
        }
        mark(BindStage::TargetSourcesBefore);
        self.sources
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        mark(BindStage::TargetImage);
        let image = self
            .policy
            .observe(DockerInspect::Image, deadline.into())
            .await
            .map_err(observe_error)?;
        let image = verified_image(image, self.image.id)?;
        if image.policy != self.image.policy || image.labels != self.image.labels {
            return Err(LaunchObserveError::Invalid);
        }
        for peer in &self.network.members {
            mark(BindStage::TargetPeer);
            let observed = self
                .policy
                .observe(DockerInspect::Container(peer.id), deadline.into())
                .await
                .map_err(observe_error)?;
            peer_metadata(
                observed.bytes(),
                peer.id,
                peer.image,
                peer.label,
                peer.owner,
            )?;
        }
        mark(BindStage::TargetFirst);
        let first = self
            .policy
            .observe(DockerInspect::Container(self.cid), deadline.into())
            .await
            .map_err(observe_error)?;
        mark(BindStage::TargetNetwork);
        let network = self
            .policy
            .observe(DockerInspect::Network(self.network.id), deadline.into())
            .await
            .map_err(observe_error)?;
        mark(BindStage::TargetSecond);
        let second = self
            .policy
            .observe(DockerInspect::Container(self.cid), deadline.into())
            .await
            .map_err(observe_error)?;
        let expected = ActualExpected {
            cid: self.cid,
            image: self.image.id,
            image_labels: &self.image.labels,
            owner: self.owner,
            network_id: self.network.id,
            network_name: &self.network.name,
            network_owner: self.network.owner,
            network_label: self.network.label.key(),
            peers: self.network.members.iter().map(|p| p.id).collect(),
            daemon: self.policy.daemon_endpoint(),
            policy_digest: self.policy.policy_digest(),
        };
        mark(BindStage::TargetActual);
        for observation in [&first, &second] {
            let actual = validate_actual_container(
                observation,
                &network,
                &self.sources,
                &expected,
                ActualState::Running,
            )
            .map_err(|_| LaunchObserveError::Invalid)?;
            let (pid, started) = actual.identity();
            if pid != self.pid || started != self.started_at || !deployment.matches_actual(&actual)
            {
                return Err(LaunchObserveError::Invalid);
            }
        }
        mark(BindStage::TargetSourcesAfter);
        self.sources
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        mark(BindStage::TargetFinish);
        if Instant::now() >= deadline || self.attached.cleanup().result().is_some() {
            return Err(LaunchObserveError::MutationUnknown);
        }
        Ok(())
    }
}

/// Operator-selected credential IDs and bounded queue settings. They are
/// validated by the checked binding and canonical metadata, not authority.
pub struct LaunchConfig {
    pub product_credential: String,
    pub export_credential: String,
    pub batch_bytes: u32,
    pub batch_events: u32,
    pub queue_bytes: u32,
    pub queue_ttl_ms: u32,
}

use crate::causal_launch_bound::{BoundInputParts, BoundLaunchInputs, BoundTransfer};
use crate::{BoundLaunchError, RelayCodec, RelayEvent};
use contour_postgres::{CausalIssuer, CausalMarkerBinder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A checked bound launch awaiting its one-use private transfer and relay.
/// Dropping it closes only the local attach/capture path.
pub struct BoundLauncher<'a> {
    transfer: BoundTransfer,
    permit_peer: tokio::net::UnixStream,
    peer: [u8; 32],
    grants: &'a CausalGrantKeys,
    policies: &'a PolicyKeys,
}
impl<'a> InertStarted<'a> {
    /// Capture the exact running mount set and invoke the checked 503 binding.
    /// No caller JSON or status boolean can substitute for the retained state.
    pub async fn bind(
        mut self,
        issuer: &mut CausalIssuer,
        binder: &mut CausalMarkerBinder,
        config: LaunchConfig,
    ) -> Result<BoundLauncher<'a>, BoundLaunchError> {
        self.progress.set(BindStage::Preflight);
        self.created
            .prelaunch
            .revalidate()
            .map_err(BoundLaunchError::Database)?;
        self.progress.set(BindStage::Sources);
        self.created
            .sources
            .revalidate()
            .map_err(|_| BoundLaunchError::Invalid)?;
        let paths = self
            .created
            .sources
            .paths()
            .map_err(|_| BoundLaunchError::Invalid)?;
        let duplicate = CandidateSources::capture(&paths).map_err(|_| BoundLaunchError::Invalid)?;
        if duplicate
            .commitment()
            .map_err(|_| BoundLaunchError::Invalid)?
            != self
                .created
                .sources
                .commitment()
                .map_err(|_| BoundLaunchError::Invalid)?
        {
            return Err(BoundLaunchError::Invalid);
        }
        self.progress.set(BindStage::Seal);
        let actual = self.actual.take().ok_or(BoundLaunchError::Invalid)?;
        let observation = actual.normalized().map_err(|_| BoundLaunchError::Invalid)?;
        let (deployment, snapshots) = duplicate
            .seal(actual)
            .map_err(|_| BoundLaunchError::Invalid)?;
        let (permit_stream, permit_peer) =
            std::os::unix::net::UnixStream::pair().map_err(|_| BoundLaunchError::Invalid)?;
        permit_peer
            .set_nonblocking(true)
            .map_err(|_| BoundLaunchError::Invalid)?;
        let permit_peer =
            tokio::net::UnixStream::from_std(permit_peer).map_err(|_| BoundLaunchError::Invalid)?;
        let attach = self.stream.take().ok_or(BoundLaunchError::Invalid)?;
        let owner_token = self.created.intent.token();
        let Prelaunch503 {
            owner,
            peer,
            grants,
            policies,
            original: _,
            deadline,
        } = self.created.prelaunch;
        let target = RunningTarget {
            policy: self.policy,
            _intent: self.created.intent,
            image: self.created.image,
            network: self.created.network,
            sources: self.created.sources,
            cid: self.created.cid,
            owner: owner_token,
            pid: self.pid,
            started_at: self.started_at,
            setup_deadline: deadline,
            attached: self.attached,
        };
        let inputs = BoundLaunchInputs::from_running(BoundInputParts {
            deployment,
            target,
            observation,
            setup_deadline: deadline,
            snapshots,
            permit_stream,
            attach,
            config,
            progress: self.progress,
        });
        let transfer = inputs
            .claim(owner, issuer, binder, &peer, grants, policies)
            .await?;
        Ok(BoundLauncher {
            transfer,
            permit_peer,
            peer,
            grants,
            policies,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundRunError {
    Transfer,
    CaptureClosed,
    Protocol,
    Deadline,
}
impl<'a> BoundLauncher<'a> {
    /// Observe local attach process-group cleanup; remote processes are not affected.
    pub fn local_cleanup(&self) -> crate::LocalCleanup {
        self.transfer.local_cleanup()
    }
    /// Perform the one-use transfer and run checked permit relay until capture
    /// closes. `ready` is sent only after the correlated CLR1/Y event. Dropping
    /// this future closes local capture/attach and does not stop the container.
    pub async fn run(
        self,
        issuer: &mut CausalIssuer,
        binder: &mut CausalMarkerBinder,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), BoundRunError> {
        use std::future::{Future, poll_fn};
        use std::task::Poll;
        let (permit, attach, codec, target, startup_deadline) = self
            .transfer
            .transfer()
            .await
            .map_err(|_| BoundRunError::Transfer)?;
        let mut permit_future = std::pin::pin!(permit.serve_bound(
            issuer,
            binder,
            &self.peer,
            self.grants,
            self.policies
        ));
        let mut relay_future = std::pin::pin!(relay_bound(
            attach,
            self.permit_peer,
            codec,
            target,
            startup_deadline,
            ready
        ));
        poll_fn(|cx| {
            if permit_future.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(BoundRunError::CaptureClosed));
            }
            if let Poll::Ready(result) = relay_future.as_mut().poll(cx) {
                return Poll::Ready(result);
            }
            Poll::Pending
        })
        .await
    }
}
trait RelayActivation {
    fn activate(&self);
}
impl RelayActivation for RunningTarget {
    fn activate(&self) {
        self.attached.activate();
    }
}
async fn relay_bound<A: RelayActivation>(
    mut attach: tokio::net::UnixStream,
    mut permit: tokio::net::UnixStream,
    mut codec: RelayCodec,
    target: A,
    startup_deadline: Instant,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<(), BoundRunError> {
    let mut ready = Some(ready);
    let mut active = false;
    let mut buffer = [0u8; 8192];
    loop {
        let read = if active {
            tokio::time::timeout(Duration::from_secs(2), attach.read(&mut buffer))
                .await
                .map_err(|_| BoundRunError::Deadline)?
        } else {
            tokio::time::timeout_at(startup_deadline, attach.read(&mut buffer))
                .await
                .map_err(|_| BoundRunError::Deadline)?
        };
        let n = read.map_err(|_| BoundRunError::CaptureClosed)?;
        if n == 0 {
            codec.end().map_err(|_| BoundRunError::Protocol)?;
            return Err(BoundRunError::CaptureClosed);
        }
        let events = codec
            .push(&buffer[..n])
            .map_err(|_| BoundRunError::Protocol)?;
        for event in events {
            match event {
                RelayEvent::Spawned { .. } => {}
                RelayEvent::Request(request) => {
                    let deadline = Instant::now() + Duration::from_millis(500);
                    tokio::time::timeout_at(deadline, permit.write_all(request.as_ref()))
                        .await
                        .map_err(|_| BoundRunError::Deadline)?
                        .map_err(|_| BoundRunError::CaptureClosed)?;
                    let mut response = [0u8; 120];
                    tokio::time::timeout_at(deadline, permit.read_exact(&mut response))
                        .await
                        .map_err(|_| BoundRunError::Deadline)?
                        .map_err(|_| BoundRunError::CaptureClosed)?;
                    codec
                        .write_reply(&mut attach, &response, deadline)
                        .await
                        .map_err(|_| BoundRunError::Protocol)?;
                }
                RelayEvent::Ready => {
                    if active || Instant::now() >= startup_deadline {
                        return Err(BoundRunError::Protocol);
                    }
                    target.activate();
                    active = true;
                    ready
                        .take()
                        .ok_or(BoundRunError::Protocol)?
                        .send(())
                        .map_err(|_| BoundRunError::CaptureClosed)?;
                }
                RelayEvent::Hello { .. } => return Err(BoundRunError::Protocol),
            }
        }
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct TestActivation(Arc<AtomicBool>);
    impl RelayActivation for TestActivation {
        fn activate(&self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = b"CBP1".to_vec();
        v.push(kind);
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(body);
        v
    }
    #[test]
    fn malformed_permit_never_reports_ready() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (host, mut proxy) = tokio::net::UnixStream::pair().unwrap();
            let (permit, mut peer) = tokio::net::UnixStream::pair().unwrap();
            let mut codec = RelayCodec::new([1; 32], [2; 32], [3; 32], 4).unwrap();
            codec.initial_frame().unwrap();
            let mut h = [0u8; 44];
            h[..32].fill(1);
            h[35] = 1;
            h[43] = 2;
            codec.push(&frame(b'H', &h)).unwrap();
            codec.bootstrap_transferred().unwrap();
            let active = Arc::new(AtomicBool::new(false));
            let (tx, rx) = tokio::sync::oneshot::channel();
            let relay = tokio::spawn(relay_bound(
                host,
                permit,
                codec,
                TestActivation(active.clone()),
                Instant::now() + Duration::from_secs(1),
                tx,
            ));
            let mut spawn = [0u8; 12];
            spawn[3] = 3;
            spawn[11] = 4;
            proxy.write_all(&frame(b'S', &spawn)).await.unwrap();
            let mut q = [0u8; 108];
            q[..4].copy_from_slice(b"CQP1");
            q[4..36].fill(2);
            q[36..68].fill(3);
            q[68..76].copy_from_slice(&1u64.to_be_bytes());
            q[76..].fill(5);
            proxy.write_all(&frame(b'Q', &q)).await.unwrap();
            let mut got = [0; 108];
            peer.read_exact(&mut got).await.unwrap();
            peer.write_all(&[0; 120]).await.unwrap();
            assert!(matches!(relay.await.unwrap(), Err(BoundRunError::Protocol)));
            assert!(rx.await.is_err());
            assert!(!active.load(Ordering::SeqCst));
        });
    }
    #[test]
    fn relay_requires_checked_reply_before_ready_and_closes_on_eof() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (host, mut proxy) = tokio::net::UnixStream::pair().unwrap();
            let (permit, mut fake_permit) = tokio::net::UnixStream::pair().unwrap();
            let mut codec = RelayCodec::new([1; 32], [2; 32], [3; 32], 4).unwrap();
            codec.initial_frame().unwrap();
            let mut h = [0u8; 44];
            h[..32].fill(1);
            h[35] = 1;
            h[43] = 2;
            codec.push(&frame(b'H', &h)).unwrap();
            codec.bootstrap_transferred().unwrap();
            let activated = Arc::new(AtomicBool::new(false));
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let relay = tokio::spawn(relay_bound(
                host,
                permit,
                codec,
                TestActivation(activated.clone()),
                Instant::now() + Duration::from_secs(1),
                ready_tx,
            ));
            let mut spawn = [0u8; 12];
            spawn[3] = 3;
            spawn[11] = 4;
            proxy.write_all(&frame(b'S', &spawn)).await.unwrap();
            let mut q = [0u8; 108];
            q[..4].copy_from_slice(b"CQP1");
            q[4..36].fill(2);
            q[36..68].fill(3);
            q[68..76].copy_from_slice(&1u64.to_be_bytes());
            q[76..].fill(5);
            proxy.write_all(&frame(b'Q', &q)).await.unwrap();
            let mut got = [0; 108];
            fake_permit.read_exact(&mut got).await.unwrap();
            assert_eq!(got, q);
            assert!(!activated.load(Ordering::SeqCst));
            let mut response = [0u8; 120];
            response[..4].copy_from_slice(b"CRP1");
            response[4..108].copy_from_slice(&q[4..]);
            response[108..116].copy_from_slice(&4u64.to_be_bytes());
            response[116..].copy_from_slice(&1000u32.to_be_bytes());
            fake_permit.write_all(&response).await.unwrap();
            let mut framed = [0u8; 129];
            proxy.read_exact(&mut framed).await.unwrap();
            assert_eq!(&framed[..5], b"CBP1R");
            assert_eq!(&framed[9..], &response);
            let mut y = [0u8; 76];
            y[..4].copy_from_slice(b"CLR1");
            y[4..36].fill(2);
            y[36..68].fill(3);
            y[68..].copy_from_slice(&4u64.to_be_bytes());
            proxy.write_all(&frame(b'Y', &y)).await.unwrap();
            ready_rx.await.unwrap();
            assert!(activated.load(Ordering::SeqCst));
            drop(proxy);
            assert!(matches!(
                relay.await.unwrap(),
                Err(BoundRunError::CaptureClosed)
            ));
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn progress_records_only_fixed_process_failure_and_deadline_observation() {
        let progress = super::BindProgress::new();
        assert_eq!(progress.process_failure(), None);
        for error in [
            super::ProcessError::Unsafe,
            super::ProcessError::Busy,
            super::ProcessError::Existing,
            super::ProcessError::Io,
            super::ProcessError::Timeout,
            super::ProcessError::OutputLimit,
            super::ProcessError::Exit,
            super::ProcessError::CleanupUnknown,
        ] {
            for reached in [false, true] {
                progress.record_process_failure(error, reached);
                assert_eq!(progress.clone().process_failure(), Some((error, reached)));
            }
        }
    }
    #[test]
    fn progress_clones_observe_only_fixed_internal_updates() {
        let progress = super::BindProgress::new();
        let reader = progress.clone();
        assert_eq!(reader.stage(), super::BindStage::NotStarted);
        progress.set(super::BindStage::TargetNetwork);
        assert_eq!(reader.stage(), super::BindStage::TargetNetwork);
        progress.set(super::BindStage::Metadata);
        assert_eq!(reader.stage(), super::BindStage::Metadata);
    }
    use super::*;
    const PIN: &str =
        "nodered/node-red@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963";
    #[test]
    fn image_labels_reject_reserved_spoofs_and_malformed_or_unbounded_values() {
        let mut image =
            serde_json::json!([{"Config":{"Labels":{"org.label-schema.version":"5.0.9"}}}]);
        let labels = image_labels(&serde_json::to_vec(&image).unwrap()).unwrap();
        assert_eq!(
            labels.get("org.label-schema.version").map(String::as_str),
            Some("5.0.9")
        );
        for key in [
            "org.apicontour.causal.owner",
            "org.apicontour.fixture-owner",
        ] {
            let mut bad = image.clone();
            bad[0]["Config"]["Labels"][key] = serde_json::json!("spoof");
            assert_eq!(
                image_labels(&serde_json::to_vec(&bad).unwrap()),
                Err(LaunchObserveError::Invalid)
            );
        }
        image[0]["Config"]["Labels"]["org.label-schema.version"] = serde_json::json!(false);
        assert_eq!(
            image_labels(&serde_json::to_vec(&image).unwrap()),
            Err(LaunchObserveError::Invalid)
        );
        image[0]["Config"]["Labels"]["org.label-schema.version"] =
            serde_json::json!("x".repeat(4097));
        assert_eq!(
            image_labels(&serde_json::to_vec(&image).unwrap()),
            Err(LaunchObserveError::Invalid)
        );
    }
    #[test]
    fn sealed_image_observation_retains_label_values() {
        let image = serde_json::json!([{"Id":format!("sha256:{}", "22".repeat(32)),
            "RepoDigests":[PIN], "Config":{"Labels":{"org.label-schema.version":"5.0.9"}}}]);
        let observed = |value: &serde_json::Value| {
            verified_image(
                ActualDockerObservation::fake(
                    DockerInspect::Image,
                    [0x66; 32],
                    serde_json::to_vec(value).unwrap(),
                ),
                [0x22; 32],
            )
            .unwrap()
        };
        let first = observed(&image);
        let mut changed = image.clone();
        changed[0]["Config"]["Labels"]["org.label-schema.version"] = serde_json::json!("changed");
        let second = observed(&changed);
        assert_eq!(first.id, second.id);
        assert_ne!(first.labels, second.labels);
    }
    #[test]
    fn creation_receipt_requires_exact_full_cid_line() {
        let text = format!("{}\n", "ab".repeat(32));
        assert_eq!(parse_cid(text.as_bytes()), Ok([0xab; 32]));
        for bad in [
            "ab".repeat(32),
            format!("{}\nextra", "ab".repeat(32)),
            format!("{}\n", "AB".repeat(32)),
            format!("{}\n", "00".repeat(32)),
        ] {
            assert!(parse_cid(bad.as_bytes()).is_err());
        }
    }
    #[test]
    fn peer_and_network_metadata_require_exact_owned_membership() {
        let id = [1; 32];
        let image = [2; 32];
        let owner = [3; 32];
        let network = [4; 32];
        let mut peer = serde_json::json!([{"Id":lower_hex(&id),"Image":format!("sha256:{}",lower_hex(&image)),"Config":{"Labels":{"org.apicontour.causal.owner":lower_hex(&owner)}}}]);
        assert!(
            peer_metadata(
                &serde_json::to_vec(&peer).unwrap(),
                id,
                image,
                OwnerLabel::Causal,
                owner
            )
            .is_ok()
        );
        peer[0]["Image"] = serde_json::json!(format!("sha256:{}", "ff".repeat(32)));
        assert_eq!(
            peer_metadata(
                &serde_json::to_vec(&peer).unwrap(),
                id,
                image,
                OwnerLabel::Causal,
                owner
            ),
            Err(LaunchObserveError::Invalid)
        );
        let mut net = serde_json::json!([{"Id":lower_hex(&network),"Name":"causal-net","Internal":true,"Labels":{"org.apicontour.fixture-owner":lower_hex(&owner)},"Containers":{(lower_hex(&id)): {}}}]);
        assert!(
            network_metadata(
                &serde_json::to_vec(&net).unwrap(),
                network,
                "causal-net",
                OwnerLabel::Fixture,
                owner,
                &[id]
            )
            .is_ok()
        );
        net[0]["Containers"]["foreign"] = serde_json::json!({});
        assert_eq!(
            network_metadata(
                &serde_json::to_vec(&net).unwrap(),
                network,
                "causal-net",
                OwnerLabel::Fixture,
                owner,
                &[id]
            ),
            Err(LaunchObserveError::Invalid)
        );
        assert!(
            network_metadata(
                &serde_json::to_vec(&net).unwrap(),
                network,
                "causal-net",
                OwnerLabel::Fixture,
                owner,
                &[id, id]
            )
            .is_err()
        );
    }
    #[test]
    fn image_metadata_requires_exact_digest_and_unique_fields() {
        let input = format!(
            "[{{\"Id\":\"sha256:{}\",\"RepoDigests\":[\"{}\"]}}]",
            "ab".repeat(32),
            PIN
        );
        assert_eq!(image_id(input.as_bytes()), Ok([0xab; 32]));
        let duplicate = format!(
            "[{{\"Id\":\"sha256:{}\",\"Id\":\"sha256:{}\",\"RepoDigests\":[\"{}\"]}}]",
            "ab".repeat(32),
            "ab".repeat(32),
            PIN
        );
        assert_eq!(
            image_id(duplicate.as_bytes()),
            Err(LaunchObserveError::Invalid)
        );
        let altered = input.replace("e085d4", "e185d4");
        assert_eq!(
            image_id(altered.as_bytes()),
            Err(LaunchObserveError::Invalid)
        );
        let nested = input.replace("}]", ",\"Other\":{\"x\":1,\"x\":2}}]");
        assert_eq!(
            image_id(nested.as_bytes()),
            Err(LaunchObserveError::Invalid)
        );
    }
}
