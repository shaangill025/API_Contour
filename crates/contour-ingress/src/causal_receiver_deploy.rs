//! Receiver-only signed preflight and actual network observation. These types
//! do not authorize a session, seed transfer, or a container mutation.
use crate::causal_launch_docker::{network_metadata, peer_metadata};
use crate::causal_launch_process::DockerInspect;
use crate::{CausalIssueOwner, DockerPolicy, LaunchObserveError, OwnerLabel};
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::CausalError;
use tokio::time::{Duration, Instant};

/// Retains the original request lock and the original setup deadline.
pub struct Prelaunch504<'a> {
    owner: CausalIssueOwner,
    peer: [u8; 32],
    grants: &'a CausalGrantKeys,
    policies: &'a PolicyKeys,
    original: [u8; 32],
    deadline: Instant,
}

/// A single independently inspected peer. It is not an authenticated TLS peer.
pub struct ReceiverPeer504 {
    id: [u8; 32],
    image: [u8; 32],
    label: OwnerLabel,
    owner: [u8; 32],
    policy: [u8; 32],
}

/// An actual internal network with exactly the independently inspected members.
pub struct ReceiverNetwork504 {
    id: [u8; 32],
    name: String,
    label: OwnerLabel,
    owner: [u8; 32],
    policy: [u8; 32],
    peers: Vec<ReceiverPeer504>,
}

impl<'a> Prelaunch504<'a> {
    pub fn prepare(
        owner: CausalIssueOwner,
        peer: [u8; 32],
        grants: &'a CausalGrantKeys,
        policies: &'a PolicyKeys,
    ) -> Result<Self, CausalError> {
        let deadline = Instant::now() + Duration::from_secs(600);
        owner.signature_preflight_504(&peer, grants, policies)?;
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

    pub fn revalidate(&self) -> Result<(), CausalError> {
        if Instant::now() >= self.deadline || self.original != self.owner.original_commitment() {
            return Err(CausalError::Deadline);
        }
        self.owner
            .signature_preflight_504(&self.peer, self.grants, self.policies)?;
        if Instant::now() >= self.deadline {
            return Err(CausalError::Deadline);
        }
        Ok(())
    }

    pub async fn inspect_peer(
        &self,
        docker: &DockerPolicy,
        id: [u8; 32],
        image: [u8; 32],
        label: OwnerLabel,
        owner: [u8; 32],
    ) -> Result<ReceiverPeer504, LaunchObserveError> {
        if [id, image, owner].contains(&[0; 32]) {
            return Err(LaunchObserveError::Invalid);
        }
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        let observed = docker
            .observe(DockerInspect::Container(id), self.deadline.into())
            .await
            .map_err(LaunchObserveError::Process)?;
        if observed.recipe() != DockerInspect::Container(id) {
            return Err(LaunchObserveError::Invalid);
        }
        peer_metadata(observed.bytes(), id, image, label, owner)?;
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        Ok(ReceiverPeer504 {
            id,
            image,
            label,
            owner,
            policy: observed.policy_digest(),
        })
    }

    pub async fn inspect_network(
        &self,
        docker: &DockerPolicy,
        id: [u8; 32],
        name: &str,
        label: OwnerLabel,
        owner: [u8; 32],
        peers: Vec<ReceiverPeer504>,
    ) -> Result<ReceiverNetwork504, LaunchObserveError> {
        if [id, owner].contains(&[0; 32]) || peers.len() > 31 {
            return Err(LaunchObserveError::Invalid);
        }
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        let observed = docker
            .observe(DockerInspect::Network(id), self.deadline.into())
            .await
            .map_err(LaunchObserveError::Process)?;
        if observed.recipe() != DockerInspect::Network(id)
            || peers.iter().any(|p| p.policy != observed.policy_digest())
        {
            return Err(LaunchObserveError::Invalid);
        }
        let ids: Vec<_> = peers.iter().map(|p| p.id).collect();
        network_metadata(observed.bytes(), id, name, label, owner, &ids)?;
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        Ok(ReceiverNetwork504 {
            id,
            name: name.into(),
            label,
            owner,
            policy: observed.policy_digest(),
            peers,
        })
    }

    /// Reinspect all peer and network observations under the same Docker policy.
    pub async fn revalidate_network(
        &self,
        docker: &DockerPolicy,
        network: &ReceiverNetwork504,
    ) -> Result<(), LaunchObserveError> {
        if docker.policy_digest() != network.policy {
            return Err(LaunchObserveError::Invalid);
        }
        let mut peers = Vec::with_capacity(network.peers.len());
        for peer in &network.peers {
            peers.push(
                self.inspect_peer(docker, peer.id, peer.image, peer.label, peer.owner)
                    .await?,
            );
        }
        self.inspect_network(
            docker,
            network.id,
            &network.name,
            network.label,
            network.owner,
            peers,
        )
        .await?;
        Ok(())
    }
}

use crate::causal_launch_docker::{one_object, parse_cid};
use crate::causal_launch_process::{FixedReceiverCreateSpec, LocalAttached, OwnedCreateIntent};
use crate::{CheckedReceiverMaterial, ReceiverCandidateSources, ReceiverImageEvidence};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// An owned create receipt; no session or bootstrap authority is conferred.
/// ```compile_fail
/// use contour_ingress::{ReceiverInertCreated, InertCreated};
/// fn wrong_profile<'a>(v: ReceiverInertCreated<'a>) -> InertCreated<'a> { v.into() }
/// ```
pub struct ReceiverInertCreated<'a> {
    prelaunch: Prelaunch504<'a>,
    intent: OwnedCreateIntent,
    image: ReceiverImageEvidence,
    network: ReceiverNetwork504,
    sources: ReceiverCandidateSources,
    material: CheckedReceiverMaterial,
    cid: [u8; 32],
}
/// A checked running proxy held at its private bootstrap boundary.
pub struct ReceiverInertStarted<'a> {
    _created: ReceiverInertCreated<'a>,
    _policy: Arc<DockerPolicy>,
    _attached: LocalAttached,
    _stream: tokio::net::UnixStream,
    _pid: u32,
    _process_start: u64,
    _started_at: String,
}
/// A receiver instance whose export credential was proved before any permit.
/// It retains the original attached proxy and the original setup deadline.
/// ```compile_fail
/// use contour_ingress::{ReceiverPreauthenticated504, ReceiverInertStarted};
/// fn forge<'a>(started: ReceiverInertStarted<'a>) -> ReceiverPreauthenticated504<'a> {
///     ReceiverPreauthenticated504 { started }
/// }
/// ```
pub struct ReceiverPreauthenticated504<'a> {
    _started: ReceiverInertStarted<'a>,
    _broker: crate::ReceiverPreauth504,
}
/// A confirmed receiver issue retained with its preauthenticated instance.
pub struct ReceiverIssued504<'a> {
    _authenticated: ReceiverPreauthenticated504<'a>,
    _session: contour_postgres::CausalReceiverSession504,
}
/// A receiver-only session with its single-use generation and marker binding
/// confirmed. It still carries no enrollment, bootstrap, or permit authority.
/// ```compile_fail
/// use contour_ingress::ReceiverMarkerBound504;
/// fn forge<'a>() -> ReceiverMarkerBound504<'a> {
///     ReceiverMarkerBound504 { _issued: todo!(), _generation: [0; 32], _product_credential: String::new() }
/// }
/// ```
/// ```compile_fail
/// use contour_ingress::{ReceiverMarkerBound504, CausalPermitOwner};
/// fn legacy(value: ReceiverMarkerBound504<'_>) -> CausalPermitOwner { value.into() }
/// ```
pub struct ReceiverMarkerBound504<'a> {
    _issued: ReceiverIssued504<'a>,
    _generation: [u8; 32],
    _product_credential: String,
}

fn valid_generation_material(
    credential: &str,
    peer: [u8; 32],
    export_leaf: [u8; 32],
    product_leaf: [u8; 32],
    marker_public: [u8; 32],
) -> bool {
    credential.len() == 36
        && credential.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && peer != [0; 32]
        && peer == export_leaf
        && product_leaf != [0; 32]
        && product_leaf != peer
        && marker_public != [0; 32]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn mounts<'a>(
    sources: &'a ReceiverCandidateSources,
    material: &'a CheckedReceiverMaterial,
) -> Result<Vec<(&'a str, &'a str)>, LaunchObserveError> {
    sources
        .revalidate()
        .map_err(|_| LaunchObserveError::Invalid)?;
    let mut result = Vec::new();
    for (dest, path, _) in sources.entries() {
        result.push((path.to_str().ok_or(LaunchObserveError::Invalid)?, dest));
    }
    for (path, dest) in material
        .deployment_paths()
        .map_err(|_| LaunchObserveError::Invalid)?
    {
        result.push((path.to_str().ok_or(LaunchObserveError::Invalid)?, dest));
    }
    if result.len() != 38 {
        return Err(LaunchObserveError::Invalid);
    }
    Ok(result)
}
impl<'a> Prelaunch504<'a> {
    /// Create exactly once after durable intent and same-request consumption.
    /// Any lost CLI result remains quarantined and is never adopted or removed.
    pub async fn create(
        mut self,
        docker: &DockerPolicy,
        journal: &Path,
        image: ReceiverImageEvidence,
        network: ReceiverNetwork504,
        sources: ReceiverCandidateSources,
        material: CheckedReceiverMaterial,
    ) -> Result<ReceiverInertCreated<'a>, LaunchObserveError> {
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        let (image_id, _, image_policy, _) = image.deployment_image();
        if image_policy != docker.policy_digest() || network.policy != image_policy {
            return Err(LaunchObserveError::Invalid);
        }
        self.revalidate_network(docker, &network).await?;
        image
            .reinspect(docker)
            .await
            .map_err(|_| LaunchObserveError::Invalid)?;
        let mount_list = mounts(&sources, &material)?;
        let mut h = Sha256::new();
        h.update(b"apicontour/receiver504-create-plan/1\n");
        h.update(self.original);
        h.update(image_id);
        h.update(image.candidate_config().as_bytes());
        h.update(network.id);
        h.update(network.owner);
        h.update(network.label.key().as_bytes());
        h.update(network.name.as_bytes());
        h.update(image_policy);
        h.update(
            material
                .deployment_commitment()
                .map_err(|_| LaunchObserveError::Invalid)?,
        );
        for peer in &network.peers {
            h.update(peer.id);
            h.update(peer.image);
            h.update(peer.owner);
            h.update(peer.label.key().as_bytes());
        }
        for (dest, path, bytes) in sources.entries() {
            h.update((dest.len() as u64).to_be_bytes());
            h.update(dest);
            h.update(path.as_os_str().as_encoded_bytes());
            h.update(Sha256::digest(bytes));
        }
        for (path, dest) in &mount_list {
            h.update((path.len() as u64).to_be_bytes());
            h.update(path);
            h.update(dest);
        }
        let plan: [u8; 32] = h.finalize().into();
        let intent = OwnedCreateIntent::prepare(journal, image_id, network.id, plan, docker)
            .map_err(LaunchObserveError::Process)?;
        self.owner
            .consume_inert_create(intent.token(), plan)
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.revalidate_network(docker, &network).await?;
        image
            .reinspect(docker)
            .await
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.revalidate().map_err(LaunchObserveError::Preflight)?;
        let mount_list = mounts(&sources, &material)?;
        let (_, arm64, _, _) = image.deployment_image();
        let spec = FixedReceiverCreateSpec {
            network: &network.name,
            owner: intent.token(),
            image: image_id,
            arm64,
            mounts: mount_list,
        };
        let output = docker
            .create_receiver_inert(&spec, self.deadline.into())
            .map_err(|_| LaunchObserveError::MutationUnknown)?
            .wait()
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let cid = parse_cid(&output).map_err(|_| LaunchObserveError::MutationUnknown)?;
        intent
            .record_cid(cid)
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        self.revalidate()
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        Ok(ReceiverInertCreated {
            prelaunch: self,
            intent,
            image,
            network,
            sources,
            material,
            cid,
        })
    }
}

fn valid_started_at(value: &str) -> bool {
    let b = value.as_bytes();
    if !(b.len() == 20 || (22..=30).contains(&b.len()))
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last().unwrap_or(&0) != b'Z'
        || (b.len() > 20 && (b[19] != b'.' || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit)))
    {
        return false;
    }
    let n = |a: usize, z: usize| {
        std::str::from_utf8(&b[a..z])
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
    };
    let (Some(y), Some(m), Some(d), Some(h), Some(min), Some(sec)) =
        (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19))
    else {
        return false;
    };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    y >= 1970
        && (1..=12).contains(&m)
        && d > 0
        && d <= days[(m - 1) as usize]
        && h < 24
        && min < 60
        && sec < 60
}
fn exact_mounts(value: &serde_json::Value, mounts: &[(&str, &str)]) -> bool {
    let Some(actual) = value.as_array() else {
        return false;
    };
    actual.len() == mounts.len()
        && mounts.iter().all(|(src, dst)| {
            actual
                .iter()
                .filter(|m| {
                    m["Type"] == "bind"
                        && m["Source"] == *src
                        && m["Destination"] == *dst
                        && m["RW"] == false
                        && m["Propagation"] == "rprivate"
                })
                .count()
                == 1
        })
}
fn valid_sysctls(host: &serde_json::Value) -> bool {
    match host.get("Sysctls") {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Object(value)) => value.is_empty(),
        _ => false,
    }
}
fn valid_namespace(host: &serde_json::Value) -> bool {
    host.get("CgroupnsMode").and_then(|v| v.as_str()) == Some("private")
        && host.get("ShmSize").and_then(|v| v.as_u64()) == Some(67_108_864)
}
fn valid_ports(settings: &serde_json::Value) -> bool {
    settings
        .get("Ports")
        .and_then(|v| v.as_object())
        .is_some_and(|ports| {
            ports
                .iter()
                .all(|(key, value)| key == "1880/tcp" && value.is_null())
        })
}
fn matches_receiver_image(
    container: &serde_json::Value,
    selected: &serde_json::Value,
    image_ref: &str,
) -> bool {
    let descriptor = selected
        .get("Descriptor")
        .and_then(|value| value.as_object());
    descriptor.is_some()
        && container.get("Image").and_then(|value| value.as_str()) == Some(image_ref)
        && container
            .get("Config")
            .and_then(|value| value.get("Image"))
            .and_then(|value| value.as_str())
            == Some(image_ref)
        && container
            .get("ImageManifestDescriptor")
            .and_then(|value| value.as_object())
            == descriptor
}
fn inspect_container(
    raw: &[u8],
    cid: [u8; 32],
    image: &ReceiverImageEvidence,
    network: &ReceiverNetwork504,
    owner: [u8; 32],
    mounts: &[(&str, &str)],
    running: bool,
) -> Result<(u64, String), LaunchObserveError> {
    use serde_json::{Value, json};
    let value = Value::Object(one_object(raw)?);
    let config = value.get("Config").ok_or(LaunchObserveError::Invalid)?;
    let host = value.get("HostConfig").ok_or(LaunchObserveError::Invalid)?;
    let state = value.get("State").ok_or(LaunchObserveError::Invalid)?;
    let settings = value
        .get("NetworkSettings")
        .ok_or(LaunchObserveError::Invalid)?;
    let (image_id, _, _, selected) = image.deployment_image();
    let image_ref = format!("sha256:{}", hex(&image_id));
    let owner_hex = hex(&owner);
    if value["Id"] != hex(&cid)
        || !matches_receiver_image(&value, selected, &image_ref)
        || value["Name"] != format!("/contour-causal-{owner_hex}")
        || config["Hostname"] != "causal-live"
        || config["User"] != "1000:1000"
        || config["WorkingDir"] != "/data"
        || config["Entrypoint"] != json!(["/usr/local/bin/node"])
        || config["Cmd"] != json!(["/adapter/receiver-integration/private-launch-proxy-504.js"])
        || config["AttachStdin"] != true
        || config["AttachStdout"] != true
        || config["AttachStderr"] != false
        || config["OpenStdin"] != true
        || config["Tty"] != false
        || host["NetworkMode"] != network.name
        || host["ReadonlyRootfs"] != true
        || host["Privileged"] != false
        || host["Init"] != true
        || host["AutoRemove"] != false
        || host["CapDrop"] != json!(["ALL"])
        || host["SecurityOpt"] != json!(["no-new-privileges:true"])
        || host["Memory"] != 536870912
        || host["NanoCpus"] != 1000000000
        || host["PidsLimit"] != 128
        || host["LogConfig"]["Type"] != "none"
        || host["RestartPolicy"]["Name"] != "no"
        || host["PublishAllPorts"] != false
        || !valid_namespace(host)
        || !valid_sysctls(host)
        || !valid_ports(settings)
    {
        return Err(LaunchObserveError::Invalid);
    }
    let expected_env = [
        "FLOWS=flows.json",
        "HOME=/data",
        "HOSTNAME=causal-live",
        "LANG=C.UTF-8",
        "NODE_PATH=/usr/src/node-red/node_modules",
        "NODE_RED_VERSION=v5.0.9",
        "NODE_VERSION=24.22.3",
        "PATH=/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ=UTC",
        "UV_USE_IO_URING=0",
        "YARN_VERSION=1.22.22",
    ];
    let env = config["Env"]
        .as_array()
        .ok_or(LaunchObserveError::Invalid)?;
    let mut actual_env: Vec<_> = env
        .iter()
        .map(|v| v.as_str().ok_or(LaunchObserveError::Invalid))
        .collect::<Result<_, _>>()?;
    actual_env.sort();
    if actual_env != expected_env {
        return Err(LaunchObserveError::Invalid);
    }
    for field in [
        "CapAdd",
        "Binds",
        "Devices",
        "DeviceRequests",
        "DeviceCgroupRules",
        "PortBindings",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "ExtraHosts",
        "GroupAdd",
        "Links",
        "VolumesFrom",
        "Ulimits",
    ] {
        let v = host.get(field).ok_or(LaunchObserveError::Invalid)?;
        if !v.is_null()
            && !v.as_array().is_some_and(|x| x.is_empty())
            && !v.as_object().is_some_and(|x| x.is_empty())
        {
            return Err(LaunchObserveError::Invalid);
        }
    }
    for field in [
        "PidMode",
        "IpcMode",
        "UsernsMode",
        "UTSMode",
        "CgroupParent",
        "CpusetCpus",
        "CpusetMems",
    ] {
        let v = host[field].as_str().ok_or(LaunchObserveError::Invalid)?;
        if !(v.is_empty() || field == "IpcMode" && v == "private") {
            return Err(LaunchObserveError::Invalid);
        }
    }
    for field in [
        "CpuShares",
        "CpuPeriod",
        "CpuQuota",
        "CpuRealtimePeriod",
        "CpuRealtimeRuntime",
        "MemoryReservation",
        "OomScoreAdj",
        "BlkioWeight",
        "CpuCount",
        "CpuPercent",
        "IOMaximumIOps",
        "IOMaximumBandwidth",
    ] {
        if host[field].as_i64() != Some(0) {
            return Err(LaunchObserveError::Invalid);
        }
    }
    for field in ["Cgroup", "VolumeDriver", "Isolation"] {
        if host[field].as_str() != Some("") {
            return Err(LaunchObserveError::Invalid);
        }
    }
    for field in [
        "BlkioWeightDevice",
        "BlkioDeviceReadBps",
        "BlkioDeviceWriteBps",
        "BlkioDeviceReadIOps",
        "BlkioDeviceWriteIOps",
    ] {
        let v = host.get(field).ok_or(LaunchObserveError::Invalid)?;
        if !v.is_null()
            && !v.as_array().is_some_and(|x| x.is_empty())
            && !v.as_object().is_some_and(|x| x.is_empty())
        {
            return Err(LaunchObserveError::Invalid);
        }
    }
    if !matches!(
        host.get("OomKillDisable"),
        Some(Value::Null) | Some(Value::Bool(false))
    ) || host["MemorySwap"]
        .as_i64()
        .is_none_or(|n| n <= 0 || n > 1_073_741_824)
        || host["LogConfig"]["Config"]
            .as_object()
            .is_none_or(|m| !m.is_empty())
    {
        return Err(LaunchObserveError::Invalid);
    }
    for (field, required) in [
        (
            "MaskedPaths",
            &["/proc/kcore", "/proc/keys", "/sys/firmware"][..],
        ),
        (
            "ReadonlyPaths",
            &[
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger",
            ][..],
        ),
    ] {
        let values = host[field].as_array().ok_or(LaunchObserveError::Invalid)?;
        if required.iter().any(|v| !values.iter().any(|x| x == v)) {
            return Err(LaunchObserveError::Invalid);
        }
    }
    if !matches!(
        host["Runtime"].as_str(),
        Some("runc") | Some("io.containerd.runc.v2")
    ) || config["Domainname"] != ""
    {
        return Err(LaunchObserveError::Invalid);
    }
    let expected_tmpfs = json!({"/data":"rw,nosuid,nodev,noexec,size=16m,mode=1777", "/tmp":"rw,nosuid,nodev,noexec,size=16m,mode=1777"});
    if host["Tmpfs"] != expected_tmpfs {
        return Err(LaunchObserveError::Invalid);
    }
    let mut labels = selected["Config"]["Labels"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    if labels
        .insert("org.apicontour.causal.owner".into(), json!(owner_hex))
        .is_some()
        || config["Labels"].as_object() != Some(&labels)
    {
        return Err(LaunchObserveError::Invalid);
    }
    if !exact_mounts(&value["Mounts"], mounts) {
        return Err(LaunchObserveError::Invalid);
    }
    let endpoints = settings["Networks"]
        .as_object()
        .ok_or(LaunchObserveError::Invalid)?;
    if endpoints.len() != 1 {
        return Err(LaunchObserveError::Invalid);
    }
    let endpoint = endpoints
        .get(&network.name)
        .ok_or(LaunchObserveError::Invalid)?;
    if running
        && (endpoint["NetworkID"] != hex(&network.id)
            || !endpoint["Aliases"]
                .as_array()
                .is_some_and(|x| x.iter().any(|a| a == "causal-node")))
    {
        return Err(LaunchObserveError::Invalid);
    }
    if !running && endpoint["NetworkID"] != "" {
        return Err(LaunchObserveError::Invalid);
    }
    let pid = state["Pid"].as_u64().ok_or(LaunchObserveError::Invalid)?;
    let started = state["StartedAt"]
        .as_str()
        .ok_or(LaunchObserveError::Invalid)?;
    if running {
        if state["Status"] != "running"
            || state["Running"] != true
            || pid == 0
            || !valid_started_at(started)
        {
            return Err(LaunchObserveError::Invalid);
        }
    } else if state["Status"] != "created"
        || state["Running"] != false
        || pid != 0
        || started != "0001-01-01T00:00:00Z"
    {
        return Err(LaunchObserveError::Invalid);
    }
    Ok((pid, started.into()))
}
impl ReceiverInertCreated<'_> {
    async fn inspect(
        &self,
        docker: &DockerPolicy,
        running: bool,
    ) -> Result<(u64, String), LaunchObserveError> {
        self.prelaunch
            .revalidate()
            .map_err(LaunchObserveError::Preflight)?;
        if docker.policy_digest() != self.network.policy {
            return Err(LaunchObserveError::Invalid);
        }
        self.image
            .reinspect(docker)
            .await
            .map_err(|_| LaunchObserveError::Invalid)?;
        for peer in &self.network.peers {
            self.prelaunch
                .inspect_peer(docker, peer.id, peer.image, peer.label, peer.owner)
                .await?;
        }
        let container = docker
            .observe(
                DockerInspect::Container(self.cid),
                self.prelaunch.deadline.into(),
            )
            .await
            .map_err(LaunchObserveError::Process)?;
        let network = docker
            .observe(
                DockerInspect::Network(self.network.id),
                self.prelaunch.deadline.into(),
            )
            .await
            .map_err(LaunchObserveError::Process)?;
        if container.recipe() != DockerInspect::Container(self.cid)
            || network.recipe() != DockerInspect::Network(self.network.id)
            || container.policy_digest() != self.network.policy
            || network.policy_digest() != self.network.policy
        {
            return Err(LaunchObserveError::Invalid);
        }
        let mut members: Vec<_> = self.network.peers.iter().map(|p| p.id).collect();
        if running {
            members.push(self.cid);
        }
        network_metadata(
            network.bytes(),
            self.network.id,
            &self.network.name,
            self.network.label,
            self.network.owner,
            &members,
        )?;
        let paths = mounts(&self.sources, &self.material)?;
        let result = inspect_container(
            container.bytes(),
            self.cid,
            &self.image,
            &self.network,
            self.intent.token(),
            &paths,
            running,
        )?;
        self.sources
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.material
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        self.prelaunch
            .revalidate()
            .map_err(LaunchObserveError::Preflight)?;
        Ok(result)
    }
    pub async fn verify_created(&self, docker: &DockerPolicy) -> Result<(), LaunchObserveError> {
        self.inspect(docker, false).await.map(|_| ())
    }
}
impl<'a> ReceiverInertCreated<'a> {
    /// Start once, verify the actual proxy process and retain the private stream.
    pub async fn start(
        self,
        docker: Arc<DockerPolicy>,
    ) -> Result<ReceiverInertStarted<'a>, LaunchObserveError> {
        use ring::rand::{SecureRandom, SystemRandom};
        self.verify_created(&docker).await?;
        self.intent
            .record_start(self.cid)
            .map_err(LaunchObserveError::Process)?;
        self.prelaunch
            .revalidate()
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let mut attached = docker
            .start_attached(self.cid, self.prelaunch.deadline.into())
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let mut stream = attached
            .take_stream()
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let mut hello = Vec::from(&b"CBP2I\0\0\0\x20"[..]);
        hello.extend_from_slice(&nonce);
        tokio::time::timeout_at(self.prelaunch.deadline, stream.write_all(&hello))
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let mut response = [0u8; 53];
        tokio::time::timeout_at(self.prelaunch.deadline, stream.read_exact(&mut response))
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        if &response[..9] != b"CBP2H\0\0\0\x2c" || response[9..41] != nonce {
            return Err(LaunchObserveError::MutationUnknown);
        }
        let pid = u32::from_be_bytes(
            response[41..45]
                .try_into()
                .map_err(|_| LaunchObserveError::MutationUnknown)?,
        );
        let start = u64::from_be_bytes(
            response[45..53]
                .try_into()
                .map_err(|_| LaunchObserveError::MutationUnknown)?,
        );
        let first = self
            .inspect(&docker, true)
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        docker
            .verify_receiver_proxy_process(self.cid, pid, start, self.prelaunch.deadline.into())
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let second = self
            .inspect(&docker, true)
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        if first != second || attached.cleanup().result().is_some() {
            return Err(LaunchObserveError::MutationUnknown);
        }
        Ok(ReceiverInertStarted {
            _created: self,
            _policy: docker,
            _attached: attached,
            _stream: stream,
            _pid: pid,
            _process_start: start,
            _started_at: first.1,
        })
    }
}

impl<'a> ReceiverInertStarted<'a> {
    /// Prove possession from a fixed Node process in this exact inspected CID.
    /// The broker is tied to the running internal receiver listener; neither
    /// process stdout nor any caller-supplied hash can create this stage.
    pub async fn preauthenticate(
        self,
        broker: &crate::ReceiverPreauth504,
    ) -> Result<ReceiverPreauthenticated504<'a>, LaunchObserveError> {
        let created = &self._created;
        let deadline = created.prelaunch.deadline;
        created
            .prelaunch
            .revalidate()
            .map_err(LaunchObserveError::Preflight)?;
        if created.material.identity().export_leaf() != created.prelaunch.peer
            || self._attached.cleanup().result().is_some()
        {
            return Err(LaunchObserveError::Invalid);
        }
        let before = created.inspect(&self._policy, true).await?;
        if before.1 != self._started_at {
            return Err(LaunchObserveError::Invalid);
        }
        self._policy
            .verify_receiver_proxy_process(
                created.cid,
                self._pid,
                self._process_start,
                deadline.into(),
            )
            .await
            .map_err(LaunchObserveError::Process)?;
        let ticket = broker
            .register(
                created.prelaunch.original,
                created.cid,
                created.prelaunch.peer,
                deadline,
            )
            .map_err(|_| LaunchObserveError::Invalid)?;
        self._policy
            .receiver_preauth_exec(created.cid, &ticket.challenge(), deadline.into())
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let proof = ticket
            .receive()
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        self._policy
            .verify_receiver_proxy_process(
                created.cid,
                self._pid,
                self._process_start,
                deadline.into(),
            )
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let after = created
            .inspect(&self._policy, true)
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        created
            .prelaunch
            .revalidate()
            .map_err(LaunchObserveError::Preflight)?;
        if before != after
            || after.1 != self._started_at
            || self._attached.cleanup().result().is_some()
        {
            return Err(LaunchObserveError::MutationUnknown);
        }
        proof
            .consume(broker, created.prelaunch.original, created.cid, deadline)
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        Ok(ReceiverPreauthenticated504 {
            _started: self,
            _broker: broker.clone(),
        })
    }
}

impl<'a> ReceiverPreauthenticated504<'a> {
    /// Issue once with the original locked request; any uncertain outcome yields no stage.
    pub async fn issue(
        mut self,
        issuer: &mut contour_postgres::CausalIssuer,
    ) -> Result<ReceiverIssued504<'a>, LaunchObserveError> {
        let started = &mut self._started;
        let created = &mut started._created;
        if !self._broker.is_active() || started._attached.cleanup().result().is_some() {
            return Err(LaunchObserveError::Invalid);
        }
        created
            .prelaunch
            .revalidate()
            .map_err(LaunchObserveError::Preflight)?;
        let before = created.inspect(&started._policy, true).await?;
        if before.1 != started._started_at {
            return Err(LaunchObserveError::Invalid);
        }
        started
            ._policy
            .verify_receiver_proxy_process(
                created.cid,
                started._pid,
                started._process_start,
                created.prelaunch.deadline.into(),
            )
            .await
            .map_err(LaunchObserveError::Process)?;
        let pre = &mut created.prelaunch;
        let session = pre
            .owner
            .issue_receiver_504_until(issuer, &pre.peer, pre.grants, pre.policies, pre.deadline)
            .await
            .map_err(LaunchObserveError::Preflight)?;
        // A successful commit followed by a failed reinspection is not authority to continue.
        if !self._broker.is_active()
            || pre.revalidate().is_err()
            || started._attached.cleanup().result().is_some()
        {
            return Err(LaunchObserveError::MutationUnknown);
        }
        started
            ._policy
            .verify_receiver_proxy_process(
                created.cid,
                started._pid,
                started._process_start,
                created.prelaunch.deadline.into(),
            )
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        let after = created
            .inspect(&started._policy, true)
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        if before != after || !self._broker.is_active() {
            return Err(LaunchObserveError::MutationUnknown);
        }
        Ok(ReceiverIssued504 {
            _authenticated: self,
            _session: session,
        })
    }
}

impl ReceiverIssued504<'_> {
    // Confirm the live target both before and after fixed process inspection;
    // the caller retains this stage across each awaited database operation.
    async fn verify_generation_target(&self) -> Result<(u64, String), LaunchObserveError> {
        let authenticated = &self._authenticated;
        let started = &authenticated._started;
        let created = &started._created;
        let pre = &created.prelaunch;
        if !authenticated._broker.is_active()
            || started._attached.cleanup().result().is_some()
            || !self._session.matches_export_pin(&pre.peer)
            || self._session.receiver_profile_504().is_none()
            || created.material.identity().export_leaf() != pre.peer
        {
            return Err(LaunchObserveError::Invalid);
        }
        pre.revalidate().map_err(LaunchObserveError::Preflight)?;
        created
            .material
            .revalidate()
            .map_err(|_| LaunchObserveError::Invalid)?;
        let first = created.inspect(&started._policy, true).await?;
        if first.1 != started._started_at {
            return Err(LaunchObserveError::Invalid);
        }
        started
            ._policy
            .verify_receiver_proxy_process(
                created.cid,
                started._pid,
                started._process_start,
                pre.deadline.into(),
            )
            .await
            .map_err(LaunchObserveError::Process)?;
        let second = created.inspect(&started._policy, true).await?;
        if first != second
            || !authenticated._broker.is_active()
            || started._attached.cleanup().result().is_some()
            || !self._session.matches_export_pin(&pre.peer)
            || self._session.receiver_profile_504().is_none()
        {
            return Err(LaunchObserveError::Invalid);
        }
        pre.revalidate().map_err(LaunchObserveError::Preflight)?;
        Ok(second)
    }
}

impl<'a> ReceiverIssued504<'a> {
    /// Claim one durable generation, then bind its retained product leaf and
    /// retained-seed-derived marker public key through the checked SQL APIs.
    /// `product_credential` selects a current SQL credential; it is not proof.
    /// Any uncertain journal or database outcome consumes this transition.
    pub async fn bind_generation(
        mut self,
        issuer: &mut contour_postgres::CausalIssuer,
        binder: &mut contour_postgres::CausalMarkerBinder,
        product_credential: &str,
    ) -> Result<ReceiverMarkerBound504<'a>, LaunchObserveError> {
        let started = &self._authenticated._started;
        let pre = &started._created.prelaunch;
        let material = started._created.material.identity();
        if !valid_generation_material(
            product_credential,
            pre.peer,
            material.export_leaf(),
            material.product_leaf(),
            material.marker_public(),
        ) {
            return Err(LaunchObserveError::Invalid);
        }
        let product_leaf = material.product_leaf();
        let marker_public = material.marker_public();
        let initial = self.verify_generation_target().await?;
        let generation = self
            ._authenticated
            ._started
            ._created
            .prelaunch
            .owner
            .claim_generation()
            .map_err(|_| LaunchObserveError::MutationUnknown)?;
        if self
            .verify_generation_target()
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?
            != initial
        {
            return Err(LaunchObserveError::MutationUnknown);
        }
        {
            let pre = &self._authenticated._started._created.prelaunch;
            issuer
                .claim_receiver_generation_504_until(
                    &mut self._session,
                    &generation,
                    &pre.peer,
                    pre.grants,
                    pre.policies,
                    pre.deadline,
                )
                .await
                .map_err(|_| LaunchObserveError::MutationUnknown)?;
        }
        if self
            .verify_generation_target()
            .await
            .map_err(|_| LaunchObserveError::MutationUnknown)?
            != initial
        {
            return Err(LaunchObserveError::MutationUnknown);
        }
        let receipt = {
            let pre = &self._authenticated._started._created.prelaunch;
            binder
                .bind_receiver_504_until(
                    &mut self._session,
                    contour_postgres::CausalReceiverMarkerInputs504 {
                        generation: &generation,
                        product_credential_id: product_credential,
                        product_leaf: &product_leaf,
                        public_key: &marker_public,
                        peer: &pre.peer,
                        grant_keys: pre.grants,
                        policy_keys: pre.policies,
                    },
                    pre.deadline,
                )
                .await
                .map_err(|_| LaunchObserveError::MutationUnknown)?
        };
        if receipt.public_key() != marker_public
            || self
                .verify_generation_target()
                .await
                .map_err(|_| LaunchObserveError::MutationUnknown)?
                != initial
        {
            return Err(LaunchObserveError::MutationUnknown);
        }
        Ok(ReceiverMarkerBound504 {
            _issued: self,
            _generation: generation,
            _product_credential: product_credential.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        exact_mounts, matches_receiver_image, valid_generation_material, valid_namespace,
        valid_ports, valid_sysctls,
    };
    use serde_json::json;
    #[test]
    fn generation_inputs_bind_actual_purpose_material_and_canonical_credential() {
        let id = "00000000-0000-4000-8000-000000000001";
        let peer = [1; 32];
        let product = [2; 32];
        let marker = [3; 32];
        assert!(valid_generation_material(id, peer, peer, product, marker));
        assert!(!valid_generation_material(
            id, peer, [4; 32], product, marker
        ));
        assert!(!valid_generation_material(id, peer, peer, peer, marker));
        assert!(!valid_generation_material(id, peer, peer, product, [0; 32]));
        assert!(!valid_generation_material(
            id, [0; 32], [0; 32], product, marker
        ));
        assert!(!valid_generation_material(
            "00000000-0000-4000-8000-00000000000A",
            peer,
            peer,
            product,
            marker
        ));
        assert!(!valid_generation_material(
            "00000000000040008000000000000001",
            peer,
            peer,
            product,
            marker
        ));
    }
    #[test]
    fn image_reference_and_exact_platform_descriptor_are_required() {
        let index = format!("sha256:{}", "11".repeat(32));
        let descriptor = json!({"digest":format!("sha256:{}", "22".repeat(32)),"mediaType":"application/vnd.oci.image.manifest.v1+json","size":1234,"platform":{"os":"linux","architecture":"arm64"}});
        let selected = json!({"Descriptor":descriptor});
        let good =
            json!({"Image":index,"Config":{"Image":index},"ImageManifestDescriptor":descriptor});
        assert!(matches_receiver_image(&good, &selected, &index));
        for (key, value) in [
            ("Image", json!(format!("sha256:{}", "33".repeat(32)))),
            ("ImageManifestDescriptor", json!(null)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(!matches_receiver_image(&bad, &selected, &index));
        }
        let mut bad = good.clone();
        bad["Config"]["Image"] = json!("sha256:other");
        assert!(!matches_receiver_image(&bad, &selected, &index));
        let mut bad = good.clone();
        bad["ImageManifestDescriptor"]["digest"] = json!(format!("sha256:{}", "44".repeat(32)));
        assert!(!matches_receiver_image(&bad, &selected, &index));
        let mut bad = good.clone();
        bad["ImageManifestDescriptor"]["platform"]["architecture"] = json!("amd64");
        assert!(!matches_receiver_image(&bad, &selected, &index));
        let mut bad = good.clone();
        bad.as_object_mut()
            .unwrap()
            .remove("ImageManifestDescriptor");
        assert!(!matches_receiver_image(&bad, &selected, &index));
        assert!(!matches_receiver_image(&good, &json!({}), &index));
    }
    #[test]
    fn mounts_reject_substitution_writable_and_extra_seed() {
        let expected = [
            ("/source/a", "/adapter/a"),
            ("/private/cert", "/run/apicontour/live/ca.pem"),
        ];
        let good = json!([{ "Type":"bind", "Source":"/source/a", "Destination":"/adapter/a", "RW":false, "Propagation":"rprivate" }, { "Type":"bind", "Source":"/private/cert", "Destination":"/run/apicontour/live/ca.pem", "RW":false, "Propagation":"rprivate" }]);
        assert!(exact_mounts(&good, &expected));
        let mut bad = good.clone();
        bad[0]["Source"] = json!("/source/swapped");
        assert!(!exact_mounts(&bad, &expected));
        let mut bad = good.clone();
        bad[1]["RW"] = json!(true);
        assert!(!exact_mounts(&bad, &expected));
        let mut bad = good.clone();
        bad.as_array_mut().unwrap().push(json!({"Type":"bind", "Source":"/private/seed", "Destination":"/run/apicontour/live/seed", "RW":false, "Propagation":"rprivate"}));
        assert!(!exact_mounts(&bad, &expected));
    }
    #[test]
    fn sysctls_accepts_docker_omission_null_or_empty_object_only() {
        for good in [json!({}), json!({"Sysctls":null}), json!({"Sysctls":{}})] {
            assert!(valid_sysctls(&good));
        }
        for bad in [
            json!({"Sysctls":{"net.ipv4.ip_forward":"1"}}),
            json!({"Sysctls":[]}),
            json!({"Sysctls":""}),
            json!({"Sysctls":false}),
        ] {
            assert!(!valid_sysctls(&bad));
        }
    }
    #[test]
    fn namespace_and_shm_require_exact_explicit_values() {
        assert!(valid_namespace(
            &json!({"CgroupnsMode":"private", "ShmSize":67108864})
        ));
        for bad in [
            json!({}),
            json!({"CgroupnsMode":"host", "ShmSize":67108864}),
            json!({"CgroupnsMode":"private"}),
            json!({"CgroupnsMode":"private", "ShmSize":67108865}),
            json!({"CgroupnsMode":"private", "ShmSize":"67108864"}),
        ] {
            assert!(!valid_namespace(&bad));
        }
    }
    #[test]
    fn ports_reject_missing_invalid_publication_and_unknown_keys() {
        for good in [json!({"Ports":{}}), json!({"Ports":{"1880/tcp":null}})] {
            assert!(valid_ports(&good));
        }
        for bad in [
            json!({}),
            json!({"Ports":null}),
            json!({"Ports":[]}),
            json!({"Ports":{"1880/tcp":[{"HostIp":"127.0.0.1", "HostPort":"1880"}]}}),
            json!({"Ports":{"9999/tcp":null}}),
        ] {
            assert!(!valid_ports(&bad));
        }
    }
}
