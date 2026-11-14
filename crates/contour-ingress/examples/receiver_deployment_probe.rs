//! Operator-supervised receiver 504 inert deployment component probe.
//! Success establishes only the checked inert lifecycle, not bootstrap or session authority.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_ingress::{
    CausalIssueOwner, DockerPolicy, OwnerLabel, Prelaunch504, ReceiverCandidateSources,
    ReceiverImageRequest, ReceiverMaterialPaths, check_receiver_material, observe_receiver_image,
};
use contour_ingress::{
    DockerInspect, HttpLimits, ReceiverCausalConfig504, ReceiverCausalServer504,
    ReceiverRegistry504,
};
use contour_postgres::{
    CausalBinding, CausalIssue, DatabaseSettings, ReceiverEvidenceTls, TrustedCa,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const INPUT_LIMIT: u64 = 32_768;
const ENVELOPE_LIMIT: u64 = 1_048_576;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    marker_seed: PathBuf,
    product_cert: PathBuf,
    product_key: PathBuf,
    export_cert: PathBuf,
    export_key: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    evidence_cert: PathBuf,
    evidence_key: PathBuf,
    ca: PathBuf,
    server_name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    docker: PathBuf,
    docker_sha256: String,
    socket: PathBuf,
    docker_config: PathBuf,
    python: PathBuf,
    python_sha256: String,
    openssl: PathBuf,
    openssl_sha256: String,
    source_root: PathBuf,
    stage_root: PathBuf,
    image_sha256: String,
    architecture: Architecture,
    owner_sha256: String,
    material: Material,
    grant_public: PathBuf,
    policy_public: PathBuf,
    grant: PathBuf,
    policy: PathBuf,
    peer: String,
    ids: [String; 10],
    nonce: String,
    issue_dir: PathBuf,
    journal_dir: PathBuf,
    source_identity: String,
    key_identity: String,
    network: String,
    network_name: String,
    network_owner: String,
    #[serde(default)]
    preauth: Option<Preauth>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preauth {
    collector_cert: PathBuf,
    collector_key: PathBuf,
    collector_ca: PathBuf,
    relay_cid: String,
    relay_image: String,
    relay_owner: String,
    external_network: String,
    external_name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Architecture {
    Arm64,
    Amd64,
}
fn digest(text: &str) -> Result<[u8; 32], ()> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(());
    }
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| ())?;
    }
    Ok(result)
}
fn parse_input(bytes: &[u8]) -> Result<Input, ()> {
    if bytes.len() as u64 > INPUT_LIMIT {
        return Err(());
    }
    serde_json::from_slice(bytes).map_err(|_| ())
}
fn read_bounded(mut reader: impl Read, limit: u64) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > limit {
        return Err(());
    }
    Ok(bytes)
}
fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>, ()> {
    read_bounded(File::open(path).map_err(|_| ())?, limit)
}
fn public(path: &Path) -> Result<[u8; 32], ()> {
    read_file(path, 32)?.try_into().map_err(|_| ())
}
// Fixture-only raw TLS relay. It never sees plaintext or receives credentials.
const RELAY: &str = "'use strict';const n=require('node:net');let live=0;const server=n.createServer(c=>{if(live>=16){c.destroy();return}live++;let done=false;const end=()=>{if(!done){done=true;live--;c.destroy();u.destroy()}};const u=n.connect({host:'host.docker.internal',port:18443});c.setTimeout(8000,end);u.setTimeout(8000,end);c.on('error',end);u.on('error',end);c.on('close',end);u.on('close',end);c.pipe(u);u.pipe(c)});server.listen(8443,'0.0.0.0',()=>process.stdout.write('READY\\n'));setTimeout(()=>server.close(),540000).unref();";
struct ListenerGuard {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), contour_ingress::IngressError>>,
}
impl Drop for ListenerGuard {
    fn drop(&mut self) {
        self.stop.take();
        self.task.abort();
    }
}
async fn relay_snapshot(
    docker: &DockerPolicy,
    p: &Preauth,
    internal_name: &str,
    internal: [u8; 32],
    image_ref: &str,
    deadline: Instant,
) -> Result<Value, ()> {
    let cid = digest(&p.relay_cid)?;
    let image = digest(&p.relay_image)?;
    let owner = digest(&p.relay_owner)?;
    let external = digest(&p.external_network)?;
    let raw = docker
        .inspect(DockerInspect::Container(cid), deadline)
        .map_err(|_| ())?
        .wait()
        .await
        .map_err(|_| ())?;
    let value: Value = serde_json::from_slice(&raw).map_err(|_| ())?;
    let rows = value.as_array().ok_or(())?;
    if rows.len() != 1 {
        return Err(());
    }
    let item = &rows[0];
    let cfg = &item["Config"];
    let host = &item["HostConfig"];
    let state = &item["State"];
    let networks = item["NetworkSettings"]["Networks"].as_object().ok_or(())?;
    let id_hex = |x: &[u8; 32]| x.iter().map(|b| format!("{b:02x}")).collect::<String>();
    if item["Id"].as_str() != Some(id_hex(&cid).as_str())
        || item["Image"].as_str() != Some(format!("sha256:{}", id_hex(&image)).as_str())
        || cfg["Image"].as_str() != Some(image_ref)
        || cfg["Labels"]["org.apicontour.fixture-owner"].as_str() != Some(id_hex(&owner).as_str())
        || cfg["Entrypoint"] != serde_json::json!(["/usr/bin/env"])
        || cfg["Cmd"] != serde_json::json!(["-i", "/usr/local/bin/node", "-e", RELAY])
        || cfg["User"].as_str() != Some("1000:1000")
        || host["ReadonlyRootfs"] != true
        || host["Privileged"] != false
        || host["PublishAllPorts"] != false
        || !host["PortBindings"].is_null() && host["PortBindings"] != serde_json::json!({})
        || state["Running"] != true
        || state["Status"].as_str() != Some("running")
        || state["Pid"].as_u64().is_none_or(|v| v == 0)
        || state["StartedAt"]
            .as_str()
            .is_none_or(|v| v.is_empty() || v.starts_with("0001-"))
        || networks.len() != 2
        || networks
            .get(internal_name)
            .and_then(|x| x["NetworkID"].as_str())
            != Some(id_hex(&internal).as_str())
        || networks
            .get(&p.external_name)
            .and_then(|x| x["NetworkID"].as_str())
            != Some(id_hex(&external).as_str())
        || !networks
            .get(internal_name)
            .and_then(|x| x["Aliases"].as_array())
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("causal-ingress")))
    {
        return Err(());
    }
    Ok(item.clone())
}
fn run() -> Result<(), &'static str> {
    if std::env::args_os().len() != 1 {
        return Err("input");
    }
    let data = read_bounded(io::stdin().lock(), INPUT_LIMIT).map_err(|_| "input")?;
    let input = parse_input(&data).map_err(|_| "input")?;
    let docker_hash = digest(&input.docker_sha256).map_err(|_| "input")?;
    let python_hash = digest(&input.python_sha256).map_err(|_| "input")?;
    let openssl_hash = digest(&input.openssl_sha256).map_err(|_| "input")?;
    let image_id = digest(&input.image_sha256).map_err(|_| "input")?;
    let owner_id = digest(&input.owner_sha256).map_err(|_| "input")?;
    let peer = digest(&input.peer).map_err(|_| "input")?;
    let source_id = digest(&input.source_identity).map_err(|_| "input")?;
    let key_id = digest(&input.key_identity).map_err(|_| "input")?;
    let network_id = digest(&input.network).map_err(|_| "input")?;
    let network_owner = digest(&input.network_owner).map_err(|_| "input")?;
    let grant_key = public(&input.grant_public).map_err(|_| "request")?;
    let policy_key = public(&input.policy_public).map_err(|_| "request")?;
    let grants = CausalGrantKeys::new(&[("fixture", grant_key)]).map_err(|_| "request")?;
    let policies = PolicyKeys::new(&[("fixture", policy_key)]).map_err(|_| "request")?;
    let ids = std::array::from_fn(|i| input.ids[i].as_str());
    let binding = CausalBinding::new(ids, peer).map_err(|_| "request")?;
    let grant = read_file(&input.grant, ENVELOPE_LIMIT).map_err(|_| "request")?;
    let policy = read_file(&input.policy, ENVELOPE_LIMIT).map_err(|_| "request")?;
    let issue = CausalIssue::new(
        binding,
        &input.nonce,
        Duration::from_secs(300),
        &grant,
        &policy,
    )
    .map_err(|_| "request")?;
    let owner = CausalIssueOwner::prepare(&input.issue_dir, issue, source_id, key_id)
        .map_err(|_| "request")?;
    let docker = Arc::new(
        DockerPolicy::new(
            &input.docker,
            &input.socket,
            &input.docker_config,
            docker_hash,
        )
        .map_err(|_| "docker")?,
    );
    let deadline = Instant::now() + Duration::from_secs(540);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime")?;
    runtime.block_on(async {
        let image = observe_receiver_image(ReceiverImageRequest {
            docker: &docker,
            python: &input.python,
            python_sha256: python_hash,
            scripts_dir: &input.source_root.join("scripts"),
            stage_path: &input.stage_root.join("receiver504-image-stage"),
            image: image_id,
            arm64: matches!(input.architecture, Architecture::Arm64),
            owner: owner_id,
            deadline,
        })
        .await
        .map_err(|_| "image")?;
        println!("receiver504_image_config={}", image.candidate_config());
        let sources = ReceiverCandidateSources::seal(&input.source_root).map_err(|_| "sources")?;
        let m = input.material;
        let paths = ReceiverMaterialPaths {
            marker_seed: m.marker_seed,
            product_cert: m.product_cert,
            product_key: m.product_key,
            export_cert: m.export_cert,
            export_key: m.export_key,
            server_cert: m.server_cert,
            server_key: m.server_key,
            evidence_cert: m.evidence_cert,
            evidence_key: m.evidence_key,
            ca: m.ca,
            server_name: m.server_name,
        };
        let material = check_receiver_material(
            &paths,
            &input.openssl,
            openssl_hash,
            &input.stage_root.join("receiver504-material-stage"),
            deadline,
        )
        .await
        .map_err(|_| "material")?;
        let prelaunch =
            Prelaunch504::prepare(owner, peer, &grants, &policies).map_err(|_| "preflight")?;
        let mut peers = Vec::new();
        let mut listener = None;
        let mut broker = None;
        let relay_before = if let Some(ref p) = input.preauth {
            let cert_pem = read_file(&p.collector_cert, 65536).map_err(|_| "preauth_config")?;
            let key_pem = read_file(&p.collector_key, 65536).map_err(|_| "preauth_config")?;
            let ca_pem = read_file(&p.collector_ca, 65536).map_err(|_| "preauth_config")?;
            if ca_pem != read_file(&paths.ca, 65536).map_err(|_| "preauth_config")? {
                return Err("preauth_config");
            }
            let cert = CertificateDer::from_pem_slice(&cert_pem).map_err(|_| "preauth_config")?;
            let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|_| "preauth_config")?;
            let ca = CertificateDer::from_pem_slice(&ca_pem).map_err(|_| "preauth_config")?;
            let tls = ReceiverEvidenceTls::from_der(
                &[cert.as_ref()],
                key.secret_der(),
                &[ca.as_ref()],
                Duration::from_secs(5),
            )
            .map_err(|_| "preauth_config")?;
            let settings = || {
                DatabaseSettings::new(
                    "localhost",
                    1,
                    "unused",
                    "unused",
                    b"unused",
                    Duration::from_secs(5),
                )
                .map_err(|_| "preauth_config")
            };
            let trust = || TrustedCa::from_pem(&ca_pem).map_err(|_| "preauth_config");
            let cfg = ReceiverCausalConfig504 {
                tls,
                registry: ReceiverRegistry504::pending_only(),
                event_database: settings()?,
                event_trust: trust()?,
                fact_database: settings()?,
                fact_trust: trust()?,
                grant_keys: CausalGrantKeys::new(&[("fixture", grant_key)])
                    .map_err(|_| "preauth_config")?,
                policy_keys: PolicyKeys::new(&[("fixture", policy_key)])
                    .map_err(|_| "preauth_config")?,
                limits: HttpLimits::new(8, Duration::from_secs(5))
                    .map_err(|_| "preauth_config")?
                    .with_database_sessions(2)
                    .map_err(|_| "preauth_config")?,
                event_slots: 1,
            };
            let socket = tokio::net::TcpListener::bind("127.0.0.1:18443")
                .await
                .map_err(|_| "preauth_listener")?;
            let (server, handle) =
                ReceiverCausalServer504::new_with_preauth(cfg).map_err(|_| "preauth_config")?;
            let (stop, shutdown) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                server
                    .serve(socket, async {
                        let _ = shutdown.await;
                    })
                    .await
            });
            listener = Some(ListenerGuard {
                stop: Some(stop),
                task,
            });
            let ready = tokio::time::Instant::now() + Duration::from_secs(5);
            while !handle.is_active() {
                if tokio::time::Instant::now() >= ready
                    || listener.as_ref().is_none_or(|v| v.task.is_finished())
                {
                    return Err("preauth_listener");
                }
                tokio::task::yield_now().await;
            }
            let relay = relay_snapshot(
                &docker,
                p,
                &input.network_name,
                network_id,
                &format!("sha256:{}", input.image_sha256),
                deadline,
            )
            .await
            .map_err(|_| "preauth_relay")?;
            peers.push(
                prelaunch
                    .inspect_peer(
                        &docker,
                        digest(&p.relay_cid).map_err(|_| "input")?,
                        digest(&p.relay_image).map_err(|_| "input")?,
                        OwnerLabel::Fixture,
                        digest(&p.relay_owner).map_err(|_| "input")?,
                    )
                    .await
                    .map_err(|_| "preauth_relay")?,
            );
            broker = Some(handle);
            Some(relay)
        } else {
            None
        };
        let network = prelaunch
            .inspect_network(
                &docker,
                network_id,
                &input.network_name,
                OwnerLabel::Fixture,
                network_owner,
                peers,
            )
            .await
            .map_err(|_| "network")?;
        let created = prelaunch
            .create(
                &docker,
                &input.journal_dir,
                image,
                network,
                sources,
                material,
            )
            .await
            .map_err(|_| "create")?;
        created
            .verify_created(&docker)
            .await
            .map_err(|_| "verify_created")?;
        let started = created.start(docker.clone()).await.map_err(|_| "start")?;
        if let Some(p) = input.preauth.as_ref() {
            let broker = broker.as_ref().ok_or("preauth_config")?;
            let before = relay_before.ok_or("preauth_relay")?;
            let authenticated = started
                .preauthenticate(broker)
                .await
                .map_err(|_| "preauth")?;
            let after = relay_snapshot(
                &docker,
                p,
                &input.network_name,
                network_id,
                &format!("sha256:{}", input.image_sha256),
                deadline,
            )
            .await
            .map_err(|_| "preauth_relay")?;
            if before != after {
                return Err("preauth_relay");
            }
            drop(authenticated);
            let mut server = listener.take().ok_or("preauth_listener")?;
            server
                .stop
                .take()
                .ok_or("preauth_listener")?
                .send(())
                .map_err(|_| "preauth_listener")?;
            tokio::time::timeout(Duration::from_secs(5), &mut server.task)
                .await
                .map_err(|_| "preauth_listener")?
                .map_err(|_| "preauth_listener")?
                .map_err(|_| "preauth_listener")?;
            println!("receiver504_preauth=pass");
            return Ok(());
        }
        // Dropping the attach closes the private stream; it can cause the proxy to exit.
        drop(started);
        Ok(())
    })
}
fn main() {
    match run() {
        Ok(()) => println!("receiver504_deployment=pass"),
        Err(phase) => {
            println!("receiver504_deployment=fail phase={phase}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn input() -> Value {
        let hash = "ab".repeat(32);
        json!({
            "docker":"/docker", "docker_sha256":hash, "socket":"/socket", "docker_config":"/config",
            "python":"/python", "python_sha256":hash, "openssl":"/openssl", "openssl_sha256":hash,
            "source_root":"/source", "stage_root":"/stage", "image_sha256":hash, "architecture":"arm64", "owner_sha256":hash,
            "material":{"marker_seed":"/seed", "product_cert":"/pc", "product_key":"/pk", "export_cert":"/ec", "export_key":"/ek", "server_cert":"/sc", "server_key":"/sk", "evidence_cert":"/vc", "evidence_key":"/vk", "ca":"/ca", "server_name":"causal-receiver"},
            "grant_public":"/gp", "policy_public":"/pp", "grant":"/g", "policy":"/p", "peer":hash,
            "ids":["a","a","a","a","a","a","a","a","a","a"], "nonce":"nonce", "issue_dir":"/issue", "journal_dir":"/journal", "source_identity":hash, "key_identity":hash, "network":hash, "network_name":"network", "network_owner":hash
        })
    }
    #[test]
    fn input_is_closed_and_bounded() {
        let good = input();
        assert!(parse_input(&serde_json::to_vec(&good).unwrap()).is_ok());
        let mut extra = good.clone();
        extra["command"] = json!("arbitrary");
        assert!(parse_input(&serde_json::to_vec(&extra).unwrap()).is_err());
        let mut extra_material = good.clone();
        extra_material["material"]["extra"] = json!("/x");
        assert!(parse_input(&serde_json::to_vec(&extra_material).unwrap()).is_err());
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("network");
        assert!(parse_input(&serde_json::to_vec(&missing).unwrap()).is_err());
        assert!(parse_input(&vec![b' '; INPUT_LIMIT as usize + 1]).is_err());
        assert!(read_bounded(&b"abcd"[..], 3).is_err());
    }
    #[test]
    fn preauth_input_is_explicit_and_closed() {
        let mut value = input();
        value["preauth"] = json!({"collector_cert":"/collector.pem","collector_key":"/collector.key","collector_ca":"/ca.pem","relay_cid":"ab".repeat(32),"relay_image":"ab".repeat(32),"relay_owner":"ab".repeat(32),"external_network":"ab".repeat(32),"external_name":"private"});
        assert!(parse_input(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["preauth"]["url"] = json!("https://elsewhere");
        assert!(parse_input(&serde_json::to_vec(&value).unwrap()).is_err());
        value["preauth"].as_object_mut().unwrap().remove("url");
        value["preauth"]
            .as_object_mut()
            .unwrap()
            .remove("relay_cid");
        assert!(parse_input(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn digest_and_architecture_are_closed() {
        assert_eq!(digest(&"ab".repeat(32)), Ok([0xab; 32]));
        for bad in [
            "AB".repeat(32),
            "ab".repeat(31),
            format!("{}gg", "ab".repeat(31)),
        ] {
            assert!(digest(&bad).is_err());
        }
        assert!(serde_json::from_str::<Architecture>("\"arm64\"").is_ok());
        assert!(serde_json::from_str::<Architecture>("\"amd64\"").is_ok());
        assert!(serde_json::from_str::<Architecture>("\"x64\"").is_err());
    }
}
