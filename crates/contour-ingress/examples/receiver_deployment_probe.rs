//! Operator-supervised receiver 504 inert deployment component probe.
//! Success establishes only the checked inert lifecycle, not bootstrap or session authority.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_ingress::{
    CausalIssueOwner, DockerPolicy, OwnerLabel, Prelaunch504, ReceiverCandidateSources,
    ReceiverImageRequest, ReceiverMaterialPaths, check_receiver_material, observe_receiver_image,
};
use contour_postgres::{CausalBinding, CausalIssue};
use serde::Deserialize;
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
        let network = prelaunch
            .inspect_network(
                &docker,
                network_id,
                &input.network_name,
                OwnerLabel::Fixture,
                network_owner,
                Vec::new(),
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
        let started = created.start(docker).await.map_err(|_| "start")?;
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
