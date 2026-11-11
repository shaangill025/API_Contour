//! Operator-supervised candidate factory component probe. Inputs are synthetic.
//! READY means the checked launcher observed the correlated startup event; it
//! does not prove exporter admission, causal wire propagation, or graph output.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_ingress::{
    CandidateSources, CausalIssueOwner, DockerPolicy, LaunchConfig, OwnerLabel, Prelaunch503,
};
use contour_postgres::{
    CausalBinding, CausalIssue, CausalIssuer, CausalMarkerBinder, DatabaseSettings, TrustedCa,
};
use serde::Deserialize;
use std::{
    env,
    fs::File,
    future::Future,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    cid: String,
    image: String,
    owner: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    host: String,
    port: u16,
    database: String,
    issuer_user: String,
    binder_user: String,
    database_ca: PathBuf,
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
    docker_binary: PathBuf,
    docker_socket: PathBuf,
    docker_config: PathBuf,
    docker_binary_sha256: String,
    image: String,
    network: String,
    network_name: String,
    network_owner: String,
    peers: Vec<Peer>,
    mounts: [PathBuf; 11],
    product_credential: String,
    export_credential: String,
    batch_bytes: u32,
    batch_events: u32,
    queue_bytes: u32,
    queue_ttl_ms: u32,
}
fn read(path: &Path) -> Result<Vec<u8>, &'static str> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| "input")?
        .take(1_048_577)
        .read_to_end(&mut data)
        .map_err(|_| "input")?;
    if data.len() > 1_048_576 {
        return Err("input");
    }
    Ok(data)
}
fn hex(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("hex identity");
    }
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).map_err(|_| "hex identity")?;
    }
    Ok(result)
}
fn public(path: &Path) -> Result<[u8; 32], &'static str> {
    read(path)?.try_into().map_err(|_| "public key")
}
async fn wait_cleanup(
    result: impl Fn() -> Option<bool>,
    deadline: tokio::time::Instant,
) -> Result<(), &'static str> {
    loop {
        match result() {
            Some(true) => return Ok(()),
            Some(false) => return Err("local cleanup unproved"),
            None if tokio::time::Instant::now() >= deadline => {
                return Err("local cleanup deadline");
            }
            None => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("factory probe: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err("arguments");
    }
    let input: Inputs = serde_json::from_slice(&read(Path::new(&args[0]))?).map_err(|_| "input")?;
    let password = env::var("CONTOUR_CAUSAL_ISSUER_PASSWORD").map_err(|_| "password")?;
    let trust = TrustedCa::from_pem(&read(&input.database_ca)?).map_err(|_| "database trust")?;
    let grants = CausalGrantKeys::new(&[("fixture", public(&input.grant_public)?)])
        .map_err(|_| "grant key")?;
    let policies =
        PolicyKeys::new(&[("fixture", public(&input.policy_public)?)]).map_err(|_| "policy key")?;
    let peer = hex(&input.peer)?;
    let ids = std::array::from_fn(|i| input.ids[i].as_str());
    let issue = CausalIssue::new(
        CausalBinding::new(ids, peer).map_err(|_| "binding")?,
        &input.nonce,
        Duration::from_secs(300),
        &read(&input.grant)?,
        &read(&input.policy)?,
    )
    .map_err(|_| "issue")?;
    let owner = CausalIssueOwner::prepare(
        &input.issue_dir,
        issue,
        hex(&input.source_identity)?,
        hex(&input.key_identity)?,
    )
    .map_err(|_| "issue journal")?;
    let docker = Arc::new(
        DockerPolicy::new(
            &input.docker_binary,
            &input.docker_socket,
            &input.docker_config,
            hex(&input.docker_binary_sha256)?,
        )
        .map_err(|_| "docker policy")?,
    );
    let settings = |user: &str| {
        DatabaseSettings::new(
            &input.host,
            input.port,
            &input.database,
            user,
            password.as_bytes(),
            Duration::from_secs(10),
        )
        .map_err(|_| "database settings")
    };
    let issuer_settings = settings(&input.issuer_user)?;
    let binder_settings = settings(&input.binder_user)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime")?
        .block_on(async {
            let mut issuer = CausalIssuer::new(
                issuer_settings
                    .connect(&trust)
                    .await
                    .map_err(|_| "issuer TLS")?,
            );
            let mut binder = CausalMarkerBinder::new(
                binder_settings
                    .connect(&trust)
                    .await
                    .map_err(|_| "binder TLS")?,
            );
            let pre =
                Prelaunch503::prepare(owner, peer, &grants, &policies).map_err(|_| "preflight")?;
            let image = pre
                .inspect_image(&docker, hex(&input.image)?)
                .await
                .map_err(|_| "image")?;
            let mut peers = Vec::new();
            for p in &input.peers {
                peers.push(
                    pre.inspect_peer(
                        &docker,
                        hex(&p.cid)?,
                        hex(&p.image)?,
                        OwnerLabel::Fixture,
                        hex(&p.owner)?,
                    )
                    .await
                    .map_err(|_| "peer")?,
                );
            }
            let network = pre
                .inspect_network(
                    &docker,
                    hex(&input.network)?,
                    &input.network_name,
                    OwnerLabel::Fixture,
                    hex(&input.network_owner)?,
                    &peers,
                )
                .await
                .map_err(|_| "network")?;
            let sources = CandidateSources::capture(&input.mounts).map_err(|_| "sources")?;
            let created = pre
                .create(&docker, &input.journal_dir, image, network, sources)
                .await
                .map_err(|_| "create")?;
            let started = created.start(docker).await.map_err(|_| "start")?;
            let bound = started
                .bind(
                    &mut issuer,
                    &mut binder,
                    LaunchConfig {
                        product_credential: input.product_credential,
                        export_credential: input.export_credential,
                        batch_bytes: input.batch_bytes,
                        batch_events: input.batch_events,
                        queue_bytes: input.queue_bytes,
                        queue_ttl_ms: input.queue_ttl_ms,
                    },
                )
                .await
                .map_err(|_| "bind")?;
            let cleanup = bound.local_cleanup();
            let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
            let mut work = Box::pin(bound.run(&mut issuer, &mut binder, ready_tx));
            std::future::poll_fn(|cx| {
                if let std::task::Poll::Ready(result) = work.as_mut().poll(cx) {
                    return std::task::Poll::Ready(Err(if result.is_ok() {
                        "unexpected completion"
                    } else {
                        "relay closed"
                    }));
                }
                match std::pin::Pin::new(&mut ready_rx).poll(cx) {
                    std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
                    std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(Err("startup closed")),
                    std::task::Poll::Pending => std::task::Poll::Pending,
                }
            })
            .await?;
            println!("READY");
            io::stdout().flush().map_err(|_| "output")?;
            let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let mut input = [0; 5];
                let good = io::stdin().read_exact(&mut input).is_ok() && &input == b"STOP\n";
                let _ = stop_tx.send(good);
            });
            std::future::poll_fn(|cx| {
                if work.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(Err("relay closed"));
                }
                match std::pin::Pin::new(&mut stop_rx).poll(cx) {
                    std::task::Poll::Ready(Ok(true)) => std::task::Poll::Ready(Ok(())),
                    std::task::Poll::Ready(_) => std::task::Poll::Ready(Err("control")),
                    std::task::Poll::Pending => std::task::Poll::Pending,
                }
            })
            .await?;
            drop(work);
            wait_cleanup(
                || cleanup.result(),
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await?;
            println!("CAPTURE_CLOSED");
            io::stdout().flush().map_err(|_| "output")?;
            Ok(())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_requires_positive_acknowledgement() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            assert_eq!(
                wait_cleanup(|| Some(true), tokio::time::Instant::now()).await,
                Ok(())
            );
            assert_eq!(
                wait_cleanup(|| Some(false), tokio::time::Instant::now()).await,
                Err("local cleanup unproved")
            );
            assert_eq!(
                wait_cleanup(|| None, tokio::time::Instant::now()).await,
                Err("local cleanup deadline")
            );
        });
    }
}
