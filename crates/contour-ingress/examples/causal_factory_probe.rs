//! Operator-supervised candidate factory component probe. Inputs are synthetic.
//! READY means the checked launcher observed the correlated startup event; it
//! does not prove exporter admission, causal wire propagation, or graph output.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_ingress::ProcessError;
use contour_ingress::{
    BindStage, BoundLaunchError, CandidateSources, CausalIssueOwner, CausalJournalError,
    DockerPolicy, LaunchConfig, OwnerLabel, Prelaunch503,
};
use contour_postgres::{
    CausalBinding, CausalError, CausalIssue, CausalIssuer, CausalMarkerBinder, DatabaseSettings,
    TrustedCa,
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
fn bind_error(error: BoundLaunchError) -> &'static str {
    match error {
        BoundLaunchError::Invalid => "bind_invalid",
        BoundLaunchError::Expired => "bind_expired",
        BoundLaunchError::Transfer => "bind_transfer",
        BoundLaunchError::Journal(error) => match error {
            CausalJournalError::Io => "bind_journal_io",
            CausalJournalError::Unsafe => "bind_journal_unsafe",
            CausalJournalError::Busy => "bind_journal_busy",
            CausalJournalError::Mismatch => "bind_journal_mismatch",
            CausalJournalError::Corrupt => "bind_journal_corrupt",
        },
        BoundLaunchError::Database(error) => match error {
            CausalError::Identity => "bind_database_identity",
            CausalError::Signature => "bind_database_signature",
            CausalError::Scope => "bind_database_scope",
            CausalError::Expired => "bind_database_expired",
            CausalError::InvalidBatch => "bind_database_invalid_batch",
            CausalError::Conflict => "bind_database_conflict",
            CausalError::Corrupt => "bind_database_corrupt",
            CausalError::LogicalQuota => "bind_database_logical_quota",
            CausalError::HistoryLimit => "bind_database_history_limit",
            CausalError::Busy => "bind_database_busy",
            CausalError::Database => "bind_database_database",
            CausalError::Deadline => "bind_database_deadline",
            CausalError::OutcomeUnknown => "bind_database_outcome_unknown",
        },
    }
}
fn bind_invalid_stage(stage: BindStage) -> &'static str {
    match stage {
        BindStage::NotStarted => "bind_invalid_not_started",
        BindStage::Preflight => "bind_invalid_preflight",
        BindStage::Sources => "bind_invalid_sources",
        BindStage::Seal => "bind_invalid_seal",
        BindStage::MountsBefore => "bind_invalid_mounts_before",
        BindStage::TargetBefore => "bind_invalid_target_before",
        BindStage::TargetStart => "bind_invalid_target_start",
        BindStage::TargetSourcesBefore => "bind_invalid_target_sources_before",
        BindStage::TargetImage => "bind_invalid_target_image",
        BindStage::TargetPeer => "bind_invalid_target_peer",
        BindStage::TargetFirst => "bind_invalid_target_first",
        BindStage::TargetNetwork => "bind_invalid_target_network",
        BindStage::TargetSecond => "bind_invalid_target_second",
        BindStage::TargetActual => "bind_invalid_target_actual",
        BindStage::TargetSourcesAfter => "bind_invalid_target_sources_after",
        BindStage::TargetFinish => "bind_invalid_target_finish",
        BindStage::Material => "bind_invalid_material",
        BindStage::Peer => "bind_invalid_peer",
        BindStage::Generation => "bind_invalid_generation",
        BindStage::Database => "bind_invalid_database",
        BindStage::Session => "bind_invalid_session",
        BindStage::MountsAfter => "bind_invalid_mounts_after",
        BindStage::TargetAfter => "bind_invalid_target_after",
        BindStage::Metadata => "bind_invalid_metadata",
        BindStage::UnixStream => "bind_invalid_unix_stream",
        BindStage::LaunchJournal => "bind_invalid_launch_journal",
        BindStage::Complete => "bind_invalid_complete",
    }
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
enum ProbeError {
    Static(&'static str),
    BindProcess(BindStage, ProcessError, bool),
}
impl From<&'static str> for ProbeError {
    fn from(value: &'static str) -> Self {
        Self::Static(value)
    }
}
fn process_class(error: ProcessError) -> &'static str {
    match error {
        ProcessError::Unsafe => "unsafe",
        ProcessError::Busy => "busy",
        ProcessError::Existing => "existing",
        ProcessError::Io => "io",
        ProcessError::Timeout => "timeout",
        ProcessError::OutputLimit => "output_limit",
        ProcessError::Exit => "exit",
        ProcessError::CleanupUnknown => "cleanup_unknown",
    }
}
fn main() {
    if let Err(error) = run() {
        match error {
            ProbeError::Static(stage) => eprintln!("factory probe: {stage}"),
            ProbeError::BindProcess(stage, error, reached) => eprintln!(
                "factory probe: {} {} {}",
                bind_invalid_stage(stage),
                process_class(error),
                if reached {
                    "deadline_reached"
                } else {
                    "deadline_not_reached"
                }
            ),
        }
        std::process::exit(1);
    }
}
fn run() -> Result<(), ProbeError> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err("arguments".into());
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
            let progress = started.bind_progress();
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
                .map_err(|error| match error {
                    BoundLaunchError::Invalid => match progress.process_failure() {
                        Some((error, reached)) => {
                            ProbeError::BindProcess(progress.stage(), error, reached)
                        }
                        None => ProbeError::Static(bind_invalid_stage(progress.stage())),
                    },
                    other => ProbeError::Static(bind_error(other)),
                })?;
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
    fn process_classes_are_fixed_and_distinct() {
        let classes = [
            (ProcessError::Unsafe, "unsafe"),
            (ProcessError::Busy, "busy"),
            (ProcessError::Existing, "existing"),
            (ProcessError::Io, "io"),
            (ProcessError::Timeout, "timeout"),
            (ProcessError::OutputLimit, "output_limit"),
            (ProcessError::Exit, "exit"),
            (ProcessError::CleanupUnknown, "cleanup_unknown"),
        ];
        for (error, expected) in classes {
            assert_eq!(process_class(error), expected);
        }
    }
    #[test]
    fn bind_stage_projection_is_fixed_and_distinct() {
        let stages = [
            BindStage::NotStarted,
            BindStage::Preflight,
            BindStage::Sources,
            BindStage::Seal,
            BindStage::MountsBefore,
            BindStage::TargetBefore,
            BindStage::TargetStart,
            BindStage::TargetSourcesBefore,
            BindStage::TargetImage,
            BindStage::TargetPeer,
            BindStage::TargetFirst,
            BindStage::TargetNetwork,
            BindStage::TargetSecond,
            BindStage::TargetActual,
            BindStage::TargetSourcesAfter,
            BindStage::TargetFinish,
            BindStage::Material,
            BindStage::Peer,
            BindStage::Generation,
            BindStage::Database,
            BindStage::Session,
            BindStage::MountsAfter,
            BindStage::TargetAfter,
            BindStage::Metadata,
            BindStage::UnixStream,
            BindStage::LaunchJournal,
            BindStage::Complete,
        ];
        let outputs: std::collections::BTreeSet<_> =
            stages.into_iter().map(bind_invalid_stage).collect();
        assert_eq!(outputs.len(), stages.len());
        assert!(outputs.iter().all(|s| s.starts_with("bind_invalid_")));
    }
    #[test]
    fn bind_errors_have_fixed_distinct_classes() {
        let cases = [
            (BoundLaunchError::Invalid, "bind_invalid"),
            (BoundLaunchError::Expired, "bind_expired"),
            (BoundLaunchError::Transfer, "bind_transfer"),
            (
                BoundLaunchError::Journal(CausalJournalError::Io),
                "bind_journal_io",
            ),
            (
                BoundLaunchError::Journal(CausalJournalError::Unsafe),
                "bind_journal_unsafe",
            ),
            (
                BoundLaunchError::Journal(CausalJournalError::Busy),
                "bind_journal_busy",
            ),
            (
                BoundLaunchError::Journal(CausalJournalError::Mismatch),
                "bind_journal_mismatch",
            ),
            (
                BoundLaunchError::Journal(CausalJournalError::Corrupt),
                "bind_journal_corrupt",
            ),
            (
                BoundLaunchError::Database(CausalError::Identity),
                "bind_database_identity",
            ),
            (
                BoundLaunchError::Database(CausalError::Signature),
                "bind_database_signature",
            ),
            (
                BoundLaunchError::Database(CausalError::Scope),
                "bind_database_scope",
            ),
            (
                BoundLaunchError::Database(CausalError::Expired),
                "bind_database_expired",
            ),
            (
                BoundLaunchError::Database(CausalError::InvalidBatch),
                "bind_database_invalid_batch",
            ),
            (
                BoundLaunchError::Database(CausalError::Conflict),
                "bind_database_conflict",
            ),
            (
                BoundLaunchError::Database(CausalError::Corrupt),
                "bind_database_corrupt",
            ),
            (
                BoundLaunchError::Database(CausalError::LogicalQuota),
                "bind_database_logical_quota",
            ),
            (
                BoundLaunchError::Database(CausalError::HistoryLimit),
                "bind_database_history_limit",
            ),
            (
                BoundLaunchError::Database(CausalError::Busy),
                "bind_database_busy",
            ),
            (
                BoundLaunchError::Database(CausalError::Database),
                "bind_database_database",
            ),
            (
                BoundLaunchError::Database(CausalError::Deadline),
                "bind_database_deadline",
            ),
            (
                BoundLaunchError::Database(CausalError::OutcomeUnknown),
                "bind_database_outcome_unknown",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(bind_error(error), expected);
        }
    }
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
