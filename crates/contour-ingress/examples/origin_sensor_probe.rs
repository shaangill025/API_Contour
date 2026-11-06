//! Isolated fixture: production Gateway and V2 pool geometry with explicit drain.
use contour_core::{PolicyKeys, QueueLimits};
use contour_delivery::{
    CollectorOwner, CollectorPool, DeliveryClient, OwnerError, RetryDirective, SendOutcome,
};
use contour_ingress::{
    CollectorTls,
    gateway::{CapturePoint, Gateway, GatewayTransport},
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::{
    env, fs,
    io::{self, BufRead},
    net::SocketAddr,
    time::Duration,
};
use tokio::time::{Instant, sleep, timeout_at};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    server_certificate_der: String,
    server_key_der: String,
    forwarder_ca_der: String,
    forwarder_leaf_der: String,
    upstream_address: SocketAddr,
    upstream_name: String,
    upstream_ca_der: String,
    upstream_client_certificate_der: String,
    upstream_client_key_der: String,
    delivery_address: SocketAddr,
    delivery_name: String,
    delivery_ca_der: String,
    delivery_client_certificate_der: String,
    delivery_client_key_der: String,
    tenant: String,
    collector: String,
    source: String,
    workload: [String; 4],
    policy_key_id: String,
    policy_key_file: String,
}
fn read(path: &str, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let data = fs::read(path).map_err(|_| "fixture file unavailable")?;
    if data.is_empty() || data.len() > maximum {
        return Err("fixture file size invalid");
    }
    Ok(data)
}
fn id() -> Result<String, &'static str> {
    let mut b = [0u8; 16];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "random unavailable")?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}
fn diagnostic_outcome(
    outcome: Result<Result<SendOutcome, OwnerError>, tokio::time::error::Elapsed>,
) -> &'static str {
    match outcome {
        Err(_) => "deadline",
        Ok(Err(OwnerError::Paused)) => "owner_paused",
        Ok(Err(OwnerError::HistoryLimit)) => "owner_history_limit",
        Ok(Err(OwnerError::Queue(_))) => "owner_queue",
        Ok(Err(OwnerError::Transport(_))) => "owner_transport",
        Ok(Err(OwnerError::Retry(_))) => "owner_retry",
        Ok(Ok(SendOutcome::Empty)) => "empty",
        Ok(Ok(SendOutcome::Acknowledged { .. })) => "acknowledged",
        Ok(Ok(SendOutcome::Deferred(directive))) => match directive {
            RetryDirective::Retry { .. } => "deferred_retry",
            RetryDirective::DiscardInvalid => "deferred_discard_invalid",
            RetryDirective::RenewAuthorizedEnrollment => "deferred_renew_authorized_enrollment",
            RetryDirective::StopConflict => "deferred_stop_conflict",
            RetryDirective::RequireSplit => "deferred_require_split",
            RetryDirective::StopRejected(_) => "deferred_stop_rejected",
            RetryDirective::StopConfiguration => "deferred_stop_configuration",
            RetryDirective::Expired => "deferred_expired",
        },
    }
}
#[derive(Clone, Copy)]
struct AdmissionStats {
    losses: u64,
    purged: u64,
    acknowledged: u64,
    records: usize,
}
async fn admission_stats(
    pool: &CollectorPool,
    deadline: Instant,
) -> Result<AdmissionStats, &'static str> {
    loop {
        let mut stats = AdmissionStats {
            losses: pool.losses(),
            purged: 0,
            acknowledged: 0,
            records: 0,
        };
        let mut complete = true;
        for slot in 0..4 {
            let Some(current) = pool.try_queue_stats(slot) else {
                complete = false;
                break;
            };
            stats.purged = stats
                .purged
                .checked_add(current.purged)
                .ok_or("purge counter overflow")?;
            stats.acknowledged = stats
                .acknowledged
                .checked_add(current.acknowledged)
                .ok_or("ack counter overflow")?;
            stats.records = stats
                .records
                .checked_add(current.records)
                .ok_or("record counter overflow")?;
        }
        if complete {
            return Ok(stats);
        }
        if Instant::now() >= deadline {
            return Err("stats deadline");
        }
        sleep(Duration::from_millis(10)).await;
    }
}
fn admission_delta(
    before: AdmissionStats,
    after: AdmissionStats,
) -> Result<(u64, u64, u64, usize), &'static str> {
    Ok((
        after
            .losses
            .checked_sub(before.losses)
            .ok_or("loss counter regressed")?,
        after
            .purged
            .checked_sub(before.purged)
            .ok_or("purge counter regressed")?,
        after
            .acknowledged
            .checked_sub(before.acknowledged)
            .ok_or("ack counter regressed")?,
        after.records,
    ))
}
fn fixture_mode(arg: Option<&str>) -> Result<(bool, bool, bool), &'static str> {
    match arg {
        None => Ok((false, false, false)),
        Some("--replacement-diagnostic") => Ok((true, false, false)),
        Some("--admission-diagnostic") => Ok((true, true, false)),
        Some("--discovery-matrix") => Ok((false, false, true)),
        _ => Err("unexpected argument"),
    }
}
fn matrix_command(enabled: bool, command: &str) -> bool {
    enabled && command == "MATRIX_DRAIN"
}
fn reject_loss(matrix: bool, losses: u64) -> bool {
    !matrix && losses != 0
}
fn main() {
    if let Err(e) = run() {
        eprintln!("origin sensor fixture: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    let path = args.next().ok_or("config missing")?;
    let (diagnostic_enabled, terminal_expected, matrix_enabled) =
        fixture_mode(args.next().as_deref())?;
    if args.next().is_some() {
        return Err("unexpected argument");
    }
    let c: Config = serde_json::from_slice(&read(&path, 16384)?).map_err(|_| "config invalid")?;
    if !c.upstream_address.ip().is_loopback() || !c.delivery_address.ip().is_loopback() {
        return Err("non-loopback fixture endpoint");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime failed")?;
    runtime.block_on(async move {
        let timeout = Duration::from_secs(5);
        let server_cert = read(&c.server_certificate_der, 65536)?;
        let server_key = read(&c.server_key_der, 16384)?;
        let forwarder_ca = read(&c.forwarder_ca_der, 65536)?;
        let forwarder = read(&c.forwarder_leaf_der, 65536)?;
        let tls = CollectorTls::from_der(&[&server_cert], &server_key, &[&forwarder_ca], timeout)
            .map_err(|_| "server TLS invalid")?;
        let delivery_ca = read(&c.delivery_ca_der, 65536)?;
        let delivery_cert = read(&c.delivery_client_certificate_der, 65536)?;
        let delivery_key = read(&c.delivery_client_key_der, 16384)?;
        let key: [u8; 32] = read(&c.policy_key_file, 32)?
            .try_into()
            .map_err(|_| "policy key invalid")?;
        // Match the production default: four independent owners, each with
        // 16 records and 16 KiB. The signed policy still governs aggregate quota.
        let mut owners = Vec::with_capacity(4);
        for _ in 0..4 {
            let client = DeliveryClient::from_der_v2(
                &c.delivery_name,
                c.delivery_address,
                [&c.tenant, &c.collector],
                &[&delivery_ca],
                &[&delivery_cert],
                &delivery_key,
                timeout,
            )
            .map_err(|_| "delivery TLS invalid")?;
            let keys =
                PolicyKeys::new(&[(&c.policy_key_id, key)]).map_err(|_| "policy key invalid")?;
            owners.push(
                CollectorOwner::new_v2(
                    client,
                    keys,
                    &[&c.source],
                    QueueLimits::new(16, 16384).map_err(|_| "queue invalid")?,
                )
                .map_err(|_| "owner invalid")?,
            );
        }
        let pool = CollectorPool::new(owners).map_err(|_| "pool invalid")?;
        pool.synchronize()
            .await
            .map_err(|_| "authority synchronization failed")?;
        let upstream_ca = read(&c.upstream_ca_der, 65536)?;
        let upstream_cert = read(&c.upstream_client_certificate_der, 65536)?;
        let upstream_key = read(&c.upstream_client_key_der, 16384)?;
        let gateway = Gateway::new(
            GatewayTransport {
                tls,
                peer_leaf: &forwarder,
                upstream: c.upstream_address,
                upstream_name: &c.upstream_name,
                upstream_ca: &upstream_ca,
                client_chain: &upstream_cert,
                client_key: &upstream_key,
            },
            CapturePoint {
                source: c.source,
                workload: c.workload,
                profile: "http_json_v1".into(),
                method: "POST".into(),
                path: "/pilot".into(),
                route: "/pilot".into(),
            },
            pool.clone(),
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "listener failed")?;
        let port = listener.local_addr().map_err(|_| "listener failed")?.port();
        let serving = tokio::spawn(gateway.serve(listener));
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in io::stdin().lock().lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        println!("READY {port}");
        let mut admission_baseline: Option<AdmissionStats> = None;
        while let Some(line) = receiver.recv().await {
            let line = line.map_err(|_| "command input failed")?;
            if line == "STOP" {
                serving.abort();
                let _ = serving.await;
                return Ok(());
            }
            if terminal_expected && line == "ADMISSION_BASELINE" && !serving.is_finished() {
                let stats = admission_stats(&pool, Instant::now() + Duration::from_secs(5)).await?;
                if stats.records != 0 {
                    return Err("admission baseline not empty");
                }
                admission_baseline = Some(stats);
                println!("BASELINE 0");
                continue;
            }
            let admission = terminal_expected && line == "ADMISSION_DRAIN";
            let diagnostic = line == "DRAIN_DIAGNOSTIC" && diagnostic_enabled;
            let matrix = matrix_command(matrix_enabled, &line);
            if (line != "DRAIN" && !diagnostic && !admission && !matrix) || serving.is_finished() {
                return Err("command or serving failed");
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut acknowledgements = 0u64;
            let mut discarded = false;
            let mut admission_failure = None;
            if admission && admission_baseline.is_none() {
                return Err("admission baseline missing");
            }
            for slot in 0..4 {
                loop {
                    if Instant::now() >= deadline {
                        if diagnostic {
                            println!("DIAG deadline {} {acknowledgements}", pool.losses());
                        } else {
                            println!("DRAIN 1 {} {acknowledgements}", pool.losses());
                        }
                        return Err("drain deadline");
                    }
                    let frozen = match pool.try_freeze(slot, &id()?, 100, 1_048_576) {
                        Ok(value) => value,
                        Err(_) => {
                            sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                    };
                    if !frozen {
                        break;
                    }
                    let outcome = timeout_at(deadline, pool.send(slot)).await;
                    if admission {
                        let category = diagnostic_outcome(outcome);
                        if category == "deferred_discard_invalid" {
                            discarded = true;
                        } else {
                            admission_failure = Some(category);
                            break;
                        }
                    } else if diagnostic {
                        let category = diagnostic_outcome(outcome);
                        if category == "acknowledged" {
                            acknowledgements += 1;
                        } else {
                            println!("DIAG {category} {} {acknowledgements}", pool.losses());
                            return Err("drain delivery failed");
                        }
                    } else {
                        match outcome {
                            Ok(Ok(SendOutcome::Acknowledged { .. })) => acknowledgements += 1,
                            _ => {
                                println!("DRAIN 2 {} {acknowledgements}", pool.losses());
                                return Err("drain delivery failed");
                            }
                        }
                    }
                }
                if admission_failure.is_some() {
                    break;
                }
            }
            if admission {
                let after = admission_stats(&pool, deadline).await?;
                let (losses, purged, acknowledged, records) = admission_delta(
                    admission_baseline
                        .take()
                        .ok_or("admission baseline missing")?,
                    after,
                )?;
                let category = admission_failure.unwrap_or(if discarded {
                    "deferred_discard_invalid"
                } else {
                    "empty"
                });
                println!("ADMISSION {category} {losses} {purged} {acknowledged} {records}");
                if category != "deferred_discard_invalid"
                    || (losses, purged, acknowledged, records) != (0, 2, 0, 0)
                {
                    return Err("admission drain failed");
                }
                continue;
            }
            let losses = pool.losses();
            if diagnostic {
                let category = if losses == 0 { "ok" } else { "loss" };
                println!("DIAG {category} {losses} {acknowledgements}");
            } else if matrix {
                println!("MATRIX {losses} {acknowledgements}");
            } else {
                println!(
                    "DRAIN {} {losses} {acknowledgements}",
                    u8::from(losses != 0)
                );
            }
            if reject_loss(matrix, losses) {
                return Err("drain loss");
            }
        }
        Err("command input closed")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_command_is_opt_in_and_legacy_loss_remains_fatal() {
        assert_eq!(fixture_mode(None), Ok((false, false, false)));
        assert_eq!(
            fixture_mode(Some("--discovery-matrix")),
            Ok((false, false, true))
        );
        assert!(fixture_mode(Some("--other")).is_err());
        assert!(!matrix_command(false, "MATRIX_DRAIN"));
        assert!(!matrix_command(true, "DRAIN"));
        assert!(matrix_command(true, "MATRIX_DRAIN"));
        assert!(reject_loss(false, 1));
        assert!(!reject_loss(false, 0));
        assert!(!reject_loss(true, 1));
    }
    #[test]
    fn admission_delta_counts_records_and_rejects_regressions() {
        let before = AdmissionStats {
            losses: 4,
            purged: 5,
            acknowledged: 6,
            records: 0,
        };
        let after = AdmissionStats {
            losses: 4,
            purged: 7,
            acknowledged: 6,
            records: 0,
        };
        assert_eq!(admission_delta(before, after), Ok((0, 2, 0, 0)));
        assert_eq!(
            admission_delta(
                before,
                AdmissionStats {
                    records: 2,
                    ..after
                }
            ),
            Ok((0, 2, 0, 2))
        );
        assert!(admission_delta(before, AdmissionStats { purged: 4, ..after }).is_err());
        assert!(admission_delta(before, AdmissionStats { losses: 3, ..after }).is_err());
        assert!(
            admission_delta(
                before,
                AdmissionStats {
                    acknowledged: 5,
                    ..after
                }
            )
            .is_err()
        );
    }

    #[test]
    fn diagnostic_classifies_outcomes_without_values() {
        for (directive, expected) in [
            (RetryDirective::DiscardInvalid, "deferred_discard_invalid"),
            (
                RetryDirective::RenewAuthorizedEnrollment,
                "deferred_renew_authorized_enrollment",
            ),
            (RetryDirective::StopRejected(418), "deferred_stop_rejected"),
            (
                RetryDirective::Retry {
                    after: Duration::from_secs(17),
                },
                "deferred_retry",
            ),
        ] {
            assert_eq!(
                diagnostic_outcome(Ok(Ok(SendOutcome::Deferred(directive)))),
                expected
            );
        }
        assert_eq!(
            diagnostic_outcome(Ok(Err(OwnerError::Paused))),
            "owner_paused"
        );
        assert_eq!(diagnostic_outcome(Ok(Ok(SendOutcome::Empty))), "empty");
    }
}
