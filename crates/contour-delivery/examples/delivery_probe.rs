//! Synthetic fixture; no enrollment/capture executable.
use contour_core::*;
use contour_delivery::{
    DeliveryClient, DeliveryError, ReceiptStatus, RetryController, RetryDirective, RetryError,
    WaitOutcome,
};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use std::{
    future::{Future, poll_fn},
    task::Poll,
};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn draft(r: &Value) -> Result<RecordDraft, Box<dyn Error>> {
    let s = |n: &str| r[n].as_str().expect("fixture text");
    let u = |n: &str| r[n].as_u64().expect("fixture integer");
    Ok(RecordDraft::from_observation(
        RecordMetadata {
            record_id: s("record_id"),
            source_id: s("source_id"),
            workload: [
                s("project_id"),
                s("service_id"),
                s("environment_id"),
                s("deployment_id"),
            ],
            protocol: s("protocol"),
            direction: s("direction"),
            visibility: s("visibility"),
            operation: s("operation"),
            route_template: s("route_template"),
            route_uncertain: false,
            parser_profile: s("parser_profile"),
            policy_revision: u("policy_revision"),
            count: u("count"),
            first_seen: Timestamp::parse(s("first_seen"))?,
            last_seen: Timestamp::parse(s("last_seen"))?,
            sample_numerator: u("sample_numerator"),
            sample_denominator: u("sample_denominator"),
            status_code: Some(u("status_code").try_into()?),
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        },
        Observation {
            shape: Shape::from_wire_json(&serde_json::to_vec(&r["structure"])?)?,
            completeness: Completeness::Complete,
            reasons: vec![],
        },
    )?)
}
async fn control_pending(
    client: &mut DeliveryClient,
    attempt: &mut DeliveryReservation<'_>,
    control_port: u16,
    late: bool,
) -> Result<(), Box<dyn Error>> {
    let mut control = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, control_port)).await?;
    let mut send = Box::pin(client.send_once(attempt));
    let mut marker = [0u8; 1];
    let mut signal = Box::pin(control.read_exact(&mut marker));
    poll_fn(|cx| {
        if send.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err("send completed before explicit cancellation"));
        }
        match signal.as_mut().poll(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err("cancellation control closed")),
            Poll::Pending => Poll::Pending,
        }
    })
    .await?;
    drop(signal);
    if late {
        if marker != [b'P'] {
            return Err("pause control marker".into());
        }
        control.write_all(b"A").await?;
        control.read_exact(&mut marker).await?;
        if marker != [b'R'] {
            return Err("resume control marker".into());
        }
        if !matches!(send.await, Err(contour_delivery::DeliveryError::Deadline)) {
            return Err("late receipt was not rejected by deadline".into());
        }
        return Ok(());
    }
    if marker != [b'C'] {
        return Err("cancellation control marker".into());
    }
    // The fixture signals only after an actual committed receipt and stalled reply.
    drop(send);
    Ok(())
}
async fn cancel_wait(
    controller: &RetryController,
    port: u16,
) -> Result<WaitOutcome, Box<dyn Error>> {
    let socket = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    let (mut reader, mut writer) = socket.into_split();
    let mut marker = [0; 1];
    let mut wait = Box::pin(controller.wait(async {
        let _ = reader.read_exact(&mut marker).await;
    }));
    poll_fn(|cx| match wait.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(Ok(())),
        Poll::Ready(_) => Poll::Ready(Err("retry wait was not pending")),
    })
    .await?;
    writer.write_all(b"A").await?;
    let outcome = wait.await?;
    if marker != [b'C'] {
        return Err("retry cancellation marker".into());
    }
    Ok(outcome)
}
fn fixture_source(body: &Value) -> Result<SourceAssignment, Box<dyn Error>> {
    let r = &body["records"][0];
    Ok(SourceAssignment::new(
        r["source_id"].as_str().unwrap(),
        [
            body["tenant_id"].as_str().unwrap(),
            body["collector_id"].as_str().unwrap(),
            r["project_id"].as_str().unwrap(),
            r["service_id"].as_str().unwrap(),
            r["environment_id"].as_str().unwrap(),
            r["deployment_id"].as_str().unwrap(),
        ],
        "runtime",
        &["http_json_v1"],
    )?)
}
async fn bounded(
    dir: &Path,
    body: &Value,
    policy: &VerifiedPolicy,
    inputs: &AdmissionInputs<'_>,
    stages: &str,
    policy_path: &Path,
    keys: &PolicyKeys,
) -> Result<(), Box<dyn Error>> {
    let (mode, port_text) = stages.split_once(':').ok_or("bounded stage")?;
    let ports = port_text
        .split(':')
        .map(str::parse::<u16>)
        .collect::<Result<Vec<_>, _>>()?;
    if ports.len() != 3 {
        return Err("bounded ports".into());
    }
    let identity = [
        body["tenant_id"].as_str().unwrap(),
        body["collector_id"].as_str().unwrap(),
    ];
    let mut measure = MemoryQueue::new(identity, QueueLimits::new(3, 1_048_576)?)?;
    for i in 1..=3 {
        let mut record = body["records"][0].clone();
        record["record_id"] = json!(format!("00000000-0000-4000-8000-{i:012x}"));
        measure.admit(draft(&record)?, inputs)?;
    }
    let full = measure.stats().bytes;
    let first = measure
        .freeze(body["batch_id"].as_str().unwrap(), 1, inputs)?
        .ok_or("measure freeze")?;
    let limit = first.wire().len() + 32; // A second record cannot fit this measured envelope.
    drop(measure);
    let mut queue = MemoryQueue::new(identity, QueueLimits::new(3, full)?)?;
    for i in 1..=3 {
        let mut record = body["records"][0].clone();
        record["record_id"] = json!(format!("00000000-0000-4000-8000-{i:012x}"));
        queue.admit(draft(&record)?, inputs)?;
    }
    assert_eq!(queue.stats().bytes, full);
    let original=queue.retained_record_times().map(|(id,queued,expires)|
        json!({"record_id":id,"queued_at":queued.as_str(),"expires_at":expires.as_str()})).collect::<Vec<_>>();
    fs::write(
        dir.join("bounded-original.json"),
        serde_json::to_vec(&original)?,
    )?;
    let root = fs::read(dir.join("ca.crt.der"))?;
    let cert = fs::read(dir.join("http-client.crt.der"))?;
    let key = fs::read(dir.join("http-client.key.der"))?;
    let mut receipts = Vec::new();
    for i in 1..=3 {
        let id = if i == 1 {
            body["batch_id"].as_str().unwrap().to_owned()
        } else {
            format!("00000000-0000-4000-8000-{i:012x}")
        };
        let view = queue
            .freeze_with_limits(&id, 500, limit, inputs)?
            .ok_or("bounded freeze")?;
        assert_eq!(view.record_count(), 1);
        assert!(view.wire().len() <= limit);
        let wire = view.wire().to_vec();
        let binding = view.binding();
        let decoded: Value = serde_json::from_slice(&wire)?;
        assert_eq!(
            decoded["records"][0]["record_id"],
            format!("00000000-0000-4000-8000-{i:012x}")
        );
        assert_eq!(
            decoded["records"][0]["queued_at"],
            original[i - 1]["queued_at"]
        );
        assert_eq!(
            decoded["records"][0]["expires_at"],
            original[i - 1]["expires_at"]
        );
        assert_eq!(
            view.deadline(),
            Timestamp::parse(original[i - 1]["expires_at"].as_str().unwrap())?.instant()
        );
        fs::write(dir.join(format!("bounded-wire-{i}.json")), &wire)?;
        let attempts = if i == 1 && mode == "bounded" {
            vec![ports[1], ports[2], ports[0]]
        } else {
            vec![ports[0]]
        };
        for (n, port) in attempts.into_iter().enumerate() {
            let mut client = DeliveryClient::from_der(
                "localhost",
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                identity,
                &[&root],
                &[&cert],
                &key,
                Duration::from_secs(5),
            )?;
            let mut attempt = queue
                .reserve_delivery(inputs)?
                .ok_or("bounded reservation")?;
            assert!(attempt.valid_until() <= policy.expires_at());
            assert_eq!(attempt.view().wire(), wire);
            match client.send_once(&mut attempt).await {
                Err(error) if i == 1 && mode == "bounded" && n < 2 => {
                    if n == 1 {
                        assert!(matches!(error, DeliveryError::Rejected { status: 413, .. }));
                    } else {
                        assert!(!matches!(error, DeliveryError::Rejected { .. }));
                    }
                    drop(attempt);
                    assert_eq!(queue.stats().bytes, full);
                    // Even a newly created controller cannot reset sticky exposure.
                    assert_eq!(
                        queue
                            .freeze_with_limits(
                                "ffffffff-ffff-4fff-8fff-ffffffffffff",
                                1,
                                limit,
                                inputs
                            )
                            .unwrap_err(),
                        QueueError::Ownership
                    );
                    let mut attempt = queue.reserve_delivery(inputs)?.ok_or("retry reservation")?;
                    let mut controller = RetryController::for_attempt(&mut attempt);
                    assert_eq!(
                        controller.on_failure(
                            binding,
                            DeliveryError::Rejected {
                                status: 413,
                                retry_after: None
                            }
                        )?,
                        RetryDirective::RequireSplit
                    );
                    assert_eq!(attempt.view().wire(), wire);
                }
                Ok(receipt) => {
                    assert_eq!(
                        receipt.status(),
                        if i == 1 && mode == "bounded" {
                            ReceiptStatus::Duplicate
                        } else {
                            ReceiptStatus::Accepted
                        }
                    );
                    receipts.push(json!({"batch_id":id,"receipt_id":receipt.receipt_id(),"accepted_at":receipt.accepted_at().as_str()}));
                    receipt.acknowledge(attempt)?;
                }
                _ => return Err("bounded delivery outcome".into()),
            }
        }
        if i == 1 && mode != "bounded" {
            // Explicit parent coordination only after the first real commit/ack.
            println!(
                "{}",
                json!({"phase":"pending","charge":queue.stats().bytes})
            );
            io::stdout().flush()?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            let fresh = VerifiedPolicy::from_signed_json(
                &fs::read(policy_path)?,
                keys,
                identity[0],
                identity[1],
                OffsetDateTime::now_utc(),
            )?;
            let sources = [fixture_source(body)?];
            let trusted = AdmissionInputs::new(identity, &fresh, &[policy], &sources)?;
            let result = queue.freeze_with_limits(
                "00000000-0000-4000-8000-000000000002",
                500,
                limit,
                &trusted,
            );
            if mode == "bounded-expire" {
                assert!(result?.is_none());
                assert_eq!(queue.stats().expired, 2);
            } else if mode == "bounded-disable" {
                assert!(result.is_err());
                assert_eq!(queue.stats().purged, 2);
                assert_eq!(
                    queue.reserve_delivery(inputs).unwrap_err(),
                    QueueError::Revision
                );
                let new_body: Value =
                    serde_json::from_slice(&fs::read(dir.join("bounded-reenroll.json"))?)?;
                let new_identity = [
                    new_body["tenant_id"].as_str().unwrap(),
                    new_body["collector_id"].as_str().unwrap(),
                ];
                let new_policy = VerifiedPolicy::from_signed_json(
                    &fs::read(dir.join("bounded-reenroll-policy.json"))?,
                    keys,
                    new_identity[0],
                    new_identity[1],
                    OffsetDateTime::now_utc(),
                )?;
                let new_sources = [fixture_source(&new_body)?];
                let reenrolled =
                    AdmissionInputs::new(new_identity, &new_policy, &[&new_policy], &new_sources)?;
                assert_eq!(
                    queue.reserve_delivery(&reenrolled).unwrap_err(),
                    QueueError::Identity
                );
                assert_eq!(queue.retained_record_times().count(), 0);
            } else {
                return Err("bounded mode".into());
            }
            assert_eq!(queue.stats().bytes, 0);
            assert_eq!(queue.stats().records, 0);
            let destinations: Vec<u16> = serde_json::from_str(&line)?;
            assert_eq!(destinations.len(), 2);
            for port in destinations {
                let mut client = DeliveryClient::from_der(
                    "localhost",
                    SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                    identity,
                    &[&root],
                    &[&cert],
                    &key,
                    Duration::from_secs(5),
                )?;
                match queue.reserve_delivery(&trusted) {
                    Ok(None) | Err(_) => {}
                    Ok(Some(mut attempt)) => {
                        let _ = client.send_once(&mut attempt).await;
                        return Err("expired/disabled pending child obtained reservation".into());
                    }
                }
            }
            println!("{}", json!({"terminal":mode,"charge":0}));
            return Ok(());
        }
    }
    assert_eq!(queue.stats().records, 0);
    assert_eq!(queue.stats().bytes, 0);
    assert_eq!(queue.stats().acknowledged, 3);
    println!(
        "{}",
        json!({"bounded":receipts,"charge":0,"wire_limit":limit})
    );
    Ok(())
}
async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(5..=6).contains(&args.len()) {
        return Err("fixture arguments".into());
    }
    let dir = Path::new(&args[1]);
    let body: Value = serde_json::from_slice(&fs::read(&args[2])?)?;
    let r = &body["records"][0];
    let s = |n: &str| r[n].as_str().expect("fixture identity");
    let identity = [
        body["tenant_id"].as_str().unwrap(),
        body["collector_id"].as_str().unwrap(),
    ];
    let key: [u8; 32] = fs::read(dir.join("signer.raw"))?
        .try_into()
        .map_err(|_| "key length")?;
    let keys = PolicyKeys::new(&[("fixture", key)])?;
    let policy = VerifiedPolicy::from_signed_json(
        &fs::read(&args[3])?,
        &keys,
        identity[0],
        identity[1],
        OffsetDateTime::now_utc(),
    )?;
    let sources = [SourceAssignment::new(
        s("source_id"),
        [
            identity[0],
            identity[1],
            s("project_id"),
            s("service_id"),
            s("environment_id"),
            s("deployment_id"),
        ],
        "runtime",
        &["http_json_v1"],
    )?];
    let inputs = AdmissionInputs::new(identity, &policy, &[&policy], &sources)?;
    if args[4].starts_with("bounded") {
        return bounded(
            dir,
            &body,
            &policy,
            &inputs,
            &args[4],
            Path::new(&args[3]),
            &keys,
        )
        .await;
    }

    let mut measure = MemoryQueue::new(identity, QueueLimits::new(1, 1_048_576)?)?;
    measure.admit(draft(r)?, &inputs)?;
    let full = measure.stats().bytes;
    drop(measure);
    let mut queue = MemoryQueue::new(identity, QueueLimits::new(1, full)?)?;
    queue.admit(draft(r)?, &inputs)?;
    assert_eq!(queue.stats().bytes, full);
    let frozen = queue
        .freeze(body["batch_id"].as_str().unwrap(), 1, &inputs)?
        .ok_or("freeze")?;
    // Synthetic fixture evidence copy, outside production transport.
    let expected = frozen.wire().to_vec();
    let digest = *frozen.digest();
    let binding = frozen.binding();
    fs::write(dir.join("delivery-wire.json"), &expected)?;
    fs::write(
        dir.join("delivery-digest.txt"),
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )?;
    let cert = fs::read(dir.join("http-client.crt.der"))?;
    let private = fs::read(dir.join("http-client.key.der"))?;
    let mut retry = None;
    for stage in args[4].split(',') {
        let (mode, port) = stage.split_once(':').ok_or("stage")?;
        let root = fs::read(dir.join(if mode == "bad-ca" {
            "untrusted.crt.der"
        } else {
            "ca.crt.der"
        }))?;
        let host = if mode == "bad-name" {
            "127.0.0.1"
        } else {
            "localhost"
        };
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port.parse::<u16>()?));
        let mut client = DeliveryClient::from_der(
            host,
            address,
            identity,
            &[&root],
            &[&cert],
            &private,
            Duration::from_secs(5),
        )?;
        // Fixture-owned authoritative file, not an online enrollment grant.
        let current = VerifiedPolicy::from_signed_json(
            &fs::read(&args[3])?,
            &keys,
            identity[0],
            identity[1],
            OffsetDateTime::now_utc(),
        )?;
        let inputs = AdmissionInputs::new(identity, &current, &[&policy], &sources)?;
        let mut attempt = queue.reserve_delivery(&inputs)?.ok_or("reservation")?;
        assert_eq!(attempt.identity(), identity);
        assert!(attempt.valid_until() <= policy.expires_at());
        {
            let v = attempt.view();
            assert_eq!(v.wire(), expected);
            assert_eq!(v.digest(), &digest);
            assert_eq!(v.binding(), binding);
        }
        if mode == "cancel" || mode == "late" {
            control_pending(
                &mut client,
                &mut attempt,
                args.get(5).ok_or("control port")?.parse()?,
                mode == "late",
            )
            .await?;
            drop(attempt);
            assert_eq!(queue.stats().bytes, full);
            println!(
                "{}",
                json!({"failure":if mode=="late" {"Deadline"}else{"Cancelled"},"charge":full})
            );
            io::stdout().flush()?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            continue;
        }
        if mode.starts_with("retry-") && retry.is_none() {
            // Bounds checked on this real frozen binding; not a statistical
            // distribution claim or seven network attempts.
            let mut bounds = RetryController::for_attempt(&mut attempt);
            for ceiling in [1, 2, 4, 8, 16, 32, 60, 60] {
                if let RetryDirective::Retry { after } =
                    bounds.on_failure(binding, DeliveryError::Transport)?
                {
                    assert!(after <= Duration::from_secs(ceiling));
                } else {
                    return Err("retry ceiling decision".into());
                }
            }

            retry = Some(RetryController::for_attempt(&mut attempt));
        }
        match client.send_once(&mut attempt).await {
            Ok(receipt) => {
                let result = json!({"status":if receipt.status()==ReceiptStatus::Accepted{"accepted"}else{"duplicate"},"receipt_id":receipt.receipt_id(),"accepted_at":receipt.accepted_at().as_str()});
                receipt.acknowledge(attempt)?;
                assert_eq!(queue.stats().bytes, 0);
                assert_eq!(queue.stats().records, 0);
                println!("{result}");
                io::stdout().flush()?;
                return Ok(());
            }
            Err(error) => {
                drop(attempt);
                assert_eq!(queue.stats().bytes, full);
                assert_eq!(queue.stats().records, 1);
                if mode.starts_with("retry-") {
                    if mode != "retry-lost" && !matches!(error, DeliveryError::Rejected { .. }) {
                        return Err("status was not classified independently of error body".into());
                    }
                    let controller = retry.as_mut().ok_or("retry controller")?;
                    let started = tokio::time::Instant::now();
                    let directive = controller.on_failure(binding, error)?;
                    println!(
                        "{}",
                        json!({"directive":format!("{directive:?}"),"charge":full,"retry_after_ms":match error {DeliveryError::Rejected {retry_after,..}=>retry_after.map(|v|v.as_millis()),_=>None}})
                    );
                    io::stdout().flush()?;
                    let mut line = String::new();
                    io::stdin().read_line(&mut line)?;
                    match directive {
                        RetryDirective::DiscardInvalid => {
                            queue.discard_frozen(binding)?;
                            assert_eq!(queue.stats().bytes, 0);
                            assert_eq!(queue.stats().purged, 1);
                            println!("{}", json!({"terminal":"discard","charge":0}));
                            return Ok(());
                        }
                        RetryDirective::RenewAuthorizedEnrollment => {
                            assert_eq!(
                                controller.on_failure(binding, DeliveryError::Transport),
                                Err(RetryError::Stopped)
                            );
                            if mode == "retry-401" {
                                let remaining =
                                    controller.retained_until() - OffsetDateTime::now_utc();
                                tokio::time::sleep(Duration::try_from(
                                    remaining.max(time::Duration::ZERO),
                                )?)
                                .await;
                                queue.expire_retained()?;
                                assert_eq!(queue.stats().bytes, 0);
                                assert_eq!(queue.stats().expired, 1);
                                println!("{}", json!({"terminal":"pause-expired","charge":0}));
                            } else {
                                println!("{}", json!({"terminal":"paused","charge":full}));
                            }
                            return Ok(());
                        }
                        RetryDirective::StopConflict | RetryDirective::RequireSplit => {
                            assert_eq!(
                                controller.on_failure(binding, DeliveryError::Transport),
                                Err(RetryError::Stopped)
                            );
                            println!("{}", json!({"terminal":"stopped","charge":full}));
                            return Ok(());
                        }
                        RetryDirective::Retry { after } => {
                            if mode == "retry-binding" {
                                queue.discard_frozen(binding)?;
                                queue.admit(draft(r)?, &inputs)?;
                                let new_binding = queue
                                    .freeze("00000000-0000-4000-8000-000000000002", 1, &inputs)?
                                    .ok_or("replacement freeze")?
                                    .binding();
                                assert_eq!(
                                    controller.on_failure(new_binding, error),
                                    Err(RetryError::Binding)
                                );
                                assert_eq!(queue.stats().bytes, full);
                                println!("{}", json!({"terminal":"binding","charge":full}));
                                return Ok(());
                            }

                            let outcome =
                                if matches!(mode, "retry-cap" | "retry-cancel" | "retry-revoke") {
                                    cancel_wait(
                                        controller,
                                        args.get(5).ok_or("retry control port")?.parse()?,
                                    )
                                    .await?
                                } else {
                                    controller.wait(std::future::pending()).await?
                                };
                            if outcome == WaitOutcome::Ready {
                                assert!(started.elapsed() >= after);
                            }
                            if outcome == WaitOutcome::Expired {
                                queue.expire_retained()?;
                                assert_eq!(queue.stats().bytes, 0);
                                assert!(queue.reserve_delivery(&inputs)?.is_none());
                                println!("{}", json!({"terminal":"expired","charge":0}));
                                return Ok(());
                            }
                            if mode == "retry-revoke" {
                                assert_eq!(outcome, WaitOutcome::Cancelled);
                                let updated = VerifiedPolicy::from_signed_json(
                                    &fs::read(&args[3])?,
                                    &keys,
                                    identity[0],
                                    identity[1],
                                    OffsetDateTime::now_utc(),
                                )?;
                                let fresh =
                                    AdmissionInputs::new(identity, &updated, &[&policy], &sources)?;
                                assert!(queue.reconcile(&fresh).is_err());
                                assert_eq!(queue.stats().bytes, 0);
                                assert_eq!(
                                    queue.reserve_delivery(&inputs).unwrap_err(),
                                    QueueError::Revision
                                );
                                // Trusted fixture operator also revokes the local identity.
                                queue.revoke();
                                assert_eq!(
                                    queue.reserve_delivery(&fresh).unwrap_err(),
                                    QueueError::Revoked
                                );
                                println!("{}", json!({"terminal":"revoked","charge":0}));
                                return Ok(());
                            }
                        }
                        _ => return Err("unexpected retry directive".into()),
                    }
                    continue;
                }
                println!("{}", json!({"failure":error.to_string(),"charge":full}));
                io::stdout().flush()?;
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
            }
        }
    }
    Err("no checked receipt".into())
}
fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fixture runtime");
    if let Err(e) = rt.block_on(run()) {
        eprintln!("delivery fixture: {e}");
        std::process::exit(1);
    }
}
