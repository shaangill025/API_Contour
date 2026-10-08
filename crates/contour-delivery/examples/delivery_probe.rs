//! Synthetic fixture; no enrollment/capture executable.
use contour_core::*;
use contour_delivery::{DeliveryClient, ReceiptStatus};
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
