//! Synthetic executable exercising the public owner against real fixture TLS.
use contour_core::*;
use contour_delivery::{CollectorOwner, DeliveryClient, SendOutcome};
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::{
    error::Error,
    fs,
    io::{self, BufRead, Write},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use tokio::io::AsyncReadExt;
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
async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    let dir = Path::new(&args[1]);
    let mut body: Value = serde_json::from_slice(&fs::read(&args[2])?)?;
    let identity = [
        body["tenant_id"].as_str().unwrap(),
        body["collector_id"].as_str().unwrap(),
    ];
    let key: [u8; 32] = fs::read(dir.join("signer.raw"))?
        .try_into()
        .map_err(|_| "key length")?;
    let mode = args.get(4).map(String::as_str).unwrap_or("valid");
    let root = fs::read(dir.join(if mode == "bad-root" {
        "untrusted.crt.der"
    } else {
        "ca.crt.der"
    }))?;
    let cert = fs::read(dir.join("http-client.crt.der"))?;
    let private = fs::read(dir.join("http-client.key.der"))?;
    let client = DeliveryClient::from_der(
        if mode == "bad-name" {
            "127.0.0.1"
        } else {
            "localhost"
        },
        SocketAddr::from((Ipv4Addr::LOCALHOST, args[3].parse::<u16>()?)),
        identity,
        &[&root],
        &[&cert],
        &private,
        Duration::from_secs(2),
    )?;
    let mut owner = CollectorOwner::new(
        client,
        PolicyKeys::new(&[("fixture", key)])?,
        &[body["records"][0]["source_id"].as_str().unwrap()],
        QueueLimits::new(500, 268_435_456)?,
    )?;
    for line in io::stdin().lock().lines() {
        let command: Value = serde_json::from_str(&line?)?;
        let action = command["action"].as_str().ok_or("action")?;
        let result: Result<Value, Box<dyn Error>> = async {
            match action {
                "refresh" => {
                    owner.refresh().await?;
                    Ok(json!({"ok":true}))
                }
                "cancel-refresh" => {
                    if tokio::time::timeout(Duration::from_millis(100), owner.refresh())
                        .await
                        .is_ok()
                    {
                        return Err("refresh completed before cancellation".into());
                    }
                    Ok(json!({"cancelled":true}))
                }
                "cancel-send" => {
                    let mut signal = tokio::net::TcpStream::connect((
                        Ipv4Addr::LOCALHOST,
                        command["control"].as_u64().ok_or("control")? as u16,
                    ))
                    .await?;
                    let mut marker = [0];
                    let mut read = Box::pin(signal.read_exact(&mut marker));
                    let mut send = Box::pin(owner.send_once());
                    poll_fn(|cx| {
                        if send.as_mut().poll(cx).is_ready() {
                            return std::task::Poll::Ready(Err(io::Error::other(
                                "send completed before cancellation",
                            )));
                        }
                        read.as_mut().poll(cx).map(|r| r.map(|_| ()))
                    })
                    .await?;
                    drop(send);
                    Ok(json!({"cancelled":true}))
                }
                "wait" => Ok(
                    json!({"wait":format!("{:?}",owner.wait_retry(std::future::pending()).await?)}),
                ),
                "admit" => {
                    if let Some(revision) = command["revision"].as_u64() {
                        body["records"][0]["policy_revision"] = json!(revision);
                    }
                    if let Some(id) = command["record_id"].as_str() {
                        body["records"][0]["record_id"] = json!(id);
                    }
                    owner.admit(draft(&body["records"][0])?)?;
                    Ok(json!({"ok":true}))
                }
                "freeze" => {
                    let present =
                        owner.freeze(body["batch_id"].as_str().unwrap(), 500, 1_048_576)?;
                    Ok(json!({"frozen":present}))
                }
                "send" => Ok(match owner.send_once().await? {
                    SendOutcome::Empty => json!({"empty":true}),
                    SendOutcome::Acknowledged { receipt_id, status } => {
                        json!({"receipt_id":receipt_id,"status":format!("{status:?}")})
                    }
                    SendOutcome::Deferred(directive) => {
                        json!({"deferred":format!("{directive:?}")})
                    }
                }),
                "expire" => {
                    owner.expire_retained()?;
                    Ok(json!({"ok":true}))
                }
                _ => Err("unknown action".into()),
            }
        }
        .await;
        let stats = owner.stats();
        println!(
            "{}",
            json!({"result":match result {Ok(value)=>value,Err(error)=>json!({"error":error.to_string()})},"live":owner.is_live(),"records":stats.records,"bytes":stats.bytes,"purged":stats.purged,"acknowledged":stats.acknowledged})
        );
        io::stdout().flush()?;
    }
    Ok(())
}
fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fixture runtime");
    if let Err(e) = rt.block_on(run()) {
        eprintln!("owner fixture: {e}");
        std::process::exit(1);
    }
}
