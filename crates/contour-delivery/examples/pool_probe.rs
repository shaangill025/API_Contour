//! Synthetic pool-to-ingress fixture. Values remain in the private fixture process.
use contour_core::{CaptureScope, PolicyKeys, QueueLimits, RecordMetadata, Timestamp};
use contour_delivery::{CollectorOwner, CollectorPool, DeliveryClient, SendOutcome, WaitOutcome};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    io::{self, BufRead, Write},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    let dir = Path::new(&args[1]);
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let body: Value = serde_json::from_str(&lines.next().ok_or("fixture input")??)?;
    let text = |value: &Value, name: &str| value[name].as_str().expect("fixture text").to_owned();
    let identity = [text(&body, "tenant_id"), text(&body, "collector_id")];
    let key: [u8; 32] = fs::read(dir.join("signer.raw"))?
        .try_into()
        .map_err(|_| "key length")?;
    let root = fs::read(dir.join("ca.crt.der"))?;
    let cert = fs::read(dir.join("http-client.crt.der"))?;
    let private = fs::read(dir.join("http-client.key.der"))?;
    let client = DeliveryClient::from_der(
        "localhost",
        SocketAddr::from((Ipv4Addr::LOCALHOST, args[2].parse::<u16>()?)),
        identity.each_ref().map(String::as_str),
        &[&root],
        &[&cert],
        &private,
        Duration::from_secs(2),
    )?;
    let record = &body["records"][0];
    let source = text(record, "source_id");
    let owner = CollectorOwner::new(
        client,
        PolicyKeys::new(&[("fixture", key)])?,
        &[&source],
        QueueLimits::new(500, 268_435_456)?,
    )?;
    let pool = CollectorPool::new(vec![owner])?;
    for line in lines {
        let action = line?;
        let result: Result<Value, Box<dyn Error>> = async {
            match action.as_str() {
                "capture" => {
                    pool.synchronize().await?;
                    let get = |name: &str| record[name].as_str().expect("fixture text");
                    let scope = CaptureScope {
                        source_id: get("source_id"),
                        workload: [
                            get("project_id"),
                            get("service_id"),
                            get("environment_id"),
                            get("deployment_id"),
                        ],
                        parser_profile: get("parser_profile"),
                        operation: get("operation"),
                        route_template: get("route_template"),
                        request_header_names: &[],
                        response_header_names: &[],
                        query_parameter_names: &[],
                    };
                    let token = pool.try_begin(&scope)?;
                    let marker = body["privacy_marker"].as_str().ok_or("privacy marker")?;
                    let payload = serde_json::to_vec(
                        &json!({"id":{"quantity":1,"SYNTHETIC_DENIED":marker}}),
                    )?;
                    pool.try_fragment(token, &payload)?;
                    let metadata = RecordMetadata {
                        record_id: get("record_id"),
                        source_id: get("source_id"),
                        workload: scope.workload,
                        protocol: get("protocol"),
                        direction: get("direction"),
                        visibility: get("visibility"),
                        operation: get("operation"),
                        route_template: get("route_template"),
                        route_uncertain: false,
                        parser_profile: get("parser_profile"),
                        policy_revision: 1,
                        count: 1,
                        first_seen: Timestamp::parse(get("first_seen"))?,
                        last_seen: Timestamp::parse(get("last_seen"))?,
                        sample_numerator: 1,
                        sample_denominator: 1,
                        status_code: None,
                        request_header_names: &[],
                        response_header_names: &[],
                        query_parameter_names: &[],
                    };
                    pool.try_finish(token, metadata)?;
                    if !pool.try_freeze(
                        0,
                        body["batch_id"].as_str().ok_or("batch id")?,
                        500,
                        1_048_576,
                    )? {
                        return Err("empty freeze".into());
                    }
                    Ok(json!({"captured":true}))
                }
                "send" => Ok(match pool.send(0).await? {
                    SendOutcome::Empty => json!({"empty":true}),
                    SendOutcome::Deferred(_) => json!({"deferred":true}),
                    SendOutcome::Acknowledged { receipt_id, status } => {
                        json!({"status":format!("{status:?}"), "receipt_id":receipt_id})
                    }
                }),
                "wait" => {
                    if pool.wait_retry(0).await? != WaitOutcome::Ready {
                        return Err("retry not ready".into());
                    }
                    Ok(json!({"waited":true}))
                }
                _ => Err("unknown action".into()),
            }
        }
        .await;
        println!("{}", result.unwrap_or_else(|_| json!({"error":true})));
        io::stdout().flush()?;
    }
    Ok(())
}
fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    if runtime.block_on(run()).is_err() {
        eprintln!("pool fixture failed");
        std::process::exit(1);
    }
}
