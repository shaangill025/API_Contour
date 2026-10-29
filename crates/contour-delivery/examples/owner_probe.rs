//! Synthetic executable exercising the public owner against real fixture TLS.
use bytes::Bytes;
use contour_core::*;
use contour_delivery::{CollectorOwner, DeliveryClient, SendOutcome};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::{
    error::Error,
    fs,
    io::{self, BufRead, Write},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use tokio::io::AsyncReadExt;
use tokio_rustls::TlsConnector;
fn draft(r: &Value) -> Result<RecordDraft, Box<dyn Error>> {
    let observation = Observation {
        shape: Shape::from_wire_json(&serde_json::to_vec(&r["structure"])?)?,
        completeness: Completeness::Complete,
        reasons: vec![],
    };
    draft_observation(r, observation)
}
fn draft_observation(r: &Value, observation: Observation) -> Result<RecordDraft, Box<dyn Error>> {
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
            status_code: if r["status_code"].is_null() {
                None
            } else {
                Some(u("status_code").try_into()?)
            },
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        },
        observation,
    )?)
}

// This is the owned fixture application's TLS client. Its bounded plaintext
// buffers are application memory, not an observer queue or IPC transport.
// Capture begins only when the owner checks scope and inspects each body.
async fn application_exchange(
    port: u16,
    root: &[u8],
    name: &str,
) -> Result<(Bytes, Bytes), Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.to_vec()))?;
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let operation = async {
        let stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
        let stream = connector
            .connect(ServerName::try_from(name.to_owned())?, stream)
            .await?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
        struct AbortOnDrop(tokio::task::JoinHandle<Result<(), hyper::Error>>);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let mut task = AbortOnDrop(tokio::spawn(connection));
        let request_body =
            Bytes::from_static(br#"{"id":{"quantity":1,"SYNTHETIC_DENIED":"SYNTHETIC_REQUEST"}}"#);
        let request = Request::builder()
            .method("GET")
            .uri("/orders/1")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(request_body.clone()))?;
        let response = sender.send_request(request).await?;
        if response.status() != 200 {
            return Err("application status".into());
        }
        let response_body = Limited::new(response.into_body(), 65536)
            .collect()
            .await
            .map_err(|_| "application response bound")?
            .to_bytes();
        drop(sender);
        (&mut task.0).await??;
        Ok::<_, Box<dyn Error>>((request_body, response_body))
    };
    tokio::time::timeout(Duration::from_secs(3), operation).await?
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
                "cancel-refresh" | "cancel-send" => {
                    let mut signal = tokio::net::TcpStream::connect((
                        Ipv4Addr::LOCALHOST,
                        command["control"].as_u64().ok_or("control")? as u16,
                    ))
                    .await?;
                    let mut marker = [0];
                    let mut read = Box::pin(signal.read_exact(&mut marker));
                    let mut operation = Box::pin(async {
                        if action == "cancel-refresh" {
                            owner.refresh().await
                        } else {
                            owner.send_once().await.map(|_| ())
                        }
                    });
                    poll_fn(|cx| {
                        if operation.as_mut().poll(cx).is_ready() {
                            return std::task::Poll::Ready(Err(io::Error::other(
                                "operation completed before cancellation",
                            )));
                        }
                        read.as_mut().poll(cx).map(|r| r.map(|_| ()))
                    })
                    .await?;
                    drop(read);
                    if marker != [b'C'] {
                        return Err("invalid cancellation marker".into());
                    }
                    drop(operation);
                    Ok(json!({"cancelled":true}))
                }
                "wait" => Ok(
                    json!({"wait":format!("{:?}",owner.wait_retry(std::future::pending()).await?)}),
                ),
                "capture-https" => {
                    let port: u16 = command["source_port"].as_u64().ok_or("source port")?.try_into()?;
                    if port == 0 { return Err("source port".into()); }
                    // The application exchange completes even when capture is paused.
                    let source_root = if command["bad_root"] == true { fs::read(dir.join("untrusted.crt.der"))? } else { root.clone() };
                    let source_name = if command["bad_name"] == true { "wrong.invalid" } else { "localhost" };
                    let (request, response) = application_exchange(port, &source_root, source_name).await?;
                    let mut admitted = 0;
                    let mut safe = true;
                    for (index, payload) in [request, response].into_iter().enumerate() {
                        let r = &body["records"][0];
                        let text = |name: &str| r[name].as_str().expect("fixture text");
                        let scope = CaptureScope { source_id: text("source_id"), workload: [text("project_id"),text("service_id"),text("environment_id"),text("deployment_id")], parser_profile: text("parser_profile"), operation: text("operation"), route_template: text("route_template"), request_header_names: &[], response_header_names: &[], query_parameter_names: &[] };
                        if let Ok((revision, observation)) = owner.inspect_json(&scope, &payload) {
                            let wire = String::from_utf8(observation.shape.to_wire_json()?)?;
                            safe &= wire.contains("quantity") && !wire.contains("SYNTHETIC_DENIED") && !wire.contains("SYNTHETIC_REQUEST") && !wire.contains("SYNTHETIC_RESPONSE");
                            let mut record = r.clone();
                            record["record_id"] = json!(if index == 0 { "00000000-0000-4000-8000-0000000000a1" } else { "00000000-0000-4000-8000-0000000000a2" });
                            record["policy_revision"] = json!(revision);
                            record["direction"] = json!(if index == 0 { "request" } else { "response" });
                            record["status_code"] = if index == 0 { Value::Null } else { json!(200) };
                            let seen = time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
                            record["first_seen"] = json!(seen);
                            record["last_seen"] = record["first_seen"].clone();
                            owner.admit(draft_observation(&record, observation)?)?;
                            admitted += 1;
                        }
                    }
                    Ok(json!({"application_ok":true,"admitted":admitted,"sanitized":safe}))
                }
                // Synthetic inspection only: no application traffic or payload
                // values are printed, exported, or queued by this probe.
                "inspect" => {
                    let record = &body["records"][0];
                    let text = |name: &str| record[name].as_str().expect("fixture text");
                    let scope = CaptureScope {
                        source_id: if command["invalid_source"] == true {
                            "ffffffff-ffff-ffff-ffff-ffffffffffff"
                        } else { text("source_id") },
                        workload: [text("project_id"), text("service_id"), text("environment_id"), text("deployment_id")],
                        parser_profile: text("parser_profile"),
                        operation: text("operation"),
                        route_template: text("route_template"),
                        request_header_names: &[], response_header_names: &[], query_parameter_names: &[],
                    };
                    let (revision, observation) = owner.inspect_json(&scope, br#"{"id":{"quantity":123,"SYNTHETIC_DENIED":"SYNTHETIC_VALUE"}}"#)?;
                    let shape = String::from_utf8(observation.shape.to_wire_json()?)?;
                    Ok(json!({"revision":revision,"partial":observation.completeness == Completeness::Partial,
                        "approved_nested":shape.contains("quantity"),
                        "denied_absent":!shape.contains("SYNTHETIC_DENIED") && !shape.contains("SYNTHETIC_VALUE")}))
                }
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
