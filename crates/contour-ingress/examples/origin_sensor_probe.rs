//! Isolated fixture: production Gateway and V2 pool with explicit single-flight drain.
use contour_core::{PolicyKeys, QueueLimits};
use contour_delivery::{CollectorOwner, CollectorPool, DeliveryClient, SendOutcome};
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
use tokio::time::{Instant, sleep};

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
fn main() {
    if let Err(e) = run() {
        eprintln!("origin sensor fixture: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    let path = args.next().ok_or("config missing")?;
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
        let key: [u8; 32] = read(&c.policy_key_file, 32)?
            .try_into()
            .map_err(|_| "policy key invalid")?;
        let keys = PolicyKeys::new(&[(&c.policy_key_id, key)]).map_err(|_| "policy key invalid")?;
        let owner = CollectorOwner::new_v2(
            client,
            keys,
            &[&c.source],
            QueueLimits::new(16, 16384).map_err(|_| "queue invalid")?,
        )
        .map_err(|_| "owner invalid")?;
        let pool = CollectorPool::new(vec![owner]).map_err(|_| "pool invalid")?;
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
        while let Some(line) = receiver.recv().await {
            let line = line.map_err(|_| "command input failed")?;
            if line == "STOP" {
                serving.abort();
                let _ = serving.await;
                return Ok(());
            }
            if line != "DRAIN" || serving.is_finished() {
                return Err("command or serving failed");
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut acknowledgements = 0u64;
            loop {
                if Instant::now() >= deadline {
                    return Err("drain deadline");
                }
                let frozen = match pool.try_freeze(0, &id()?, 100, 1_048_576) {
                    Ok(value) => value,
                    Err(_) => {
                        sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                if !frozen {
                    break;
                }
                match pool.send(0).await {
                    Ok(SendOutcome::Acknowledged { .. }) => acknowledgements += 1,
                    _ => return Err("drain delivery failed"),
                }
            }
            println!("DRAIN 0 {} {acknowledgements}", pool.losses());
        }
        Err("command input closed")
    })
}
