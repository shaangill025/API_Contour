//! Synthetic performance fixture: a gateway whose collector pool is never synchronized.
//! This example is not a production runtime.
use contour_core::{PolicyKeys, QueueLimits};
use contour_delivery::{CollectorOwner, CollectorPool, DeliveryClient};
use contour_ingress::{
    CollectorTls,
    gateway::{CapturePoint, Gateway, GatewayTransport},
};
use serde::Deserialize;
use std::{env, fs, future::Future, io::Read, net::SocketAddr, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: SocketAddr,
    server_certificate_der: String,
    server_key_der: String,
    forwarder_ca_der: String,
    forwarder_leaf_der: String,
    upstream_address: String,
    upstream_name: String,
    upstream_ca_der: String,
    upstream_client_certificate_der: Option<String>,
    upstream_client_key_der: Option<String>,
    delivery_address: String,
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
    method: String,
    path: String,
    route: String,
    parser_profile: String,
    slots: usize,
    records_per_slot: usize,
    bytes_per_slot: usize,
}
fn read(path: &str, max: usize) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    fs::File::open(path)
        .map_err(|_| "file unavailable")?
        .take((max + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|_| "file unavailable")?;
    if out.is_empty() || out.len() > max {
        return Err("file size invalid");
    }
    Ok(out)
}
fn optional(path: &Option<String>, max: usize) -> Result<Vec<u8>, &'static str> {
    match path {
        Some(path) => read(path, max),
        None => Ok(Vec::new()),
    }
}
// Resolution happens once, before the listener starts. Request data never
// participates in this lookup and all later connections use the chosen socket.
async fn resolve_with<F, Fut>(input: &str, lookup: F) -> Result<SocketAddr, &'static str>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = Result<Vec<SocketAddr>, ()>>,
{
    if let Ok(address) = input.parse::<SocketAddr>() {
        return if address.port() != 0 {
            Ok(address)
        } else {
            Err("invalid address")
        };
    }
    let (host, port) = input.rsplit_once(':').ok_or("invalid address")?;
    let port = port.parse::<u16>().map_err(|_| "invalid address")?;
    let name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_| "invalid address")?;
    if port == 0 || host.len() > 253 || !matches!(name, rustls::pki_types::ServerName::DnsName(_)) {
        return Err("invalid address");
    }
    let addresses = tokio::time::timeout(Duration::from_secs(3), lookup(host.to_owned(), port))
        .await
        .map_err(|_| "resolution deadline")?
        .map_err(|_| "resolution failed")?;
    addresses
        .into_iter()
        .find(|address| address.port() == port)
        .ok_or("resolution failed")
}
async fn resolve(input: &str) -> Result<SocketAddr, &'static str> {
    resolve_with(input, |host, port| async move {
        let addresses = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| ())?;
        Ok(addresses.take(16).collect())
    })
    .await
}
fn main() {
    if let Err(code) = run() {
        // Every error is a closed static code; configuration values and error
        // objects never enter startup diagnostics.
        eprintln!("native gateway failed: {code}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    let path = args.next().ok_or("configuration missing")?;
    if args.next().is_some() {
        return Err("unexpected argument");
    }
    let c: Config =
        serde_json::from_slice(&read(&path, 16384)?).map_err(|_| "invalid configuration")?;
    if !(1..=8).contains(&c.slots) {
        return Err("invalid slots");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime unavailable")?;
    let upstream_address = runtime.block_on(resolve(&c.upstream_address))?;
    let delivery_address = runtime.block_on(resolve(&c.delivery_address))?;
    let timeout = Duration::from_secs(5);
    let server_cert = read(&c.server_certificate_der, 65536)?;
    let server_key = read(&c.server_key_der, 16384)?;
    let forwarder_ca = read(&c.forwarder_ca_der, 65536)?;
    let forwarder_leaf = read(&c.forwarder_leaf_der, 65536)?;
    let tls = CollectorTls::from_der(&[&server_cert], &server_key, &[&forwarder_ca], timeout)
        .map_err(|_| "invalid server TLS")?;
    let delivery_ca = read(&c.delivery_ca_der, 65536)?;
    let delivery_cert = read(&c.delivery_client_certificate_der, 65536)?;
    let delivery_key = read(&c.delivery_client_key_der, 16384)?;
    let policy_key: [u8; 32] = read(&c.policy_key_file, 32)?
        .try_into()
        .map_err(|_| "invalid policy key")?;
    let mut owners = Vec::new();
    for _ in 0..c.slots {
        let client = DeliveryClient::from_der(
            &c.delivery_name,
            delivery_address,
            [&c.tenant, &c.collector],
            &[&delivery_ca],
            &[&delivery_cert],
            &delivery_key,
            timeout,
        )
        .map_err(|_| "invalid delivery TLS")?;
        let keys =
            PolicyKeys::new(&[(&c.policy_key_id, policy_key)]).map_err(|_| "invalid policy key")?;
        let limits = QueueLimits::new(c.records_per_slot, c.bytes_per_slot)
            .map_err(|_| "invalid queue limits")?;
        owners.push(
            CollectorOwner::new(client, keys, &[&c.source], limits).map_err(|_| "invalid owner")?,
        );
    }
    let pool = CollectorPool::new(owners).map_err(|_| "invalid pool")?;
    let upstream_ca = read(&c.upstream_ca_der, 65536)?;
    let upstream_cert = optional(&c.upstream_client_certificate_der, 65536)?;
    let upstream_key = optional(&c.upstream_client_key_der, 16384)?;
    let point = CapturePoint {
        source: c.source,
        workload: c.workload,
        profile: c.parser_profile,
        method: c.method,
        path: c.path,
        route: c.route,
    };
    let gateway = Gateway::new(
        GatewayTransport {
            tls,
            peer_leaf: &forwarder_leaf,
            upstream: upstream_address,
            upstream_name: &c.upstream_name,
            upstream_ca: &upstream_ca,
            client_chain: &upstream_cert,
            client_key: &upstream_key,
        },
        point,
        pool.clone(),
    )?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(c.listen)
            .await
            .map_err(|_| "listener unavailable")?;
        gateway.serve(listener).await
    })
}
