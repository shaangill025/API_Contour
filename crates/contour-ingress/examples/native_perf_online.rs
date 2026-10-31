//! Fixture-only online gateway. Synchronizes before serving; never refreshes during measurement.
use contour_core::{PolicyKeys, QueueLimits};
use contour_delivery::{
    CollectorOwner, CollectorPool, DeliveryClient, RetryDirective, SendOutcome,
};
use contour_ingress::{
    CollectorTls,
    gateway::{CapturePoint, Gateway, GatewayTransport},
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::{
    env, fs,
    future::Future,
    io::Read,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::time::sleep;

// Fixture-only signal: handler does no I/O and never touches capture authority.
static SNAPSHOT_REQUESTED: AtomicBool = AtomicBool::new(false);
#[derive(Default)]
struct Counters {
    ack: AtomicU64,
    deferred: AtomicU64,
    error: AtomicU64,
    empty: AtomicU64,
}
fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(1))
    });
}
#[cfg(target_os = "linux")]
extern "C" fn metrics_signal(_: libc::c_int) {
    SNAPSHOT_REQUESTED.store(true, Ordering::Release);
}
#[cfg(target_os = "linux")]
struct MetricsSignal(libc::sigaction);
#[cfg(target_os = "linux")]
impl MetricsSignal {
    fn install() -> Result<Self, &'static str> {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = metrics_signal as *const () as usize;
            if libc::sigemptyset(&mut action.sa_mask) != 0 {
                return Err("metrics signal mask");
            }
            let mut old = std::mem::zeroed();
            if libc::sigaction(libc::SIGUSR1, &action, &mut old) != 0 {
                return Err("metrics signal setup");
            }
            Ok(Self(old))
        }
    }
}
#[cfg(target_os = "linux")]
impl Drop for MetricsSignal {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGUSR1, &self.0, std::ptr::null_mut());
        }
    }
}
#[cfg(not(target_os = "linux"))]
struct MetricsSignal;
#[cfg(not(target_os = "linux"))]
impl MetricsSignal {
    fn install() -> Result<Self, &'static str> {
        Err("metrics require Linux")
    }
}

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
fn new_id() -> Option<String> {
    let mut b = [0; 16];
    SystemRandom::new().fill(&mut b).ok()?;
    b[6] = b[6] & 15 | 64;
    b[8] = b[8] & 63 | 128;
    Some(format!(
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
    if let Err(code) = run() {
        // Every error is a closed static code; configuration values and error
        // objects never enter startup diagnostics.
        eprintln!("native gateway failed: {code}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    let _metrics_signal = MetricsSignal::install()?;
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
        // Complete the real authority exchange before allowing any request. The
        // operator bounds the measured window to well within the issued lease.
        pool.synchronize()
            .await
            .map_err(|_| "authority unavailable")?;
        let listener = tokio::net::TcpListener::bind(c.listen)
            .await
            .map_err(|_| "listener unavailable")?;
        let poll = pool.clone();
        let counters = Arc::new(Counters::default());
        let snapshot = counters.clone();
        let (metric_slots, metric_records, metric_bytes) = (c.slots, c.records_per_slot, c.bytes_per_slot);
        tokio::spawn(async move {
            let mut sequence = 0u64;
            loop {
                let _ = poll.poll_authority();
                // poll_authority has returned and released its gate before output.
                if SNAPSHOT_REQUESTED.swap(false, Ordering::AcqRel) {
                    sequence = sequence.saturating_add(1);
                    println!("NATIVE_PERF_METRICS {{\"sequence\":{},\"losses\":{},\"ack\":{},\"deferred\":{},\"error\":{},\"empty\":{},\"slots\":{},\"records_per_slot\":{},\"bytes_per_slot\":{}}}",
                        sequence, poll.losses(), snapshot.ack.load(Ordering::Relaxed),
                        snapshot.deferred.load(Ordering::Relaxed), snapshot.error.load(Ordering::Relaxed),
                        snapshot.empty.load(Ordering::Relaxed), metric_slots, metric_records, metric_bytes);
                }
                sleep(Duration::from_millis(100)).await;
            }
        });
        for slot in 0..c.slots {
            let p: Arc<CollectorPool> = pool.clone();
            let counters = counters.clone();
            tokio::spawn(async move {
                loop {
                    if let Some(id) = new_id() {
                        let _ = p.try_freeze(slot, &id, 100, 1_048_576);
                    }
                    match p.send(slot).await {
                        Ok(SendOutcome::Acknowledged { .. }) => increment(&counters.ack),
                        Ok(SendOutcome::Empty) => increment(&counters.empty),
                        Ok(SendOutcome::Deferred(directive)) => {
                            increment(&counters.deferred);
                            if matches!(directive, RetryDirective::Retry { .. }) {
                                let _ = p.wait_retry(slot).await;
                            }
                        }
                        Err(_) => increment(&counters.error),
                    }
                    sleep(Duration::from_millis(500)).await;
                }
            });
        }
        gateway.serve(listener).await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metric_increment_saturates_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);
        increment(&counter);
        increment(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
