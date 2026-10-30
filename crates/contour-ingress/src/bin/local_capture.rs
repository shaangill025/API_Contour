//! Owned local runtime; configuration contains paths, never key bytes.
use contour_core::PolicyKeys;
use contour_ingress::{CollectorTls, HttpLimits, IngestionServer, PrincipalRegistry};
use contour_postgres::{DatabaseSettings, TrustedCa};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::time::sleep;

static STOPPING: AtomicBool = AtomicBool::new(false);
extern "C" fn stop_signal(_: libc::c_int) {
    STOPPING.store(true, Ordering::Release);
}
struct SignalGuard {
    old_term: libc::sigaction,
    old_int: libc::sigaction,
    active: bool,
}
impl SignalGuard {
    fn install() -> Result<Self, &'static str> {
        // The handler only stores a lock-free atomic flag; all cleanup runs in normal code.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = stop_signal as *const () as usize;
            if libc::sigemptyset(&mut action.sa_mask) != 0 {
                return Err("signal mask failed");
            }
            let mut old_term = std::mem::zeroed();
            let mut old_int = std::mem::zeroed();
            if libc::sigaction(libc::SIGTERM, &action, &mut old_term) != 0 {
                return Err("signal registration failed");
            }
            if libc::sigaction(libc::SIGINT, &action, &mut old_int) != 0 {
                if libc::sigaction(libc::SIGTERM, &old_term, std::ptr::null_mut()) != 0 {
                    return Err("signal restoration failed");
                }
                return Err("signal registration failed");
            }
            Ok(Self {
                old_term,
                old_int,
                active: true,
            })
        }
    }
}
impl SignalGuard {
    fn restore(&mut self) -> Result<(), &'static str> {
        if !self.active {
            return Ok(());
        }
        let term = unsafe { libc::sigaction(libc::SIGTERM, &self.old_term, std::ptr::null_mut()) };
        let int = unsafe { libc::sigaction(libc::SIGINT, &self.old_int, std::ptr::null_mut()) };
        if term != 0 || int != 0 {
            return Err("signal restoration failed");
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for SignalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    database_host: String,
    database_port: u16,
    database_name: String,
    database_user: String,
    password_file: String,
    ca_file: String,
    tenant: String,
    collector: String,
    server_certificate_der: Option<String>,
    server_key_der: Option<String>,
    client_ca_der: Option<String>,
    collector_certificate_der: Option<String>,
    policy_key_file: Option<String>,
    listen: Option<String>,
}
fn read(path: &str, max: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "configuration file unavailable")?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "configuration file unavailable")?;
    if bytes.is_empty() || bytes.len() > max {
        return Err("configuration file size invalid");
    }
    Ok(bytes)
}
fn required(v: &Option<String>) -> Result<&str, &'static str> {
    v.as_deref().ok_or("configuration incomplete")
}
fn main() {
    if run().is_err() {
        eprintln!("local capture runtime failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    let mode = args.next().ok_or("mode missing")?;
    let path = args.next().ok_or("configuration missing")?;
    if args.next().is_some() {
        return Err("unexpected argument");
    }
    let c: Config =
        serde_json::from_slice(&read(&path, 16384)?).map_err(|_| "configuration invalid")?;
    let timeout = Duration::from_secs(5);
    let password = read(&c.password_file, 4096)?;
    let settings = DatabaseSettings::new(
        &c.database_host,
        c.database_port,
        &c.database_name,
        &c.database_user,
        &password,
        timeout,
    )
    .map_err(|_| "database settings invalid")?;
    let trust =
        TrustedCa::from_pem(&read(&c.ca_file, 65536)?).map_err(|_| "database trust invalid")?;
    let mut signals = SignalGuard::install()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime unavailable")?;
    let outcome = runtime.block_on(async move {
        match mode.as_str() {
            "ingress" => {
                let cert = read(required(&c.server_certificate_der)?, 65536)?;
                let key = read(required(&c.server_key_der)?, 16384)?;
                let ca = read(required(&c.client_ca_der)?, 65536)?;
                let collector = read(required(&c.collector_certificate_der)?, 65536)?;
                let policy: [u8; 32] = read(required(&c.policy_key_file)?, 32)?
                    .try_into()
                    .map_err(|_| "policy key invalid")?;
                let tls = CollectorTls::from_der(&[&cert], &key, &[&ca], timeout)
                    .map_err(|_| "ingress TLS invalid")?;
                let fingerprint: [u8; 32] = Sha256::digest(&collector).into();
                let registry = PrincipalRegistry::new(&[(fingerprint, [&c.tenant, &c.collector])])
                    .map_err(|_| "principal invalid")?;
                let keys =
                    PolicyKeys::new(&[("local", policy)]).map_err(|_| "policy key invalid")?;
                let server = IngestionServer::new(
                    tls,
                    registry,
                    settings,
                    trust,
                    keys,
                    HttpLimits::new(8, timeout).map_err(|_| "limits invalid")?,
                );
                let listen = required(&c.listen)?
                    .parse::<std::net::SocketAddr>()
                    .map_err(|_| "listen invalid")?;
                let listener = tokio::net::TcpListener::bind(listen)
                    .await
                    .map_err(|_| "listener failed")?;
                server
                    .serve(listener, async {
                        while !STOPPING.load(Ordering::Acquire) {
                            sleep(Duration::from_millis(100)).await;
                        }
                    })
                    .await
                    .map_err(|_| "ingress failed")?;
            }
            "check" => {
                let mut connection = settings
                    .connect(&trust)
                    .await
                    .map_err(|_| "worker database unavailable")?;
                connection
                    .pending_catalog_batches([&c.tenant, &c.collector], None, 1)
                    .await
                    .map_err(|_| "worker poll unavailable")?;
                connection
                    .close()
                    .await
                    .map_err(|_| "worker cleanup failed")?;
            }
            "worker" => {
                let mut after: Option<String> = None;
                while !STOPPING.load(Ordering::Acquire) {
                    let mut connection = match settings.connect(&trust).await {
                        Ok(c) => c,
                        Err(_) => {
                            sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    };
                    let page = connection
                        .pending_catalog_batches([&c.tenant, &c.collector], after.as_deref(), 32)
                        .await;
                    match page {
                        Ok(ids) if ids.is_empty() => {
                            after = None;
                            let _ = connection.close().await;
                            sleep(Duration::from_secs(1)).await;
                        }
                        Ok(ids) => {
                            for id in ids {
                                if STOPPING.load(Ordering::Acquire) {
                                    break;
                                }
                                // Advance even on poison/unknown; wrap on an empty page so every pending ID is retried.
                                after = Some(id.clone());
                                if connection
                                    .process_catalog_batch([&c.tenant, &c.collector], &id)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            let _ = connection.close().await;
                        }
                        Err(_) => {
                            let _ = connection.close().await;
                            sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
            _ => return Err("mode invalid"),
        }
        Ok(())
    });
    signals.restore()?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sigterm_requests_shutdown_and_restores_previous_handler() {
        STOPPING.store(false, Ordering::Release);
        let mut before: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut before) },
            0
        );
        {
            let _guard = SignalGuard::install().unwrap();
            assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            assert!(STOPPING.load(Ordering::Acquire));
        }
        let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut after) },
            0
        );
        assert_eq!(after.sa_sigaction, before.sa_sigaction);
    }
}
