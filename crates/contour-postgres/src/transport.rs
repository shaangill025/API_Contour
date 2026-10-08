use crate::DatabaseSettings;
use native_tls::{Certificate, Protocol, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use std::{fmt, time::Duration};
use tokio::{
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use tokio_postgres::Client;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Trust,
    Runtime,
    Connection,
    Deadline,
    Query,
    Shutdown,
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TransportError {}

/// Explicit deployment trust anchors only; no system-root fallback or TLS bypass.
pub struct TrustedCa(MakeTlsConnector);
impl fmt::Debug for TrustedCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrustedCa")
    }
}
impl TrustedCa {
    /// Parse all input as 1–8 PEM certificates, at most 64 KiB including whitespace.
    pub fn from_pem(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(TransportError::Trust);
        }
        let mut remaining = std::str::from_utf8(bytes).map_err(|_| TransportError::Trust)?;
        let mut builder = TlsConnector::builder();
        builder
            .disable_built_in_roots(true)
            .min_protocol_version(Some(Protocol::Tlsv12))
            .use_sni(true);
        let mut count = 0;
        loop {
            remaining = remaining.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
            if remaining.is_empty() {
                break;
            }
            if count == 8 || !remaining.starts_with("-----BEGIN CERTIFICATE-----") {
                return Err(TransportError::Trust);
            }
            let end = remaining
                .find("-----END CERTIFICATE-----")
                .ok_or(TransportError::Trust)?
                + "-----END CERTIFICATE-----".len();
            let certificate = Certificate::from_pem(&remaining.as_bytes()[..end])
                .map_err(|_| TransportError::Trust)?;
            builder.add_root_certificate(certificate);
            count += 1;
            remaining = &remaining[end..];
        }
        if count == 0 {
            return Err(TransportError::Trust);
        }
        let connector = builder.build().map_err(|_| TransportError::Trust)?;
        Ok(Self(MakeTlsConnector::new(connector)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// Owns the client and driver task. No raw-client or arbitrary-query public API.
pub struct ConnectedDatabase {
    pub(crate) client: Option<Client>,
    driver: Option<JoinHandle<Result<(), tokio_postgres::Error>>>,
    pub(crate) deadline: Duration,
    pub(crate) reusable: bool,
}
impl fmt::Debug for ConnectedDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectedDatabase")
    }
}
impl DatabaseSettings {
    /// One resolved IP only, preserving the configured TLS hostname and port.
    /// IPv4 is preferred before connecting; there is no address retry/fallback.
    /// Caller budget can only shorten the configured connection deadline.
    pub async fn connect_single_until(
        &self,
        trust: &TrustedCa,
        deadline: Instant,
    ) -> Result<ConnectedDatabase, TransportError> {
        tokio::runtime::Handle::try_current().map_err(|_| TransportError::Runtime)?;
        let deadline = deadline.min(Instant::now() + self.deadline);
        let work = async {
            let host = match self.config.get_hosts().first() {
                Some(tokio_postgres::config::Host::Tcp(host)) => host,
                _ => return Err(TransportError::Connection),
            };
            let port = *self
                .config
                .get_ports()
                .first()
                .ok_or(TransportError::Connection)?;
            let mut addresses = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| TransportError::Connection)?;
            let first = addresses.next().ok_or(TransportError::Connection)?;
            let address = if first.is_ipv4() {
                first
            } else {
                addresses.find(|address| address.is_ipv4()).unwrap_or(first)
            };
            let mut config = self.config.clone();
            config.hostaddr(address.ip());
            let (client, connection) = config
                .connect(trust.0.clone())
                .await
                .map_err(|_| TransportError::Connection)?;
            Ok(ConnectedDatabase {
                client: Some(client),
                driver: Some(tokio::spawn(connection)),
                deadline: self.deadline,
                reusable: false,
            })
        };
        timeout_at(deadline, work)
            .await
            .map_err(|_| TransportError::Deadline)?
    }
    /// Requires a Tokio runtime with I/O and timers enabled. Timeout is cooperative;
    /// OS DNS work in Tokio's blocking pool may outlive cancellation of this future.
    pub async fn connect(&self, trust: &TrustedCa) -> Result<ConnectedDatabase, TransportError> {
        tokio::runtime::Handle::try_current().map_err(|_| TransportError::Runtime)?;
        let (client, connection) = timeout(self.deadline, self.config.connect(trust.0.clone()))
            .await
            .map_err(|_| TransportError::Deadline)?
            .map_err(|_| TransportError::Connection)?;
        Ok(ConnectedDatabase {
            client: Some(client),
            driver: Some(tokio::spawn(connection)),
            deadline: self.deadline,
            reusable: false,
        })
    }
}
impl ConnectedDatabase {
    /// Read-only reuse evidence, not authentication or reusable policy authority.
    /// Only confirmed transaction completion with empty context marks readiness.
    pub fn is_reusable(&self) -> bool {
        self.reusable
            && self
                .client
                .as_ref()
                .is_some_and(|client| !client.is_closed())
            && self
                .driver
                .as_ref()
                .is_some_and(|driver| !driver.is_finished())
    }
    pub(crate) fn invalidate(&mut self) {
        self.reusable = false;
        self.client.take();
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
    /// Fixed health query proves the actual PostgreSQL session negotiated TLS.
    pub async fn health(&self) -> Result<TlsVersion, TransportError> {
        let client = self.client.as_ref().ok_or(TransportError::Shutdown)?;
        let row = timeout(self.deadline, client.query_one(
            "SELECT ssl, version FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid()", &[]))
            .await.map_err(|_| TransportError::Deadline)?.map_err(|_| TransportError::Query)?;
        let ssl: bool = row.try_get(0).map_err(|_| TransportError::Query)?;
        let version: String = row.try_get(1).map_err(|_| TransportError::Query)?;
        match (ssl, version.as_str()) {
            (true, "TLSv1.2") => Ok(TlsVersion::Tls12),
            (true, "TLSv1.3") => Ok(TlsVersion::Tls13),
            _ => Err(TransportError::Query),
        }
    }
    /// Drop the client and await driver shutdown within the configured deadline.
    pub async fn close(mut self) -> Result<(), TransportError> {
        self.reusable = false;
        self.client.take();
        // Retain ownership across await so cancellation also aborts the driver.
        let driver = self.driver.as_mut().ok_or(TransportError::Shutdown)?;
        match timeout(self.deadline, driver).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(_) => Err(TransportError::Shutdown),
            Err(_) => {
                if let Some(driver) = &self.driver {
                    driver.abort();
                }
                Err(TransportError::Deadline)
            }
        }
    }
}
impl Drop for ConnectedDatabase {
    fn drop(&mut self) {
        self.client.take();
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn close_deadline_aborts_owned_driver() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let driver =
                    tokio::spawn(std::future::pending::<Result<(), tokio_postgres::Error>>());
                let abort = driver.abort_handle();
                let session = ConnectedDatabase {
                    client: None,
                    driver: Some(driver),
                    deadline: Duration::from_millis(1),
                    reusable: false,
                };
                assert_eq!(session.close().await, Err(TransportError::Deadline));
                tokio::task::yield_now().await;
                assert!(abort.is_finished());
            });
    }
    #[test]
    fn cancellation_of_close_aborts_owned_driver() {
        use std::future::Future;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let driver =
                    tokio::spawn(std::future::pending::<Result<(), tokio_postgres::Error>>());
                let abort = driver.abort_handle();
                let session = ConnectedDatabase {
                    client: None,
                    driver: Some(driver),
                    deadline: Duration::from_secs(1),
                    reusable: false,
                };
                let mut close = Box::pin(session.close());
                std::future::poll_fn(|cx| {
                    assert!(close.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                drop(close);
                tokio::task::yield_now().await;
                assert!(abort.is_finished());
            });
    }
    // Public certificate only, generated by OpenSSL; ephemeral private key discarded.
    const CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBnDCCAUGgAwIBAgIUfG5Knevd8P5jYfwHbOMMUk+WPpIwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYQVBJQ29udG91ciBpbmVydCB1bml0IENBMB4XDTI2MTAwNzE4
MDcyM1oXDTM2MTAwNDE4MDcyM1owIzEhMB8GA1UEAwwYQVBJQ29udG91ciBpbmVy
dCB1bml0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2YRA+B5rviMiv2wF
QxIn18HikcxdLcTQZmyteDS9fF3xjkum2h+eW7BCTcvM3Byh7dROFhkdRu8S/sJ6
fMbUI6NTMFEwHQYDVR0OBBYEFFiJr8T+jJtN2/a5+YgRAZsiUPXjMB8GA1UdIwQY
MBaAFFiJr8T+jJtN2/a5+YgRAZsiUPXjMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDSQAwRgIhAO+8agjVOEXCKjiIubZ0cMXVINstB0Xe55YZbJqGWOPOAiEA
yhJX38TR9DM9wPkeA7ciTipLCzu5OKdtuWDX1jxxwCw=
-----END CERTIFICATE-----
"#;
    #[test]
    fn complete_bundle_bounds_and_redaction() {
        let trust = TrustedCa::from_pem(CERT.as_bytes()).unwrap();
        assert_eq!(format!("{trust:?}"), "TrustedCa");
        assert!(TrustedCa::from_pem(format!(" \n{CERT}\t{CERT} ").as_bytes()).is_ok());
        assert!(TrustedCa::from_pem(CERT.repeat(8).as_bytes()).is_ok());
        for bytes in [
            vec![b' '; 65_537],
            b" \n".to_vec(),
            vec![255],
            CERT.repeat(9).into_bytes(),
            format!("{CERT}trailing").into_bytes(),
            format!("garbage{CERT}").into_bytes(),
            format!("{CERT}-----BEGIN PRIVATE KEY-----").into_bytes(),
            b"-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----".to_vec(),
        ] {
            assert_eq!(
                TrustedCa::from_pem(&bytes).unwrap_err(),
                TransportError::Trust
            );
        }
        let max = format!("{CERT}{}", " ".repeat(65_536 - CERT.len()));
        assert!(TrustedCa::from_pem(max.as_bytes()).is_ok());
        assert_eq!(TransportError::Connection.to_string(), "Connection");
    }
    #[test]
    fn empty_ca_bundle_is_rejected() {
        assert_eq!(TrustedCa::from_pem(b"").unwrap_err(), TransportError::Trust);
    }
}
