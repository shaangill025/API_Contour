//! Checked deployment settings and owned PostgreSQL TLS transport.
//! The async deadline covers DNS/socket/TLS/auth cooperatively; OS DNS helpers may
//! outlive cancellation. Socket timeouts also apply separately per address.
use std::{fmt, net::IpAddr, time::Duration};
use tokio_postgres::{Config, config::SslMode};
mod authority;
mod catalog;
mod catalog_reader;
pub use catalog_reader::{CatalogCursor, CatalogPage, CatalogReadError, CatalogReadScope};
mod refresh;
mod submit;
mod transaction;
mod transport;
pub use authority::AuthorityError;
pub use catalog::{CatalogError, CatalogStatus};
pub use refresh::{AuthorityRead, AuthorityReadRequest, AuthoritySource};
pub use submit::{DurableReceipt, ReceiptStatus, SubmitError};
pub use transport::{ConnectedDatabase, TlsVersion, TransportError, TrustedCa};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsError {
    Host,
    Port,
    Database,
    User,
    Password,
    Deadline,
}
impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SettingsError {}

/// Approved deployment configuration, never a request-supplied destination.
/// No DSN, arbitrary options, mutable driver config or deserialization surface.
/// Password storage belongs to the driver; this type does not promise erasure.
pub struct DatabaseSettings {
    pub(crate) config: Config,
    pub(crate) deadline: Duration,
}
impl fmt::Debug for DatabaseSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseSettings")
            .field(
                "tls_required",
                &(self.config.get_ssl_mode() == SslMode::Require),
            )
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}
impl DatabaseSettings {
    /// One ASCII DNS name or standard IPv4/IPv6 address, nonzero port, explicit
    /// database/user (1–63 UTF-8 bytes, no controls), password (1–4096 bytes),
    /// and deadline (1 ms–30 s). DNS terminal dots are rejected; no normalization.
    /// Use connect with explicit trust anchors to establish verified TLS transport.
    pub fn new(
        host: &str,
        port: u16,
        database: &str,
        user: &str,
        password: &[u8],
        deadline: Duration,
    ) -> Result<Self, SettingsError> {
        if !valid_host(host) {
            return Err(SettingsError::Host);
        }
        if port == 0 {
            return Err(SettingsError::Port);
        }
        if !identifier(database) {
            return Err(SettingsError::Database);
        }
        if !identifier(user) {
            return Err(SettingsError::User);
        }
        if password.is_empty() || password.len() > 4096 {
            return Err(SettingsError::Password);
        }
        if deadline < Duration::from_millis(1) || deadline > Duration::from_secs(30) {
            return Err(SettingsError::Deadline);
        }
        // Typed setters treat every argument as data, never connection-string syntax.
        let mut config = Config::new();
        config
            .host(host)
            .port(port)
            .dbname(database)
            .user(user)
            .password(password)
            .ssl_mode(SslMode::Require)
            .application_name("APIContour")
            .connect_timeout(deadline);
        Ok(Self { config, deadline })
    }
}
fn identifier(text: &str) -> bool {
    !text.is_empty() && text.len() <= 63 && !text.chars().any(char::is_control)
}
fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_postgres::config::Host;
    fn settings(host: &str) -> Result<DatabaseSettings, SettingsError> {
        DatabaseSettings::new(
            host,
            5432,
            "contour",
            "ingest",
            b"SYNTHETIC_SECRET",
            Duration::from_secs(1),
        )
    }
    #[test]
    fn unix_socket_destination_is_rejected() {
        assert_eq!(
            settings("/var/run/postgresql").unwrap_err(),
            SettingsError::Host
        );
    }
    #[test]
    fn exact_single_destination_and_tls_configuration() {
        for host in [
            "db",
            "DB.example",
            "db-1.example",
            "127.0.0.1",
            "2001:db8::1",
            "::1",
        ] {
            let settings = settings(host).unwrap();
            let config = &settings.config;
            assert_eq!(config.get_hosts(), &[Host::Tcp(host.to_owned())]);
            assert!(config.get_hostaddrs().is_empty());
            assert_eq!(config.get_ports(), &[5432]);
            assert_eq!(config.get_user(), Some("ingest"));
            assert_eq!(config.get_dbname(), Some("contour"));
            assert_eq!(config.get_password(), Some(b"SYNTHETIC_SECRET".as_slice()));
            assert_eq!(config.get_ssl_mode(), SslMode::Require);
            assert_eq!(config.get_application_name(), Some("APIContour"));
            assert!(config.get_options().is_none());
            assert_eq!(config.get_connect_timeout(), Some(&Duration::from_secs(1)));
            assert_eq!(settings.deadline, Duration::from_secs(1));
        }
    }
    #[test]
    fn unsafe_host_syntax_and_bounds() {
        for host in [
            "",
            "/tmp",
            "\\server",
            "postgres://db",
            "db:5432",
            "db,other",
            "host=db",
            "[::1]",
            "db.",
            ".db",
            "db..example",
            "-db",
            "db-",
            "db_name",
            "déb",
            "db\0",
            "db\n",
            "db sslmode=disable",
            "db?sslmode=disable",
            "db/path",
            "db#fragment",
            "db%2eexample",
        ] {
            assert_eq!(settings(host).unwrap_err(), SettingsError::Host, "{host:?}");
        }
        let label = "a".repeat(63);
        assert!(settings(&label).is_ok());
        assert!(settings(&"a".repeat(64)).is_err());
        let maximum = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(maximum.len(), 253);
        assert!(settings(&maximum).is_ok());
        assert_eq!(settings(&(maximum + "a")).unwrap_err(), SettingsError::Host);
    }
    #[test]
    fn identifiers_password_port_and_deadline_boundaries() {
        let check = |db: &str, user: &str, password: &[u8], port, deadline| {
            DatabaseSettings::new("db", port, db, user, password, deadline)
        };
        let good = Duration::from_millis(1);
        for name in ["", "a\0b", "a\nb", "a\u{0085}b"] {
            assert_eq!(
                check(name, "u", b"p", 1, good).unwrap_err(),
                SettingsError::Database
            );
            assert_eq!(
                check("d", name, b"p", 1, good).unwrap_err(),
                SettingsError::User
            );
        }
        let unicode = "é".repeat(31) + "x";
        assert_eq!(unicode.len(), 63);
        assert!(
            check(
                &unicode,
                &unicode,
                &[9; 4096],
                u16::MAX,
                Duration::from_secs(30)
            )
            .is_ok()
        );
        assert_eq!(
            check(&(unicode.clone() + "x"), "u", b"p", 1, good).unwrap_err(),
            SettingsError::Database
        );
        assert_eq!(
            check("d", &(unicode + "x"), b"p", 1, good).unwrap_err(),
            SettingsError::User
        );
        for password in [b"".as_slice(), &[9; 4097]] {
            assert_eq!(
                check("d", "u", password, 1, good).unwrap_err(),
                SettingsError::Password
            );
        }
        assert_eq!(
            check("d", "u", b"p", 0, good).unwrap_err(),
            SettingsError::Port
        );
        for deadline in [
            Duration::ZERO,
            good - Duration::from_nanos(1),
            Duration::from_secs(30) + Duration::from_nanos(1),
        ] {
            assert_eq!(
                check("d", "u", b"p", 1, deadline).unwrap_err(),
                SettingsError::Deadline
            );
        }
    }
    #[test]
    fn options_are_data_and_debug_is_redacted() {
        let input = "sslmode=disable options=-c";
        let settings = DatabaseSettings::new(
            "db",
            5432,
            input,
            input,
            b"SYNTHETIC_SECRET",
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(settings.config.get_user(), Some(input));
        assert_eq!(settings.config.get_dbname(), Some(input));
        assert_eq!(settings.config.get_ssl_mode(), SslMode::Require);
        assert!(settings.config.get_options().is_none());
        for debug in [format!("{settings:?}"), format!("{settings:#?}")] {
            for sensitive in ["SYNTHETIC_SECRET", input, "dbname", "password"] {
                assert!(!debug.contains(sensitive));
            }
            assert!(debug.contains("tls_required"));
        }
        assert_eq!(SettingsError::Password.to_string(), "Password");
    }
}
