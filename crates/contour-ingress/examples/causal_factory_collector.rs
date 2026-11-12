//! Fixture collector: exact 300-second issue retry after bound-launch evidence.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_ingress::{CausalRegistry, CausalServer, CollectorTls, HttpLimits};
use contour_postgres::{CausalBinding, CausalIssue, CausalIssuer, DatabaseSettings, TrustedCa};
use serde::Deserialize;
use std::{
    env,
    fs::File,
    io::{self, BufRead, Read, Write},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    host: String,
    port: u16,
    database: String,
    issuer_user: String,
    inbox_user: String,
    database_ca: String,
    grant_public: String,
    policy_public: String,
    grant: String,
    policy: String,
    peer: String,
    ids: [String; 10],
    nonce: String,
    server_certificate: String,
    server_key: String,
    client_ca: String,
}
fn read(path: &str) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "input")?
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| "input")?;
    if bytes.len() > 1_048_576 {
        return Err("input");
    }
    Ok(bytes)
}
fn pin(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("pin");
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| "pin")?;
    }
    Ok(bytes)
}
fn tuple(line: &str) -> Result<(u64, i128, i128), &'static str> {
    let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
    if parts.len() != 4
        || parts[0] != "GO"
        || parts[1..]
            .iter()
            .any(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("control");
    }
    let epoch = parts[1].parse().map_err(|_| "control")?;
    let issued = parts[2].parse().map_err(|_| "control")?;
    let expires = parts[3].parse().map_err(|_| "control")?;
    if epoch == 0 || issued >= expires {
        return Err("control");
    }
    Ok((epoch, issued, expires))
}
fn same_session(expected: (u64, i128, i128), epoch: u64, issued: i128, expires: i128) -> bool {
    issued % 1000 == 0 && expires % 1000 == 0 && expected == (epoch, issued / 1000, expires / 1000)
}
fn advance_nonce<'a>(original: &str, requested: &'a str) -> Result<&'a str, &'static str> {
    if requested == original {
        return Err("advance nonce");
    }
    Ok(requested)
}
fn main() {
    if let Err(error) = run() {
        eprintln!("collector fixture: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 1 && !(args.len() == 3 && args[1] == "--advance") {
        return Err("arguments");
    }
    let input: Inputs = serde_json::from_slice(&read(&args[0])?).map_err(|_| "input")?;
    let peer = pin(&input.peer)?;
    let grants = CausalGrantKeys::new(&[(
        "fixture",
        read(&input.grant_public)?.try_into().map_err(|_| "key")?,
    )])
    .map_err(|_| "key")?;
    let policies = PolicyKeys::new(&[(
        "fixture",
        read(&input.policy_public)?.try_into().map_err(|_| "key")?,
    )])
    .map_err(|_| "key")?;
    let ids = std::array::from_fn(|i| input.ids[i].as_str());
    // The new nonce is accepted only in the explicit late negative phase;
    // normal startup always retries the bound launch's original issue.
    let nonce = if args.len() == 3 {
        advance_nonce(&input.nonce, &args[2])?
    } else {
        &input.nonce
    };
    let issue = CausalIssue::new(
        CausalBinding::new(ids, peer).map_err(|_| "binding")?,
        nonce,
        Duration::from_secs(300),
        &read(&input.grant)?,
        &read(&input.policy)?,
    )
    .map_err(|_| "issue")?;
    let trust = TrustedCa::from_pem(&read(&input.database_ca)?).map_err(|_| "database trust")?;
    let issuer_password = env::var("CONTOUR_CAUSAL_ISSUER_PASSWORD").map_err(|_| "password")?;
    let inbox_password = env::var("CONTOUR_CAUSAL_INBOX_PASSWORD").map_err(|_| "password")?;
    let settings = |user: &str, password: &str| {
        DatabaseSettings::new(
            &input.host,
            input.port,
            &input.database,
            user,
            password.as_bytes(),
            Duration::from_secs(10),
        )
        .map_err(|_| "database settings")
    };
    let issuer_settings = settings(&input.issuer_user, &issuer_password)?;
    if args.len() == 3 {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "runtime")?
            .block_on(async {
                let connection = issuer_settings
                    .connect(&trust)
                    .await
                    .map_err(|_| "issuer TLS")?;
                let mut issuer = CausalIssuer::new(connection);
                let session = issuer
                    .issue(&issue, &peer, &grants, &policies)
                    .await
                    .map_err(|_| "advance issue")?;
                let issued = session.issued_at().unix_timestamp_nanos();
                let expires = session.expires_at().unix_timestamp_nanos();
                if issued % 1000 != 0 || expires % 1000 != 0 {
                    return Err("session mismatch");
                }
                println!(
                    "ADVANCED {} {} {}",
                    session.epoch(),
                    issued / 1000,
                    expires / 1000
                );
                Ok(())
            });
    }
    let inbox_settings = settings(&input.inbox_user, &inbox_password)?;
    let cert = read(&input.server_certificate)?;
    let key = read(&input.server_key)?;
    let ca = read(&input.client_ca)?;
    let tls = CollectorTls::from_der(&[&cert], &key, &[&ca], Duration::from_secs(5))
        .map_err(|_| "TLS")?;
    let (go_tx, go_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let control = std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        let first = lines
            .next()
            .and_then(Result::ok)
            .and_then(|line| tuple(&line).ok());
        let _ = go_tx.send(first);
        let stop = lines
            .next()
            .and_then(Result::ok)
            .is_some_and(|line| line == "STOP");
        let _ = stop_tx.send(stop);
    });
    println!("WAITING");
    io::stdout().flush().map_err(|_| "output")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime")?
        .block_on(async {
            let expected = go_rx.await.map_err(|_| "control")?.ok_or("control")?;
            let connection = issuer_settings
                .connect(&trust)
                .await
                .map_err(|_| "issuer TLS")?;
            let mut issuer = CausalIssuer::new(connection);
            let session = issuer
                .issue(&issue, &peer, &grants, &policies)
                .await
                .map_err(|_| "issue retry")?;
            if !same_session(
                expected,
                session.epoch(),
                session.issued_at().unix_timestamp_nanos(),
                session.expires_at().unix_timestamp_nanos(),
            ) {
                return Err("session mismatch");
            }
            drop(issuer);
            let registry = CausalRegistry::new(vec![(peer, session)]).map_err(|_| "registry")?;
            let server = CausalServer::new(
                tls,
                registry,
                inbox_settings,
                trust,
                grants,
                policies,
                HttpLimits::new(2, Duration::from_secs(5)).map_err(|_| "limits")?,
            );
            let listener = tokio::net::TcpListener::bind("0.0.0.0:8443")
                .await
                .map_err(|_| "listener")?;
            println!("READY {}", expected.0);
            io::stdout().flush().map_err(|_| "output")?;
            let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed = stopped.clone();
            let stop = async move {
                if stop_rx.await == Ok(true) {
                    observed.store(true, std::sync::atomic::Ordering::Release);
                }
            };
            server.serve(listener, stop).await.map_err(|_| "server")?;
            if !stopped.load(std::sync::atomic::Ordering::Acquire) {
                return Err("control");
            }
            Ok::<(), &'static str>(())
        })?;
    control.join().map_err(|_| "control")?;
    println!("STOPPED");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_session_required() {
        let value = tuple("GO 7 1000 2000").unwrap();
        assert!(same_session(value, 7, 1_000_000, 2_000_000));
        for (epoch, issued, expires) in [
            (8, 1_000_000, 2_000_000),
            (7, 1_001_000, 2_000_000),
            (7, 1_000_000, 2_001_000),
            (7, 1_000_001, 2_000_000),
        ] {
            assert!(!same_session(value, epoch, issued, expires));
        }
        for invalid in [
            "GO 0 1 2",
            "GO 1 2 2",
            "GO -1 1 2",
            "GO 1 1 2 extra",
            "GO 1 1 2\nSTOP",
        ] {
            assert!(tuple(invalid).is_err());
        }
    }
    #[test]
    fn peer_pin_is_exact_lowercase_hex() {
        assert!(pin(&"a".repeat(64)).is_ok());
        for value in ["A".repeat(64), "g".repeat(64), "a".repeat(63)] {
            assert!(pin(&value).is_err());
        }
    }
    #[test]
    fn advance_requires_a_different_nonce() {
        assert!(advance_nonce("original", "original").is_err());
        assert_eq!(advance_nonce("original", "new").unwrap(), "new");
    }
}
