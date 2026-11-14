//! Synthetic, opt-in SQL29 probe. Input is private and bounded; output is a fixed label.
//! A verified TLS peer is obtained only from the connection carrying the fact.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::{
    CausalBinding, CausalError, CausalIssue, CausalIssuer, DatabaseSettings, ReceiverEvidenceTls,
    ReceiverFactInbox, ReceiverFactRequest, ReceiverFactSelectors, TrustedCa,
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use serde_json::Value;
use std::{
    io::{self, Read},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout_at},
};
use tokio_rustls::TlsConnector;

fn unhex(s: &str, max: usize) -> Result<Vec<u8>, ()> {
    if s.is_empty()
        || s.len() % 2 != 0
        || s.len() > max * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).map_err(|_| ())?, 16).map_err(|_| ()))
        .collect()
}
fn hex32(s: &str) -> Result<[u8; 32], ()> {
    unhex(s, 32)?.try_into().map_err(|_| ())
}

fn run() -> Result<Option<[u8; 32]>, ()> {
    let mut raw = Vec::new();
    io::stdin()
        .lock()
        .take(262145)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
    if raw.is_empty() || raw.len() > 262144 {
        return Err(());
    }
    let input: Value = serde_json::from_slice(&raw).map_err(|_| ())?;
    raw.fill(0);
    let o = input.as_object().ok_or(())?;
    let keys = [
        "ca_pem",
        "epoch",
        "grant",
        "grant_public",
        "ids",
        "mode",
        "nonce",
        "issuer_password",
        "peer",
        "policy",
        "policy_public",
        "port",
        "writer_password",
        "writer_user",
        "generation",
        "credential",
        "fact",
        "server_cert_der",
        "server_key_der",
        "client_cert_der",
        "client_key_der",
        "client_ca_der",
    ];
    if o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)) {
        return Err(());
    }
    let get = |name: &str| o.get(name).and_then(Value::as_str).ok_or(());
    let mode = get("mode")?;
    if !matches!(
        mode,
        "positive"
            | "retry-denied"
            | "wrong-generation"
            | "wrong-credential"
            | "wrong-scope"
            | "wrong-role"
            | "wrong-leaf"
            | "revoked"
            | "deadline"
    ) {
        return Err(());
    }
    let writer_user = get("writer_user")?;
    if (mode == "wrong-role" && writer_user != "causal_issuer_login")
        || (mode != "wrong-role" && writer_user != "causal_receiver_writer_login")
    {
        return Err(());
    }
    let ids: Vec<&str> = o
        .get("ids")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .map(|v| v.as_str().ok_or(()))
        .collect::<Result<_, _>>()?;
    let ids: [&str; 10] = ids.try_into().map_err(|_| ())?;
    let peer = hex32(get("peer")?)?;
    let grant = serde_json::to_vec(o.get("grant").ok_or(())?).map_err(|_| ())?;
    let policy = serde_json::to_vec(o.get("policy").ok_or(())?).map_err(|_| ())?;
    let issue = CausalIssue::new(
        CausalBinding::new(ids, peer).map_err(|_| ())?,
        get("nonce")?,
        Duration::from_secs(60),
        &grant,
        &policy,
    )
    .map_err(|_| ())?;
    let grants =
        CausalGrantKeys::new(&[("fixture", hex32(get("grant_public")?)?)]).map_err(|_| ())?;
    let policies =
        PolicyKeys::new(&[("fixture", hex32(get("policy_public")?)?)]).map_err(|_| ())?;
    let port = get("port")?.parse::<u16>().map_err(|_| ())?;
    let issuer_settings = DatabaseSettings::new(
        "localhost",
        port,
        "contour_local",
        "causal_issuer_login",
        get("issuer_password")?.as_bytes(),
        Duration::from_secs(10),
    )
    .map_err(|_| ())?;
    let writer_settings = DatabaseSettings::new(
        "localhost",
        port,
        "contour_local",
        writer_user,
        get("writer_password")?.as_bytes(),
        Duration::from_secs(10),
    )
    .map_err(|_| ())?;
    let trust = TrustedCa::from_pem(get("ca_pem")?.as_bytes()).map_err(|_| ())?;
    let expected_epoch = get("epoch")?.parse::<u64>().map_err(|_| ())?;
    let selectors =
        ReceiverFactSelectors::new(get("generation")?, get("credential")?).map_err(|_| ())?;
    let fact = get("fact")?.as_bytes().to_vec();
    if fact.is_empty() || fact.len() > 65536 {
        return Err(());
    }
    let server_cert = unhex(get("server_cert_der")?, 16384)?;
    let server_key = unhex(get("server_key_der")?, 16384)?;
    let client_cert = unhex(get("client_cert_der")?, 16384)?;
    let client_key = unhex(get("client_key_der")?, 16384)?;
    let ca = unhex(get("client_ca_der")?, 16384)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?
        .block_on(async {
            let mut issuer =
                CausalIssuer::new(issuer_settings.connect(&trust).await.map_err(|_| ())?);
            let session = issuer
                .issue_receiver_504_until(
                    &issue,
                    &peer,
                    &grants,
                    &policies,
                    Instant::now() + Duration::from_secs(8),
                )
                .await
                .map_err(|_| ())?;
            let view = session.receiver_profile_504().ok_or(())?;
            if view.tenant_id() != ids[0]
                || view.runtime_id() != ids[1]
                || view.epoch() != expected_epoch
                || view.nonce() != get("nonce")?
                || view.verified_remaining().is_zero()
            {
                return Err(());
            }
            let mut inbox =
                ReceiverFactInbox::new(writer_settings.connect(&trust).await.map_err(|_| ())?);
            let acceptor = ReceiverEvidenceTls::from_der(
                &[&server_cert],
                &server_key,
                &[&ca],
                Duration::from_secs(5),
            )
            .map_err(|_| ())?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut roots = RootCertStore::empty();
            roots.add(CertificateDer::from(ca)).map_err(|_| ())?;
            let client = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|_| ())?
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    vec![CertificateDer::from(client_cert)],
                    PrivateKeyDer::try_from(client_key).map_err(|_| ())?,
                )
                .map_err(|_| ())?;
            let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
            let address = listener.local_addr().map_err(|_| ())?;
            let until = Instant::now() + Duration::from_secs(8);
            let send = tokio::spawn(async move {
                let socket = TcpStream::connect(address).await.map_err(|_| ())?;
                let name = ServerName::try_from("localhost").map_err(|_| ())?;
                let mut stream = TlsConnector::from(Arc::new(client))
                    .connect(name, socket)
                    .await
                    .map_err(|_| ())?;
                stream
                    .write_all(&(fact.len() as u32).to_be_bytes())
                    .await
                    .map_err(|_| ())?;
                stream.write_all(&fact).await.map_err(|_| ())?;
                stream.flush().await.map_err(|_| ())?;
                Ok::<(), ()>(())
            });
            let receive = async {
                let (socket, remote) = listener.accept().await.map_err(|_| ())?;
                if !remote.ip().is_loopback() {
                    return Err(());
                }
                let mut connection = acceptor.accept_until(socket, until).await.map_err(|_| ())?;
                let mut len = [0u8; 4];
                connection.read_exact(&mut len).await.map_err(|_| ())?;
                let n = u32::from_be_bytes(len) as usize;
                if n == 0 || n > 65536 {
                    return Err(());
                }
                let mut received = vec![0; n];
                connection.read_exact(&mut received).await.map_err(|_| ())?;
                let deadline = if mode == "deadline" {
                    Instant::now()
                } else {
                    until
                };
                let result = inbox
                    .accept_until(
                        &session,
                        connection.peer(),
                        ReceiverFactRequest {
                            selectors: &selectors,
                            canonical_fact: &received,
                        },
                        &grants,
                        &policies,
                        deadline,
                    )
                    .await;
                let digest = match mode {
                    "positive" => {
                        let receipt = result.map_err(|_| ())?;
                        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
                            .tls13()
                            .ok_or(())?;
                        let hash = suite.common.hash_provider.hash(receipt.as_bytes());
                        Some(hash.as_ref().try_into().map_err(|_| ())?)
                    }
                    "deadline" => {
                        if !matches!(result, Err(CausalError::Deadline)) {
                            return Err(());
                        }
                        None
                    }
                    "wrong-role" => {
                        if !matches!(result, Err(CausalError::Identity)) {
                            return Err(());
                        }
                        None
                    }
                    _ => {
                        if !matches!(result, Err(CausalError::Scope)) {
                            return Err(());
                        }
                        None
                    }
                };
                Ok::<Option<[u8; 32]>, ()>(digest)
            };
            let digest = timeout_at(until, receive).await.map_err(|_| ())??;
            timeout_at(until, send)
                .await
                .map_err(|_| ())?
                .map_err(|_| ())??;
            Ok(digest)
        })
}
fn main() {
    match run() {
        Ok(Some(digest)) => {
            let text: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            println!("PASS receiver-fact-probe {text}");
        }
        Ok(None) => println!("PASS receiver-fact-probe"),
        Err(()) => {
            eprintln!("FAIL receiver-fact-probe");
            std::process::exit(1);
        }
    }
}
