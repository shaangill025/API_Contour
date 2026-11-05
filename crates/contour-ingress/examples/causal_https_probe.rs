//! Owned synthetic fixture only. Arguments: host port database pg-ca issuer-user
//! inbox-user grant-public policy-public grant-envelope policy-envelope leaf-hex,
//! ten identity UUIDs, nonce, TLS fixture directory. Passwords come from
//! CONTOUR_CAUSAL_ISSUER_PASSWORD / CONTOUR_CAUSAL_INBOX_PASSWORD. A committed
//! issuer session is created locally before the mandatory-mTLS listener starts.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_ingress::{CausalRegistry, CausalServer, CollectorTls, HttpLimits};
use contour_postgres::{CausalBinding, CausalIssue, CausalIssuer, DatabaseSettings, TrustedCa};
use std::{
    env,
    fs::File,
    io::{self, Read},
    path::Path,
    time::Duration,
};
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
fn read(p: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(p)
        .map_err(|_| "fixture input unavailable")?
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| "fixture input unavailable")?;
    if bytes.len() > 1_048_576 {
        return Err("fixture input too large".into());
    }
    Ok(bytes)
}
fn run() -> Result<(), String> {
    let a: Vec<String> = env::args().skip(1).collect();
    if a.len() != 23 {
        return Err("fixture arguments invalid".into());
    }
    let port = a[1].parse().map_err(|_| "fixture port invalid")?;
    let trust = TrustedCa::from_pem(&read(&a[3])?).map_err(|_| "fixture trust invalid")?;
    let grant_key: [u8; 32] = read(&a[6])?.try_into().map_err(|_| "grant key invalid")?;
    let policy_key: [u8; 32] = read(&a[7])?.try_into().map_err(|_| "policy key invalid")?;
    let grants =
        CausalGrantKeys::new(&[("fixture", grant_key)]).map_err(|_| "grant key invalid")?;
    let policies = PolicyKeys::new(&[("fixture", policy_key)]).map_err(|_| "policy key invalid")?;
    if a[10].len() != 64 || !a[10].is_ascii() {
        return Err("peer pin invalid".into());
    }
    let mut peer = [0u8; 32];
    for (i, b) in peer.iter_mut().enumerate() {
        *b = u8::from_str_radix(&a[10][i * 2..i * 2 + 2], 16).map_err(|_| "peer pin invalid")?;
    }
    let ids: [&str; 10] = std::array::from_fn(|i| a[11 + i].as_str());
    let binding = CausalBinding::new(ids, peer).map_err(|_| "binding invalid")?;
    let issue = CausalIssue::new(
        binding,
        &a[21],
        Duration::from_secs(60),
        &read(&a[8])?,
        &read(&a[9])?,
    )
    .map_err(|_| "issue invalid")?;
    let issuer_pass =
        env::var("CONTOUR_CAUSAL_ISSUER_PASSWORD").map_err(|_| "issuer credential missing")?;
    let inbox_pass =
        env::var("CONTOUR_CAUSAL_INBOX_PASSWORD").map_err(|_| "inbox credential missing")?;
    let settings = |name: &str, password: &str| {
        DatabaseSettings::new(
            &a[0],
            port,
            &a[2],
            name,
            password.as_bytes(),
            Duration::from_secs(10),
        )
        .map_err(|_| "database configuration invalid".to_string())
    };
    let issuer_settings = settings(&a[4], &issuer_pass)?;
    let inbox_settings = settings(&a[5], &inbox_pass)?;
    let tlsdir = Path::new(&a[22]);
    let tlsread = |name: &str| read(tlsdir.join(name).to_str().ok_or("fixture path invalid")?);
    let cert = tlsread("server.crt.der")?;
    let key = tlsread("server.key.der")?;
    let ca = tlsread("ca.crt.der")?;
    let tls = CollectorTls::from_der(&[&cert], &key, &[&ca], Duration::from_secs(5))
        .map_err(|_| "TLS configuration invalid")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "fixture runtime failed")?
        .block_on(async {
            let connection = issuer_settings
                .connect(&trust)
                .await
                .map_err(|_| "issuer TLS failed")?;
            let mut issuer = CausalIssuer::new(connection);
            let session = issuer
                .issue(&issue, &peer, &grants, &policies)
                .await
                .map_err(|_| "session issue failed")?;
            drop(issuer);
            let epoch = session.epoch();
            let registry =
                CausalRegistry::new(vec![(peer, session)]).map_err(|_| "registry invalid")?;
            let server = CausalServer::new(
                tls,
                registry,
                inbox_settings,
                trust,
                grants,
                policies,
                HttpLimits::new(2, Duration::from_secs(5)).map_err(|_| "limits invalid")?,
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|_| "listener failed")?;
            let listen_port = listener.local_addr().map_err(|_| "address failed")?.port();
            let (send, receive) = tokio::sync::oneshot::channel();
            let reader = std::thread::spawn(move || {
                let mut line = String::new();
                let _ = io::stdin().read_line(&mut line);
                let _ = send.send(());
            });
            println!("READY {listen_port} {epoch}");
            server
                .serve(listener, async {
                    let _ = receive.await;
                })
                .await
                .map_err(|_| "server failed")?;
            reader.join().map_err(|_| "fixture reader failed")?;
            println!("STOPPED");
            Ok(())
        })
}
