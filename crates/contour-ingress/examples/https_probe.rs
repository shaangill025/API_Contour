//! Owned synthetic integration server. No production credentials or default binding.
use contour_core::PolicyKeys;
use contour_ingress::{CollectorTls, HttpLimits, IngestionServer, PrincipalRegistry};
use contour_postgres::{DatabaseSettings, TrustedCa};
use sha2::{Digest, Sha256};
use std::{env, fs, io, path::PathBuf, time::Duration};
fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("HTTPS fixture arguments missing");
    }
    let directory = PathBuf::from(&args[1]);
    let read = |name: &str| fs::read(directory.join(name)).map_err(|_| "fixture input missing");
    let cert = read("server.crt.der")?;
    let key = read("server.key.der")?;
    let ca = read("ca.crt.der")?;
    let client = read("http-client.crt.der")?;
    let deadline = Duration::from_millis(args[4].parse().map_err(|_| "deadline invalid")?);
    let tls = CollectorTls::from_der(&[&cert], &key, &[&ca], deadline)
        .map_err(|_| "TLS configuration invalid")?;
    let pin: [u8; 32] = Sha256::digest(&client).into();
    let registry =
        PrincipalRegistry::new(&[(pin, [&args[2], &args[3]])]).map_err(|_| "registry invalid")?;
    // Invalid operator bindings fail before accepting any peer or copying scope.
    if PrincipalRegistry::new(&[(pin, [&args[2], &args[3]]), (pin, [&args[2], &args[3]])]).is_ok() {
        return Err("duplicate pin accepted");
    }
    let settings = DatabaseSettings::new(
        "localhost",
        args[0].parse().map_err(|_| "port invalid")?,
        "contour_fixture",
        "contour_tls",
        env::var("CONTOUR_FIXTURE_PASSWORD")
            .map_err(|_| "credential missing")?
            .as_bytes(),
        deadline,
    )
    .map_err(|_| "database configuration invalid")?;
    let trust = TrustedCa::from_pem(&read("ca.crt")?).map_err(|_| "trust invalid")?;
    let public = read("signer.raw")?
        .try_into()
        .map_err(|_| "policy key invalid")?;
    let keys = PolicyKeys::new(&[("fixture", public)]).map_err(|_| "policy key invalid")?;
    let server = IngestionServer::new(
        tls,
        registry,
        settings,
        trust,
        keys,
        HttpLimits::new(2, deadline).map_err(|_| "limits invalid")?,
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime failed")?
        .block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|_| "listener failed")?;
            let port = listener
                .local_addr()
                .map_err(|_| "listener address failed")?
                .port();
            let (send, receive) = tokio::sync::oneshot::channel();
            let (finish, finished) = tokio::sync::oneshot::channel();
            let reader = std::thread::spawn(move || {
                let mut line = String::new();
                let _ = io::stdin().read_line(&mut line);
                let _ = send.send(());
                line.clear();
                let _ = io::stdin().read_line(&mut line);
                let _ = finish.send(());
            });
            println!("READY {port}");
            let result = server
                .serve(listener, async {
                    let _ = receive.await;
                })
                .await;
            println!("STOPPED");
            // Keep the runtime alive until the parent observes backend/socket cleanup.
            let _ = finished.await;
            reader.join().map_err(|_| "shutdown reader failed")?;
            result.map_err(|_| "HTTPS server failed")
        })
}
