//! Owned synthetic integration server. No production credentials or default binding.
use contour_core::PolicyKeys;
use contour_ingress::{CollectorTls, HttpLimits, IngestionServer, PrincipalRegistry};
use contour_postgres::{DatabaseSettings, TrustedCa};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::{env, fs, io, path::PathBuf, time::Duration};
fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if ![5, 6, 7, 9].contains(&args.len()) {
        return Err("HTTPS fixture arguments missing");
    }
    let directory = PathBuf::from(&args[1]);
    let read = |name: &str| fs::read(directory.join(name)).map_err(|_| "fixture input missing");
    let cert = read("server.crt.der")?;
    let key = read("server.key.der")?;
    let ca = read("ca.crt.der")?;
    let client = read("http-client.crt.der")?;
    let deadline = Duration::from_millis(args[4].parse().map_err(|_| "deadline invalid")?);
    let database_deadline = args.get(5).map_or(Ok(deadline), |value| {
        value
            .parse()
            .map(Duration::from_millis)
            .map_err(|_| "database deadline invalid")
    })?;
    let drop_serving = args.get(6).is_some_and(|value| value == "drop");
    let budget_check = args.get(6).is_some_and(|value| value == "budget");
    let tls = CollectorTls::from_der(&[&cert], &key, &[&ca], deadline)
        .map_err(|_| "TLS configuration invalid")?;
    let pin: [u8; 32] = Sha256::digest(&client).into();
    let other = args
        .get(7)
        .map(|_| read("http-other.crt.der"))
        .transpose()?;
    let mut mappings = vec![(pin, [&args[2][..], &args[3][..]])];
    if let Some(other) = other {
        mappings.push((Sha256::digest(other).into(), [&args[7], &args[8]]));
    }
    let registry = PrincipalRegistry::new(&mappings).map_err(|_| "registry invalid")?;
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
        database_deadline,
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
            let result = if drop_serving {
                let operation = server.serve(listener, std::future::pending::<()>());
                tokio::pin!(operation);
                tokio::pin!(receive);
                std::future::poll_fn(|context| {
                    if let std::task::Poll::Ready(result) = operation.as_mut().poll(context) {
                        return std::task::Poll::Ready(result);
                    }
                    receive.as_mut().poll(context).map(|_| Ok(()))
                })
                .await
            } else {
                server
                    .serve(listener, async {
                        if budget_check {
                            tokio::time::sleep(deadline + Duration::from_secs(3)).await;
                            let capacity = server.database_capacity();
                            assert!(
                                capacity.running == 0
                                    && capacity.quarantined == 2
                                    && !capacity.closed,
                                "pool job exceeded original HTTP budget"
                            );
                            fs::write(directory.join("budget-state"), "0|2")
                                .expect("fixture capacity observation failed");
                        }
                        let _ = receive.await;
                    })
                    .await
            };
            if !server.database_capacity().closed {
                return Err("serving cancellation did not seal capacity");
            }
            let replacement = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|_| "listener failed")?;
            if server.serve(replacement, async {}).await.is_ok() {
                return Err("sealed server restarted");
            }
            println!("STOPPED");
            // Keep the runtime alive until the parent observes backend/socket cleanup.
            let _ = finished.await;
            reader.join().map_err(|_| "shutdown reader failed")?;
            result.map_err(|_| "HTTPS server failed")
        })
}
