//! Dedicated synthetic live-fixture probe; no reusable authorization token.
use contour_core::{Batch, PolicyKeys};
use contour_postgres::{AuthorityError, DatabaseSettings, TransportError, TrustedCa};
use std::{env, fs, future::Future, task::Poll, time::Duration};

fn main() {
    if let Err(message) = probe() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
fn probe() -> Result<(), &'static str> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 8 {
        return Err("authority fixture arguments missing");
    }
    let port = args[0].parse().map_err(|_| "port invalid")?;
    let trust = TrustedCa::from_pem(&fs::read(&args[1]).map_err(|_| "trust missing")?)
        .map_err(|_| "trust invalid")?;
    let public: [u8; 32] = fs::read(&args[2])
        .map_err(|_| "signer missing")?
        .try_into()
        .map_err(|_| "signer invalid")?;
    let keys = PolicyKeys::new(&[("fixture", public)]).map_err(|_| "signer invalid")?;
    let batch = Batch::from_wire_json(&fs::read(&args[3]).map_err(|_| "batch missing")?)
        .map_err(|_| "batch invalid")?;
    let expected = [args[5].as_str(), args[6].as_str()];
    let deadline = Duration::from_millis(args[7].parse().map_err(|_| "deadline invalid")?);
    let password = env::var("CONTOUR_FIXTURE_PASSWORD").map_err(|_| "credential missing")?;
    let settings = DatabaseSettings::new(
        "localhost",
        port,
        "contour_fixture",
        "contour_tls",
        password.as_bytes(),
        deadline,
    )
    .map_err(|_| "settings invalid")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime failed")?
        .block_on(async {
            let mut connection = settings.connect(&trust).await.map_err(|_| "TLS failed")?;
            if args[4] == "HarnessMismatch" {
                use std::io::{self, Write};
                println!("UNEXPECTED");
                io::stdout().flush().map_err(|_| "output failed")?;
                let mut acknowledgement = String::new();
                io::stdin()
                    .read_line(&mut acknowledgement)
                    .map_err(|_| "ack failed")?;
                return Err("unexpected harness acknowledgement");
            }
            let result = if args[4] == "Cancel" {
                let mut future = Box::pin(connection.validate_authority(&batch, expected, &keys));
                let until = tokio::time::Instant::now() + Duration::from_millis(600);
                while tokio::time::Instant::now() < until {
                    let completed =
                        std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_ready()))
                            .await;
                    if completed {
                        return Err("cancellation did not reach blocked transaction");
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                drop(future);
                connection.validate_authority(&batch, expected, &keys).await
            } else {
                connection.validate_authority(&batch, expected, &keys).await
            };
            let actual = match result {
                Ok(()) => "Ok".to_owned(),
                Err(error) => error.to_string(),
            };
            let wanted = if args[4] == "Cancel" {
                "Invalidated"
            } else {
                &args[4]
            };
            if actual != wanted {
                eprintln!("safe result: {actual}");
                return Err("authority outcome mismatch");
            }
            if matches!(
                result,
                Err(AuthorityError::Deadline | AuthorityError::Invalidated)
            ) {
                if connection.health().await != Err(TransportError::Shutdown) {
                    return Err("uncertain session was reused");
                }
            } else {
                connection
                    .health()
                    .await
                    .map_err(|_| "rolled back session not reusable")?;
                connection.close().await.map_err(|_| "close failed")?;
            }
            tokio::task::yield_now().await;
            println!("{actual}");
            use std::io::{self, Write};
            io::stdout().flush().map_err(|_| "probe output failed")?;
            let mut acknowledgement = String::new();
            if io::stdin()
                .read_line(&mut acknowledgement)
                .map_err(|_| "probe acknowledgement failed")?
                == 0
            {
                return Err("probe acknowledgement missing");
            }
            Ok(())
        })
}
