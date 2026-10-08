//! Synthetic local integration probe; never a public SQL or authority interface.
use contour_core::{Batch, PolicyKeys};
use contour_postgres::{AuthorityError, DatabaseSettings, SubmitError, TransportError, TrustedCa};
use std::{
    env, fs,
    future::Future,
    io::{self, Write},
    task::Poll,
    time::Duration,
};
fn main() {
    if let Err(message) = probe() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
fn probe() -> Result<(), &'static str> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 8 {
        return Err("submission fixture arguments missing");
    }
    let trust = TrustedCa::from_pem(&fs::read(&args[1]).map_err(|_| "trust missing")?)
        .map_err(|_| "trust invalid")?;
    let public = fs::read(&args[2])
        .map_err(|_| "signer missing")?
        .try_into()
        .map_err(|_| "signer invalid")?;
    let keys = PolicyKeys::new(&[("fixture", public)]).map_err(|_| "signer invalid")?;
    let batch = Batch::from_wire_json(&fs::read(&args[3]).map_err(|_| "batch missing")?)
        .map_err(|_| "batch invalid")?;
    let expected = [args[5].as_str(), args[6].as_str()];
    let settings = DatabaseSettings::new(
        "localhost",
        args[0].parse().map_err(|_| "port invalid")?,
        "contour_fixture",
        "contour_tls",
        env::var("CONTOUR_FIXTURE_PASSWORD")
            .map_err(|_| "credential missing")?
            .as_bytes(),
        Duration::from_millis(args[7].parse().map_err(|_| "deadline invalid")?),
    )
    .map_err(|_| "settings invalid")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime failed")?
        .block_on(async {
            let mut connection = settings.connect(&trust).await.map_err(|_| "TLS failed")?;
            let result = if args[4] == "Cancel" {
                let mut future = Box::pin(connection.submit_batch(&batch, expected, &keys));
                let until = tokio::time::Instant::now() + Duration::from_millis(600);
                while tokio::time::Instant::now() < until {
                    if std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_ready()))
                        .await
                    {
                        return Err("cancel was not blocked");
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                drop(future);
                connection.submit_batch(&batch, expected, &keys).await
            } else {
                connection.submit_batch(&batch, expected, &keys).await
            };
            let actual = match &result {
                Ok(receipt) => format!(
                    "Accepted {} {}",
                    receipt.id(),
                    receipt.accepted_at().unix_timestamp_nanos()
                ),
                Err(SubmitError::Authority(error)) => error.to_string(),
                Err(error) => error.to_string(),
            };
            let wanted = if args[4] == "Cancel" {
                "Invalidated"
            } else {
                &args[4]
            };
            if !actual.starts_with(wanted) {
                return Err("submission outcome mismatch");
            }
            if matches!(
                result,
                Err(SubmitError::OutcomeUnknown
                    | SubmitError::Authority(
                        AuthorityError::Deadline | AuthorityError::Invalidated
                    ))
            ) {
                if connection.health().await != Err(TransportError::Shutdown) {
                    return Err("uncertain session reused");
                }
            } else {
                connection
                    .health()
                    .await
                    .map_err(|_| "confirmed session not reusable")?;
                connection.close().await.map_err(|_| "close failed")?;
            }
            tokio::task::yield_now().await;
            println!("{actual}");
            io::stdout().flush().map_err(|_| "output failed")?;
            let mut acknowledgement = String::new();
            if io::stdin()
                .read_line(&mut acknowledgement)
                .map_err(|_| "ack failed")?
                == 0
            {
                return Err("ack missing");
            }
            Ok(())
        })
}
