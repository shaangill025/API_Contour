//! Synthetic local integration probe; never a public SQL or authority interface.
use contour_postgres::{CatalogError, DatabaseSettings, TransportError, TrustedCa};
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
    if args.len() != 7 {
        return Err("catalog fixture arguments missing");
    }
    let trust = TrustedCa::from_pem(&fs::read(&args[1]).map_err(|_| "trust missing")?)
        .map_err(|_| "trust invalid")?;
    let expected = [args[4].as_str(), args[5].as_str()];
    let settings = DatabaseSettings::new(
        "localhost",
        args[0].parse().map_err(|_| "port invalid")?,
        "contour_fixture",
        "contour_catalog_tls",
        env::var("CONTOUR_FIXTURE_PASSWORD")
            .map_err(|_| "credential missing")?
            .as_bytes(),
        Duration::from_millis(args[6].parse().map_err(|_| "deadline invalid")?),
    )
    .map_err(|_| "settings invalid")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime failed")?
        .block_on(async {
            let mut connection = settings.connect(&trust).await.map_err(|_| "TLS failed")?;
            let result = if args[3] == "Cancel" {
                let mut future = Box::pin(connection.process_catalog_batch(expected, &args[2]));
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
                connection.process_catalog_batch(expected, &args[2]).await
            } else {
                connection.process_catalog_batch(expected, &args[2]).await
            };
            let actual = match &result {
                Ok(status) => format!("{status:?}"),
                Err(error) => error.to_string(),
            };
            let wanted = if args[3] == "Cancel" {
                "Invalidated"
            } else if args[3] == "ProcessedInvalidated" {
                "Processed"
            } else {
                &args[3]
            };
            if actual != wanted
                && !(wanted == "Either"
                    && matches!(actual.as_str(), "Processed" | "AlreadyProcessed"))
            {
                return Err("catalog outcome mismatch");
            }
            if args[3] == "ProcessedInvalidated"
                || matches!(
                    result,
                    Err(CatalogError::OutcomeUnknown
                        | CatalogError::Deadline
                        | CatalogError::Invalidated)
                )
            {
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
