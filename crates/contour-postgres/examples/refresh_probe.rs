//! Owned synthetic read probe; static output only, no public online grant.
use contour_core::PolicyKeys;
use contour_postgres::{
    AuthorityError, AuthorityReadRequest, DatabaseSettings, TransportError, TrustedCa,
};
use std::{
    env, fs,
    future::Future,
    io::{self, Write},
    path::PathBuf,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;

fn main() {
    if let Err(message) = probe() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
fn probe() -> Result<(), &'static str> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 9 {
        return Err("refresh arguments missing");
    }
    let path = PathBuf::from(&args[3]);
    if fs::metadata(&path).map_err(|_| "request missing")?.len() > 20_000 {
        return Err("fixture request too large");
    }
    let text = fs::read_to_string(&path).map_err(|_| "request missing")?;
    let sources = text.lines().collect::<Vec<_>>();
    let request = match AuthorityReadRequest::new([&args[5], &args[6]], &sources) {
        Ok(request) => request,
        Err(error) => {
            if error.to_string() != args[4] {
                return Err("preflight result mismatch");
            }
            println!("{error}");
            return Ok(()); // No database settings, runtime or connection created.
        }
    };
    let configured = Duration::from_millis(args[7].parse().map_err(|_| "budget invalid")?);
    let budget = Duration::from_millis(args[8].parse().map_err(|_| "budget invalid")?);
    let trust = TrustedCa::from_pem(&fs::read(&args[1]).map_err(|_| "trust missing")?)
        .map_err(|_| "trust invalid")?;
    let public = fs::read(&args[2])
        .map_err(|_| "key missing")?
        .try_into()
        .map_err(|_| "key invalid")?;
    let keys = PolicyKeys::new(&[("fixture", public)]).map_err(|_| "key invalid")?;
    let settings = DatabaseSettings::new(
        "localhost",
        args[0].parse().map_err(|_| "port invalid")?,
        "contour_fixture",
        "contour_tls",
        env::var("CONTOUR_FIXTURE_PASSWORD")
            .map_err(|_| "credential missing")?
            .as_bytes(),
        configured,
    )
    .map_err(|_| "settings invalid")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime failed")?
        .block_on(async {
            let mut connection = settings
                .connect_single_until(&trust, Instant::now() + configured)
                .await
                .map_err(|_| "TLS failed")?;
            if connection.is_reusable() {
                return Err("fresh connection is not a clean transaction proof");
            }
            let started = Instant::now();
            let deadline = started + budget;
            let result = if args[4] == "Cancel" {
                let mut future =
                    Box::pin(connection.read_authority_until(&request, &keys, deadline));
                let cancel = Instant::now() + Duration::from_millis(600);
                while Instant::now() < cancel {
                    if std::future::poll_fn(|context| {
                        Poll::Ready(future.as_mut().poll(context).is_ready())
                    })
                    .await
                    {
                        return Err("cancel read did not reach held lock");
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                drop(future);
                connection.read_authority(&request, &keys).await
            } else {
                connection
                    .read_authority_until(&request, &keys, deadline)
                    .await
            };
            let actual = match &result {
                Ok(_) => "Ok".to_owned(),
                Err(error) => error.to_string(),
            };
            let wanted = if args[4] == "Cancel" {
                "Invalidated"
            } else {
                &args[4]
            };
            if actual != wanted {
                eprintln!("safe result: {actual}");
                return Err("refresh result mismatch");
            }
            if started.elapsed() > budget + Duration::from_secs(2) {
                return Err("read extended original deadline");
            }
            if let Ok(read) = &result {
                if read.identity() != request.identity()
                    || read.sources().len() != request.source_ids().len()
                    || read
                        .policy()
                        .validate_capture_at(read.checked_at())
                        .is_err()
                {
                    return Err("sealed result inconsistent");
                }
                let mut output = format!(
                    "{}|{}|{}|{}\n",
                    read.policy().revision(),
                    read.checked_at().unix_timestamp_nanos() / 1000,
                    read.identity()[0],
                    read.identity()[1]
                );
                for source in read.sources() {
                    let _checked_syntax = source.assignment();
                    output.push_str(&format!(
                        "{}|{}|{}|{}\n",
                        source.source_id(),
                        source.identity().join("|"),
                        source.technique(),
                        source.parser_profiles().join(",")
                    ));
                }
                fs::write(path.with_extension("envelope"), read.signed_envelope())
                    .map_err(|_| "artifact write failed")?;
                fs::write(path.with_extension("result"), output)
                    .map_err(|_| "artifact write failed")?;
            }
            if matches!(
                result,
                Err(AuthorityError::Deadline | AuthorityError::Invalidated)
            ) {
                if connection.is_reusable()
                    || connection.health().await != Err(TransportError::Shutdown)
                {
                    return Err("uncertain session reusable");
                }
            } else {
                if !connection.is_reusable() {
                    return Err("clean rollback not confirmed");
                }
                connection
                    .health()
                    .await
                    .map_err(|_| "clean session unhealthy")?;
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
