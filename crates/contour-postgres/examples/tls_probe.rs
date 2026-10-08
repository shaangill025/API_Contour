//! Dedicated live-fixture probe, mandatory through test-postgres-tls.py.
use contour_postgres::{DatabaseSettings, TransportError, TrustedCa};
use std::{
    env, fs, io,
    time::{Duration, Instant},
};

fn main() {
    if let Err(message) = probe() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
fn probe() -> Result<(), &'static str> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("fixture arguments missing");
    }
    let port = args[1].parse().map_err(|_| "fixture port invalid")?;
    let trust = TrustedCa::from_pem(&fs::read(&args[2]).map_err(|_| "fixture CA missing")?)
        .map_err(|_| "fixture CA invalid")?;
    let password = env::var("CONTOUR_FIXTURE_PASSWORD").map_err(|_| "fixture password missing")?;
    let deadline = Duration::from_millis(args[3].parse().map_err(|_| "fixture deadline invalid")?);
    let settings = DatabaseSettings::new(
        &args[0],
        port,
        "contour_fixture",
        "contour_tls",
        password.as_bytes(),
        deadline,
    )
    .map_err(|_| "fixture settings invalid")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime unavailable")?;
    runtime.block_on(async {
        let started = Instant::now();
        let connected = if args[4] == "SingleConnection" {
            settings
                .connect_single_until(&trust, tokio::time::Instant::now() + deadline)
                .await
        } else {
            settings.connect(&trust).await
        };
        match args[4].as_str() {
            "success" | "drop" => {
                let connected = connected.map_err(|_| "trusted TLS connection failed")?;
                connected
                    .health()
                    .await
                    .map_err(|_| "PostgreSQL TLS health failed")?;
                if args[4] == "success" {
                    connected.close().await.map_err(|_| "driver close failed")?;
                } else {
                    drop(connected);
                    tokio::task::yield_now().await;
                }
                println!("TLS_CONNECTED");
                io::Write::flush(&mut io::stdout()).map_err(|_| "fixture output failed")?;
                // Keep the runtime alive until the parent observes backend cleanup.
                let mut acknowledgement = String::new();
                if io::stdin()
                    .read_line(&mut acknowledgement)
                    .map_err(|_| "fixture acknowledgement failed")?
                    == 0
                {
                    return Err("fixture acknowledgement missing");
                }
            }
            "HealthDeadline" => {
                let connected = connected.map_err(|_| "synthetic authenticated TLS failed")?;
                if connected.health().await != Err(TransportError::Deadline) {
                    return Err("unexpected health timeout result");
                }
                drop(connected);
                tokio::task::yield_now().await;
                println!("Deadline");
            }
            "Connection" | "SingleConnection" | "Deadline" => {
                let expected = if args[4] == "Deadline" {
                    TransportError::Deadline
                } else {
                    TransportError::Connection
                };
                match connected {
                    Err(actual) if actual == expected => (),
                    _ => return Err("unexpected transport result"),
                }
                if started.elapsed() > deadline + Duration::from_secs(2) {
                    return Err("connection exceeded fixture budget");
                }
                println!("{expected}");
            }
            _ => return Err("unknown fixture scenario"),
        }
        Ok(())
    })?;
    // Flush fixed output only; never render native errors, paths or passwords.
    io::Write::flush(&mut io::stdout()).map_err(|_| "fixture output failed")
}
