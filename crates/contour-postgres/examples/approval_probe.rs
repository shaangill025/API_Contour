//! Synthetic restricted-login fixture. Input and output are local fixture data.
use contour_postgres::{
    ApprovalError, ApprovalRequest, DatabaseSettings, DeclaredScope, TransportError, TrustedCa,
};
use serde_json::json;
use std::{
    env, fs,
    future::Future,
    io::{self, Write},
    task::Poll,
    time::Duration,
};
fn main() {
    if run().is_err() {
        eprintln!("approval probe failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 15 {
        return Err("arguments".into());
    }
    let trust = TrustedCa::from_pem(&fs::read(&args[1])?)?;
    let scope = DeclaredScope::new([&args[2], &args[3], &args[4], &args[5]])?;
    let request = ApprovalRequest::new(
        &args[6],
        &args[7],
        &args[8],
        if args[9] == "-" { None } else { Some(&args[9]) },
        &args[10],
    )?;
    let cancel = args[11] == "cancel";
    let budget = Duration::from_millis(args[13].parse()?);
    let settings = DatabaseSettings::new(
        "localhost",
        args[0].parse()?,
        "contour_fixture",
        "contour_approval_writer_tls",
        env::var("CONTOUR_FIXTURE_PASSWORD")?.as_bytes(),
        Duration::from_secs(10),
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut connection = settings.connect(&trust).await?;
            let deadline = tokio::time::Instant::now() + budget;
            let mut future =
                Box::pin(connection.approve_declared_until(&scope, &request, deadline));
            let result = if cancel {
                use tokio::io::AsyncReadExt;
                let mut control =
                    tokio::net::TcpStream::connect(("127.0.0.1", args[14].parse::<u16>()?)).await?;
                let mut marker = [0];
                let mut signal = Box::pin(control.read_exact(&mut marker));
                std::future::poll_fn(|cx| {
                    if future.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(std::io::Error::other("cancel not pending")));
                    }
                    signal.as_mut().poll(cx)
                })
                .await?;
                drop(signal);
                if marker != [b'C'] {
                    return Err("cancel marker".into());
                }
                drop(future);
                Err(ApprovalError::Invalidated)
            } else {
                future.await
            };
            let (outcome, value) = match result {
                Ok(stored) => (
                    format!("{:?}", stored.status()),
                    json!({"id":stored.event_id(),"created":stored.created_micros()}),
                ),
                Err(error) => (error.to_string(), json!(null)),
            };
            if outcome != args[12]
                && !(args[12] == "Either"
                    && matches!(outcome.as_str(), "Approved" | "Duplicate" | "Conflict"))
            {
                println!("{outcome}");
                io::stdout().flush()?;
                return Err("outcome mismatch".into());
            }
            let reusable = connection.health().await.is_ok();
            if matches!(
                outcome.as_str(),
                "Deadline" | "Invalidated" | "OutcomeUnknown"
            ) && (reusable
                || connection.health().await != Err(TransportError::Shutdown)
                || !matches!(
                    connection.approve_declared(&scope, &request).await,
                    Err(ApprovalError::Invalidated)
                ))
            {
                return Err("failed session reused".into());
            }
            if reusable {
                connection.close().await?;
            }
            tokio::task::yield_now().await;
            println!(
                "{}",
                json!({"outcome":outcome,"value":value,"reusable":reusable})
            );
            io::stdout().flush()?;
            if tokio::task::spawn_blocking(|| {
                let mut ack = String::new();
                io::stdin().read_line(&mut ack)
            })
            .await??
                == 0
            {
                return Err("ack missing".into());
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })
}
