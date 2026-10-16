//! Synthetic restricted-login fixture. Input and output are local fixture data.
use contour_core::DeclaredContract;
use contour_postgres::{
    DatabaseSettings, DeclaredScope, DeclaredStoreError, TransportError, TrustedCa,
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
        eprintln!("declared store probe failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 12 {
        return Err("arguments".into());
    }
    let trust = TrustedCa::from_pem(&fs::read(&args[1])?)?;
    let graph = DeclaredContract::from_wire_json(&fs::read(&args[2])?)?;
    let scope = DeclaredScope::new([&args[3], &args[4], &args[5], &args[6]])?;
    let read = args[8].contains("read");
    let cancel = args[8].starts_with("cancel");
    let budget = Duration::from_millis(args[10].parse()?);
    let settings = DatabaseSettings::new(
        "localhost",
        args[0].parse()?,
        "contour_fixture",
        if read {
            "contour_declared_reader_tls"
        } else {
            "contour_declared_writer_tls"
        },
        env::var("CONTOUR_FIXTURE_PASSWORD")?.as_bytes(),
        Duration::from_secs(10),
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut connection=settings.connect(&trust).await?;
        let deadline=tokio::time::Instant::now()+budget;
        let mut future:std::pin::Pin<Box<dyn Future<Output=_>>>=if read {
            Box::pin(connection.read_declared_until(&scope,&args[7],deadline))
        } else { Box::pin(connection.store_declared_until(&scope,&args[7],&graph,deadline)) };
        let result=if cancel {
            use tokio::io::AsyncReadExt;
            let mut control=tokio::net::TcpStream::connect(("127.0.0.1",args[11].parse::<u16>()?)).await?;
            let mut marker=[0];
            let mut signal=Box::pin(control.read_exact(&mut marker));
            std::future::poll_fn(|cx| {
                if future.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(std::io::Error::other("cancel not pending")));
                }
                signal.as_mut().poll(cx)
            }).await?;
            drop(signal);
            if marker!=[b'C'] { return Err("cancel marker".into()); }
            drop(future);
            Err(DeclaredStoreError::Invalidated)
        } else { future.await };
        let (outcome,value)=match result {
            Ok(stored)=>(format!("{:?}",stored.status()),json!({"id":stored.version_id(),"created":stored.created_micros(),"graph":serde_json::from_slice::<serde_json::Value>(&stored.graph().to_wire_json()?)?})),
            Err(error)=>(error.to_string(),json!(null)),
        };
        if outcome!=args[9] && !(args[9]=="Either" && matches!(outcome.as_str(),"Stored"|"Duplicate")) { println!("{outcome}");io::stdout().flush()?;return Err("outcome mismatch".into()); }
        let reusable=connection.health().await.is_ok();
        if matches!(outcome.as_str(),"Deadline"|"Invalidated"|"OutcomeUnknown")
            && (reusable || connection.health().await!=Err(TransportError::Shutdown)
                || !matches!(connection.read_declared(&scope,&args[7]).await,Err(DeclaredStoreError::Invalidated))) { return Err("failed session reused".into()); }
        if reusable { connection.close().await?; }
        tokio::task::yield_now().await;
        println!("{}",json!({"outcome":outcome,"value":value,"reusable":reusable}));io::stdout().flush()?;
        if tokio::task::spawn_blocking(|| { let mut ack=String::new();io::stdin().read_line(&mut ack) }).await??==0 { return Err("ack missing".into()); }
        Ok::<(),Box<dyn std::error::Error>>(())
    })
}
