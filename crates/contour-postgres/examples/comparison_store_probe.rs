//! Synthetic restricted-login fixture. Input and output are local fixture data.
use contour_postgres::{
    ComparisonInput, ComparisonRequest, ComparisonStoreError, DatabaseSettings, DeclaredScope,
    TransportError, TrustedCa,
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
        eprintln!("comparison store probe failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 16 {
        return Err("arguments".into());
    }
    let trust = TrustedCa::from_pem(&fs::read(&args[1])?)?;
    let scope = DeclaredScope::new([&args[2], &args[3], &args[4], &args[5]])?;
    let read = args[12].contains("read");
    let cancel = args[12].starts_with("cancel");
    let budget = Duration::from_millis(args[14].parse()?);
    let identity = if let Ok(path) = env::var("CONTOUR_FIXTURE_ID_TOKEN") {
        let verifier = contour_auth::IdTokenVerifier::new(
            "https://idp.example.test/realms/demo",
            "apicontour",
            include_bytes!("../../contour-auth/tests/fixtures/public-jwks.json"),
        )?;
        Some(
            verifier.verify(
                &fs::read_to_string(path)?,
                "server-generated-one-use-nonce",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            )?,
        )
    } else {
        None
    };
    let settings = DatabaseSettings::new(
        "localhost",
        args[0].parse()?,
        "contour_fixture",
        if read {
            "contour_comparison_reader_tls"
        } else {
            "contour_comparison_writer_tls"
        },
        env::var("CONTOUR_FIXTURE_PASSWORD")?.as_bytes(),
        Duration::from_secs(10),
    )?;
    let input = |kind: &str, id: &str| match kind {
        "declared" => ComparisonInput::declared(id),
        "approved" => ComparisonInput::approved(id),
        _ => Err(ComparisonStoreError::Scope),
    };
    let request = ComparisonRequest::new(
        &args[6],
        &args[7],
        input(&args[8], &args[9])?,
        input(&args[10], &args[11])?,
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut connection=settings.connect(&trust).await?;
        let deadline=tokio::time::Instant::now()+budget;
        let mut future:std::pin::Pin<Box<dyn Future<Output=_>>>=if let Some(identity)=identity.as_ref() {
            if read { Box::pin(connection.read_comparison_as_human_until(identity,&scope,&args[6],&args[7],deadline)) }
            else { Box::pin(connection.store_comparison_as_human_until(identity,&scope,&request,deadline)) }
        } else if read {
            Box::pin(connection.read_comparison_until(&scope,&args[6],&args[7],deadline))
        } else { Box::pin(connection.store_comparison_until(&scope,&request,deadline)) };
        let result=if cancel {
            use tokio::io::AsyncReadExt;
            let mut control=tokio::net::TcpStream::connect(("127.0.0.1",args[15].parse::<u16>()?)).await?;
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
            Err(ComparisonStoreError::Invalidated)
        } else { future.await };
        let (outcome,value)=match result {
            Ok(stored)=>(format!("{:?}",stored.status()),json!({"id":stored.comparison_id(),"created":stored.created_micros(),"inputs":stored.inputs().each_ref().map(|i|[i.kind(),i.id()]),"versions":stored.versions(),"result":serde_json::from_slice::<serde_json::Value>(&stored.result().to_wire_json()?)?})),
            Err(error)=>(error.to_string(),json!(null)),
        };
        if outcome!=args[13] && !(args[13]=="Either" && matches!(outcome.as_str(),"Stored"|"Duplicate"|"Conflict")) { println!("{outcome}");io::stdout().flush()?;return Err("outcome mismatch".into()); }
        let reusable=connection.health().await.is_ok();
        if matches!(outcome.as_str(),"Deadline"|"Invalidated"|"OutcomeUnknown")
            && (reusable || connection.health().await!=Err(TransportError::Shutdown)
                || !matches!(connection.read_comparison(&scope,&args[6],&args[7]).await,Err(ComparisonStoreError::Invalidated))) { return Err("failed session reused".into()); }
        if reusable { connection.close().await?; }
        tokio::task::yield_now().await;
        println!("{}",json!({"outcome":outcome,"value":value,"reusable":reusable}));io::stdout().flush()?;
        if tokio::task::spawn_blocking(|| { let mut ack=String::new();io::stdin().read_line(&mut ack) }).await??==0 { return Err("ack missing".into()); }
        Ok::<(),Box<dyn std::error::Error>>(())
    })
}
