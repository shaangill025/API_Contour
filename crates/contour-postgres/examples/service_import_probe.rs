//! Local synthetic whole-service import integration probe.
use contour_core::{ServiceImportPolicy, import_service_declared};
use contour_postgres::{DatabaseSettings, ServiceImportError, ServiceImportScope, TrustedCa};
use serde_json::json;
use std::{
    env, fs,
    io::{self, Write},
    time::Duration,
};
fn main() {
    if run().is_err() {
        eprintln!("service import probe failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 12 {
        return Err("arguments".into());
    }
    let trust = TrustedCa::from_pem(&fs::read(&args[1])?)?;
    let scope = ServiceImportScope::new([&args[3], &args[4], &args[5]])?;
    let policy = ServiceImportPolicy::new(
        [&args[3], &args[4], &args[5], &args[6]],
        &[("/source", "/orders")],
        &["id"],
        &["application/json", "text/plain"],
    )?;
    let bundle = import_service_declared("openapi_json", &fs::read(&args[2])?, &policy)?;
    // Optional synthetic ID token enables the human path in the owned TLS fixture.
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
        if identity.is_some() && args[8].contains("read") {
            "contour_human_reader_tls"
        } else if identity.is_some() {
            "contour_human_writer_tls"
        } else if args[8].contains("read") {
            "contour_declared_reader_tls"
        } else {
            "contour_declared_writer_tls"
        },
        env::var("CONTOUR_FIXTURE_PASSWORD")?.as_bytes(),
        Duration::from_secs(10),
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut connection=settings.connect(&trust).await?;
        let deadline=tokio::time::Instant::now()+Duration::from_millis(args[9].parse()?);
        let (outcome,value)=if args[8]=="resolve" {
            match if let Some(identity)=identity.as_ref() {connection.resolve_import_default_as_human_until(identity,&scope,deadline).await} else {connection.resolve_import_default_until(&scope,deadline).await} {
                Ok(scope)=>("Resolved".to_owned(),json!(scope)),Err(e)=>(e.to_string(),json!(null))
            }
        } else {
            let mut future:std::pin::Pin<Box<dyn std::future::Future<Output=_>>>=if let Some(identity)=identity.as_ref() {
                if args[8].contains("read") {
                    Box::pin(connection.read_service_import_as_human_until(identity,&scope,&args[7],deadline))
                } else {Box::pin(connection.store_service_import_as_human_until(identity,&scope,&args[7],&bundle,deadline))}
            } else if args[8].contains("read") {
                Box::pin(connection.read_service_import_until(&scope,&args[7],deadline))
            } else {Box::pin(connection.store_service_import_until(&scope,&args[7],&bundle,deadline))};
            let result=if args[8].starts_with("cancel") {
                use tokio::io::AsyncReadExt;
                let mut control=tokio::net::TcpStream::connect(("127.0.0.1",args[11].parse::<u16>()?)).await?;
                let mut marker=[0];
                let mut signal=Box::pin(control.read_exact(&mut marker));
                std::future::poll_fn(|cx| {
                    if future.as_mut().poll(cx).is_ready() {
                        return std::task::Poll::Ready(Err(std::io::Error::other("cancel not pending")));
                    }
                    signal.as_mut().poll(cx)
                }).await?;
                drop(signal);
                if marker!=[b'C'] {return Err("cancel marker".into());}
                drop(future);
                Err(ServiceImportError::Invalidated)
            } else {future.await};
            match result {
                Ok(stored)=>{
                    let mut members=Vec::new();
                    for member in stored.members() {
                        members.push(json!({"version":member.declared().version_id(),"selector":format!("{:?}",member.selector()),
                            "media":member.media_type(),"graph":serde_json::from_slice::<serde_json::Value>(&member.declared().graph().to_wire_json()?)?}));
                    }
                    (format!("{:?}",stored.status()),json!({"id":stored.contract_id(),"scope":stored.scope(),
                        "revision":stored.revision(),"created":stored.created_micros(),"warnings":format!("{:?}",stored.warnings()),"members":members}))
                },Err(e)=>(e.to_string(),json!(null))
            }
        };
        if outcome!=args[10] && !(args[10]=="Either" && matches!(outcome.as_str(),"Stored"|"Duplicate")) {
            println!("{outcome}");io::stdout().flush()?;return Err("unexpected outcome".into());
        }
        let reusable=connection.health().await.is_ok();
        if reusable {connection.close().await?;}
        tokio::task::yield_now().await;
        println!("{}",json!({"outcome":outcome,"value":value,"reusable":reusable}));io::stdout().flush()?;
        if tokio::task::spawn_blocking(||{let mut ack=String::new();io::stdin().read_line(&mut ack)}).await??==0 {return Err("ack missing".into());}
        Ok::<(),Box<dyn std::error::Error>>(())
    })
}
