//! Synthetic operator-scoped reader fixture, never an HTTP or user auth adapter.
use contour_postgres::{
    CatalogReadError, CatalogReadScope, DatabaseSettings, TransportError, TrustedCa,
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
        eprintln!("catalog reader probe failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 9 {
        return Err("arguments missing".into());
    }
    let trust = TrustedCa::from_pem(&fs::read(&args[1])?)?;
    let scope = CatalogReadScope::new([&args[2], &args[3], &args[4], &args[5]])?;
    let limit = if args[6] == "default" {
        None
    } else {
        Some(args[6].parse::<u16>()?)
    };
    let read_budget = Duration::from_millis(args[8].parse()?);
    // Establish TLS before measuring the deliberately short lock-wait deadline.
    let connection_budget = read_budget.max(Duration::from_secs(10));
    let settings = DatabaseSettings::new(
        "localhost",
        args[0].parse()?,
        "contour_fixture",
        "contour_catalog_reader_tls",
        env::var("CONTOUR_FIXTURE_PASSWORD")?.as_bytes(),
        connection_budget,
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut connection=settings.connect(&trust).await.map_err(|_| {
            eprintln!("reader TLS setup failed");
            "reader TLS setup failed"
        })?;
        let mut pages=Vec::new();
        let mut cursor=None;
        let mut actual="Read".to_owned();
        if args[7]=="Cancel" {
            let mut future=Box::pin(connection.read_catalog_until(&scope,limit,None,tokio::time::Instant::now()+read_budget));
            let until=tokio::time::Instant::now()+Duration::from_millis(600);
            while tokio::time::Instant::now()<until {
                if std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_ready())).await { eprintln!("reader cancel did not remain pending"); return Err("cancel not pending".into()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            drop(future);
            if !matches!(connection.read_catalog(&scope,limit,None).await,Err(CatalogReadError::Invalidated)) { return Err("cancel retained session".into()); }
            actual="Invalidated".to_owned();
        } else {
            for _ in 0..100 {
                match connection.read_catalog_until(&scope,limit,cursor.as_ref(),tokio::time::Instant::now()+read_budget).await {
                    Ok(page)=> {
                        let value:serde_json::Value=serde_json::from_slice(page.json())?;
                        pages.push(json!({"page":value,"bytes":page.json().len(),"more":page.next().is_some()}));
                        if args[7]=="Cursor" {
                            let wrong=CatalogReadScope::new([&args[2],&args[3],"00000000-0000-0000-0000-000000ffffff",&args[5]])?;
                            if !matches!(connection.read_catalog(&wrong,limit,page.next()).await,Err(CatalogReadError::Cursor)) { return Err("cursor scope not rejected".into()); }
                            actual="Cursor".to_owned();break;
                        }
                        cursor=page.next().cloned();
                        if cursor.is_none() { break; }
                    },
                    Err(error)=> { actual=error.to_string();break; }
                }
            }
        }
        let wanted=if args[7]=="Cancel" { "Invalidated" } else { &args[7] };
        if actual!=wanted { println!("{actual}");io::stdout().flush()?;return Err("outcome mismatch".into()); }
        if matches!(actual.as_str(),"Deadline"|"Invalidated") {
            if connection.health().await!=Err(TransportError::Shutdown) { return Err("failed session reused".into()); }
        } else { connection.health().await?;connection.close().await?; }
        tokio::task::yield_now().await;
        println!("{}",json!({"outcome":actual,"pages":pages}));io::stdout().flush()?;
        let acknowledged=tokio::task::spawn_blocking(|| {
            let mut ack=String::new();io::stdin().read_line(&mut ack)
        }).await??;
        if acknowledged==0 { return Err("ack missing".into()); }
        Ok::<(),Box<dyn std::error::Error>>(())
    })
}
