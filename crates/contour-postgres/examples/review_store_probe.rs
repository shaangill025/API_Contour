//! Synthetic restricted service login; input/output are local fixture data.
use contour_postgres::{
    DatabaseSettings, DeclaredScope, HumanReviewDecisionRequest, HumanReviewRequest,
    ReviewDecisionRequest, ReviewRequest, ReviewStoreError, TransportError, TrustedCa,
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
        eprintln!("review store probe failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let a = env::args().skip(1).collect::<Vec<_>>();
    if a.len() != 17 {
        return Err("arguments".into());
    }
    let trust = TrustedCa::from_pem(&fs::read(&a[1])?)?;
    let scope = DeclaredScope::new([&a[2], &a[3], &a[4], &a[5]])?;
    let mode = a[13].strip_prefix("cancel-").unwrap_or(&a[13]);
    let cancel = a[13].starts_with("cancel-");
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
        a[0].parse()?,
        "contour_fixture",
        if mode == "read" {
            "contour_review_reader_tls"
        } else {
            "contour_review_writer_tls"
        },
        env::var("CONTOUR_FIXTURE_PASSWORD")?.as_bytes(),
        Duration::from_secs(10),
    )?;
    let expected = if a[10] == "-" {
        None
    } else {
        Some(a[10].as_str())
    };
    let create = ReviewRequest::new(&a[6], &a[7], &a[8], &a[9], expected, &a[11])?;
    let decision = if mode == "approve" {
        ReviewDecisionRequest::approve(&a[6], &a[7], a[12].parse()?, &a[11], &a[8])?
    } else {
        ReviewDecisionRequest::reject(&a[6], &a[7], a[12].parse()?, &a[11])?
    };
    let human_create = HumanReviewRequest::new(&a[6], &a[7], &a[8], &a[9], expected)?;
    let human_decision = if mode == "approve" {
        HumanReviewDecisionRequest::approve(&a[6], &a[7], a[12].parse()?, &a[8])?
    } else {
        HumanReviewDecisionRequest::reject(&a[6], &a[7], a[12].parse()?)?
    };
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
        let mut connection=settings.connect(&trust).await?;let deadline=tokio::time::Instant::now()+Duration::from_millis(a[15].parse()?);
        let mut future:std::pin::Pin<Box<dyn Future<Output=_>>>=if let Some(identity)=identity.as_ref() { match mode {
            "store"=>Box::pin(connection.store_review_as_human_until(identity,&scope,&human_create,deadline)),
            "read"=>Box::pin(connection.read_review_as_human_until(identity,&scope,&a[6],&a[7],deadline)),
            "approve"|"reject"=>Box::pin(connection.decide_review_as_human_until(identity,&scope,&human_decision,deadline)),_=>return Err("mode".into())}
        } else { match mode{
            "store"=>Box::pin(connection.store_review_until(&scope,&create,deadline)),
            "read"=>Box::pin(connection.read_review_until(&scope,&a[6],&a[7],deadline)),
            "approve"|"reject"=>Box::pin(connection.decide_review_until(&scope,&decision,deadline)),_=>return Err("mode".into())}};
        let result=if cancel{
            use tokio::io::AsyncReadExt;
            let mut control=tokio::net::TcpStream::connect(("127.0.0.1",a[16].parse::<u16>()?)).await?;let mut marker=[0];let mut signal=Box::pin(control.read_exact(&mut marker));
            std::future::poll_fn(|cx|{if future.as_mut().poll(cx).is_ready(){return Poll::Ready(Err(std::io::Error::other("cancel not pending")));}signal.as_mut().poll(cx)}).await?;
            drop(signal);if marker!=[b'C']{return Err("marker".into());}drop(future);Err(ReviewStoreError::Invalidated)
        }else{future.await};
        let(outcome,value)=match result{Ok(s)=>(format!("{:?}",s.status()),json!({"id":s.review_id(),"operation":s.operation_id(),"comparison":s.comparison_id(),"candidate":s.candidate_version_id(),"expected":s.expected_event_id(),"creator":s.creator_actor_id(),"created":s.created_micros(),"revision":s.revision(),"status":format!("{:?}",s.review_status()),"actor":s.deciding_actor_id(),"event":s.approval_event_id(),"decided":s.decided_micros()})),Err(e)=>(e.to_string(),json!(null))};
        if outcome!=a[14]&&!(a[14]=="Either"&&matches!(outcome.as_str(),"Stored"|"Decided"|"Duplicate"|"Conflict")){println!("{outcome}");io::stdout().flush()?;return Err("outcome".into());}
        let reusable=connection.health().await.is_ok();
        if matches!(outcome.as_str(),"Deadline"|"Invalidated"|"OutcomeUnknown")&&(reusable||connection.health().await!=Err(TransportError::Shutdown)||!matches!(connection.read_review(&scope,&a[6],&a[7]).await,Err(ReviewStoreError::Invalidated))){return Err("reused".into());}
        if reusable{connection.close().await?;}tokio::task::yield_now().await;
        println!("{}",json!({"outcome":outcome,"value":value,"reusable":reusable}));io::stdout().flush()?;
        if tokio::task::spawn_blocking(||{let mut ack=String::new();io::stdin().read_line(&mut ack)}).await??==0{return Err("ack".into());}
        Ok::<(),Box<dyn std::error::Error>>(())
    })
}
