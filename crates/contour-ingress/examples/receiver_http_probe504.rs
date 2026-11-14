//! Private, synthetic HTTP/mTLS and first-connect recovery qualification.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_ingress::{
    HttpLimits, ReceiverBinding504, ReceiverCausalConfig504, ReceiverCausalServer504,
    ReceiverRegistry504,
};
use contour_postgres::{
    CausalBinding, CausalIssue, CausalIssuer, DatabaseSettings, ReceiverEvidenceTls,
    ReceiverFactSelectors, TrustedCa,
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
    time::{Instant, timeout_at},
};
use tokio_rustls::TlsConnector;
fn unhex(s: &str, max: usize) -> Result<Vec<u8>, ()> {
    if s.is_empty()
        || s.len() % 2 != 0
        || s.len() > max * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).map_err(|_| ())?, 16).map_err(|_| ()))
        .collect()
}
fn hex32(s: &str) -> Result<[u8; 32], ()> {
    unhex(s, 32)?.try_into().map_err(|_| ())
}

async fn request(
    addr: std::net::SocketAddr,
    ca: &[u8],
    cert: Option<(&[u8], &[u8])>,
    wire: &[u8],
) -> Result<Vec<u8>, ()> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.to_vec()))
        .map_err(|_| ())?;
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| ())?
            .with_root_certificates(roots);
    let config = match cert {
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(cert.to_vec())],
                PrivateKeyDer::try_from(key.to_vec()).map_err(|_| ())?,
            )
            .map_err(|_| ())?,
        None => builder.with_no_client_auth(),
    };
    let socket = TcpStream::connect(addr).await.map_err(|_| ())?;
    let mut stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").map_err(|_| ())?, socket)
        .await
        .map_err(|_| ())?;
    stream.write_all(wire).await.map_err(|_| ())?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.map_err(|_| ())?;
    if bytes.len() > 8192 {
        return Err(());
    }
    Ok(bytes)
}
fn wire(path: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn status(bytes: &[u8], expected: u16) -> Result<(), ()> {
    if !bytes.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()) {
        return Err(());
    }
    Ok(())
}
fn closed_error(bytes: &[u8], code: &str) -> Result<(), ()> {
    status(bytes, 503)?;
    let split = bytes.windows(4).position(|x| x == b"\r\n\r\n").ok_or(())? + 4;
    let headers = std::str::from_utf8(&bytes[..split])
        .map_err(|_| ())?
        .to_ascii_lowercase();
    if !headers.contains("content-type: application/json\r\n") {
        return Err(());
    }
    let body = &bytes[split..];
    let v: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let obj = v.as_object().ok_or(())?;
    let id = v.get("request_id").and_then(Value::as_str).ok_or(())?;
    if obj.len() != 4
        || v.get("code").and_then(Value::as_str) != Some(code)
        || v.get("message").and_then(Value::as_str) != Some("Request could not be completed")
        || v.get("retryable").and_then(Value::as_bool) != Some(true)
        || id.len() != 36
        || !id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        || serde_json::to_vec(&v).map_err(|_| ())? != body
    {
        return Err(());
    }
    Ok(())
}
fn run() -> Result<([u8; 32], [u8; 32]), ()> {
    let mut raw = Vec::new();
    io::stdin()
        .lock()
        .take(262145)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
    if raw.is_empty() || raw.len() > 262144 {
        return Err(());
    }
    let input: Value = serde_json::from_slice(&raw).map_err(|_| ())?;
    raw.fill(0);
    let o = input.as_object().ok_or(())?;
    let get = |name: &str| o.get(name).and_then(Value::as_str).ok_or(());
    let ids: Vec<&str> = o
        .get("ids")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .map(|v| v.as_str().ok_or(()))
        .collect::<Result<_, _>>()?;
    let ids: [&str; 10] = ids.try_into().map_err(|_| ())?;
    let peer = hex32(get("peer")?)?;
    let grant = serde_json::to_vec(o.get("grant").ok_or(())?).map_err(|_| ())?;
    let policy = serde_json::to_vec(o.get("policy").ok_or(())?).map_err(|_| ())?;
    let issue = CausalIssue::new(
        CausalBinding::new(ids, peer).map_err(|_| ())?,
        get("nonce")?,
        Duration::from_secs(60),
        &grant,
        &policy,
    )
    .map_err(|_| ())?;
    let grants =
        CausalGrantKeys::new(&[("fixture", hex32(get("grant_public")?)?)]).map_err(|_| ())?;
    let policies =
        PolicyKeys::new(&[("fixture", hex32(get("policy_public")?)?)]).map_err(|_| ())?;
    let port = get("port")?.parse::<u16>().map_err(|_| ())?;
    let dbca = get("ca_pem")?.as_bytes();
    let cert = |name: &str| unhex(get(name)?, 16384);
    let ca = cert("client_ca_der")?;
    let server = cert("server_cert_der")?;
    let server_key = cert("server_key_der")?;
    let evidence = cert("client_cert_der")?;
    let evidence_key = cert("client_key_der")?;
    let export = cert("export_cert_der")?;
    let export_key = cert("export_key_der")?;
    let other = cert("other_cert_der")?;
    let other_key = cert("other_key_der")?;
    let untrusted = cert("untrusted_cert_der")?;
    let untrusted_key = cert("untrusted_key_der")?;
    if <[u8; 32]>::from(Sha256::digest(&export)) != peer {
        return Err(());
    }
    let evidence_pin: [u8; 32] = Sha256::digest(&evidence).into();
    if evidence_pin == peer {
        return Err(());
    }
    let fact = get("fact")?.as_bytes().to_vec();
    let batch = get("batch")?.as_bytes().to_vec();
    let selectors =
        ReceiverFactSelectors::new(get("generation")?, get("credential")?).map_err(|_| ())?;
    let settings = |port, user: &str, password: &str| {
        DatabaseSettings::new(
            "localhost",
            port,
            "contour_local",
            user,
            password.as_bytes(),
            Duration::from_secs(5),
        )
        .map_err(|_| ())
    };
    let trust = || TrustedCa::from_pem(dbca).map_err(|_| ());
    tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| ())?.block_on(async {
        let until=Instant::now()+Duration::from_secs(25);
        timeout_at(until, async {
            let mut issuer=CausalIssuer::new(settings(port,"causal_issuer_login",get("issuer_password")?)?.connect(&trust()?).await.map_err(|_| ())?);
            let session=issuer.issue_receiver_504_until(&issue,&peer,&grants,&policies,until).await.map_err(|_| ())?;
            let view=session.receiver_profile_504().ok_or(())?; if view.epoch()!=1 || view.nonce()!=get("nonce")? { return Err(()); }
            drop(issuer);
            let proxy=TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?; let proxy_port=proxy.local_addr().map_err(|_| ())?.port();
            let forward=Arc::new(AtomicBool::new(false)); let drops=Arc::new(AtomicUsize::new(0)); let arrivals=Arc::new(AtomicUsize::new(0)); let forwarded=Arc::new(AtomicUsize::new(0)); let f=forward.clone(); let d=drops.clone(); let a=arrivals.clone(); let connected=forwarded.clone();
            let proxy_task=tokio::spawn(async move { let mut tasks=JoinSet::new(); loop {
                let Ok((mut incoming,peer))=proxy.accept().await else { break };
                while tasks.try_join_next().is_some() {}
                if !peer.ip().is_loopback() { continue; }
                a.fetch_add(1,Ordering::SeqCst);
                if !f.load(Ordering::SeqCst) { d.fetch_add(1,Ordering::SeqCst); drop(incoming); continue; }
                if tasks.len()>=2 { drop(incoming); continue; }
                let connected=connected.clone();
                tasks.spawn(async move { if let Ok(mut remote)=TcpStream::connect(("127.0.0.1",port)).await { connected.fetch_add(1,Ordering::SeqCst); let _=tokio::io::copy_bidirectional(&mut incoming,&mut remote).await; } });
            } });
            let registry=ReceiverRegistry504::new(vec![ReceiverBinding504 { session,export_pin:peer,evidence_pin,selectors }]).map_err(|_| ())?;
            let tls=ReceiverEvidenceTls::from_der(&[&server],&server_key,&[&ca],Duration::from_secs(5)).map_err(|_| ())?;
            let server=ReceiverCausalServer504::new(ReceiverCausalConfig504 { tls, registry, event_database: settings(port,"causal_event_writer_login",get("event_password")?)?, event_trust: trust()?, fact_database: settings(proxy_port,"causal_receiver_writer_login",get("writer_password")?)?, fact_trust: trust()?, grant_keys: grants, policy_keys: policies, limits: HttpLimits::new(8,Duration::from_secs(5)).map_err(|_| ())?.with_database_sessions(2).map_err(|_| ())?, event_slots: 1 }).map_err(|_| ())?;
            let listener=TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?; let addr=listener.local_addr().map_err(|_| ())?; let (stop,shutdown)=oneshot::channel::<()>();
            let server_task=tokio::spawn(async move { server.serve(listener,async { let _=shutdown.await; }).await });
            let result=async {
                let event=wire("/v1/causal-events",&batch); let fact_wire=wire("/v1/causal-evidence/receiver",&fact);
                let event_response=request(addr,&ca,Some((&export,&export_key)),&event).await?; status(&event_response,200)?;
                let split=event_response.windows(4).position(|x|x==b"\r\n\r\n").ok_or(())?+4;
                let event_body=&event_response[split..];
                let event_receipt: Value=serde_json::from_slice(event_body).map_err(|_| ())?;
                if event_receipt.as_object().is_none_or(|o| o.len()!=7) || serde_json::to_vec(&event_receipt).map_err(|_| ())? != event_body { return Err(()); }
                let event_receipt_digest: [u8;32]=Sha256::digest(event_body).into();
                let event_batch: Value=serde_json::from_slice(&batch).map_err(|_| ())?;
                let event_digest: String=Sha256::digest([b"apicontour/causal-events/1\n".as_slice(),&batch].concat()).iter().map(|b|format!("{b:02x}")).collect();
                if event_receipt.get("batch_id")!=event_batch.get("batch_id") || event_receipt.get("batch_digest").and_then(Value::as_str)!=Some(event_digest.as_str()) || event_receipt.get("status").and_then(Value::as_str)!=Some("duplicate") || event_receipt.get("receipt_id").and_then(Value::as_str).is_none() { return Err(()); }
                status(&request(addr,&ca,Some((&evidence,&evidence_key)),&event).await?,403)?;
                status(&request(addr,&ca,Some((&export,&export_key)),&fact_wire).await?,403)?;
                status(&request(addr,&ca,Some((&other,&other_key)),&fact_wire).await?,403)?;
                if request(addr,&ca,None,&fact_wire).await.is_ok() { return Err(()); }
                if request(addr,&ca,Some((&untrusted,&untrusted_key)),&fact_wire).await.is_ok() { return Err(()); }
                let framed=b"POST /v1/causal-evidence/receiver HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTrailer: x-extra\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                status(&request(addr,&ca,Some((&evidence,&evidence_key)),framed).await?,415)?;
                let oversize=wire("/v1/causal-evidence/receiver",&vec![b'x';4097]); status(&request(addr,&ca,Some((&evidence,&evidence_key)),&oversize).await?,413)?;
                let first=request(addr,&ca,Some((&evidence,&evidence_key)),&fact_wire).await?; closed_error(&first,"database_unavailable")?; if drops.load(Ordering::SeqCst)!=1 || arrivals.load(Ordering::SeqCst)!=1 || forwarded.load(Ordering::SeqCst)!=0 { return Err(()); }
                forward.store(true,Ordering::SeqCst);
                let second=request(addr,&ca,Some((&evidence,&evidence_key)),&fact_wire).await?;
                if status(&second,200).is_err() {
                    closed_error(&second,"database_capacity_unavailable")?;
                    if arrivals.load(Ordering::SeqCst)!=1 || drops.load(Ordering::SeqCst)!=1 || forwarded.load(Ordering::SeqCst)!=0 { return Err(()); }
                    eprintln!("RED receiver-http-pool-recovery {}",event_receipt_digest.iter().map(|b|format!("{b:02x}")).collect::<String>());
                    return Err(());
                }
                if arrivals.load(Ordering::SeqCst)!=2 || drops.load(Ordering::SeqCst)!=1 || forwarded.load(Ordering::SeqCst)!=1 { return Err(()); }
                let headers=std::str::from_utf8(&second).map_err(|_| ())?.to_ascii_lowercase();
                if !headers.contains("content-type: application/json\r\n") { return Err(()); }
                let split=second.windows(4).position(|x|x==b"\r\n\r\n").ok_or(())?+4; let body=&second[split..]; let receipt: Value=serde_json::from_slice(body).map_err(|_| ())?;
                let digest: String=Sha256::digest([b"apicontour/causal-evidence/receiver/1\n".as_slice(),&fact].concat()).iter().map(|b|format!("{b:02x}")).collect();
                if receipt.get("fact_digest").and_then(Value::as_str)!=Some(digest.as_str()) || receipt.get("status").and_then(Value::as_str)!=Some("stored") || serde_json::to_vec(&receipt).map_err(|_| ())? != body { return Err(()); }
                Ok::<([u8;32],[u8;32]),()>((Sha256::digest(body).into(),event_receipt_digest))
            }.await;
            let _=stop.send(()); let _=server_task.await; proxy_task.abort(); let _=proxy_task.await; result
        }).await.map_err(|_| ())?
    })
}
fn main() {
    match run() {
        Ok((fact, event)) => println!(
            "PASS receiver-http-probe {} {}",
            fact.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            event.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
        Err(()) => {
            eprintln!("FAIL receiver-http-probe");
            std::process::exit(1);
        }
    }
}
