//! Synthetic, in-process Business handler fixture; not HTTP or session evidence.
use bytes::Bytes;
use contour_auth::IdTokenVerifier;
use contour_platform::business::Business;
use http_body_util::BodyExt;
use hyper::Request;
use std::{
    env, fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() {
    if run().is_err() {
        // Fixture errors never print token, configuration, credentials or response bodies.
        eprintln!("human origin business probe failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("arguments".into());
    }
    let verifier = IdTokenVerifier::new(
        "https://idp.example.test/realms/demo",
        "apicontour",
        include_bytes!("../../contour-auth/tests/fixtures/public-jwks.json"),
    )?;
    let identity = verifier.verify(
        &fs::read_to_string(env::var("CONTOUR_FIXTURE_ID_TOKEN")?)?,
        "server-generated-one-use-nonce",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let business = Business::from_file(Path::new(&args[0]))?;
    let request = Request::builder()
        .method("GET")
        .uri(&args[1])
        .body(Bytes::new())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let response = business.handle(request, identity).await;
        let status = response.status().as_u16();
        if response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
        {
            return Err("content type".into());
        }
        let bytes = response.into_body().collect().await?.to_bytes();
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("response too large".into());
        }
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        println!("{}", serde_json::json!({"status":status,"body":body}));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
