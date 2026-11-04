//! Synthetic integration probe. Never use real business data or credentials.
//! Arguments: host port database ca-pem issuer-user inbox-user grant-public-raw
//! policy-public-raw grant-envelope policy-envelope batch-json leaf-hex, then
//! tenant runtime collector source project service environment deployment
//! instance lifecycle nonce (canonical UUIDs). Both public keys use key id
//! "fixture". The batch's epoch is replaced with the committed issued epoch.
//! Passwords are supplied through CONTOUR_CAUSAL_ISSUER_PASSWORD and
//! CONTOUR_CAUSAL_INBOX_PASSWORD; neither is printed.
use contour_core::{CausalEventBatch, CausalGrantKeys, PolicyKeys};
use contour_postgres::{
    CausalBinding, CausalInbox, CausalIssue, CausalIssuer, DatabaseSettings, TrustedCa,
};
use std::{env, fs::File, io::Read, time::Duration};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let a: Vec<String> = env::args().skip(1).collect();
    if a.len() != 23 {
        return Err("fixture arguments invalid".into());
    }
    let read = |p: &str| {
        let file = File::open(p).map_err(|_| "fixture input unavailable".to_string())?;
        let mut bytes = Vec::new();
        file.take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| "fixture input unavailable".to_string())?;
        if bytes.len() > 1_048_576 {
            return Err("fixture input too large".to_string());
        }
        Ok(bytes)
    };
    let port = a[1].parse().map_err(|_| "fixture port invalid")?;
    let trust = TrustedCa::from_pem(&read(&a[3])?).map_err(|_| "fixture trust invalid")?;
    let grant_public: [u8; 32] = read(&a[6])?
        .try_into()
        .map_err(|_| "fixture grant key invalid")?;
    let policy_public: [u8; 32] = read(&a[7])?
        .try_into()
        .map_err(|_| "fixture policy key invalid")?;
    let grants = CausalGrantKeys::new(&[("fixture", grant_public)])
        .map_err(|_| "fixture grant key invalid")?;
    let policies =
        PolicyKeys::new(&[("fixture", policy_public)]).map_err(|_| "fixture policy key invalid")?;
    if a[11].len() != 64 || !a[11].is_ascii() {
        return Err("fixture peer pin invalid".into());
    }
    let mut peer = [0u8; 32];
    for (i, part) in peer.iter_mut().enumerate() {
        *part = u8::from_str_radix(&a[11][2 * i..2 * i + 2], 16)
            .map_err(|_| "fixture peer pin invalid")?;
    }
    let ids: [&str; 10] = std::array::from_fn(|i| a[12 + i].as_str());
    let binding = CausalBinding::new(ids, peer).map_err(|e| e.to_string())?;
    let issue = CausalIssue::new(
        binding,
        &a[22],
        Duration::from_secs(60),
        &read(&a[8])?,
        &read(&a[9])?,
    )
    .map_err(|e| e.to_string())?;
    let issuer_pass = env::var("CONTOUR_CAUSAL_ISSUER_PASSWORD")
        .map_err(|_| "fixture issuer password missing")?;
    let inbox_pass =
        env::var("CONTOUR_CAUSAL_INBOX_PASSWORD").map_err(|_| "fixture inbox password missing")?;
    let settings = |user: &str, password: &str| {
        DatabaseSettings::new(
            &a[0],
            port,
            &a[2],
            user,
            password.as_bytes(),
            Duration::from_secs(10),
        )
        .map_err(|_| "fixture settings invalid".to_string())
    };
    let issuer_settings = settings(&a[4], &issuer_pass)?;
    let inbox_settings = settings(&a[5], &inbox_pass)?;
    let input = read(&a[10])?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "fixture runtime failed")?
        .block_on(async {
            let connection = issuer_settings
                .connect(&trust)
                .await
                .map_err(|_| "fixture issuer TLS failed")?;
            let mut issuer = CausalIssuer::new(connection);
            let session = issuer
                .issue(&issue, &peer, &grants, &policies)
                .await
                .map_err(|e| e.to_string())?;
            let mut batch: serde_json::Value =
                serde_json::from_slice(&input).map_err(|_| "fixture batch invalid")?;
            if !batch.is_object() {
                return Err("fixture batch invalid".to_string());
            }
            batch["session_epoch"] = serde_json::json!(session.epoch());
            let encoded = serde_json::to_vec(&batch).map_err(|_| "fixture batch invalid")?;
            let canonical = CausalEventBatch::from_wire_json(&encoded)
                .map_err(|_| "fixture batch invalid")?
                .canonical_bytes()
                .map_err(|_| "fixture batch invalid")?;
            let connection = inbox_settings
                .connect(&trust)
                .await
                .map_err(|_| "fixture inbox TLS failed")?;
            let mut inbox = CausalInbox::new(connection);
            let first = inbox
                .accept(&session, &peer, &canonical, &grants, &policies)
                .await
                .map_err(|e| e.to_string())?;
            if first.duplicate() {
                return Err("fixture first receipt duplicate".to_string());
            }
            let retry = inbox
                .accept(&session, &peer, &canonical, &grants, &policies)
                .await
                .map_err(|e| e.to_string())?;
            if !retry.duplicate()
                || retry.id() != first.id()
                || retry.accepted_at() != first.accepted_at()
            {
                return Err("fixture retry mismatch".to_string());
            }
            println!("PASS: causal issue and exact committed batch retry");
            Ok(())
        })
}
