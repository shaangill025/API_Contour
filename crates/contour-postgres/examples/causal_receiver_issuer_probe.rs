//! Synthetic fixed-profile issuer probe. No peer or deployment authority.
//! Private bounded input goes over stdin; output contains only fixed labels.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::{
    CausalBinding, CausalError, CausalIssue, CausalIssuer, DatabaseSettings, TrustedCa,
};
use serde_json::Value;
use std::{
    io::{self, Read},
    time::Duration,
};
use tokio::time::Instant;

fn hex32(s: &str) -> Result<[u8; 32], ()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    let mut bytes = [0; 32];
    for (dst, part) in bytes.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        *dst =
            u8::from_str_radix(std::str::from_utf8(part).map_err(|_| ())?, 16).map_err(|_| ())?;
    }
    Ok(bytes)
}

fn run() -> Result<(), ()> {
    let mut raw = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
    if raw.is_empty() || raw.len() > 65536 {
        return Err(());
    }
    let input: Value = serde_json::from_slice(&raw).map_err(|_| ())?;
    raw.fill(0);
    let o = input.as_object().ok_or(())?;
    let keys = [
        "ca_pem",
        "epoch",
        "grant",
        "grant_public",
        "ids",
        "mode",
        "nonce",
        "password",
        "peer",
        "policy",
        "policy_public",
        "port",
        "user",
    ];
    if o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)) {
        return Err(());
    }
    let get = |name: &str| o.get(name).and_then(Value::as_str).ok_or(());
    let mode = get("mode")?;
    let user = get("user")?;
    if !matches!(
        mode,
        "positive"
            | "generic"
            | "wrong-profile"
            | "wrong-peer"
            | "wrong-signature"
            | "wrong-scope"
            | "expired"
            | "wrong-role"
            | "deadline"
            | "unknown"
    ) {
        return Err(());
    }
    if (mode == "wrong-role" && user != "causal_provisioner_login")
        || (mode != "wrong-role" && user != "causal_issuer_login")
    {
        return Err(());
    }
    let ids = o.get("ids").and_then(Value::as_array).ok_or(())?;
    if ids.len() != 10 {
        return Err(());
    }
    let ids: Vec<&str> = ids
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
    let settings = DatabaseSettings::new(
        "localhost",
        port,
        "contour_local",
        user,
        get("password")?.as_bytes(),
        Duration::from_secs(10),
    )
    .map_err(|_| ())?;
    let trust = TrustedCa::from_pem(get("ca_pem")?.as_bytes()).map_err(|_| ())?;
    let expected_epoch = get("epoch")?.parse::<u64>().map_err(|_| ())?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?
        .block_on(async {
            let mut issuer = CausalIssuer::new(settings.connect(&trust).await.map_err(|_| ())?);
            if mode == "generic" {
                if !matches!(
                    issuer.issue(&issue, &peer, &grants, &policies).await,
                    Err(CausalError::Identity)
                ) {
                    return Err(());
                }
                return Ok(());
            }
            let selected = if mode == "wrong-peer" {
                [0x7f; 32]
            } else {
                peer
            };
            let deadline = match mode {
                "deadline" => Instant::now(),
                "unknown" => Instant::now() + Duration::from_secs(1),
                _ => Instant::now() + Duration::from_secs(8),
            };
            let result = issuer
                .issue_receiver_504_until(&issue, &selected, &grants, &policies, deadline)
                .await;
            if mode == "positive" {
                let session = result.map_err(|_| ())?;
                let view = session.receiver_profile_504().ok_or(())?;
                if view.tenant_id() != ids[0]
                    || view.runtime_id() != ids[1]
                    || view.nonce() != get("nonce")?
                    || view.epoch() != expected_epoch
                    || view.profile_id() != "00000000-0000-4000-8000-000000000504"
                    || view.profile_name() != "nodered_5_0_9_receiver_v1"
                    || view.profile_sha256()
                        != "af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d"
                    || view.verified_remaining().is_zero()
                {
                    return Err(());
                }
            } else {
                let expected = match mode {
                    "wrong-profile" | "wrong-peer" | "wrong-scope" | "wrong-role" => {
                        CausalError::Identity
                    }
                    "wrong-signature" => CausalError::Signature,
                    "expired" => CausalError::Expired,
                    "deadline" => CausalError::Deadline,
                    "unknown" => CausalError::OutcomeUnknown,
                    _ => return Err(()),
                };
                if !matches!(result,Err(e) if e==expected) {
                    return Err(());
                }
            }
            Ok(())
        })
}
fn main() {
    if run().is_ok() {
        println!("PASS receiver-issuer-probe");
    } else {
        eprintln!("FAIL receiver-issuer-probe");
        std::process::exit(1);
    }
}
