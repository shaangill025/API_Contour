//! Synthetic SQL24 candidate bridge probe. No private-key possession or launch claim.
//! Uses the existing bridge fixture's 23 positional inputs followed by a closed mode.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::{
    CausalBinding, CausalError, CausalIssue, CausalIssuer, CausalMarkerBinder, DatabaseSettings,
    TrustedCa,
};
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    time::Duration,
};

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn read(path: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    File::open(path)
        .map_err(|_| "fixture input")?
        .take(1_048_577)
        .read_to_end(&mut out)
        .map_err(|_| "fixture input")?;
    if out.len() > 1_048_576 {
        return Err("fixture input");
    }
    Ok(out)
}
fn barrier() -> Result<(), &'static str> {
    println!("READY");
    io::stdout().flush().map_err(|_| "fixture control")?;
    let mut bytes = [0; 3];
    io::stdin()
        .read_exact(&mut bytes)
        .map_err(|_| "fixture control")?;
    if &bytes != b"GO\n" {
        return Err("fixture control");
    }
    Ok(())
}
fn run() -> Result<(), String> {
    let a: Vec<String> = env::args().skip(1).collect();
    if a.len() != 24
        || !matches!(
            a[23].as_str(),
            "positive"
                | "legacy"
                | "weak"
                | "wrong_role"
                | "revoked"
                | "expired"
                | "cancel"
                | "issue_unknown"
                | "issue_context_unknown"
                | "issue_retry"
                | "quota"
                | "marker_unknown"
                | "negative_identity"
                | "negative_scope"
                | "negative_expired"
                | "negative_signature"
        )
    {
        return Err("fixture arguments".into());
    }
    let port = a[1].parse().map_err(|_| "fixture port")?;
    let trust = TrustedCa::from_pem(&read(&a[3])?).map_err(|_| "fixture trust")?;
    let grant_key: [u8; 32] = read(&a[6])?.try_into().map_err(|_| "fixture key")?;
    let policy_key: [u8; 32] = read(&a[7])?.try_into().map_err(|_| "fixture key")?;
    let grants = CausalGrantKeys::new(&[("fixture", grant_key)]).map_err(|_| "fixture key")?;
    let policies = PolicyKeys::new(&[("fixture", policy_key)]).map_err(|_| "fixture key")?;
    if a[11].len() != 64 || !a[11].is_ascii() {
        return Err("fixture peer".into());
    }
    let mut peer = [0u8; 32];
    for (i, part) in peer.iter_mut().enumerate() {
        *part = u8::from_str_radix(&a[11][i * 2..i * 2 + 2], 16).map_err(|_| "fixture peer")?;
    }
    let ids = std::array::from_fn(|i| a[12 + i].as_str());
    let issue = CausalIssue::new(
        CausalBinding::new(ids, peer).map_err(|_| "fixture binding")?,
        &a[22],
        Duration::from_secs(if a[23] == "expired" { 3 } else { 60 }),
        &read(&a[8])?,
        &read(&a[9])?,
    )
    .map_err(|_| "fixture issue")?;
    let password = env::var("CONTOUR_CAUSAL_ISSUER_PASSWORD").map_err(|_| "fixture password")?;
    let settings = |user: &str| {
        DatabaseSettings::new(
            &a[0],
            port,
            &a[2],
            user,
            password.as_bytes(),
            Duration::from_secs(10),
        )
        .map_err(|_| "fixture settings")
    };
    let issuer_settings = settings(&a[4])?;
    let binder_settings = settings(&a[5])?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "fixture runtime")?
        .block_on(async {
            let mut issuer = CausalIssuer::new(
                issuer_settings
                    .connect(&trust)
                    .await
                    .map_err(|_| "issuer TLS")?,
            );
            if a[23].starts_with("negative_") {
                let result = issuer.issue(&issue, &peer, &grants, &policies).await;
                let expected = match a[23].as_str() {
                    "negative_identity" => CausalError::Identity,
                    "negative_scope" => CausalError::Scope,
                    "negative_expired" => CausalError::Expired,
                    "negative_signature" => CausalError::Signature,
                    _ => return Err("fixture mode"),
                };
                if !matches!(result, Err(error) if error == expected) {
                    return Err("negative issue mismatch");
                }
                println!("REFUSED");
                return Ok(());
            }
            if a[23] == "issue_context_unknown" {
                let result = issuer.issue(&issue, &peer, &grants, &policies).await;
                match result {
                    Err(CausalError::OutcomeUnknown) => println!("CONTEXT_OUTCOME_UNKNOWN"),
                    Ok(_) => println!("CONTEXT_UNEXPECTED_SUCCESS"),
                    Err(_) => println!("CONTEXT_WRONG_OUTCOME"),
                }
                return Ok(());
            }
            if a[23] == "issue_unknown" {
                let result = issuer
                    .issue_until(
                        &issue,
                        &peer,
                        &grants,
                        &policies,
                        tokio::time::Instant::now() + Duration::from_secs(1),
                    )
                    .await;
                if !matches!(result, Err(CausalError::OutcomeUnknown)) {
                    return Err("issue outcome mismatch");
                }
                println!("OUTCOME_UNKNOWN");
                return Ok(());
            }
            let mut session = issuer
                .issue(&issue, &peer, &grants, &policies)
                .await
                .map_err(|_| "issuer failure")?;
            if a[23] == "issue_retry" {
                if session.wire_profile_503().is_none() {
                    return Err("retry view missing");
                }
                println!("RETRIED");
                return Ok(());
            }
            if a[23] == "legacy" {
                if session.wire_profile_503().is_some() {
                    return Err("legacy candidate view");
                }
                println!("LEGACY");
                return Ok(());
            }
            let generation = [0xa1; 32];
            let claim = issuer
                .claim_generation(&mut session, &generation, &peer, &grants, &policies)
                .await;
            if a[23] == "quota" {
                if !matches!(claim, Err(CausalError::LogicalQuota))
                    || session.wire_profile_503().is_some()
                {
                    return Err("quota mismatch");
                }
                println!("QUOTA");
                return Ok(());
            }
            claim.map_err(|_| "claim failure")?;
            let mut binder = CausalMarkerBinder::new(
                binder_settings
                    .connect(&trust)
                    .await
                    .map_err(|_| "binder TLS")?,
            );
            let leaf = [0x03; 32];
            let credential = "fa000000-0000-4000-8000-000000000003";
            if matches!(a[23].as_str(), "revoked" | "expired") {
                barrier()?;
            }
            let key = if a[23] == "weak" { [0; 32] } else { grant_key };
            if a[23] == "cancel" {
                let timed = tokio::time::timeout(
                    Duration::from_secs(1),
                    binder.bind(
                        &mut session,
                        &generation,
                        credential,
                        &leaf,
                        &key,
                        &peer,
                        &grants,
                        &policies,
                    ),
                )
                .await;
                if timed.is_ok() || !session.verified_remaining().is_zero() {
                    return Err("cancellation mismatch");
                }
                println!("CANCELLED");
                return Ok(());
            }
            if a[23] == "marker_unknown" {
                let result = binder
                    .bind_until(
                        &mut session,
                        &generation,
                        credential,
                        &leaf,
                        &key,
                        &peer,
                        &grants,
                        &policies,
                        tokio::time::Instant::now() + Duration::from_secs(1),
                    )
                    .await;
                if !matches!(result, Err(CausalError::OutcomeUnknown))
                    || session.wire_profile_503().is_some()
                {
                    return Err("marker outcome mismatch");
                }
                // Ambiguous commit is terminal. Only an operator may reconcile it.
                println!("MARKER_OUTCOME_UNKNOWN");
                return Ok(());
            }
            let first = binder
                .bind(
                    &mut session,
                    &generation,
                    credential,
                    &leaf,
                    &key,
                    &peer,
                    &grants,
                    &policies,
                )
                .await;
            if a[23] != "positive" {
                let expected = match a[23].as_str() {
                    "weak" => CausalError::Signature,
                    "wrong_role" => CausalError::Database,
                    "revoked" => CausalError::Scope,
                    "expired" => CausalError::Scope,
                    _ => return Err("fixture mode"),
                };
                if !matches!(first,Err(e) if e==expected) || !session.verified_remaining().is_zero()
                {
                    return Err("negative mismatch");
                }
                println!("REFUSED");
                return Ok(());
            }
            let first = first.map_err(|_| "first bind")?;
            {
                let view = session.wire_profile_503().ok_or("candidate view missing")?;
                if view.tenant_id() != ids[0]
                    || view.runtime_id() != ids[1]
                    || view.nonce() != a[22]
                    || view.epoch() == 0
                    || view.profile_id() != "00000000-0000-4000-8000-000000000503"
                    || view.profile_name() != "nodered_5_0_9_wire_v1"
                    || view.profile_sha256()
                        != "a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e"
                    || view.verified_remaining().is_zero()
                    || view.verified_until() <= tokio::time::Instant::now()
                {
                    return Err("candidate view mismatch");
                }
            }
            let duplicate = binder
                .bind(
                    &mut session,
                    &generation,
                    credential,
                    &leaf,
                    &key,
                    &peer,
                    &grants,
                    &policies,
                )
                .await
                .map_err(|_| "duplicate bind")?;
            if first.bound_at() != duplicate.bound_at()
                || first.public_key() != duplicate.public_key()
                || first.public_key() != key
            {
                return Err("duplicate mismatch");
            }
            let changed = binder
                .bind(
                    &mut session,
                    &generation,
                    credential,
                    &leaf,
                    &policy_key,
                    &peer,
                    &grants,
                    &policies,
                )
                .await;
            if !matches!(changed, Err(CausalError::Conflict))
                || !session.verified_remaining().is_zero()
            {
                return Err("conflict mismatch");
            }
            println!("BOUND {}", first.bound_at().unix_timestamp_nanos() / 1000);
            if session.wire_profile_503().is_some() {
                return Err("invalidated view");
            }
            println!("CONFLICT_INVALIDATED");
            Ok(())
        })
        .map_err(str::to_string)
}
