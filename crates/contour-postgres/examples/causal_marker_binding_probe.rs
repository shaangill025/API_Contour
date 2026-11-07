//! Synthetic SQL23 bridge probe. No private-key possession or launch claim.
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
            "positive" | "weak" | "wrong_role" | "revoked" | "expired" | "cancel"
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
            let mut session = issuer
                .issue(&issue, &peer, &grants, &policies)
                .await
                .map_err(|_| "issuer failure")?;
            let generation = [0xa1; 32];
            issuer
                .claim_generation(&mut session, &generation, &peer, &grants, &policies)
                .await
                .map_err(|_| "claim failure")?;
            let mut binder = CausalMarkerBinder::new(
                binder_settings
                    .connect(&trust)
                    .await
                    .map_err(|_| "binder TLS")?,
            );
            let leaf = [0x11; 32];
            let credential = "fa000000-0000-4000-8000-000000000001";
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
            println!("CONFLICT_INVALIDATED");
            Ok(())
        })
        .map_err(str::to_string)
}
