//! Synthetic journal recovery fixture; never use real inputs or credentials.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_ingress::{CausalIssueOwner, CausalJournalError};
use contour_postgres::{
    CausalBinding, CausalError, CausalIssue, CausalIssuer, DatabaseSettings, TrustedCa,
};
use std::{
    env,
    fs::File,
    io::{self, BufRead, Read, Write},
    path::Path,
    time::Duration,
};

fn read(path: &str) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "input")?
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| "input")?;
    if bytes.len() > 1_048_576 {
        return Err("input");
    }
    Ok(bytes)
}
fn wait() -> Result<(), &'static str> {
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|_| "control")?;
    if line != "GO\n" {
        return Err("control");
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    // Bridge base arguments, then journal directory and a test mutation.
    let a: Vec<String> = env::args().skip(1).collect();
    if a.len() != 25 {
        return Err("arguments");
    }
    let mode = a[24].as_str();
    if ![
        "normal",
        "nonce",
        "envelope",
        "source",
        "config",
        "issue_error",
        "wrong_key",
        "later",
        "old_rejected",
    ]
    .contains(&mode)
    {
        return Err("mode");
    }
    let mut peer = [0u8; 32];
    if a[11].len() != 64 || !a[11].is_ascii() {
        return Err("peer");
    }
    for (i, part) in peer.iter_mut().enumerate() {
        *part = u8::from_str_radix(&a[11][2 * i..2 * i + 2], 16).map_err(|_| "peer")?;
    }
    let ids: [&str; 10] = std::array::from_fn(|i| a[12 + i].as_str());
    let binding = CausalBinding::new(ids, peer).map_err(|_| "binding")?;
    let mut grant = read(&a[8])?;
    if mode == "envelope" {
        grant.push(b' ');
    }
    let nonce = if mode == "nonce" || mode == "later" {
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    } else {
        &a[22]
    };
    let issue = CausalIssue::new(
        binding,
        nonce,
        Duration::from_secs(300),
        &grant,
        &read(&a[9])?,
    )
    .map_err(|_| "issue")?;
    let source = if mode == "source" { [2; 32] } else { [1; 32] };
    let config = if mode == "config" { [4; 32] } else { [3; 32] };
    let mut owner =
        CausalIssueOwner::prepare(Path::new(&a[23]), issue, source, config).map_err(|error| {
            match error {
                CausalJournalError::Busy => "BUSY",
                CausalJournalError::Mismatch => "MISMATCH",
                CausalJournalError::Corrupt => "CORRUPT",
                CausalJournalError::Unsafe => "UNSAFE",
                CausalJournalError::Io => "IO",
            }
        })?;
    println!("PREPARED");
    io::stdout().flush().map_err(|_| "output")?;
    wait()?;
    let grant_key: [u8; 32] = read(if mode == "wrong_key" { &a[7] } else { &a[6] })?
        .try_into()
        .map_err(|_| "key")?;
    let policy_key: [u8; 32] = read(&a[7])?.try_into().map_err(|_| "key")?;
    let grants = CausalGrantKeys::new(&[("fixture", grant_key)]).map_err(|_| "key")?;
    let policies = PolicyKeys::new(&[("fixture", policy_key)]).map_err(|_| "key")?;
    let trust = TrustedCa::from_pem(&read(&a[3])?).map_err(|_| "trust")?;
    let password = env::var("CONTOUR_CAUSAL_ISSUER_PASSWORD").map_err(|_| "password")?;
    let settings = DatabaseSettings::new(
        &a[0],
        a[1].parse().map_err(|_| "port")?,
        &a[2],
        &a[4],
        password.as_bytes(),
        Duration::from_secs(10),
    )
    .map_err(|_| "settings")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime")?
        .block_on(async {
            let connection = settings.connect(&trust).await.map_err(|_| "connect")?;
            let mut issuer = CausalIssuer::new(connection);
            let actual_peer = if mode == "issue_error" {
                [0x44; 32]
            } else {
                peer
            };
            let result = owner
                .issue(&mut issuer, &actual_peer, &grants, &policies)
                .await;
            if mode == "issue_error" || mode == "wrong_key" || mode == "old_rejected" {
                let expected = match mode {
                    // The issuer rejects the peer mismatch before authority checks.
                    "issue_error" => CausalError::Identity,
                    "wrong_key" => CausalError::Signature,
                    _ => CausalError::Conflict,
                };
                if !matches!(result, Err(error) if error == expected) {
                    return Err("unexpected issue result");
                }
                println!("ISSUE_ERROR");
            } else {
                let session = result.map_err(|_| "issue")?;
                println!("ISSUED");
                io::stdout().flush().map_err(|_| "output")?;
                wait()?;
                println!(
                    "SESSION {} {} {}",
                    session.epoch(),
                    session.issued_at().unix_timestamp_nanos() / 1000,
                    session.expires_at().unix_timestamp_nanos() / 1000
                );
            }
            io::stdout().flush().map_err(|_| "output")?;
            wait()?;
            // Keep the owner live until after the parent explicitly releases it.
            drop(owner);
            Ok(())
        })
}
