//! Synthetic SQL28 reader probe. No peer possession or deployment authority.
//! Private JSON input is read from stdin; only fixed labels are printed.
use contour_core::Timestamp;
use contour_postgres::{
    CausalReceiverReadError, CausalReceiverReader, CausalReceiverSelector, DatabaseSettings,
    TrustedCa,
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
    let mut out = [0; 32];
    for (i, part) in s.as_bytes().chunks_exact(2).enumerate() {
        out[i] =
            u8::from_str_radix(std::str::from_utf8(part).map_err(|_| ())?, 16).map_err(|_| ())?;
    }
    Ok(out)
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
        "commitment",
        "credential_id",
        "epoch",
        "expires_at",
        "generation",
        "leaf",
        "mode",
        "password",
        "port",
        "runtime",
        "tenant",
        "user",
    ];
    if o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)) {
        return Err(());
    }
    let get = |key: &str| o.get(key).and_then(Value::as_str).ok_or(());
    let mode = get("mode")?;
    let user = get("user")?;
    if !matches!(
        (mode, user),
        ("positive", "receiver_reader_login")
            | ("unavailable", "receiver_reader_login")
            | ("denied", "receiver_wrong_login")
            | ("denied", "receiver_mixed_login")
    ) {
        return Err(());
    }
    let port = get("port")?.parse::<u16>().map_err(|_| ())?;
    let password = get("password")?;
    let settings = DatabaseSettings::new(
        "localhost",
        port,
        "contour_local",
        user,
        password.as_bytes(),
        Duration::from_secs(10),
    )
    .map_err(|_| ())?;
    let ca = TrustedCa::from_pem(get("ca_pem")?.as_bytes()).map_err(|_| ())?;
    let epoch = get("epoch")?.parse::<u64>().map_err(|_| ())?;
    let leaf = hex32(get("leaf")?)?;
    let commitment = hex32(get("commitment")?)?;
    let tenant = get("tenant")?;
    let runtime = get("runtime")?;
    let generation = get("generation")?;
    let selected =
        CausalReceiverSelector::new(tenant, runtime, epoch, generation, leaf).map_err(|_| ())?;
    let expected_expires = Timestamp::parse(get("expires_at")?)
        .map_err(|_| ())?
        .instant();
    let credential = get("credential_id")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?
        .block_on(async {
            let connection = settings.connect(&ca).await.map_err(|_| ())?;
            let mut reader = CausalReceiverReader::new(connection);
            if mode == "denied" {
                if !matches!(
                    reader
                        .read_until(&selected, Instant::now() + Duration::from_secs(5))
                        .await,
                    Err(CausalReceiverReadError::Identity)
                ) {
                    return Err(());
                }
                return Ok(());
            }
            if mode == "unavailable" {
                if !matches!(
                    reader
                        .read_until(&selected, Instant::now() + Duration::from_secs(5))
                        .await,
                    Err(CausalReceiverReadError::Unavailable)
                ) {
                    return Err(());
                }
                return Ok(());
            }
            if !matches!(
                reader.read_until(&selected, Instant::now()).await,
                Err(CausalReceiverReadError::Deadline)
            ) {
                return Err(());
            }
            let first = reader
                .read_until(&selected, Instant::now() + Duration::from_secs(5))
                .await
                .map_err(|_| ())?;
            if first.metadata().commitment() != &commitment
                || first.metadata().evidence_credential_id() != credential
                || first.metadata().expires_at().instant() != expected_expires
            {
                return Err(());
            }
            let second = reader
                .read_until(&selected, Instant::now() + Duration::from_secs(5))
                .await
                .map_err(|_| ())?;
            if second.metadata().commitment() != &commitment {
                return Err(());
            }
            for wrong in [
                CausalReceiverSelector::new(tenant, runtime, epoch, generation, [0x7f; 32]),
                CausalReceiverSelector::new(
                    tenant,
                    runtime,
                    epoch,
                    "11111111111111111111111111111111",
                    leaf,
                ),
                CausalReceiverSelector::new(
                    "00000000-0000-4000-8000-000000000009",
                    runtime,
                    epoch,
                    generation,
                    leaf,
                ),
                CausalReceiverSelector::new(
                    tenant,
                    runtime,
                    epoch.checked_add(1).ok_or(())?,
                    generation,
                    leaf,
                ),
            ] {
                if reader
                    .read_until(
                        &wrong.map_err(|_| ())?,
                        Instant::now() + Duration::from_secs(5),
                    )
                    .await
                    .is_ok()
                {
                    return Err(());
                }
            }
            Ok(())
        })
}
fn main() {
    if run().is_err() {
        eprintln!("FAIL receiver_reader_probe");
        std::process::exit(1);
    }
    println!("PASS receiver_reader_probe");
}
