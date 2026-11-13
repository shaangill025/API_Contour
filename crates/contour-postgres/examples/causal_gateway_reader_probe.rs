//! Synthetic SQL30 gateway reader probe. No peer possession or deployment authority.
//! Private JSON input is read from stdin; only fixed labels are printed.
use contour_core::Timestamp;
use contour_postgres::{
    CausalGatewayReadError, CausalGatewayReader, CausalGatewaySelector, DatabaseSettings, TrustedCa,
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
        "metadata_sha256",
        "expires_at",
        "generation",
        "leaf",
        "mode",
        "password",
        "port",
        "gateway",
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
        ("positive", "gateway_reader_login")
            | ("unavailable", "gateway_reader_login")
            | ("denied", "gateway_wrong_login")
            | ("denied", "gateway_mixed_login")
            | ("denied", "gateway_transitive_login")
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
    let leaf = hex32(get("leaf")?)?;
    let commitment = hex32(get("metadata_sha256")?)?;
    let tenant = get("tenant")?;
    let gateway = get("gateway")?;
    let generation = get("generation")?;
    let selected = CausalGatewaySelector::new(tenant, gateway, generation, leaf).map_err(|_| ())?;
    let expected_expires = Timestamp::parse(get("expires_at")?)
        .map_err(|_| ())?
        .instant();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?
        .block_on(async {
            let connection = settings.connect(&ca).await.map_err(|_| ())?;
            let mut reader = CausalGatewayReader::new(connection);
            if mode == "denied" {
                if !matches!(
                    reader
                        .read_until(&selected, Instant::now() + Duration::from_secs(5))
                        .await,
                    Err(CausalGatewayReadError::Identity)
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
                    Err(CausalGatewayReadError::Unavailable)
                ) {
                    return Err(());
                }
                return Ok(());
            }
            if !matches!(
                reader.read_until(&selected, Instant::now()).await,
                Err(CausalGatewayReadError::Deadline)
            ) {
                return Err(());
            }
            let first = reader
                .read_until(&selected, Instant::now() + Duration::from_secs(5))
                .await
                .map_err(|_| ())?;
            if first.metadata().metadata_sha256() != commitment
                || first.metadata().expires_at() != expected_expires
            {
                return Err(());
            }
            let second = reader
                .read_until(&selected, Instant::now() + Duration::from_secs(5))
                .await
                .map_err(|_| ())?;
            if second.metadata().metadata_sha256() != commitment {
                return Err(());
            }
            for wrong in [
                CausalGatewaySelector::new(tenant, gateway, generation, [0x7f; 32]),
                CausalGatewaySelector::new(
                    tenant,
                    gateway,
                    "11111111111111111111111111111111",
                    leaf,
                ),
                CausalGatewaySelector::new(
                    "00000000-0000-4000-8000-000000000009",
                    gateway,
                    generation,
                    leaf,
                ),
            ] {
                if !matches!(
                    reader
                        .read_until(
                            &wrong.map_err(|_| ())?,
                            Instant::now() + Duration::from_secs(5),
                        )
                        .await,
                    Err(CausalGatewayReadError::Unavailable)
                ) {
                    return Err(());
                }
            }
            Ok(())
        })
}
fn main() {
    if run().is_err() {
        eprintln!("FAIL gateway_reader_probe");
        std::process::exit(1);
    }
    println!("PASS gateway_reader_probe");
}
