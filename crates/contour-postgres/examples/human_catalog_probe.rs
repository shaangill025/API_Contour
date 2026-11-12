//! Synthetic TLS integration probe; the fixture supplies a signed test token.
use contour_postgres::{
    DatabaseSettings, DeclaredScope, HumanCatalogResource, HumanOrigin, TrustedCa,
};
use serde_json::json;
use std::{env, fs, time::Duration};
fn main() {
    if let Err(e) = run() {
        eprintln!("catalog probe failed: {e}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<_> = env::args().skip(1).collect();
    if a.len() != 9 {
        return Err("arguments".into());
    }
    let trust = TrustedCa::from_pem(&fs::read(&a[1])?)?;
    let scope = DeclaredScope::new([&a[2], &a[3], &a[4], &a[5]])?;
    let verifier = contour_auth::IdTokenVerifier::new(
        "https://idp.example.test/realms/demo",
        "apicontour",
        include_bytes!("../../contour-auth/tests/fixtures/public-jwks.json"),
    )?;
    let identity = verifier.verify(
        &fs::read_to_string(env::var("CONTOUR_FIXTURE_ID_TOKEN")?)?,
        "server-generated-one-use-nonce",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    let settings = DatabaseSettings::new(
        "localhost",
        a[0].parse()?,
        "contour_fixture",
        "contour_human_reader_tls",
        env::var("CONTOUR_FIXTURE_PASSWORD")?.as_bytes(),
        Duration::from_secs(10),
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut db = settings.connect(&trust).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let outcome = if a[6] == "list" {
            match db.list_operations_as_human_until(&identity, &scope, a[7].parse()?, if a[8] == "-" { None } else { Some(&a[8]) }, deadline).await {
                Ok(page) => json!({"outcome":"Read", "items":page.items.iter().map(value).collect::<Vec<_>>(), "next_cursor":page.next_cursor}),
                Err(e) => json!({"outcome":e.to_string()})
            }
        } else if a[6] == "with-origin" {
            match db.list_operations_with_origins_as_human_until(&identity, &scope, a[7].parse()?, if a[8] == "-" { None } else { Some(&a[8]) }, deadline).await {
                Ok(page) => json!({"outcome":"Read", "items":page.items.iter().map(value).collect::<Vec<_>>(), "next_cursor":page.next_cursor}),
                Err(e) => json!({"outcome":e.to_string()})
            }
        } else if a[6] == "historical-expiry-reuse" || a[6] == "historical-repeat" {
            let observation = env::var("CONTOUR_FIXTURE_OBSERVATION")?;
            let first = db.read_observation_origin_as_human_until(&identity, &scope, &a[8], &observation, deadline).await;
            let reuse_identity = verifier.verify(&fs::read_to_string(env::var("CONTOUR_FIXTURE_REUSE_TOKEN")?)?, "server-generated-one-use-nonce", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())?;
            let second = db.read_observation_origin_as_human_until(&reuse_identity, &scope, &a[8], &observation, deadline).await;
            let describe = |result: Result<serde_json::Value, contour_postgres::HumanObservationError>| match result {
                Ok(value) => value.get("status").and_then(serde_json::Value::as_str).unwrap_or("invalid").to_owned(),
                Err(error) => error.to_string(),
            };
            json!({"outcome":describe(first),"reuse":describe(second)})
        } else if a[6] == "historical-cancel" {
            let observation = env::var("CONTOUR_FIXTURE_OBSERVATION")?;
            let cancelled = tokio::time::timeout(Duration::from_secs(2), db.read_observation_origin_as_human_until(&identity, &scope, &a[8], &observation, deadline)).await;
            let reuse = db.read_observation_origin_as_human_until(&identity, &scope, &a[8], &observation, deadline).await;
            json!({"outcome":if cancelled.is_err() {"Cancelled"} else {"NotCancelled"}, "reuse":match reuse {Err(e)=>e.to_string(),Ok(_)=>"Read".to_owned()}})
        } else if a[6] == "historical-origin" {
            let observation = env::var("CONTOUR_FIXTURE_OBSERVATION")?;
            match db.read_observation_origin_as_human_until(&identity, &scope, &a[8], &observation, deadline).await {
                Ok(item) => json!({"outcome":"Read", "item":item}), Err(e) => json!({"outcome":e.to_string()})
            }
        } else if a[6] == "origin-detail" {
            match db.read_operation_with_origins_as_human_until(&identity, &scope, &a[8], deadline).await {
                Ok(item) => json!({"outcome":"Read", "item":value(&item)}), Err(e) => json!({"outcome":e.to_string()})
            }
        } else if a[6] == "origin" {
            let values: Vec<String> = env::var("CONTOUR_FIXTURE_ORIGIN")?.split(',').map(str::to_owned).collect();
            let origin = HumanOrigin::new(values.try_into().map_err(|_| "origin fields")?)?;
            match db.list_operations_by_origin_as_human_until(&identity, &scope, a[7].parse()?, if a[8] == "-" { None } else { Some(&a[8]) }, &origin, deadline).await {
                Ok(page) => json!({"outcome":"Read", "items":page.items.iter().map(value).collect::<Vec<_>>(), "next_cursor":page.next_cursor}),
                Err(e) => json!({"outcome":e.to_string()})
            }
        } else if a[6].starts_with("lookup-") {
            let kind = if a[6] == "lookup-comparison" { HumanCatalogResource::Comparison } else { HumanCatalogResource::Review };
            match db.lookup_operation_as_human_until(&identity, &scope, kind, &a[8], deadline).await {
                Ok(operation) => json!({"outcome":"Read", "operation":operation}),
                Err(e) => json!({"outcome":e.to_string()})
            }
        } else {
            match db.read_operation_as_human_until(&identity, &scope, &a[8], deadline).await {
                Ok(item) => json!({"outcome":"Read", "item":value(&item)}), Err(e) => json!({"outcome":e.to_string()})
            }
        };
        finish_close(&a[6], &outcome, db.close().await)?;
        println!("{outcome}");
        Ok::<(),Box<dyn std::error::Error>>(())
    })
}
fn value(o: &contour_postgres::HumanCatalogOperation) -> serde_json::Value {
    json!({"id":o.id,"project_id":o.project_id,"service_id":o.service_id,"environment_id":o.environment_id,"protocol":o.protocol,"direction":o.direction,"operation":o.operation,"route_template":o.route_template,"approved_contract_id":o.approved_contract_id,"last_seen":o.last_seen,"visibility":o.visibility,"completeness":o.completeness,"origin_evidence_available":o.origin_evidence_available,"origins_truncated":o.origins_truncated,"origins":o.origins.iter().map(|origin| json!({"project_id":origin.ids[0],"service_id":origin.ids[1],"environment_id":origin.ids[2],"deployment_id":origin.ids[3],"instance_id":origin.ids[4]})).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_invalidated_connection_accepts_only_expected_shutdown() {
        let cancelled = json!({"outcome":"Cancelled","reuse":"Invalidated"});
        assert!(
            finish_close(
                "historical-cancel",
                &cancelled,
                Err(contour_postgres::TransportError::Shutdown)
            )
            .is_ok()
        );
        for bad in [
            json!({"outcome":"NotCancelled","reuse":"Invalidated"}),
            json!({"outcome":"Cancelled","reuse":"Read"}),
        ] {
            assert!(
                finish_close(
                    "historical-cancel",
                    &bad,
                    Err(contour_postgres::TransportError::Shutdown)
                )
                .is_err()
            );
        }
        assert!(
            finish_close(
                "historical-cancel",
                &cancelled,
                Err(contour_postgres::TransportError::Deadline)
            )
            .is_err()
        );
        assert!(finish_close("historical-cancel", &cancelled, Ok(())).is_err());
        assert!(
            finish_close(
                "other",
                &cancelled,
                Err(contour_postgres::TransportError::Shutdown)
            )
            .is_err()
        );
        assert!(finish_close("other", &json!({}), Ok(())).is_ok());
    }
}

fn finish_close(
    mode: &str,
    outcome: &serde_json::Value,
    result: Result<(), contour_postgres::TransportError>,
) -> Result<(), contour_postgres::TransportError> {
    if mode == "historical-cancel" {
        if *outcome == json!({"outcome":"Cancelled","reuse":"Invalidated"})
            && result == Err(contour_postgres::TransportError::Shutdown)
        {
            return Ok(());
        }
        return Err(result
            .err()
            .unwrap_or(contour_postgres::TransportError::Shutdown));
    }
    result
}
