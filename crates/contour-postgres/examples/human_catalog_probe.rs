//! Synthetic TLS integration probe; the fixture supplies a signed test token.
use contour_postgres::{DatabaseSettings, DeclaredScope, HumanCatalogResource, TrustedCa};
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
        println!("{outcome}");
        db.close().await?;
        Ok::<(),Box<dyn std::error::Error>>(())
    })
}
fn value(o: &contour_postgres::HumanCatalogOperation) -> serde_json::Value {
    json!({"id":o.id,"project_id":o.project_id,"service_id":o.service_id,"environment_id":o.environment_id,"protocol":o.protocol,"direction":o.direction,"operation":o.operation,"route_template":o.route_template,"approved_contract_id":o.approved_contract_id,"last_seen":o.last_seen,"visibility":o.visibility,"completeness":o.completeness})
}
