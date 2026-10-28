//! Operator-scoped business API. Database methods enforce current membership.
use crate::{BusinessRequest, PlatformError, PlatformResponse, response};
use contour_auth::VerifiedIdentity;
use contour_core::{
    DeclaredCompatibility, DeclaredVersionDifferenceKind as Difference, ImportBundleWarning,
    ImportError, ServiceImportPolicy, import_service_declared,
};
use contour_postgres::{
    ComparisonInput, ComparisonRequest, ComparisonStoreError, ComparisonStored, DatabaseSettings,
    DeclaredScope, HumanCatalogError, HumanCatalogOperation, HumanCatalogResource,
    HumanReviewDecisionRequest, HumanReviewRequest, ReviewStatus, ReviewStoreError, ReviewStored,
    ServiceImportError, ServiceImportScope, TrustedCa,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    database_host: String,
    database_port: u16,
    database_name: String,
    database_user: String,
    database_password_file: PathBuf,
    database_ca_file: PathBuf,
    tenant_id: String,
    project_id: String,
    service_id: String,
    environment_id: String,
    routes: Vec<(String, String)>,
    approved_names: Vec<String>,
    approved_media: Vec<String>,
}
pub struct Business {
    db: DatabaseSettings,
    ca: TrustedCa,
    ids: [String; 4],
    routes: Vec<(String, String)>,
    names: Vec<String>,
    media: Vec<String>,
}
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, PlatformError> {
    let file = std::fs::File::open(path).map_err(|_| PlatformError::Configuration)?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PlatformError::Configuration)?;
    if bytes.len() as u64 > max {
        return Err(PlatformError::Configuration);
    }
    Ok(bytes)
}
impl Business {
    pub fn from_file(path: &Path) -> Result<Self, PlatformError> {
        let config: Config = serde_json::from_slice(&read_bounded(path, 65536)?)
            .map_err(|_| PlatformError::Configuration)?;
        let ids = [
            config.tenant_id,
            config.project_id,
            config.service_id,
            config.environment_id,
        ];
        DeclaredScope::new(ids.each_ref().map(String::as_str))
            .map_err(|_| PlatformError::Configuration)?;
        let routes: Vec<_> = config
            .routes
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let names: Vec<_> = config.approved_names.iter().map(String::as_str).collect();
        let media: Vec<_> = config.approved_media.iter().map(String::as_str).collect();
        ServiceImportPolicy::new(ids.each_ref().map(String::as_str), &routes, &names, &media)
            .map_err(|_| PlatformError::Configuration)?;
        let password = read_bounded(&config.database_password_file, 4096)?;
        let db = DatabaseSettings::new(
            &config.database_host,
            config.database_port,
            &config.database_name,
            &config.database_user,
            &password,
            Duration::from_secs(18),
        )
        .map_err(|_| PlatformError::Configuration)?;
        let ca = TrustedCa::from_pem(&read_bounded(&config.database_ca_file, 65536)?)
            .map_err(|_| PlatformError::Configuration)?;
        Ok(Self {
            db,
            ca,
            ids,
            routes: config.routes,
            names: config.approved_names,
            media: config.approved_media,
        })
    }
    /// Dependency readiness only; authorization is checked separately per request.
    pub async fn ready(&self) -> bool {
        tokio::time::timeout(Duration::from_secs(2), async {
            let db = self
                .db
                .connect_single_until(&self.ca, Instant::now() + Duration::from_secs(2))
                .await
                .ok()?;
            db.health().await.ok()?;
            db.close().await.ok()?;
            Some(())
        })
        .await
        .is_ok_and(|result| result.is_some())
    }
    pub async fn handle(
        &self,
        request: BusinessRequest,
        identity: VerifiedIdentity,
    ) -> PlatformResponse {
        let create = request.method() == hyper::Method::POST
            && matches!(
                request.uri().path(),
                "/v1/contracts/import" | "/v1/comparisons" | "/v1/reviews"
            );
        let key = if create {
            match idempotency_key(&request) {
                Ok(key) => key,
                Err(status) => return error(status),
            }
        } else {
            None
        };
        match self.execute(request, &identity, key.as_deref()).await {
            Ok(value) => {
                let mut result = reply(200, value);
                if let Some(key) = key {
                    if let Ok(value) = hyper::header::HeaderValue::from_str(&key) {
                        result.headers_mut().insert("x-resource-id", value);
                    }
                }
                result
            }
            Err(status) => error(status),
        }
    }
    async fn execute(
        &self,
        request: BusinessRequest,
        identity: &VerifiedIdentity,
        idempotency_key: Option<&str>,
    ) -> Result<Value, u16> {
        let deadline = Instant::now() + Duration::from_secs(18);
        let scope =
            DeclaredScope::new(self.ids.each_ref().map(String::as_str)).map_err(|_| 503u16)?;
        let path = request.uri().path();
        let method = request.method().as_str();
        let mut db = self
            .db
            .connect_single_until(&self.ca, deadline)
            .await
            .map_err(|_| 503u16)?;
        if method == "GET" && path == "/v1/operations" {
            let (limit, cursor) = query(request.uri().query())?;
            let page = db
                .list_operations_as_human_until(
                    identity,
                    &scope,
                    limit,
                    cursor.as_deref(),
                    deadline,
                )
                .await
                .map_err(catalog_error)?;
            return Ok(
                json!({"items":page.items.into_iter().map(operation).collect::<Vec<_>>(),"next_cursor":page.next_cursor}),
            );
        }
        if method == "GET" && path.starts_with("/v1/operations/") {
            no_query(&request)?;
            let id = segment(path, "/v1/operations/")?;
            let op = db
                .read_operation_as_human_until(identity, &scope, id, deadline)
                .await
                .map_err(catalog_error)?;
            return Ok(operation(op));
        }
        if method == "POST" && path == "/v1/contracts/import" {
            no_query(&request)?;
            let body: Import = parse(&request)?;
            if body.project_id != self.ids[1] || body.service_id != self.ids[2] {
                return Err(403);
            }
            if body.format != "openapi_json" {
                return Err(422);
            }
            let service_scope = ServiceImportScope::new([
                self.ids[0].as_str(),
                self.ids[1].as_str(),
                self.ids[2].as_str(),
            ])
            .map_err(|_| 503u16)?;
            let resolved = db
                .resolve_import_default_as_human_until(identity, &service_scope, deadline)
                .await
                .map_err(import_error)?;
            if resolved != self.ids {
                return Err(409);
            }
            let routes: Vec<_> = self
                .routes
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect();
            let names: Vec<_> = self.names.iter().map(String::as_str).collect();
            let media: Vec<_> = self.media.iter().map(String::as_str).collect();
            let policy = ServiceImportPolicy::new(
                self.ids.each_ref().map(String::as_str),
                &routes,
                &names,
                &media,
            )
            .map_err(|_| 503u16)?;
            let bundle = import_service_declared(&body.format, body.content.as_bytes(), &policy)
                .map_err(|e| {
                    if e == ImportError::Size {
                        413u16
                    } else {
                        422u16
                    }
                })?;
            let id = match idempotency_key {
                Some(id) => id.to_owned(),
                None => random_uuid()?,
            };
            let stored = db
                .store_service_import_as_human_until(
                    identity,
                    &service_scope,
                    &id,
                    &bundle,
                    deadline,
                )
                .await
                .map_err(import_error)?;
            return Ok(
                json!({"id":stored.contract_id(),"project_id":self.ids[1],"service_id":self.ids[2],"kind":"declared","revision":stored.revision(),"created_at":timestamp(stored.created_micros())?,"warnings":stored.warnings().iter().map(|w| match w {ImportBundleWarning::RemovedValue=>"removed_value",ImportBundleWarning::UnsupportedConstruct=>"unsupported_construct",ImportBundleWarning::PartialImport=>"partial_import"}).collect::<Vec<_>>() }),
            );
        }
        if method == "POST" && path == "/v1/comparisons" {
            no_query(&request)?;
            let b: Comparison = parse(&request)?;
            let id = match idempotency_key {
                Some(id) => id.to_owned(),
                None => random_uuid()?,
            };
            let left = input(&b.left_kind, &b.left_id)?;
            let right = input(&b.right_kind, &b.right_id)?;
            let req = ComparisonRequest::new(&b.operation_id, &id, left, right)
                .map_err(comparison_error)?;
            // Resolve immutable display identity before committing the comparison.
            // The store still checks fresh authority in its own transaction.
            let op = db
                .read_operation_as_human_until(identity, &scope, &b.operation_id, deadline)
                .await
                .map_err(catalog_error)?;
            let stored = db
                .store_public_comparison_as_human_until(identity, &scope, &req, deadline)
                .await
                .map_err(comparison_error)?;
            return comparison(&stored, &b.operation_id, &op.direction);
        }
        if method == "GET" && path.starts_with("/v1/comparisons/") {
            no_query(&request)?;
            let id = segment(path, "/v1/comparisons/")?;
            let opid = db
                .lookup_operation_as_human_until(
                    identity,
                    &scope,
                    HumanCatalogResource::Comparison,
                    id,
                    deadline,
                )
                .await
                .map_err(catalog_error)?;
            let stored = db
                .read_public_comparison_as_human_until(identity, &scope, &opid, id, deadline)
                .await
                .map_err(comparison_error)?;
            let op = db
                .read_operation_as_human_until(identity, &scope, &opid, deadline)
                .await
                .map_err(catalog_error)?;
            return comparison(&stored, &opid, &op.direction);
        }
        if method == "POST" && path == "/v1/reviews" {
            no_query(&request)?;
            let b: Review = parse(&request)?;
            let id = match idempotency_key {
                Some(id) => id.to_owned(),
                None => random_uuid()?,
            };
            let req = HumanReviewRequest::new(
                &b.operation_id,
                &id,
                &b.comparison_id,
                &b.candidate_contract_id,
                b.expected_baseline_id.as_deref(),
            )
            .map_err(review_error)?;
            let stored = db
                .store_public_review_as_human_until(identity, &scope, &req, deadline)
                .await
                .map_err(review_error)?;
            return review(&stored);
        }
        if let Some(rest) = path.strip_prefix("/v1/reviews/") {
            no_query(&request)?;
            let (id, decision) = if let Some(id) = rest.strip_suffix("/decision") {
                (id, true)
            } else {
                (rest, false)
            };
            if id.is_empty() || id.contains('/') {
                return Err(404);
            }
            if !(method == "GET" && !decision || method == "POST" && decision) {
                return Err(404);
            }
            let opid = db
                .lookup_operation_as_human_until(
                    identity,
                    &scope,
                    HumanCatalogResource::Review,
                    id,
                    deadline,
                )
                .await
                .map_err(catalog_error)?;
            let stored = if decision {
                let b: Decision = parse(&request)?;
                let req = match b.decision.as_str() {
                    "approve" => HumanReviewDecisionRequest::approve(
                        &opid,
                        id,
                        b.expected_revision,
                        &event_uuid(id),
                    ),
                    "reject" => HumanReviewDecisionRequest::reject(&opid, id, b.expected_revision),
                    _ => return Err(422),
                }
                .map_err(review_error)?;
                db.decide_public_review_as_human_until(identity, &scope, &req, deadline)
                    .await
                    .map_err(review_error)?
            } else {
                db.read_public_review_as_human_until(identity, &scope, &opid, id, deadline)
                    .await
                    .map_err(review_error)?
            };
            return review(&stored);
        }
        Err(404)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    project_id: String,
    service_id: String,
    format: String,
    content: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Comparison {
    operation_id: String,
    left_id: String,
    left_kind: String,
    right_id: String,
    right_kind: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    operation_id: String,
    comparison_id: String,
    candidate_contract_id: String,
    #[serde(deserialize_with = "required_nullable")]
    expected_baseline_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    decision: String,
    expected_revision: u64,
}
fn required_nullable<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
fn parse<T: serde::de::DeserializeOwned>(request: &BusinessRequest) -> Result<T, u16> {
    serde_json::from_slice(request.body()).map_err(|_| 400u16)
}
fn no_query(request: &BusinessRequest) -> Result<(), u16> {
    if request.uri().query().is_some() {
        Err(400)
    } else {
        Ok(())
    }
}
fn segment<'a>(path: &'a str, prefix: &str) -> Result<&'a str, u16> {
    let id = path.strip_prefix(prefix).ok_or(404u16)?;
    if id.is_empty() || id.contains('/') {
        Err(404)
    } else {
        Ok(id)
    }
}
fn query(q: Option<&str>) -> Result<(u16, Option<String>), u16> {
    let mut limit = None;
    let mut cursor = None;
    if let Some(q) = q {
        for item in q.split('&') {
            let (key, value) = item.split_once('=').ok_or(400u16)?;
            match key {
                "limit" if limit.is_none() => {
                    limit = Some(value.parse::<u16>().map_err(|_| 400u16)?)
                }
                "cursor" if cursor.is_none() && !value.is_empty() => {
                    cursor = Some(value.to_owned())
                }
                _ => return Err(400),
            }
        }
    }
    let limit = limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(400);
    }
    Ok((limit, cursor))
}
fn idempotency_key(request: &BusinessRequest) -> Result<Option<String>, u16> {
    let mut values = request.headers().get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(400);
    }
    let value = value.to_str().map_err(|_| 400u16)?;
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
    {
        return Err(400);
    }
    Ok(Some(value.to_owned()))
}
fn random_uuid() -> Result<String, u16> {
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).map_err(|_| 503u16)?;
    Ok(uuid_bytes(bytes))
}
fn uuid_bytes(mut b: [u8; 16]) -> String {
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}
fn event_uuid(id: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"APIContour public review approval event v1\0");
    hash.update(id.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid_bytes(bytes)
}
fn input(kind: &str, id: &str) -> Result<ComparisonInput, u16> {
    match kind {
        "declared" => ComparisonInput::declared(id),
        "approved" => ComparisonInput::approved(id),
        "observed" => return Err(422),
        _ => return Err(400),
    }
    .map_err(comparison_error)
}
fn timestamp(micros: i64) -> Result<String, u16> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1000)
        .map_err(|_| 503u16)?
        .format(&Rfc3339)
        .map_err(|_| 503u16)
}
fn operation(o: HumanCatalogOperation) -> Value {
    json!({"id":o.id,"project_id":o.project_id,"service_id":o.service_id,"environment_id":o.environment_id,"protocol":o.protocol,"direction":o.direction,"operation":o.operation,"route_template":o.route_template,"approved_contract_id":o.approved_contract_id,"last_seen":o.last_seen,"visibility":o.visibility,"completeness":o.completeness})
}
fn comparison(c: &ComparisonStored, operation: &str, direction: &str) -> Result<Value, u16> {
    let inputs = c.public_inputs().ok_or(503u16)?;
    let result = match c.result().compatibility() {
        DeclaredCompatibility::Compatible => "compatible",
        DeclaredCompatibility::Incompatible => "incompatible",
        DeclaredCompatibility::Inconclusive => "inconclusive",
    };
    let differences: Vec<_> = c.result().differences().iter().map(|d| {
        let kind = match d.kind { Difference::TypeChanged=>"type_changed",Difference::NullMembershipChanged=>"nullability_changed",Difference::RequirednessChanged=>"requiredness_changed",Difference::FieldAdded=>"added",Difference::FieldRemoved=>"removed",Difference::AdditionalPolicyChanged|Difference::InsufficientEvidence=>"unknown" };
        json!({"path":d.path,"kind":kind,"assessment":"inconclusive","reason":if d.kind == Difference::InsufficientEvidence {"insufficient_evidence"} else {"structural_difference"}})
    }).collect();
    Ok(
        json!({"id":c.comparison_id(),"operation_id":operation,"left_id":inputs[0].id(),"left_kind":inputs[0].kind(),"right_id":inputs[1].id(),"right_kind":inputs[1].kind(),"direction":direction,"result":result,"differences":differences}),
    )
}
fn review(r: &ReviewStored) -> Result<Value, u16> {
    Ok(
        json!({"id":r.review_id(),"operation_id":r.operation_id(),"comparison_id":r.comparison_id(),"candidate_contract_id":r.public_candidate_id().ok_or(503u16)?,"expected_baseline_id":r.expected_event_id(),"revision":r.revision(),"status":match r.review_status() {ReviewStatus::Pending=>"pending",ReviewStatus::Approved=>"approved",ReviewStatus::Rejected=>"rejected"},"created_at":timestamp(r.created_micros())?,"deciding_actor_id":r.deciding_actor_id(),"decided_at":r.decided_micros().map(timestamp).transpose()?}),
    )
}
fn catalog_error(e: HumanCatalogError) -> u16 {
    match e {
        HumanCatalogError::Scope | HumanCatalogError::Limit => 400,
        HumanCatalogError::Forbidden => 403,
        HumanCatalogError::NotFound => 404,
        _ => 503,
    }
}
fn comparison_error(e: ComparisonStoreError) -> u16 {
    match e {
        ComparisonStoreError::Scope => 400,
        ComparisonStoreError::Forbidden => 403,
        ComparisonStoreError::NotFound => 404,
        ComparisonStoreError::Conflict => 409,
        ComparisonStoreError::UnsupportedDirection | ComparisonStoreError::Limit => 422,
        _ => 503,
    }
}
fn review_error(e: ReviewStoreError) -> u16 {
    match e {
        ReviewStoreError::Scope => 400,
        ReviewStoreError::Forbidden => 403,
        ReviewStoreError::NotFound => 404,
        ReviewStoreError::Conflict => 409,
        _ => 503,
    }
}
fn import_error(e: ServiceImportError) -> u16 {
    match e {
        ServiceImportError::Scope => 400,
        ServiceImportError::Forbidden => 403,
        ServiceImportError::NotFound => 404,
        ServiceImportError::MissingDefault
        | ServiceImportError::DefaultChanged
        | ServiceImportError::Conflict => 409,
        ServiceImportError::UnsupportedProjection => 422,
        _ => 503,
    }
}
fn reply(status: u16, value: Value) -> PlatformResponse {
    response(status, "application/json", value.to_string())
}
fn error(status: u16) -> PlatformResponse {
    reply(
        status,
        json!({"code":match status {400=>"invalid_request",403=>"forbidden",404=>"not_found",409=>"conflict",413=>"too_large",422=>"invalid_input",_=>"unavailable"},"message":"Request could not be completed.","request_id":random_uuid().unwrap_or_else(|_| "00000000-0000-4000-8000-000000000000".to_owned()),"retryable":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queries_are_bounded_and_unambiguous() {
        assert_eq!(query(None), Ok((50, None)));
        assert_eq!(
            query(Some("limit=200&cursor=abc")),
            Ok((200, Some("abc".into())))
        );
        assert_eq!(query(Some("limit=1&limit=2")), Err(400));
        assert_eq!(query(Some("limit=201")), Err(400));
        assert_eq!(query(Some("cursor=")), Err(400));
        assert_eq!(query(Some("tenant=other")), Err(400));
    }
    #[test]
    fn request_objects_reject_unknown_and_duplicate_fields() {
        assert!(
            serde_json::from_str::<Decision>(
                r#"{"decision":"approve","expected_revision":1,"actor":"x"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Decision>(
                r#"{"decision":"approve","decision":"reject","expected_revision":1}"#
            )
            .is_err()
        );
    }
    #[test]
    fn idempotency_keys_are_canonical_single_uuid_headers() {
        let mut request = BusinessRequest::new(bytes::Bytes::new());
        assert_eq!(idempotency_key(&request), Ok(None));
        request.headers_mut().append(
            "idempotency-key",
            hyper::header::HeaderValue::from_static("12345678-1234-4234-8234-123456789abc"),
        );
        assert_eq!(
            idempotency_key(&request).unwrap().as_deref(),
            Some("12345678-1234-4234-8234-123456789abc")
        );
        request.headers_mut().append(
            "idempotency-key",
            hyper::header::HeaderValue::from_static("12345678-1234-4234-8234-123456789abc"),
        );
        assert_eq!(idempotency_key(&request), Err(400));
        request.headers_mut().remove("idempotency-key");
        request.headers_mut().append(
            "idempotency-key",
            hyper::header::HeaderValue::from_static("12345678-1234-4234-8234-123456789ABC"),
        );
        assert_eq!(idempotency_key(&request), Err(400));
    }
    #[test]
    fn approval_event_is_stable_and_domain_bound() {
        let id = "00000000-0000-4000-8000-000000000001";
        assert_eq!(event_uuid(id), event_uuid(id));
        assert_ne!(
            event_uuid(id),
            event_uuid("00000000-0000-4000-8000-000000000002")
        );
        assert_eq!(event_uuid(id).len(), 36);
        assert_eq!(timestamp(0).unwrap(), "1970-01-01T00:00:00Z");
    }
}
