//! Internal operator-scoped history reader. This is not user authentication or HTTP.
use crate::{
    AuthorityError, ConnectedDatabase,
    transaction::{
        CancellationGuard, check_deadline, configure_tenant, database_error, empty_context,
    },
};
use contour_core::{Batch, OperationKey, Shape};
use serde_json::{Value, json};
use std::{fmt, io};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{IsolationLevel, Row, Transaction};

const MAX_PAGE: usize = 1_048_576;
// Includes all eight UUID strings in the private cursor and conservative metadata.
const CURSOR_BUDGET: usize = 512;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogReadError {
    Scope,
    Cursor,
    Limit,
    NotFound,
    Corrupt,
    Database,
    Deadline,
    Invalidated,
}
impl fmt::Display for CatalogReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CatalogReadError {}
impl From<AuthorityError> for CatalogReadError {
    fn from(error: AuthorityError) -> Self {
        match error {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Invalidated => Self::Invalidated,
            _ => Self::Database,
        }
    }
}
/// Trusted operator input, not proof that an end user has these permissions.
#[derive(Clone, PartialEq, Eq)]
pub struct CatalogReadScope {
    ids: [String; 4],
}
impl CatalogReadScope {
    /// Tenant, project, service, operation UUID. No environment filter in this slice.
    pub fn new(ids: [&str; 4]) -> Result<Self, CatalogReadError> {
        if !ids.iter().all(|id| uuid(id)) {
            return Err(CatalogReadError::Scope);
        }
        Ok(Self {
            ids: ids.map(str::to_owned),
        })
    }
}
/// Private, in-memory continuation. No deserialize or public cursor wire format.
#[derive(Clone)]
pub struct CatalogCursor {
    scope: CatalogReadScope,
    after: [String; 4],
}
/// JSON is an internal evidence projection, not the public catalog API schema.
pub struct CatalogPage {
    bytes: Vec<u8>,
    next: Option<CatalogCursor>,
}
impl CatalogPage {
    pub fn json(&self) -> &[u8] {
        &self.bytes
    }
    pub fn next(&self) -> Option<&CatalogCursor> {
        self.next.as_ref()
    }
}
impl fmt::Debug for CatalogPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CatalogPage")
    }
}
impl ConnectedDatabase {
    /// Read one operation and an evidence page. Default 50, maximum 200 items.
    /// Each call has its own immutable-row snapshot; later inserts are not a
    /// cross-page snapshot. Counts are original source counts, never summed.
    pub async fn read_catalog(
        &mut self,
        scope: &CatalogReadScope,
        limit: Option<u16>,
        cursor: Option<&CatalogCursor>,
    ) -> Result<CatalogPage, CatalogReadError> {
        self.read_catalog_until(scope, limit, cursor, Instant::now() + self.deadline)
            .await
    }
    pub async fn read_catalog_until(
        &mut self,
        scope: &CatalogReadScope,
        limit: Option<u16>,
        cursor: Option<&CatalogCursor>,
        deadline: Instant,
    ) -> Result<CatalogPage, CatalogReadError> {
        let limit = limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(CatalogReadError::Limit);
        }
        if cursor.is_some_and(|cursor| cursor.scope != *scope) {
            return Err(CatalogReadError::Cursor);
        }
        if self.client.is_none() {
            return Err(CatalogReadError::Invalidated);
        }
        let deadline = deadline.min(Instant::now() + self.deadline);
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(self);
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CatalogReadError::Invalidated)?;
            let transaction = client
                .build_transaction()
                .isolation_level(IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .await
                .map_err(database_error)?;
            let result = async {
                configure_tenant(
                    &transaction,
                    &scope.ids[0],
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await?;
                page(&transaction, scope, limit, cursor, deadline).await
            }
            .await;
            transaction.rollback().await.map_err(database_error)?;
            empty_context(client).await?;
            check_deadline(deadline)?;
            if !matches!(result, Err(CatalogReadError::Deadline)) {
                guard.confirm();
            }
            result
        };
        timeout_at(deadline, work)
            .await
            .map_err(|_| CatalogReadError::Deadline)?
    }
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
fn corrupt<T>(_: T) -> CatalogReadError {
    CatalogReadError::Corrupt
}
struct BoundedJson(Vec<u8>);
impl io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_PAGE.saturating_sub(self.0.len()) {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(value: &Value) -> Result<Vec<u8>, CatalogReadError> {
    let mut writer = BoundedJson(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(corrupt)?;
    Ok(writer.0)
}
async fn operation(
    transaction: &Transaction<'_>,
    scope: &CatalogReadScope,
) -> Result<[String; 8], CatalogReadError> {
    let [tenant, project, service, operation] = &scope.ids;
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] =
        &[tenant, project, service, operation];
    let metadata = transaction.query_opt("SELECT identity_version,octet_length(canonical_key),octet_length(operation_hash) FROM contour.operations WHERE tenant_id=$1::text::uuid AND project_id=$2::text::uuid AND service_id=$3::text::uuid AND operation_id=$4::text::uuid",params).await.map_err(database_error)?.ok_or(CatalogReadError::NotFound)?;
    if metadata.try_get::<_, i16>(0).map_err(corrupt)? != 1
        || !(1..=2048).contains(&metadata.try_get::<_, i32>(1).map_err(corrupt)?)
        || metadata.try_get::<_, i32>(2).map_err(corrupt)? != 32
    {
        return Err(CatalogReadError::Corrupt);
    }
    let row = transaction.query_one("SELECT canonical_key,encode(operation_hash,'hex'),environment_id::text FROM contour.operations WHERE tenant_id=$1::text::uuid AND project_id=$2::text::uuid AND service_id=$3::text::uuid AND operation_id=$4::text::uuid AND octet_length(canonical_key) BETWEEN 1 AND 2048 AND octet_length(operation_hash)=32",params).await.map_err(database_error)?;
    let parts =
        OperationKey::decode_canonical(row.try_get(0).map_err(corrupt)?).map_err(corrupt)?;
    let key =
        OperationKey::from_components(parts.each_ref().map(String::as_str)).map_err(corrupt)?;
    if parts[0] != *tenant
        || parts[1] != *project
        || parts[2] != *service
        || parts[3] != row.try_get::<_, &str>(2).map_err(corrupt)?
        || key.fingerprint().map_err(corrupt)? != row.try_get::<_, &str>(1).map_err(corrupt)?
    {
        return Err(CatalogReadError::Corrupt);
    }
    Ok(parts)
}
async fn page(
    transaction: &Transaction<'_>,
    scope: &CatalogReadScope,
    limit: u16,
    cursor: Option<&CatalogCursor>,
    deadline: Instant,
) -> Result<CatalogPage, CatalogReadError> {
    let parts = operation(transaction, scope).await?;
    let [tenant, project, service, operation] = &scope.ids;
    let zero = [
        "00000000-0000-0000-0000-000000000000".to_owned(),
        "00000000-0000-0000-0000-000000000000".to_owned(),
        "00000000-0000-0000-0000-000000000000".to_owned(),
        "00000000-0000-0000-0000-000000000000".to_owned(),
    ];
    let after = cursor.map_or(&zero, |cursor| &cursor.after);
    let has_cursor = cursor.is_some();
    let count = i64::from(limit) + 1;
    // Only UUIDs and length/validity metadata. Never fetch shape or name documents
    // for a page until every candidate's individual bound is known.
    let rows = transaction.query("SELECT w.variant_id::text,w.source_id::text,w.batch_id::text,w.record_id::text,w.collector_id::text,(octet_length(v.canonical_structure) BETWEEN 1 AND 65536 AND octet_length(v.structure_wire) BETWEEN 1 AND 65536 AND octet_length(v.structure_hash)=32 AND v.canonicalization_version=1 AND octet_length(v.parser_profile) BETWEEN 1 AND 64 AND octet_length(v.policy_revision::text) BETWEEN 1 AND 20 AND octet_length(w.observation_count::text) BETWEEN 1 AND 10 AND octet_length(w.sample_numerator::text) BETWEEN 1 AND 7 AND octet_length(w.sample_denominator::text) BETWEEN 1 AND 7 AND octet_length(w.visibility) BETWEEN 1 AND 16 AND octet_length(w.completeness) BETWEEN 1 AND 16 AND cardinality(w.reasons)<=8 AND octet_length(w.reasons::text)<=128 AND octet_length(w.first_seen) BETWEEN 20 AND 35 AND octet_length(w.last_seen) BETWEEN 20 AND 35 AND octet_length(w.queued_at) BETWEEN 20 AND 35 AND octet_length(w.expires_at) BETWEEN 20 AND 35 AND octet_length(w.request_header_names) BETWEEN 2 AND 49537 AND octet_length(w.response_header_names) BETWEEN 2 AND 49537 AND octet_length(w.query_parameter_names) BETWEEN 2 AND 49537) FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id) WHERE w.tenant_id=$1::text::uuid AND w.project_id=$2::text::uuid AND w.service_id=$3::text::uuid AND w.operation_id=$4::text::uuid AND (NOT $5 OR (w.variant_id,w.source_id,w.batch_id,w.record_id)>($6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid)) ORDER BY w.variant_id,w.source_id,w.batch_id,w.record_id LIMIT $10", &[tenant,project,service,operation,&has_cursor,&after[0],&after[1],&after[2],&after[3],&count]).await.map_err(database_error)?;
    if rows
        .iter()
        .any(|row| row.try_get::<_, bool>(5).ok() != Some(true))
    {
        return Err(CatalogReadError::Corrupt);
    }
    let mut bytes = b"{\"operation\":".to_vec();
    bytes.extend_from_slice(&encode(
        &json!({"id":operation,"identity_version":1,"key":parts}),
    )?);
    bytes.extend_from_slice(b",\"items\":[");
    let suffix = b"]}";
    let mut last = None;
    let mut more = rows.len() > usize::from(limit);
    for (index, row) in rows.iter().take(usize::from(limit)).enumerate() {
        check_deadline(deadline)?;
        let item = evidence(transaction, scope, &parts, row).await?;
        let encoded = encode(&item)?;
        let needed =
            bytes.len() + encoded.len() + usize::from(index > 0) + suffix.len() + CURSOR_BUDGET;
        if needed > MAX_PAGE {
            more = true;
            break;
        }
        if index > 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(&encoded);
        last = Some([
            row.try_get::<_, String>(0).map_err(corrupt)?,
            row.try_get(1).map_err(corrupt)?,
            row.try_get(2).map_err(corrupt)?,
            row.try_get(3).map_err(corrupt)?,
        ]);
    }
    bytes.extend_from_slice(suffix);
    if more && last.is_none() {
        return Err(CatalogReadError::Corrupt);
    }
    let next = if more {
        Some(CatalogCursor {
            scope: scope.clone(),
            after: last.ok_or(CatalogReadError::Corrupt)?,
        })
    } else {
        None
    };
    Ok(CatalogPage { bytes, next })
}
async fn evidence(
    transaction: &Transaction<'_>,
    scope: &CatalogReadScope,
    parts: &[String; 8],
    metadata: &Row,
) -> Result<Value, CatalogReadError> {
    let [tenant, project, service, operation] = &scope.ids;
    let variant: &str = metadata.try_get(0).map_err(corrupt)?;
    let source: &str = metadata.try_get(1).map_err(corrupt)?;
    let batch: &str = metadata.try_get(2).map_err(corrupt)?;
    let record: &str = metadata.try_get(3).map_err(corrupt)?;
    let collector: &str = metadata.try_get(4).map_err(corrupt)?;
    let row=transaction.query_one("SELECT row_to_json(w)::text,v.parser_profile,v.policy_revision::text,v.canonical_structure,v.structure_wire,encode(v.structure_hash,'hex') FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id) WHERE w.tenant_id=$1::text::uuid AND w.project_id=$2::text::uuid AND w.service_id=$3::text::uuid AND w.operation_id=$4::text::uuid AND w.variant_id=$5::text::uuid AND w.source_id=$6::text::uuid AND w.batch_id=$7::text::uuid AND w.record_id=$8::text::uuid", &[tenant,project,service,operation,&variant,&source,&batch,&record]).await.map_err(database_error)?;
    let stored: Value = serde_json::from_str(row.try_get(0).map_err(corrupt)?).map_err(corrupt)?;
    let wire: &[u8] = row.try_get(4).map_err(corrupt)?;
    let shape = Shape::from_wire_json(wire).map_err(corrupt)?;
    if shape.to_wire_json().map_err(corrupt)? != wire
        || shape.canonical_bytes().map_err(corrupt)?
            != row.try_get::<_, &[u8]>(3).map_err(corrupt)?
        || shape.fingerprint().map_err(corrupt)? != row.try_get::<_, &str>(5).map_err(corrupt)?
    {
        return Err(CatalogReadError::Corrupt);
    }
    let mut record_value = json!({"protocol":parts[4],"direction":parts[5],"operation":parts[6],"route_template":parts[7],"parser_profile":row.try_get::<_,&str>(1).map_err(corrupt)?,"policy_revision":row.try_get::<_,&str>(2).map_err(corrupt)?.parse::<u64>().map_err(corrupt)?,"structure":serde_json::from_slice::<Value>(wire).map_err(corrupt)?});
    for field in [
        "record_id",
        "source_id",
        "project_id",
        "service_id",
        "environment_id",
        "deployment_id",
        "visibility",
        "completeness",
        "reasons",
        "route_uncertain",
        "status_code",
        "first_seen",
        "last_seen",
        "queued_at",
        "expires_at",
        "sample_numerator",
        "sample_denominator",
    ] {
        record_value[field] = stored[field].clone();
    }
    record_value["count"] = stored["observation_count"].clone();
    for field in [
        "request_header_names",
        "response_header_names",
        "query_parameter_names",
    ] {
        let text = stored[field].as_str().ok_or(CatalogReadError::Corrupt)?;
        let hex = text.strip_prefix("\\x").ok_or(CatalogReadError::Corrupt)?;
        if hex.len() % 2 != 0 || hex.len() > 2 * 49537 {
            return Err(CatalogReadError::Corrupt);
        }
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).map_err(corrupt))
            .collect::<Result<Vec<_>, _>>()?;
        record_value[field] = serde_json::from_slice::<Value>(&bytes).map_err(corrupt)?;
    }
    if stored["environment_id"] != parts[3] || stored["collector_id"] != collector {
        return Err(CatalogReadError::Corrupt);
    }
    // Synthetic validation envelope only: created_at=original queued_at. It grants
    // no new capture authority and is not emitted. The checked decoder validates
    // exact timestamps, sampling, completeness/reasons, names and original TTL.
    let envelope = json!({"wire_version":1,"tenant_id":tenant,"collector_id":collector,"batch_id":batch,"created_at":record_value["queued_at"],"records":[record_value]});
    let checked = Batch::from_wire_json(&encode(&envelope)?).map_err(corrupt)?;
    let observation = checked
        .operation_observations()
        .next()
        .ok_or(CatalogReadError::Corrupt)?;
    if observation.key.components() != parts.each_ref().map(String::as_str) {
        return Err(CatalogReadError::Corrupt);
    }
    Ok(
        json!({"variant_id":variant,"collector_id":collector,"batch_id":batch,"canonicalization_version":observation.canonicalization_version,"structure_fingerprint":shape.fingerprint().map_err(corrupt)?,"record":envelope["records"][0]}),
    )
}
