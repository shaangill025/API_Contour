//! Whole-service persistence with explicit operator and authenticated human APIs.
use crate::{
    AuthorityError, CatalogError, ConnectedDatabase, DeclaredScope, DeclaredStatus,
    DeclaredStoreError, DeclaredStored,
    catalog::store_operation,
    declared_store::{load, uuid},
    transaction::{
        CancellationGuard, begin, check_deadline, configure_tenant, database_error, empty_context,
    },
};
use contour_core::{
    DeclaredImportBundle, ImportBodySelector, ImportBundleWarning, MAX_IMPORT_GRAPH_BYTES,
    MAX_IMPORT_GRAPH_NODES, MAX_IMPORT_MEMBERS, ResponseSelector,
};
use std::{collections::BTreeSet, fmt};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceImportError {
    Scope,
    Forbidden,
    NotFound,
    MissingDefault,
    DefaultChanged,
    Conflict,
    RevisionExhausted,
    UnsupportedProjection,
    Corrupt,
    Database,
    Deadline,
    Invalidated,
    OutcomeUnknown,
}
impl fmt::Display for ServiceImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ServiceImportError {}
impl From<AuthorityError> for ServiceImportError {
    fn from(value: AuthorityError) -> Self {
        match value {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Invalidated => Self::Invalidated,
            _ => Self::Database,
        }
    }
}
impl From<CatalogError> for ServiceImportError {
    fn from(value: CatalogError) -> Self {
        match value {
            CatalogError::Deadline => Self::Deadline,
            CatalogError::Collision => Self::Conflict,
            CatalogError::Corrupt => Self::Corrupt,
            _ => Self::Database,
        }
    }
}
impl From<DeclaredStoreError> for ServiceImportError {
    fn from(value: DeclaredStoreError) -> Self {
        match value {
            DeclaredStoreError::Deadline => Self::Deadline,
            DeclaredStoreError::Invalidated => Self::Invalidated,
            DeclaredStoreError::Corrupt | DeclaredStoreError::NotFound => Self::Corrupt,
            _ => Self::Database,
        }
    }
}
/// Parsed tenant, project and service. Operator callers must trust this scope;
/// human APIs check it against current memberships. Environment resolves separately.
pub struct ServiceImportScope {
    ids: [String; 3],
}
impl ServiceImportScope {
    pub fn new(ids: [&str; 3]) -> Result<Self, ServiceImportError> {
        if !ids.iter().all(|id| uuid(id)) {
            return Err(ServiceImportError::Scope);
        }
        Ok(Self {
            ids: ids.map(str::to_owned),
        })
    }
}
pub struct StoredImportMember {
    declared: DeclaredStored,
    selector: ImportBodySelector,
    media_type: String,
}
impl StoredImportMember {
    pub fn declared(&self) -> &DeclaredStored {
        &self.declared
    }
    pub fn selector(&self) -> ImportBodySelector {
        self.selector
    }
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}
pub struct StoredServiceImport {
    status: DeclaredStatus,
    contract_id: String,
    scope: [String; 4],
    revision: u64,
    created_micros: i64,
    warnings: Vec<ImportBundleWarning>,
    members: Vec<StoredImportMember>,
}
impl fmt::Debug for StoredServiceImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredServiceImport")
    }
}
impl StoredServiceImport {
    pub fn status(&self) -> DeclaredStatus {
        self.status
    }
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }
    pub fn scope(&self) -> [&str; 4] {
        self.scope.each_ref().map(String::as_str)
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn created_micros(&self) -> i64 {
        self.created_micros
    }
    pub fn warnings(&self) -> &[ImportBundleWarning] {
        &self.warnings
    }
    pub fn members(&self) -> &[StoredImportMember] {
        &self.members
    }
}
#[derive(Clone, Copy)]
enum Request<'a> {
    Resolve,
    Read(&'a str),
    Store(&'a str, &'a DeclaredImportBundle),
}
enum Value {
    Scope([String; 4]),
    Stored(StoredServiceImport),
}
impl Value {
    fn inserted(&self) -> bool {
        matches!(self,Self::Stored(s) if s.status==DeclaredStatus::Stored)
    }
}
impl ConnectedDatabase {
    pub async fn resolve_import_default_until(
        &mut self,
        scope: &ServiceImportScope,
        deadline: Instant,
    ) -> Result<[String; 4], ServiceImportError> {
        match self
            .import_transaction(scope, Request::Resolve, None, deadline)
            .await?
        {
            Value::Scope(scope) => Ok(scope),
            _ => Err(ServiceImportError::Corrupt),
        }
    }
    /// Reuse the same contract ID and checked bundle after OutcomeUnknown.
    pub async fn store_service_import_until(
        &mut self,
        scope: &ServiceImportScope,
        contract_id: &str,
        bundle: &DeclaredImportBundle,
        deadline: Instant,
    ) -> Result<StoredServiceImport, ServiceImportError> {
        if bundle.scope()[..3] != scope.ids.each_ref().map(String::as_str) {
            return Err(ServiceImportError::Scope);
        }
        match self
            .import_transaction(scope, Request::Store(contract_id, bundle), None, deadline)
            .await?
        {
            Value::Stored(stored) => Ok(stored),
            _ => Err(ServiceImportError::Corrupt),
        }
    }
    pub async fn read_service_import_until(
        &mut self,
        scope: &ServiceImportScope,
        contract_id: &str,
        deadline: Instant,
    ) -> Result<StoredServiceImport, ServiceImportError> {
        match self
            .import_transaction(scope, Request::Read(contract_id), None, deadline)
            .await?
        {
            Value::Stored(stored) => Ok(stored),
            _ => Err(ServiceImportError::Corrupt),
        }
    }
    /// Requires current service-owner membership; locks authorization until rollback.
    pub async fn resolve_import_default_as_human_until(
        &mut self,
        identity: &contour_auth::VerifiedIdentity,
        scope: &ServiceImportScope,
        deadline: Instant,
    ) -> Result<[String; 4], ServiceImportError> {
        match self
            .import_transaction(scope, Request::Resolve, Some(identity), deadline)
            .await?
        {
            Value::Scope(scope) => Ok(scope),
            _ => Err(ServiceImportError::Corrupt),
        }
    }
    /// Requires current service-owner membership, including for historical retries.
    /// Reuse the same contract ID and checked bundle after OutcomeUnknown.
    pub async fn store_service_import_as_human_until(
        &mut self,
        identity: &contour_auth::VerifiedIdentity,
        scope: &ServiceImportScope,
        contract_id: &str,
        bundle: &DeclaredImportBundle,
        deadline: Instant,
    ) -> Result<StoredServiceImport, ServiceImportError> {
        if bundle.scope()[..3] != scope.ids.each_ref().map(String::as_str) {
            return Err(ServiceImportError::Scope);
        }
        match self
            .import_transaction(
                scope,
                Request::Store(contract_id, bundle),
                Some(identity),
                deadline,
            )
            .await?
        {
            Value::Stored(stored) => Ok(stored),
            _ => Err(ServiceImportError::Corrupt),
        }
    }
    /// Requires current viewer or service-owner membership. Use a dedicated login
    /// with human lookup and business reader privileges, not provisioning rights.
    pub async fn read_service_import_as_human_until(
        &mut self,
        identity: &contour_auth::VerifiedIdentity,
        scope: &ServiceImportScope,
        contract_id: &str,
        deadline: Instant,
    ) -> Result<StoredServiceImport, ServiceImportError> {
        match self
            .import_transaction(scope, Request::Read(contract_id), Some(identity), deadline)
            .await?
        {
            Value::Stored(stored) => Ok(stored),
            _ => Err(ServiceImportError::Corrupt),
        }
    }
    async fn import_transaction(
        &mut self,
        scope: &ServiceImportScope,
        request: Request<'_>,
        identity: Option<&contour_auth::VerifiedIdentity>,
        deadline: Instant,
    ) -> Result<Value, ServiceImportError> {
        if let Request::Read(id) | Request::Store(id, _) = request {
            if !uuid(id) {
                return Err(ServiceImportError::Scope);
            }
        }
        if self.client.is_none() {
            return Err(ServiceImportError::Invalidated);
        }
        let deadline = deadline.min(Instant::now() + self.deadline);
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(self);
        let mut committing = false;
        let mut committed = None;
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(ServiceImportError::Invalidated)?;
            let tx = if identity.is_some() || matches!(request, Request::Store(..)) {
                begin(client).await?
            } else {
                client
                    .build_transaction()
                    .read_only(true)
                    .start()
                    .await
                    .map_err(database_error)?
            };
            let prepared = async {
                configure_tenant(
                    &tx,
                    &scope.ids[0],
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await?;
                if let Some(identity) = identity {
                    crate::human_authorization::authorize(
                        &tx,
                        identity,
                        scope.ids.each_ref().map(String::as_str),
                        !matches!(request, Request::Read(..)),
                    )
                    .await?;
                }
                let value = match request {
                    Request::Resolve => Value::Scope(default_scope(&tx, scope, false).await?),
                    Request::Read(id) => {
                        Value::Stored(load_import(&tx, scope, id, deadline).await?)
                    }
                    Request::Store(id, bundle) => {
                        Value::Stored(store_import(&tx, scope, id, bundle, deadline).await?)
                    }
                };
                if value.inserted() {
                    tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
                        .await
                        .map_err(database_error)?;
                    tx.query_one("SELECT set_config('synchronous_commit','on',true)", &[])
                        .await
                        .map_err(database_error)?;
                }
                if let Some(identity) = identity {
                    crate::human_authorization::check_expiry(&tx, identity).await?;
                }
                check_deadline(deadline)?;
                Ok::<_, ServiceImportError>(value)
            }
            .await;
            match prepared {
                Ok(value) if value.inserted() => {
                    committing = true;
                    tx.commit()
                        .await
                        .map_err(|_| ServiceImportError::OutcomeUnknown)?;
                    committed = Some(value);
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(None)
                }
                result => {
                    tx.rollback().await.map_err(database_error)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    if !matches!(result, Err(ServiceImportError::Deadline)) {
                        guard.confirm();
                    }
                    result.map(Some)
                }
            }
        };
        let result = timeout_at(deadline, work).await;
        if let Some(stored) = committed {
            return Ok(stored);
        }
        match result {
            Ok(Ok(Some(value))) => Ok(value),
            Ok(Ok(None)) => Err(ServiceImportError::Database),
            Ok(Err(error)) => Err(error),
            Err(_) if committing => Err(ServiceImportError::OutcomeUnknown),
            Err(_) => Err(ServiceImportError::Deadline),
        }
    }
}
async fn default_scope(
    tx: &Transaction<'_>,
    scope: &ServiceImportScope,
    lock: bool,
) -> Result<[String; 4], ServiceImportError> {
    let sql = if lock {
        "SELECT environment_id::text FROM contour.service_import_defaults WHERE tenant_id=$1::text::uuid AND project_id=$2::text::uuid AND service_id=$3::text::uuid FOR UPDATE"
    } else {
        "SELECT environment_id::text FROM contour.service_import_defaults WHERE tenant_id=$1::text::uuid AND project_id=$2::text::uuid AND service_id=$3::text::uuid"
    };
    let ids = &scope.ids;
    let row = tx
        .query_opt(sql, &[&ids[0], &ids[1], &ids[2]])
        .await
        .map_err(database_error)?
        .ok_or(ServiceImportError::MissingDefault)?;
    let environment: String = row.try_get(0).map_err(|_| ServiceImportError::Corrupt)?;
    if !uuid(&environment) {
        return Err(ServiceImportError::Corrupt);
    }
    Ok([ids[0].clone(), ids[1].clone(), ids[2].clone(), environment])
}
fn selector_text(selector: ImportBodySelector) -> String {
    match selector {
        ImportBodySelector::Request => "request".into(),
        ImportBodySelector::Response(ResponseSelector::Status(code)) => format!("response:{code}"),
        ImportBodySelector::Response(ResponseSelector::Class(code)) => format!("response:{code}XX"),
        ImportBodySelector::Response(ResponseSelector::Default) => "response:default".into(),
    }
}
fn parse_selector(text: &str) -> Result<ImportBodySelector, ServiceImportError> {
    if text == "request" {
        return Ok(ImportBodySelector::Request);
    }
    let status = text
        .strip_prefix("response:")
        .ok_or(ServiceImportError::Corrupt)?;
    let value = if status == "default" {
        ResponseSelector::Default
    } else if status.len() == 3 && matches!(status.as_bytes()[0], b'1'..=b'5') {
        if &status.as_bytes()[1..] == b"XX" {
            ResponseSelector::Class(status.as_bytes()[0] - b'0')
        } else if status.bytes().all(|b| b.is_ascii_digit()) {
            ResponseSelector::Status(status.parse().map_err(|_| ServiceImportError::Corrupt)?)
        } else {
            return Err(ServiceImportError::Corrupt);
        }
    } else {
        return Err(ServiceImportError::Corrupt);
    };
    Ok(ImportBodySelector::Response(value))
}
fn warning_text(warning: ImportBundleWarning) -> &'static str {
    match warning {
        ImportBundleWarning::RemovedValue => "removed_value",
        ImportBundleWarning::UnsupportedConstruct => "unsupported_construct",
        ImportBundleWarning::PartialImport => "partial_import",
    }
}
fn parse_warning(value: &str) -> Result<ImportBundleWarning, ServiceImportError> {
    match value {
        "removed_value" => Ok(ImportBundleWarning::RemovedValue),
        "unsupported_construct" => Ok(ImportBundleWarning::UnsupportedConstruct),
        "partial_import" => Ok(ImportBundleWarning::PartialImport),
        _ => Err(ServiceImportError::Corrupt),
    }
}
async fn store_import(
    tx: &Transaction<'_>,
    scope: &ServiceImportScope,
    id: &str,
    bundle: &DeclaredImportBundle,
    deadline: Instant,
) -> Result<StoredServiceImport, ServiceImportError> {
    match load_import(tx, scope, id, deadline).await {
        Ok(stored) => return exact_retry(stored, bundle),
        Err(ServiceImportError::NotFound) => {}
        Err(e) => return Err(e),
    }
    let resolved = default_scope(tx, scope, true).await?;
    // Fresh statement after the lock observes a concurrent winner's commit.
    match load_import(tx, scope, id, deadline).await {
        Ok(stored) => return exact_retry(stored, bundle),
        Err(ServiceImportError::NotFound) => {}
        Err(e) => return Err(e),
    }
    if resolved.each_ref().map(String::as_str) != bundle.scope() {
        return Err(ServiceImportError::DefaultChanged);
    }
    let ids = &scope.ids;
    let row=tx.query_one("SELECT coalesce(max(revision),0) FROM contour.public_declared_contracts WHERE tenant_id=$1::text::uuid AND project_id=$2::text::uuid AND service_id=$3::text::uuid",&[&ids[0],&ids[1],&ids[2]]).await.map_err(database_error)?;
    let previous: i64 = row.try_get(0).map_err(|_| ServiceImportError::Corrupt)?;
    if !(0..9_007_199_254_740_991).contains(&previous) {
        return Err(ServiceImportError::RevisionExhausted);
    }
    let revision = previous + 1;
    let count = i32::try_from(bundle.members().len()).map_err(|_| ServiceImportError::Corrupt)?;
    let warnings: Vec<_> = bundle
        .warnings()
        .iter()
        .copied()
        .map(warning_text)
        .collect();
    let inserted=tx.execute("INSERT INTO contour.public_declared_contracts(tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,warnings,projection_version) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6,$7,$8,2) ON CONFLICT DO NOTHING",&[&ids[0],&id,&ids[1],&ids[2],&resolved[3],&revision,&count,&warnings]).await.map_err(database_error)?;
    if inserted != 1 {
        return Err(ServiceImportError::Conflict);
    }
    for member in bundle.members() {
        check_deadline(deadline)?;
        let operation = store_operation(tx, member.graph().operation()).await?;
        let wire = member
            .graph()
            .to_wire_json()
            .map_err(|_| ServiceImportError::Corrupt)?;
        let row=tx.query_one("INSERT INTO contour.declared_versions(tenant_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,1,$6) RETURNING version_id::text",&[&ids[0],&operation,&ids[1],&ids[2],&resolved[3],&wire]).await.map_err(database_error)?;
        let version: String = row.try_get(0).map_err(|_| ServiceImportError::Corrupt)?;
        let selector = selector_text(member.selector());
        tx.execute("INSERT INTO contour.public_declared_members(tenant_id,contract_id,version_id,operation_id,project_id,service_id,environment_id,body_selector,media_type) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8,$9)",&[&ids[0],&id,&version,&operation,&ids[1],&ids[2],&resolved[3],&selector,&member.media_type()]).await.map_err(database_error)?;
    }
    let mut stored = load_import(tx, scope, id, deadline).await?;
    stored.status = DeclaredStatus::Stored;
    Ok(stored)
}
fn exact_retry(
    mut stored: StoredServiceImport,
    bundle: &DeclaredImportBundle,
) -> Result<StoredServiceImport, ServiceImportError> {
    if stored.scope() != bundle.scope() || stored.warnings() != bundle.warnings() {
        return Err(ServiceImportError::Conflict);
    }
    let mut expected = bundle
        .members()
        .iter()
        .map(|m| {
            Ok((
                m.selector(),
                m.media_type().to_owned(),
                m.graph()
                    .to_wire_json()
                    .map_err(|_| ServiceImportError::Corrupt)?,
            ))
        })
        .collect::<Result<Vec<_>, ServiceImportError>>()?;
    let mut actual = stored
        .members
        .iter()
        .map(|m| {
            Ok((
                m.selector,
                m.media_type.clone(),
                m.declared
                    .graph()
                    .to_wire_json()
                    .map_err(|_| ServiceImportError::Corrupt)?,
            ))
        })
        .collect::<Result<Vec<_>, ServiceImportError>>()?;
    expected.sort();
    actual.sort();
    if expected != actual {
        return Err(ServiceImportError::Conflict);
    }
    stored.status = DeclaredStatus::Duplicate;
    Ok(stored)
}
async fn load_import(
    tx: &Transaction<'_>,
    scope: &ServiceImportScope,
    id: &str,
    deadline: Instant,
) -> Result<StoredServiceImport, ServiceImportError> {
    let ids = &scope.ids;
    let params: [&(dyn tokio_postgres::types::ToSql + Sync); 4] = [&ids[0], &id, &ids[1], &ids[2]];
    let header=tx.query_opt("SELECT environment_id::text,projection_version,revision,member_count,floor(extract(epoch FROM created_at)*1000000)::bigint,cardinality(warnings)<=3 AND array_position(warnings,NULL) IS NULL AND warnings <@ ARRAY['removed_value','unsupported_construct','partial_import']::text[] FROM contour.public_declared_contracts WHERE tenant_id=$1::text::uuid AND contract_id=$2::text::uuid AND project_id=$3::text::uuid AND service_id=$4::text::uuid",&params).await.map_err(database_error)?.ok_or(ServiceImportError::NotFound)?;
    if header
        .try_get::<_, i16>(1)
        .map_err(|_| ServiceImportError::Corrupt)?
        != 2
    {
        return Err(ServiceImportError::UnsupportedProjection);
    }
    let environment: String = header.try_get(0).map_err(|_| ServiceImportError::Corrupt)?;
    let revision: i64 = header.try_get(2).map_err(|_| ServiceImportError::Corrupt)?;
    let count: i32 = header.try_get(3).map_err(|_| ServiceImportError::Corrupt)?;
    if !(1..=9_007_199_254_740_991).contains(&revision)
        || !(0..=MAX_IMPORT_MEMBERS as i32).contains(&count)
        || !header
            .try_get::<_, bool>(5)
            .map_err(|_| ServiceImportError::Corrupt)?
    {
        return Err(ServiceImportError::Corrupt);
    }
    let full_scope = DeclaredScope::new([&ids[0], &ids[1], &ids[2], &environment])
        .map_err(|_| ServiceImportError::Corrupt)?;
    let row=tx.query_one("SELECT warnings FROM contour.public_declared_contracts WHERE tenant_id=$1::text::uuid AND contract_id=$2::text::uuid AND project_id=$3::text::uuid AND service_id=$4::text::uuid",&params).await.map_err(database_error)?;
    let raw: Vec<String> = row.try_get(0).map_err(|_| ServiceImportError::Corrupt)?;
    let mut warnings = raw
        .iter()
        .map(|w| parse_warning(w))
        .collect::<Result<Vec<_>, _>>()?;
    warnings.sort();
    if warnings.windows(2).any(|w| w[0] == w[1]) {
        return Err(ServiceImportError::Corrupt);
    }
    // Inspect aggregate payload sizes and bounded metadata before fetching graph bytes.
    let rows=tx.query("SELECT m.version_id::text,octet_length(m.body_selector),octet_length(m.media_type),octet_length(d.declared_wire) FROM contour.public_declared_members m JOIN contour.declared_versions d USING(tenant_id,version_id,operation_id,project_id,service_id,environment_id) WHERE m.tenant_id=$1::text::uuid AND m.contract_id=$2::text::uuid AND m.project_id=$3::text::uuid AND m.service_id=$4::text::uuid LIMIT 4097",&params).await.map_err(database_error)?;
    if rows.len() != count as usize {
        return Err(ServiceImportError::Corrupt);
    }
    let mut total = 0usize;
    for row in &rows {
        let selector: i32 = row.try_get(1).map_err(|_| ServiceImportError::Corrupt)?;
        let media: i32 = row.try_get(2).map_err(|_| ServiceImportError::Corrupt)?;
        let bytes: i32 = row.try_get(3).map_err(|_| ServiceImportError::Corrupt)?;
        if !(1..=16).contains(&selector)
            || !(1..=128).contains(&media)
            || !(1..=1_048_576).contains(&bytes)
        {
            return Err(ServiceImportError::Corrupt);
        }
        total = total
            .checked_add(bytes as usize)
            .ok_or(ServiceImportError::Corrupt)?;
        if total > MAX_IMPORT_GRAPH_BYTES {
            return Err(ServiceImportError::Corrupt);
        }
    }
    let mut members = Vec::new();
    let mut nodes = 0usize;
    let mut identities = BTreeSet::new();
    for row in rows {
        check_deadline(deadline)?;
        let version: String = row.try_get(0).map_err(|_| ServiceImportError::Corrupt)?;
        let metadata=tx.query_one("SELECT body_selector,media_type FROM contour.public_declared_members WHERE tenant_id=$1::text::uuid AND contract_id=$2::text::uuid AND version_id=$3::text::uuid",&[&ids[0],&id,&version]).await.map_err(database_error)?;
        let selector = parse_selector(
            metadata
                .try_get(0)
                .map_err(|_| ServiceImportError::Corrupt)?,
        )?;
        let media: String = metadata
            .try_get(1)
            .map_err(|_| ServiceImportError::Corrupt)?;
        let token = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        };
        if !media
            .split_once('/')
            .is_some_and(|(a, b)| token(a) && token(b))
        {
            return Err(ServiceImportError::Corrupt);
        }
        let declared = load(tx, &full_scope, &version).await?;
        let key = declared.graph().operation();
        let direction = if selector == ImportBodySelector::Request {
            "request"
        } else {
            "response"
        };
        if key.components()[4] != "http"
            || key.components()[5] != direction
            || !matches!(
                key.components()[6],
                "DELETE" | "GET" | "HEAD" | "OPTIONS" | "PATCH" | "POST" | "PUT" | "TRACE"
            )
        {
            return Err(ServiceImportError::Corrupt);
        }
        let identity = (
            key.canonical_bytes()
                .map_err(|_| ServiceImportError::Corrupt)?,
            selector,
            media.clone(),
        );
        if !identities.insert(identity) {
            return Err(ServiceImportError::Corrupt);
        }
        nodes += declared.graph().nodes().len();
        if nodes > MAX_IMPORT_GRAPH_NODES {
            return Err(ServiceImportError::Corrupt);
        }
        members.push(StoredImportMember {
            declared,
            selector,
            media_type: media,
        });
    }
    // Graph wire contains its canonical operation identity; sorting is stable across reloads.
    members.sort_by_cached_key(|m| {
        (
            m.declared
                .graph()
                .operation()
                .components()
                .map(str::to_owned),
            m.selector,
            m.media_type.clone(),
        )
    });
    Ok(StoredServiceImport {
        status: DeclaredStatus::Read,
        contract_id: id.to_owned(),
        scope: full_scope.ids,
        revision: revision as u64,
        created_micros: header.try_get(4).map_err(|_| ServiceImportError::Corrupt)?,
        warnings,
        members,
    })
}

impl From<crate::human_authorization::HumanAuthorizationError> for ServiceImportError {
    fn from(value: crate::human_authorization::HumanAuthorizationError) -> Self {
        use crate::human_authorization::HumanAuthorizationError as H;
        match value {
            H::Forbidden => Self::Forbidden,
            H::Corrupt => Self::Corrupt,
            H::Database => Self::Database,
            H::Deadline => Self::Deadline,
            H::Invalidated => Self::Invalidated,
        }
    }
}
