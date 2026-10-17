//! Internal persistence for checked sanitized graphs; no end-user authorization.
use crate::{
    AuthorityError, CatalogError, ConnectedDatabase,
    catalog::store_operation,
    transaction::{
        CancellationGuard, begin, check_deadline, configure_tenant, database_error, empty_context,
    },
};
use contour_core::DeclaredContract;
use std::fmt;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredStoreError {
    Scope,
    NotFound,
    Conflict,
    Corrupt,
    Database,
    Deadline,
    Invalidated,
    OutcomeUnknown,
}
impl fmt::Display for DeclaredStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DeclaredStoreError {}
impl From<AuthorityError> for DeclaredStoreError {
    fn from(error: AuthorityError) -> Self {
        match error {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Invalidated => Self::Invalidated,
            _ => Self::Database,
        }
    }
}
impl From<CatalogError> for DeclaredStoreError {
    fn from(error: CatalogError) -> Self {
        match error {
            CatalogError::Deadline => Self::Deadline,
            CatalogError::Collision => Self::Conflict,
            CatalogError::Corrupt => Self::Corrupt,
            _ => Self::Database,
        }
    }
}
/// Independently trusted operator scope: tenant, project, service, environment.
#[derive(Clone)]
pub struct DeclaredScope {
    pub(crate) ids: [String; 4],
}
impl DeclaredScope {
    pub fn new(ids: [&str; 4]) -> Result<Self, DeclaredStoreError> {
        if !ids.iter().all(|id| uuid(id)) {
            return Err(DeclaredStoreError::Scope);
        }
        Ok(Self {
            ids: ids.map(str::to_owned),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredStatus {
    Stored,
    Duplicate,
    Read,
}
/// Internal UUID and server timestamp are not the public numeric contract revision.
pub struct DeclaredStored {
    status: DeclaredStatus,
    version_id: String,
    created_micros: i64,
    graph: DeclaredContract,
}
impl DeclaredStored {
    pub fn status(&self) -> DeclaredStatus {
        self.status
    }
    pub fn version_id(&self) -> &str {
        &self.version_id
    }
    pub fn created_micros(&self) -> i64 {
        self.created_micros
    }
    pub fn graph(&self) -> &DeclaredContract {
        &self.graph
    }
}
impl fmt::Debug for DeclaredStored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeclaredStored")
    }
}
impl ConnectedDatabase {
    /// Stable caller UUID is the retry identity. Never change it after OutcomeUnknown.
    pub async fn store_declared(
        &mut self,
        scope: &DeclaredScope,
        version_id: &str,
        graph: &DeclaredContract,
    ) -> Result<DeclaredStored, DeclaredStoreError> {
        self.store_declared_until(scope, version_id, graph, Instant::now() + self.deadline)
            .await
    }
    pub async fn store_declared_until(
        &mut self,
        scope: &DeclaredScope,
        version_id: &str,
        graph: &DeclaredContract,
        deadline: Instant,
    ) -> Result<DeclaredStored, DeclaredStoreError> {
        if graph.operation().components()[..4] != scope.ids.each_ref().map(String::as_str) {
            return Err(DeclaredStoreError::Scope);
        }
        self.declared_transaction(scope, version_id, Some(graph), deadline)
            .await
    }
    /// Use a separate declared-reader login. Missing and wrong scope both return NotFound.
    pub async fn read_declared(
        &mut self,
        scope: &DeclaredScope,
        version_id: &str,
    ) -> Result<DeclaredStored, DeclaredStoreError> {
        self.read_declared_until(scope, version_id, Instant::now() + self.deadline)
            .await
    }
    pub async fn read_declared_until(
        &mut self,
        scope: &DeclaredScope,
        version_id: &str,
        deadline: Instant,
    ) -> Result<DeclaredStored, DeclaredStoreError> {
        self.declared_transaction(scope, version_id, None, deadline)
            .await
    }
    async fn declared_transaction(
        &mut self,
        scope: &DeclaredScope,
        version_id: &str,
        graph: Option<&DeclaredContract>,
        deadline: Instant,
    ) -> Result<DeclaredStored, DeclaredStoreError> {
        if !uuid(version_id) {
            return Err(DeclaredStoreError::Scope);
        }
        if self.client.is_none() {
            return Err(DeclaredStoreError::Invalidated);
        }
        let deadline = deadline.min(Instant::now() + self.deadline);
        check_deadline(deadline)?;
        let wire = graph
            .map(DeclaredContract::to_wire_json)
            .transpose()
            .map_err(|_| DeclaredStoreError::Corrupt)?;
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(self);
        let mut committing = false;
        let mut committed = None;
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(DeclaredStoreError::Invalidated)?;
            let transaction = if graph.is_some() {
                begin(client).await?
            } else {
                client
                    .build_transaction()
                    .read_only(true)
                    .start()
                    .await
                    .map_err(database_error)?
            };
            let prepared=async {
                configure_tenant(&transaction,&scope.ids[0],deadline.saturating_duration_since(Instant::now())).await?;
                let mut inserted=false;
                if let Some(graph)=graph {
                    let operation=store_operation(&transaction,graph.operation()).await?;
                    let ids=&scope.ids;
                    inserted=transaction.execute("INSERT INTO contour.declared_versions(tenant_id,version_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,1,$7) ON CONFLICT DO NOTHING", &[&ids[0],&version_id,&operation,&ids[1],&ids[2],&ids[3],&wire.as_ref().ok_or(DeclaredStoreError::Corrupt)?]).await.map_err(database_error)? != 0;
                }
                // Separate statement after conflict: load the winner's committed bytes.
                let mut stored=load(&transaction,scope,version_id).await.map_err(|error| {
                    if graph.is_some() && error==DeclaredStoreError::NotFound { DeclaredStoreError::Conflict } else { error }
                })?;
                check_deadline(deadline)?;
                if let Some(wire)=&wire {
                    if stored.graph.to_wire_json().map_err(|_|DeclaredStoreError::Corrupt)? != *wire { return Err(DeclaredStoreError::Conflict); }
                    stored.status=if inserted { DeclaredStatus::Stored } else { DeclaredStatus::Duplicate };
                }
                if inserted { transaction.query_one("SELECT set_config('synchronous_commit','on',true)",&[]).await.map_err(database_error)?; }
                check_deadline(deadline)?;
                Ok::<_,DeclaredStoreError>(stored)
            }.await;
            match prepared {
                Ok(stored) if stored.status == DeclaredStatus::Stored => {
                    committing = true;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| DeclaredStoreError::OutcomeUnknown)?;
                    committed = Some(stored);
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(None)
                }
                result => {
                    transaction.rollback().await.map_err(database_error)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    if !matches!(result, Err(DeclaredStoreError::Deadline)) {
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
            Ok(Ok(Some(stored))) => Ok(stored),
            Ok(Ok(None)) => Err(DeclaredStoreError::Database),
            Ok(Err(error)) => Err(error),
            Err(_) if committing => Err(DeclaredStoreError::OutcomeUnknown),
            Err(_) => Err(DeclaredStoreError::Deadline),
        }
    }
}
pub(crate) fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
pub(crate) async fn load(
    transaction: &Transaction<'_>,
    scope: &DeclaredScope,
    version_id: &str,
) -> Result<DeclaredStored, DeclaredStoreError> {
    let ids = &scope.ids;
    let params: [&(dyn tokio_postgres::types::ToSql + Sync); 5] =
        [&ids[0], &version_id, &ids[1], &ids[2], &ids[3]];
    let row=transaction.query_opt("SELECT d.codec_version,octet_length(d.declared_wire),o.identity_version,octet_length(o.canonical_key),octet_length(o.operation_hash) FROM contour.declared_versions d JOIN contour.operations o USING(tenant_id,operation_id,project_id,service_id,environment_id) WHERE d.tenant_id=$1::text::uuid AND d.version_id=$2::text::uuid AND d.project_id=$3::text::uuid AND d.service_id=$4::text::uuid AND d.environment_id=$5::text::uuid",&params).await.map_err(database_error)?.ok_or(DeclaredStoreError::NotFound)?;
    if row
        .try_get::<_, i16>(0)
        .map_err(|_| DeclaredStoreError::Corrupt)?
        != 1
        || !(1..=1048576).contains(
            &row.try_get::<_, i32>(1)
                .map_err(|_| DeclaredStoreError::Corrupt)?,
        )
        || row
            .try_get::<_, i16>(2)
            .map_err(|_| DeclaredStoreError::Corrupt)?
            != 1
        || !(1..=2048).contains(
            &row.try_get::<_, i32>(3)
                .map_err(|_| DeclaredStoreError::Corrupt)?,
        )
        || row
            .try_get::<_, i32>(4)
            .map_err(|_| DeclaredStoreError::Corrupt)?
            != 32
    {
        return Err(DeclaredStoreError::Corrupt);
    }
    let row=transaction.query_opt("SELECT d.declared_wire,o.canonical_key,encode(o.operation_hash,'hex'),floor(extract(epoch FROM d.created_at)*1000000)::bigint FROM contour.declared_versions d JOIN contour.operations o USING(tenant_id,operation_id,project_id,service_id,environment_id) WHERE d.tenant_id=$1::text::uuid AND d.version_id=$2::text::uuid AND d.project_id=$3::text::uuid AND d.service_id=$4::text::uuid AND d.environment_id=$5::text::uuid AND d.codec_version=1 AND octet_length(d.declared_wire) BETWEEN 1 AND 1048576 AND o.identity_version=1 AND octet_length(o.canonical_key) BETWEEN 1 AND 2048 AND octet_length(o.operation_hash)=32",&params).await.map_err(database_error)?.ok_or(DeclaredStoreError::Corrupt)?;
    let bytes: &[u8] = row.try_get(0).map_err(|_| DeclaredStoreError::Corrupt)?;
    let graph = DeclaredContract::from_wire_json(bytes).map_err(|_| DeclaredStoreError::Corrupt)?;
    let operation = graph.operation();
    if operation.components()[..4] != ids.each_ref().map(String::as_str)
        || operation
            .canonical_bytes()
            .map_err(|_| DeclaredStoreError::Corrupt)?
            != row
                .try_get::<_, &[u8]>(1)
                .map_err(|_| DeclaredStoreError::Corrupt)?
        || operation
            .fingerprint()
            .map_err(|_| DeclaredStoreError::Corrupt)?
            != row
                .try_get::<_, &str>(2)
                .map_err(|_| DeclaredStoreError::Corrupt)?
        || graph
            .to_wire_json()
            .map_err(|_| DeclaredStoreError::Corrupt)?
            != bytes
    {
        return Err(DeclaredStoreError::Corrupt);
    }
    Ok(DeclaredStored {
        status: DeclaredStatus::Read,
        version_id: version_id.to_owned(),
        created_micros: row.try_get(3).map_err(|_| DeclaredStoreError::Corrupt)?,
        graph,
    })
}
