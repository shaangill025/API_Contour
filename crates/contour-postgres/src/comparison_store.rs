//! Internal immutable comparisons; caller identities never supply result bytes.
use crate::{
    AuthorityError, ConnectedDatabase, DeclaredScope, DeclaredStoreError,
    declared_store::{load, uuid},
    transaction::{
        CancellationGuard, begin, check_deadline, configure_tenant, database_error, empty_context,
    },
};
use contour_core::{DeclaredVersionComparison, DeclaredVersionError, compare_declared_versions};
use std::fmt;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComparisonStoreError {
    Scope,
    NotFound,
    Conflict,
    Corrupt,
    UnsupportedDirection,
    Limit,
    Database,
    Deadline,
    Invalidated,
    OutcomeUnknown,
}
type Error = ComparisonStoreError;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<AuthorityError> for Error {
    fn from(e: AuthorityError) -> Self {
        match e {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Invalidated => Self::Invalidated,
            _ => Self::Database,
        }
    }
}
impl From<DeclaredStoreError> for Error {
    fn from(e: DeclaredStoreError) -> Self {
        match e {
            DeclaredStoreError::NotFound => Self::NotFound,
            DeclaredStoreError::Corrupt => Self::Corrupt,
            DeclaredStoreError::Deadline => Self::Deadline,
            _ => Self::Database,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct ComparisonInput {
    kind: &'static str,
    id: String,
}
impl ComparisonInput {
    pub fn declared(version: &str) -> Result<Self, Error> {
        Self::new("declared", version)
    }
    pub fn approved(event: &str) -> Result<Self, Error> {
        Self::new("approved", event)
    }
    fn new(kind: &'static str, id: &str) -> Result<Self, Error> {
        if !uuid(id) {
            return Err(Error::Scope);
        }
        Ok(Self {
            kind,
            id: id.into(),
        })
    }
    pub fn kind(&self) -> &str {
        self.kind
    }
    pub fn id(&self) -> &str {
        &self.id
    }
}
#[derive(Clone)]
pub struct ComparisonRequest {
    operation: String,
    id: String,
    inputs: [ComparisonInput; 2],
}
impl ComparisonRequest {
    pub fn new(
        operation: &str,
        id: &str,
        left: ComparisonInput,
        right: ComparisonInput,
    ) -> Result<Self, Error> {
        if !uuid(operation) || !uuid(id) {
            return Err(Error::Scope);
        }
        Ok(Self {
            operation: operation.into(),
            id: id.into(),
            inputs: [left, right],
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComparisonStatus {
    Stored,
    Duplicate,
    Read,
}
pub struct ComparisonStored {
    status: ComparisonStatus,
    id: String,
    inputs: [ComparisonInput; 2],
    versions: [String; 2],
    created_micros: i64,
    result: DeclaredVersionComparison,
}
impl ComparisonStored {
    pub fn status(&self) -> ComparisonStatus {
        self.status
    }
    pub fn comparison_id(&self) -> &str {
        &self.id
    }
    pub fn inputs(&self) -> &[ComparisonInput; 2] {
        &self.inputs
    }
    pub fn versions(&self) -> &[String; 2] {
        &self.versions
    }
    pub fn created_micros(&self) -> i64 {
        self.created_micros
    }
    pub fn result(&self) -> &DeclaredVersionComparison {
        &self.result
    }
}
impl fmt::Debug for ComparisonStored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ComparisonStored")
    }
}
impl ConnectedDatabase {
    /// Requires comparison-writer plus declared-reader roles. Retry unchanged identities.
    pub async fn store_comparison(
        &mut self,
        scope: &DeclaredScope,
        request: &ComparisonRequest,
    ) -> Result<ComparisonStored, Error> {
        self.store_comparison_until(scope, request, Instant::now() + self.deadline)
            .await
    }
    pub async fn store_comparison_until(
        &mut self,
        scope: &DeclaredScope,
        request: &ComparisonRequest,
        deadline: Instant,
    ) -> Result<ComparisonStored, Error> {
        self.comparison_transaction(
            scope,
            &request.operation,
            &request.id,
            Some(&request.inputs),
            deadline,
        )
        .await
    }
    /// Requires comparison-reader plus declared-reader roles; recomputes exact inputs.
    pub async fn read_comparison(
        &mut self,
        scope: &DeclaredScope,
        operation: &str,
        id: &str,
    ) -> Result<ComparisonStored, Error> {
        self.read_comparison_until(scope, operation, id, Instant::now() + self.deadline)
            .await
    }
    pub async fn read_comparison_until(
        &mut self,
        scope: &DeclaredScope,
        operation: &str,
        id: &str,
        deadline: Instant,
    ) -> Result<ComparisonStored, Error> {
        self.comparison_transaction(scope, operation, id, None, deadline)
            .await
    }
    async fn comparison_transaction(
        &mut self,
        scope: &DeclaredScope,
        operation: &str,
        id: &str,
        inputs: Option<&[ComparisonInput; 2]>,
        deadline: Instant,
    ) -> Result<ComparisonStored, Error> {
        if !uuid(operation) || !uuid(id) {
            return Err(Error::Scope);
        }
        if self.client.is_none() {
            return Err(Error::Invalidated);
        }
        let deadline = deadline.min(Instant::now() + self.deadline);
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(self);
        let mut committing = false;
        let mut committed = None;
        let work = async {
            let client = guard.connection.client.as_mut().ok_or(Error::Invalidated)?;
            let transaction = if inputs.is_some() {
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
                    &transaction,
                    &scope.ids[0],
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await?;
                let stored = prepare(&transaction, scope, operation, id, inputs, deadline).await?;
                if stored.status == ComparisonStatus::Stored {
                    transaction
                        .query_one("SELECT set_config('synchronous_commit','on',true)", &[])
                        .await
                        .map_err(database_error)?;
                }
                check_deadline(deadline)?;
                Ok::<_, Error>(stored)
            }
            .await;
            match prepared {
                Ok(stored) if stored.status == ComparisonStatus::Stored => {
                    committing = true;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| Error::OutcomeUnknown)?;
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
                    if !matches!(result, Err(Error::Deadline)) {
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
            Ok(Ok(None)) => Err(Error::Database),
            Ok(Err(e)) => Err(e),
            Err(_) if committing => Err(Error::OutcomeUnknown),
            Err(_) => Err(Error::Deadline),
        }
    }
}
async fn resolve(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    operation: &str,
    input: &ComparisonInput,
) -> Result<String, Error> {
    let ids = &scope.ids;
    let query = if input.kind == "declared" {
        "SELECT version_id::text FROM contour.declared_versions WHERE tenant_id=$1::text::uuid AND operation_id=$2::text::uuid AND version_id=$3::text::uuid AND project_id=$4::text::uuid AND service_id=$5::text::uuid AND environment_id=$6::text::uuid"
    } else {
        "SELECT version_id::text FROM contour.approval_events WHERE tenant_id=$1::text::uuid AND operation_id=$2::text::uuid AND event_id=$3::text::uuid AND project_id=$4::text::uuid AND service_id=$5::text::uuid AND environment_id=$6::text::uuid"
    };
    tx.query_opt(
        query,
        &[&ids[0], &operation, &input.id, &ids[1], &ids[2], &ids[3]],
    )
    .await
    .map_err(database_error)?
    .ok_or(Error::NotFound)?
    .try_get(0)
    .map_err(|_| Error::Corrupt)
}
async fn evaluate(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    versions: &[String; 2],
    deadline: Instant,
) -> Result<DeclaredVersionComparison, Error> {
    let left = load(tx, scope, &versions[0]).await?;
    let right = load(tx, scope, &versions[1]).await?;
    check_deadline(deadline)?;
    let result = compare_declared_versions(left.graph(), right.graph()).map_err(|e| match e {
        DeclaredVersionError::OperationScope => Error::Corrupt,
        DeclaredVersionError::UnsupportedDirection => Error::UnsupportedDirection,
        _ => Error::Limit,
    })?;
    check_deadline(deadline)?;
    Ok(result)
}
async fn prepare(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    operation: &str,
    id: &str,
    inputs: Option<&[ComparisonInput; 2]>,
    deadline: Instant,
) -> Result<ComparisonStored, Error> {
    let ids = &scope.ids;
    let mut inserted = false;
    let expected = if let Some(inputs) = inputs {
        let versions = [
            resolve(tx, scope, operation, &inputs[0]).await?,
            resolve(tx, scope, operation, &inputs[1]).await?,
        ];
        let wire = evaluate(tx, scope, &versions, deadline)
            .await?
            .to_wire_json()
            .map_err(|_| Error::Limit)?;
        check_deadline(deadline)?;
        let events = inputs.each_ref().map(|input| {
            if input.kind == "approved" {
                Some(input.id.as_str())
            } else {
                None
            }
        });
        inserted=tx.execute("INSERT INTO contour.comparisons(tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,left_kind,left_version_id,left_event_id,right_kind,right_version_id,right_event_id,evaluator_version,result_codec_version,result_wire) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7,$8::text::uuid,$9::text::uuid,$10,$11::text::uuid,$12::text::uuid,1,1,$13) ON CONFLICT DO NOTHING",&[&ids[0],&id,&operation,&ids[1],&ids[2],&ids[3],&inputs[0].kind,&versions[0],&events[0],&inputs[1].kind,&versions[1],&events[1],&wire]).await.map_err(database_error)? != 0;
        Some((versions, wire))
    } else {
        None
    };
    // A new READ COMMITTED statement observes the winner of a concurrent insert.
    let params: [&(dyn tokio_postgres::types::ToSql + Sync); 6] =
        [&ids[0], &id, &operation, &ids[1], &ids[2], &ids[3]];
    let row=tx.query_opt("SELECT left_kind,left_version_id::text,left_event_id::text,right_kind,right_version_id::text,right_event_id::text,evaluator_version,result_codec_version,octet_length(result_wire),floor(extract(epoch FROM created_at)*1000000)::bigint FROM contour.comparisons WHERE tenant_id=$1::text::uuid AND comparison_id=$2::text::uuid AND operation_id=$3::text::uuid AND project_id=$4::text::uuid AND service_id=$5::text::uuid AND environment_id=$6::text::uuid",&params).await.map_err(database_error)?.ok_or(if inputs.is_some(){Error::Conflict}else{Error::NotFound})?;
    for index in [6, 7] {
        if row.try_get::<_, i16>(index).map_err(|_| Error::Corrupt)? != 1 {
            return Err(Error::Corrupt);
        }
    }
    if !(1..=1_048_576).contains(&row.try_get::<_, i32>(8).map_err(|_| Error::Corrupt)?) {
        return Err(Error::Corrupt);
    }
    let versions: [String; 2] = [
        row.try_get(1).map_err(|_| Error::Corrupt)?,
        row.try_get(4).map_err(|_| Error::Corrupt)?,
    ];
    let side = |offset| -> Result<ComparisonInput, Error> {
        let kind: &str = row.try_get(offset).map_err(|_| Error::Corrupt)?;
        let version: &str = row.try_get(offset + 1).map_err(|_| Error::Corrupt)?;
        let event: Option<&str> = row.try_get(offset + 2).map_err(|_| Error::Corrupt)?;
        match (kind, event) {
            ("declared", None) => ComparisonInput::declared(version),
            ("approved", Some(event)) => ComparisonInput::approved(event),
            _ => Err(Error::Corrupt),
        }
        .map_err(|_| Error::Corrupt)
    };
    let actual = [side(0)?, side(3)?];
    if let Some(inputs) = inputs {
        if inputs != &actual {
            return Err(Error::Conflict);
        }
    }
    for i in 0..2 {
        let resolved = resolve(tx, scope, operation, &actual[i])
            .await
            .map_err(|e| {
                if e == Error::NotFound {
                    Error::Corrupt
                } else {
                    e
                }
            })?;
        if resolved != versions[i] {
            return Err(Error::Corrupt);
        }
    }
    let row_bytes=tx.query_opt("SELECT result_wire FROM contour.comparisons WHERE tenant_id=$1::text::uuid AND comparison_id=$2::text::uuid AND operation_id=$3::text::uuid AND project_id=$4::text::uuid AND service_id=$5::text::uuid AND environment_id=$6::text::uuid AND evaluator_version=1 AND result_codec_version=1 AND octet_length(result_wire) BETWEEN 1 AND 1048576",&params).await.map_err(database_error)?.ok_or(Error::Corrupt)?;
    let bytes: &[u8] = row_bytes.try_get(0).map_err(|_| Error::Corrupt)?;
    let result = DeclaredVersionComparison::from_wire_json(bytes).map_err(|_| Error::Corrupt)?;
    let recomputed = if let Some((expected_versions, wire)) = expected {
        if expected_versions != versions {
            return Err(Error::Corrupt);
        }
        wire
    } else {
        evaluate(tx, scope, &versions, deadline)
            .await
            .map_err(|e| match e {
                Error::NotFound | Error::Limit | Error::UnsupportedDirection => Error::Corrupt,
                _ => e,
            })?
            .to_wire_json()
            .map_err(|_| Error::Corrupt)?
    };
    if result.to_wire_json().map_err(|_| Error::Corrupt)? != bytes || recomputed != bytes {
        return Err(Error::Corrupt);
    }
    check_deadline(deadline)?;
    Ok(ComparisonStored {
        status: if inserted {
            ComparisonStatus::Stored
        } else if inputs.is_some() {
            ComparisonStatus::Duplicate
        } else {
            ComparisonStatus::Read
        },
        id: id.into(),
        inputs: actual,
        versions,
        created_micros: row.try_get(9).map_err(|_| Error::Corrupt)?,
        result,
    })
}
