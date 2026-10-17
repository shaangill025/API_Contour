//! Trusted internal association CAS, not authenticated public review decisions.
use crate::{
    AuthorityError, ConnectedDatabase, DeclaredScope,
    declared_store::uuid,
    transaction::{
        CancellationGuard, begin, check_deadline, configure_tenant, database_error, empty_context,
    },
};
use std::fmt;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    Scope,
    NotFound,
    Conflict,
    Corrupt,
    Database,
    Deadline,
    Invalidated,
    OutcomeUnknown,
}
impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ApprovalError {}
impl From<AuthorityError> for ApprovalError {
    fn from(error: AuthorityError) -> Self {
        match error {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Invalidated => Self::Invalidated,
            _ => Self::Database,
        }
    }
}
/// UUID identity is distinct from both public contract and review revisions.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    operation: String,
    event: String,
    version: String,
    expected: Option<String>,
    actor: String,
}
impl ApprovalRequest {
    pub fn new(
        operation: &str,
        event: &str,
        version: &str,
        expected: Option<&str>,
        actor: &str,
    ) -> Result<Self, ApprovalError> {
        if ![operation, event, version, actor].into_iter().all(uuid)
            || expected.is_some_and(|id| !uuid(id) || id == event)
        {
            return Err(ApprovalError::Scope);
        }
        Ok(Self {
            operation: operation.into(),
            event: event.into(),
            version: version.into(),
            expected: expected.map(str::to_owned),
            actor: actor.into(),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalStatus {
    Approved,
    Duplicate,
}
pub struct ApprovalStored {
    status: ApprovalStatus,
    event: String,
    created_micros: i64,
}
impl ApprovalStored {
    pub fn status(&self) -> ApprovalStatus {
        self.status
    }
    pub fn event_id(&self) -> &str {
        &self.event
    }
    pub fn created_micros(&self) -> i64 {
        self.created_micros
    }
}
impl fmt::Debug for ApprovalStored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalStored")
    }
}
impl ConnectedDatabase {
    /// Retry uncertain results with the same event UUID and every original input.
    pub async fn approve_declared(
        &mut self,
        scope: &DeclaredScope,
        request: &ApprovalRequest,
    ) -> Result<ApprovalStored, ApprovalError> {
        self.approve_declared_until(scope, request, Instant::now() + self.deadline)
            .await
    }
    pub async fn approve_declared_until(
        &mut self,
        scope: &DeclaredScope,
        request: &ApprovalRequest,
        deadline: Instant,
    ) -> Result<ApprovalStored, ApprovalError> {
        if self.client.is_none() {
            return Err(ApprovalError::Invalidated);
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
                .ok_or(ApprovalError::Invalidated)?;
            let transaction = begin(client).await?;
            let prepared = async {
                configure_tenant(
                    &transaction,
                    &scope.ids[0],
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await?;
                let result = replace(&transaction, scope, request).await?;
                if result.status == ApprovalStatus::Approved {
                    transaction
                        .query_one("SELECT set_config('synchronous_commit','on',true)", &[])
                        .await
                        .map_err(database_error)?;
                }
                check_deadline(deadline)?;
                Ok::<_, ApprovalError>(result)
            }
            .await;
            match prepared {
                Ok(stored) if stored.status == ApprovalStatus::Approved => {
                    committing = true;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| ApprovalError::OutcomeUnknown)?;
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
                    if !matches!(result, Err(ApprovalError::Deadline)) {
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
            Ok(Ok(None)) => Err(ApprovalError::Database),
            Ok(Err(error)) => Err(error),
            Err(_) if committing => Err(ApprovalError::OutcomeUnknown),
            Err(_) => Err(ApprovalError::Deadline),
        }
    }
}
async fn existing(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    r: &ApprovalRequest,
) -> Result<Option<ApprovalStored>, ApprovalError> {
    let ids = &scope.ids;
    let row=tx.query_opt("SELECT operation_id::text,project_id::text,service_id::text,environment_id::text,version_id::text,expected_event_id::text,actor_id::text,floor(extract(epoch FROM created_at)*1000000)::bigint FROM contour.approval_events WHERE tenant_id=$1::text::uuid AND event_id=$2::text::uuid",&[&ids[0],&r.event]).await.map_err(database_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let values = [&r.operation, &ids[1], &ids[2], &ids[3], &r.version];
    for (index, wanted) in values.into_iter().enumerate() {
        if row
            .try_get::<_, &str>(index)
            .map_err(|_| ApprovalError::Corrupt)?
            != wanted
        {
            return Err(ApprovalError::Conflict);
        }
    }
    if row
        .try_get::<_, Option<String>>(5)
        .map_err(|_| ApprovalError::Corrupt)?
        != r.expected
        || row
            .try_get::<_, &str>(6)
            .map_err(|_| ApprovalError::Corrupt)?
            != r.actor
    {
        return Err(ApprovalError::Conflict);
    }
    Ok(Some(ApprovalStored {
        status: ApprovalStatus::Duplicate,
        event: r.event.clone(),
        created_micros: row.try_get(7).map_err(|_| ApprovalError::Corrupt)?,
    }))
}
async fn replace(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    r: &ApprovalRequest,
) -> Result<ApprovalStored, ApprovalError> {
    if let Some(stored) = existing(tx, scope, r).await? {
        return Ok(stored);
    }
    let ids = &scope.ids;
    let params: [&(dyn tokio_postgres::types::ToSql + Sync); 6] =
        [&ids[0], &r.operation, &ids[1], &ids[2], &ids[3], &r.version];
    // Identity columns only: the approval role cannot fetch declared graph bytes.
    if tx.query_opt("SELECT 1 FROM contour.declared_versions WHERE tenant_id=$1::text::uuid AND operation_id=$2::text::uuid AND project_id=$3::text::uuid AND service_id=$4::text::uuid AND environment_id=$5::text::uuid AND version_id=$6::text::uuid",&params).await.map_err(database_error)?.is_none() {return Err(ApprovalError::NotFound);}
    tx.execute("INSERT INTO contour.approval_heads(tenant_id,operation_id,project_id,service_id,environment_id) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid) ON CONFLICT DO NOTHING",&params[..5]).await.map_err(database_error)?;
    // A separate READ COMMITTED statement sees a competing initial inserter's commit.
    let head=tx.query_opt("SELECT current_event_id::text FROM contour.approval_heads WHERE tenant_id=$1::text::uuid AND operation_id=$2::text::uuid AND project_id=$3::text::uuid AND service_id=$4::text::uuid AND environment_id=$5::text::uuid FOR UPDATE",&params[..5]).await.map_err(database_error)?.ok_or(ApprovalError::NotFound)?;
    // Exact retry is valid even if subsequent approvals moved the head again.
    if let Some(stored) = existing(tx, scope, r).await? {
        return Ok(stored);
    }
    if head
        .try_get::<_, Option<String>>(0)
        .map_err(|_| ApprovalError::Corrupt)?
        != r.expected
    {
        return Err(ApprovalError::Conflict);
    }
    let inserted=tx.execute("INSERT INTO contour.approval_events(tenant_id,operation_id,project_id,service_id,environment_id,version_id,event_id,expected_event_id,actor_id) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid) ON CONFLICT DO NOTHING",&[&ids[0],&r.operation,&ids[1],&ids[2],&ids[3],&r.version,&r.event,&r.expected,&r.actor]).await.map_err(database_error)?;
    let mut stored = existing(tx, scope, r)
        .await?
        .ok_or(ApprovalError::Corrupt)?;
    if inserted != 0 {
        if tx.execute("UPDATE contour.approval_heads SET current_event_id=$3::text::uuid WHERE tenant_id=$1::text::uuid AND operation_id=$2::text::uuid",&[&ids[0],&r.operation,&r.event]).await.map_err(database_error)?!=1 {return Err(ApprovalError::Corrupt);}
        stored.status = ApprovalStatus::Approved;
    }
    Ok(stored)
}
