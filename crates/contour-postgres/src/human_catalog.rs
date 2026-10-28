//! Bounded human-authorized operation catalog. Scope is supplied by the operator.
use crate::{
    AuthorityError, ConnectedDatabase, DeclaredScope,
    declared_store::uuid,
    transaction::{
        CancellationGuard, begin, check_deadline, configure_tenant, database_error, empty_context,
    },
};
use contour_auth::VerifiedIdentity;
use contour_core::OperationKey;
use std::fmt;
use tokio::time::{Instant, timeout_at};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HumanCatalogError {
    Scope,
    Limit,
    Forbidden,
    NotFound,
    Corrupt,
    Database,
    Deadline,
    Invalidated,
}
impl fmt::Display for HumanCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for HumanCatalogError {}
impl From<AuthorityError> for HumanCatalogError {
    fn from(e: AuthorityError) -> Self {
        match e {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Invalidated => Self::Invalidated,
            _ => Self::Database,
        }
    }
}
impl From<crate::human_authorization::HumanAuthorizationError> for HumanCatalogError {
    fn from(e: crate::human_authorization::HumanAuthorizationError) -> Self {
        use crate::human_authorization::HumanAuthorizationError as H;
        match e {
            H::Forbidden => Self::Forbidden,
            H::Corrupt => Self::Corrupt,
            H::Database => Self::Database,
            H::Deadline => Self::Deadline,
            H::Invalidated => Self::Invalidated,
        }
    }
}
/// Observation fields are absent when no observation exists; approval is an event ID.
#[derive(Clone, Debug)]
pub struct HumanCatalogOperation {
    pub id: String,
    pub project_id: String,
    pub service_id: String,
    pub environment_id: String,
    pub protocol: String,
    pub direction: String,
    pub operation: String,
    pub route_template: String,
    pub approved_contract_id: Option<String>,
    pub last_seen: Option<String>,
    pub visibility: Option<String>,
    pub completeness: Option<String>,
}
pub struct HumanCatalogPage {
    pub items: Vec<HumanCatalogOperation>,
    pub next_cursor: Option<String>,
}
#[derive(Clone, Copy)]
pub enum HumanCatalogResource {
    Comparison,
    Review,
}
enum Selection<'a> {
    Page(u16, Option<&'a str>),
    Detail(&'a str),
    Resource(HumanCatalogResource, &'a str),
}
impl ConnectedDatabase {
    /// The cursor is a UUID; every call independently enforces the supplied scope.
    /// Pages are independent snapshots, and concurrent inserts may appear in later pages.
    pub async fn list_operations_as_human_until(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        limit: u16,
        cursor: Option<&str>,
        deadline: Instant,
    ) -> Result<HumanCatalogPage, HumanCatalogError> {
        if !(1..=200).contains(&limit) {
            return Err(HumanCatalogError::Limit);
        }
        if cursor.is_some_and(|v| !uuid(v)) {
            return Err(HumanCatalogError::Scope);
        }
        self.human_catalog_transaction(identity, scope, Selection::Page(limit, cursor), deadline)
            .await
    }
    pub async fn read_operation_as_human_until(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        operation: &str,
        deadline: Instant,
    ) -> Result<HumanCatalogOperation, HumanCatalogError> {
        if !uuid(operation) {
            return Err(HumanCatalogError::Scope);
        }
        self.human_catalog_transaction(identity, scope, Selection::Detail(operation), deadline)
            .await?
            .items
            .into_iter()
            .next()
            .ok_or(HumanCatalogError::NotFound)
    }
    pub async fn lookup_operation_as_human_until(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        resource: HumanCatalogResource,
        id: &str,
        deadline: Instant,
    ) -> Result<String, HumanCatalogError> {
        if !uuid(id) {
            return Err(HumanCatalogError::Scope);
        }
        self.human_catalog_transaction(identity, scope, Selection::Resource(resource, id), deadline)
            .await?
            .items
            .into_iter()
            .next()
            .map(|o| o.id)
            .ok_or(HumanCatalogError::NotFound)
    }
    async fn human_catalog_transaction(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        selection: Selection<'_>,
        deadline: Instant,
    ) -> Result<HumanCatalogPage, HumanCatalogError> {
        if self.client.is_none() {
            return Err(HumanCatalogError::Invalidated);
        }
        let deadline = deadline.min(Instant::now() + self.deadline);
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(self);
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(HumanCatalogError::Invalidated)?;
            let tx = begin(client).await?;
            let result = async {
                configure_tenant(&tx, &scope.ids[0], deadline.saturating_duration_since(Instant::now())).await?;
                crate::human_authorization::authorize(&tx, identity, [&scope.ids[0], &scope.ids[1], &scope.ids[2]], false).await?;
                let resource_operation;
                let (limit, cursor, operation) = match selection {
                    Selection::Page(limit, cursor) => (limit, cursor, None),
                    Selection::Detail(operation) => (1, None, Some(operation)),
                    Selection::Resource(resource, id) => {
                        let sql = match resource {
                            HumanCatalogResource::Comparison => "SELECT operation_id::text FROM contour.comparisons WHERE tenant_id=$1::text::uuid AND project_id=$2::text::uuid AND service_id=$3::text::uuid AND environment_id=$4::text::uuid AND comparison_id=$5::text::uuid AND public_projection=2",
                            HumanCatalogResource::Review => "SELECT r.operation_id::text FROM contour.review_requests r JOIN contour.comparisons c ON c.tenant_id=r.tenant_id AND c.comparison_id=r.comparison_id WHERE r.tenant_id=$1::text::uuid AND r.project_id=$2::text::uuid AND r.service_id=$3::text::uuid AND r.environment_id=$4::text::uuid AND r.review_id=$5::text::uuid AND c.public_projection=2",
                        };
                        let row = tx.query_opt(sql, &[&scope.ids[0], &scope.ids[1], &scope.ids[2], &scope.ids[3], &id]).await.map_err(database_error)?.ok_or(HumanCatalogError::NotFound)?;
                        resource_operation = row.try_get::<_, String>(0).map_err(|_| HumanCatalogError::Corrupt)?;
                        (1, None, Some(resource_operation.as_str()))
                    }
                };
                let rows = tx.query("SELECT o.operation_id::text,o.canonical_key,encode(o.operation_hash,'hex'),o.identity_version,h.current_event_id::text,w.last_seen,w.visibility,w.completeness FROM contour.operations o LEFT JOIN contour.approval_heads h USING(tenant_id,operation_id,project_id,service_id,environment_id) LEFT JOIN LATERAL (SELECT last_seen,visibility,completeness FROM contour.observation_windows w WHERE w.tenant_id=o.tenant_id AND w.operation_id=o.operation_id AND w.project_id=o.project_id AND w.service_id=o.service_id AND w.environment_id=o.environment_id ORDER BY w.last_seen::timestamptz DESC,w.collector_id,w.batch_id,w.record_id LIMIT 1) w ON true WHERE o.tenant_id=$1::text::uuid AND o.project_id=$2::text::uuid AND o.service_id=$3::text::uuid AND o.environment_id=$4::text::uuid AND ($5::text IS NULL OR o.operation_id>$5::text::uuid) AND ($6::text IS NULL OR o.operation_id=$6::text::uuid) ORDER BY o.operation_id LIMIT $7", &[&scope.ids[0],&scope.ids[1],&scope.ids[2],&scope.ids[3],&cursor,&operation,&(i64::from(limit)+1)]).await.map_err(database_error)?;
                let more = rows.len() > usize::from(limit);
                let mut items = Vec::new();
                for row in rows.iter().take(usize::from(limit)) {
                    check_deadline(deadline)?;
                    fn bad<T>(_: T) -> HumanCatalogError { HumanCatalogError::Corrupt }
                    let parts = OperationKey::decode_canonical(row.try_get(1).map_err(bad)?).map_err(bad)?;
                    let key = OperationKey::from_components(parts.each_ref().map(String::as_str)).map_err(bad)?;
                    if parts[..4] != scope.ids || row.try_get::<_, i16>(3).map_err(bad)? != 1 || key.fingerprint().map_err(bad)? != row.try_get::<_, &str>(2).map_err(bad)? { return Err(HumanCatalogError::Corrupt); }
                    items.push(HumanCatalogOperation { id: row.try_get(0).map_err(bad)?, project_id: parts[1].clone(), service_id: parts[2].clone(), environment_id: parts[3].clone(), protocol: parts[4].clone(), direction: parts[5].clone(), operation: parts[6].clone(), route_template: parts[7].clone(), approved_contract_id: row.try_get(4).map_err(bad)?, last_seen: row.try_get(5).map_err(bad)?, visibility: row.try_get(6).map_err(bad)?, completeness: row.try_get(7).map_err(bad)? });
                }
                let next_cursor = if more { items.last().map(|v| v.id.clone()) } else { None };
                crate::human_authorization::check_expiry(&tx, identity).await?;
                check_deadline(deadline)?;
                Ok(HumanCatalogPage { items, next_cursor })
            }.await;
            tx.rollback().await.map_err(database_error)?;
            empty_context(client).await?;
            check_deadline(deadline)?;
            if !matches!(result, Err(HumanCatalogError::Deadline)) {
                guard.confirm();
            }
            result
        };
        timeout_at(deadline, work)
            .await
            .map_err(|_| HumanCatalogError::Deadline)?
    }
}
