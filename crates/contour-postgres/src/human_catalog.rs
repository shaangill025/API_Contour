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
use std::{collections::HashMap, fmt};
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
    pub origin_evidence_available: bool,
    pub origins: Vec<HumanOrigin>,
    pub origins_truncated: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HumanOrigin {
    pub ids: [String; 5],
}
impl HumanOrigin {
    pub fn new(ids: [String; 5]) -> Result<Self, HumanCatalogError> {
        if ids.iter().all(|id| uuid(id)) {
            Ok(Self { ids })
        } else {
            Err(HumanCatalogError::Scope)
        }
    }
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
#[derive(Clone, Copy)]
enum Selection<'a> {
    Page(u16, Option<&'a str>, Option<&'a HumanOrigin>, bool),
    Detail(&'a str, bool),
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
        self.human_catalog_transaction(
            identity,
            scope,
            Selection::Page(limit, cursor, None, false),
            deadline,
        )
        .await
    }
    pub async fn list_operations_with_origins_as_human_until(
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
        self.human_catalog_transaction(
            identity,
            scope,
            Selection::Page(limit, cursor, None, true),
            deadline,
        )
        .await
    }
    pub async fn list_operations_by_origin_as_human_until(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        limit: u16,
        cursor: Option<&str>,
        origin: &HumanOrigin,
        deadline: Instant,
    ) -> Result<HumanCatalogPage, HumanCatalogError> {
        if !(1..=200).contains(&limit) {
            return Err(HumanCatalogError::Limit);
        }
        if cursor.is_some_and(|v| !uuid(v)) || !origin.ids.iter().all(|v| uuid(v)) {
            return Err(HumanCatalogError::Scope);
        }
        self.human_catalog_transaction(
            identity,
            scope,
            Selection::Page(limit, cursor, Some(origin), true),
            deadline,
        )
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
        self.human_catalog_transaction(
            identity,
            scope,
            Selection::Detail(operation, false),
            deadline,
        )
        .await?
        .items
        .into_iter()
        .next()
        .ok_or(HumanCatalogError::NotFound)
    }
    pub async fn read_operation_with_origins_as_human_until(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        operation: &str,
        deadline: Instant,
    ) -> Result<HumanCatalogOperation, HumanCatalogError> {
        if !uuid(operation) {
            return Err(HumanCatalogError::Scope);
        }
        self.human_catalog_transaction(
            identity,
            scope,
            Selection::Detail(operation, true),
            deadline,
        )
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
                let with_origin = matches!(selection, Selection::Page(_, _, _, true) | Selection::Detail(_, true));
                let resource_operation;
                let (limit, cursor, operation, origin_filter) = match selection {
                    Selection::Page(limit, cursor, origin, _) => (limit, cursor, None, origin),
                    Selection::Detail(operation, _) => (1, None, Some(operation), None),
                    Selection::Resource(resource, id) => {
                        let sql = match resource {
                            HumanCatalogResource::Comparison => "SELECT operation_id::text FROM contour.comparisons WHERE tenant_id=$1::text::uuid AND project_id=$2::text::uuid AND service_id=$3::text::uuid AND environment_id=$4::text::uuid AND comparison_id=$5::text::uuid AND public_projection=2",
                            HumanCatalogResource::Review => "SELECT r.operation_id::text FROM contour.review_requests r JOIN contour.comparisons c ON c.tenant_id=r.tenant_id AND c.comparison_id=r.comparison_id WHERE r.tenant_id=$1::text::uuid AND r.project_id=$2::text::uuid AND r.service_id=$3::text::uuid AND r.environment_id=$4::text::uuid AND r.review_id=$5::text::uuid AND c.public_projection=2",
                        };
                        let row = tx.query_opt(sql, &[&scope.ids[0], &scope.ids[1], &scope.ids[2], &scope.ids[3], &id]).await.map_err(database_error)?.ok_or(HumanCatalogError::NotFound)?;
                        resource_operation = row.try_get::<_, String>(0).map_err(|_| HumanCatalogError::Corrupt)?;
                        (1, None, Some(resource_operation.as_str()), None)
                    }
                };
                let origin_available: bool = with_origin && tx.query_one("SELECT to_regprocedure('contour.human_origin_operation(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid)') IS NOT NULL", &[]).await.map_err(database_error)?.try_get(0).map_err(|_| HumanCatalogError::Corrupt)?;
                let candidates: Option<Vec<String>> = if let Some(origin) = origin_filter {
                    if !origin_available { return Err(HumanCatalogError::Database); }
                    crate::human_authorization::authorize(&tx, identity, [&scope.ids[0], &origin.ids[0], &origin.ids[1]], false).await?;
                    let ids = &origin.ids;
                    let rows = tx.query("SELECT operation_id::text FROM contour.human_origin_candidates($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid,$10::text::uuid,$11)", &[&scope.ids[0],&scope.ids[1],&scope.ids[2],&scope.ids[3],&ids[0],&ids[1],&ids[2],&ids[3],&ids[4],&cursor,&(i32::from(limit)+1)]).await.map_err(database_error)?;
                    Some(rows.iter().map(|r| r.try_get(0).map_err(|_| HumanCatalogError::Corrupt)).collect::<Result<Vec<String>,_>>()?)
                } else { None };
                // A filtered page takes its observation fields only from the verified
                // origin head; it must not scan or sort unrelated target history.
                let window_join = if origin_filter.is_some() {
                    "LEFT JOIN LATERAL (SELECT NULL::text AS last_seen,NULL::text AS visibility,NULL::text AS completeness) w ON true"
                } else {
                    "LEFT JOIN LATERAL (SELECT last_seen,visibility,completeness FROM contour.observation_windows w WHERE w.tenant_id=o.tenant_id AND w.operation_id=o.operation_id AND w.project_id=o.project_id AND w.service_id=o.service_id AND w.environment_id=o.environment_id ORDER BY w.last_seen::timestamptz DESC,w.collector_id,w.batch_id,w.record_id LIMIT 1) w ON true"
                };
                let sql = format!("SELECT o.operation_id::text,o.canonical_key,encode(o.operation_hash,'hex'),o.identity_version,h.current_event_id::text,w.last_seen,w.visibility,w.completeness FROM contour.operations o LEFT JOIN contour.approval_heads h USING(tenant_id,operation_id,project_id,service_id,environment_id) {window_join} WHERE o.tenant_id=$1::text::uuid AND o.project_id=$2::text::uuid AND o.service_id=$3::text::uuid AND o.environment_id=$4::text::uuid AND ($5::text IS NULL OR o.operation_id>$5::text::uuid) AND ($6::text IS NULL OR o.operation_id=$6::text::uuid) AND ($8::text[] IS NULL OR o.operation_id=ANY($8::text[]::uuid[])) ORDER BY o.operation_id LIMIT $7");
                let rows = tx.query(&sql, &[&scope.ids[0],&scope.ids[1],&scope.ids[2],&scope.ids[3],&cursor,&operation,&(i64::from(limit)+1),&candidates]).await.map_err(database_error)?;
                if let Some(expected) = &candidates {
                    let actual = rows.iter().map(|row| row.try_get::<_, String>(0).map_err(|_| HumanCatalogError::Corrupt)).collect::<Result<Vec<_>,_>>()?;
                    if &actual != expected { return Err(HumanCatalogError::Corrupt); }
                }
                let more = rows.len() > usize::from(limit);
                let mut items = Vec::new();
                let mut origin_authority: HashMap<(String, String), bool> = HashMap::new();
                for row in rows.iter().take(usize::from(limit)) {
                    check_deadline(deadline)?;
                    fn bad<T>(_: T) -> HumanCatalogError { HumanCatalogError::Corrupt }
                    let parts = OperationKey::decode_canonical(row.try_get(1).map_err(bad)?).map_err(bad)?;
                    let key = OperationKey::from_components(parts.each_ref().map(String::as_str)).map_err(bad)?;
                    if parts[..4] != scope.ids || row.try_get::<_, i16>(3).map_err(bad)? != 1 || key.fingerprint().map_err(bad)? != row.try_get::<_, &str>(2).map_err(bad)? { return Err(HumanCatalogError::Corrupt); }
                    let operation_id: String = row.try_get(0).map_err(bad)?;
                    let mut origins = Vec::new();
                    let mut origins_truncated = false;
                    let mut last_seen: Option<String> = row.try_get(5).map_err(bad)?;
                    let mut visibility: Option<String> = row.try_get(6).map_err(bad)?;
                    let mut completeness: Option<String> = row.try_get(7).map_err(bad)?;
                    if origin_available {
                        let f = origin_filter.map(|v| &v.ids);
                        let fp = f.map(|v| v[0].as_str()); let fs = f.map(|v| v[1].as_str());
                        let fe = f.map(|v| v[2].as_str()); let fd = f.map(|v| v[3].as_str()); let fi = f.map(|v| v[4].as_str());
                        let evidence = tx.query("SELECT origin_project_id::text,origin_service_id::text,origin_environment_id::text,origin_deployment_id::text,instance_id::text,truncated,last_seen,visibility,completeness FROM contour.human_origin_operation($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid,$10::text::uuid)", &[&scope.ids[0],&scope.ids[1],&scope.ids[2],&scope.ids[3],&operation_id,&fp,&fs,&fe,&fd,&fi]).await.map_err(database_error)?;
                        for e in evidence {
                            if e.try_get::<_,bool>(5).map_err(bad)? { origins_truncated = true; continue; }
                            let origin = HumanOrigin::new([e.try_get(0).map_err(bad)?,e.try_get(1).map_err(bad)?,e.try_get(2).map_err(bad)?,e.try_get(3).map_err(bad)?,e.try_get(4).map_err(bad)?])?;
                            if origins.contains(&origin) { continue; }
                            let authority_key = (origin.ids[0].clone(), origin.ids[1].clone());
                            let allowed = if let Some(allowed) = origin_authority.get(&authority_key) { *allowed } else {
                                let allowed = match crate::human_authorization::authorize(&tx, identity, [&scope.ids[0], &origin.ids[0], &origin.ids[1]], false).await {
                                    Ok(_) => true,
                                    Err(crate::human_authorization::HumanAuthorizationError::Forbidden) => false,
                                    Err(e) => return Err(e.into()),
                                };
                                origin_authority.insert(authority_key, allowed);
                                allowed
                            };
                            if allowed {
                                if origin_filter.is_some() {
                                    last_seen = Some(e.try_get(6).map_err(bad)?);
                                    visibility = Some(e.try_get(7).map_err(bad)?);
                                    completeness = Some(e.try_get(8).map_err(bad)?);
                                }
                                origins.push(origin);
                            }
                        }
                        if origin_filter.is_some() && !origins.iter().any(|v| Some(v)==origin_filter) { return Err(HumanCatalogError::Corrupt); }
                    }
                    items.push(HumanCatalogOperation { id: row.try_get(0).map_err(bad)?, project_id: parts[1].clone(), service_id: parts[2].clone(), environment_id: parts[3].clone(), protocol: parts[4].clone(), direction: parts[5].clone(), operation: parts[6].clone(), route_template: parts[7].clone(), approved_contract_id: row.try_get(4).map_err(bad)?, last_seen, visibility, completeness, origin_evidence_available: origin_available, origins, origins_truncated });
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
