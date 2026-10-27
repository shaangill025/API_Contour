//! Trusted internal review transactions; actor authorization belongs to the caller.
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
pub enum ReviewStoreError {
    Scope,
    Forbidden,
    NotFound,
    Conflict,
    Corrupt,
    Database,
    Deadline,
    Invalidated,
    OutcomeUnknown,
}
type Error = ReviewStoreError;
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
#[derive(Clone, PartialEq, Eq)]
pub struct ReviewRequest {
    operation: String,
    id: String,
    comparison: String,
    candidate: String,
    expected: Option<String>,
    creator: String,
}
impl ReviewRequest {
    pub fn new(
        operation: &str,
        id: &str,
        comparison: &str,
        candidate: &str,
        expected: Option<&str>,
        creator: &str,
    ) -> Result<Self, Error> {
        if ![operation, id, comparison, candidate, creator]
            .into_iter()
            .all(uuid)
            || expected.is_some_and(|v| !uuid(v))
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            operation: operation.into(),
            id: id.into(),
            comparison: comparison.into(),
            candidate: candidate.into(),
            expected: expected.map(str::to_owned),
            creator: creator.into(),
        })
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct ReviewDecisionRequest {
    operation: String,
    id: String,
    revision: u64,
    actor: String,
    event: Option<String>,
}
impl ReviewDecisionRequest {
    pub fn approve(
        operation: &str,
        id: &str,
        expected_revision: u64,
        actor: &str,
        event: &str,
    ) -> Result<Self, Error> {
        Self::new(operation, id, expected_revision, actor, Some(event))
    }
    pub fn reject(
        operation: &str,
        id: &str,
        expected_revision: u64,
        actor: &str,
    ) -> Result<Self, Error> {
        Self::new(operation, id, expected_revision, actor, None)
    }
    fn new(
        operation: &str,
        id: &str,
        revision: u64,
        actor: &str,
        event: Option<&str>,
    ) -> Result<Self, Error> {
        if ![operation, id, actor].into_iter().all(uuid)
            || event.is_some_and(|v| !uuid(v))
            || revision == 0
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            operation: operation.into(),
            id: id.into(),
            revision,
            actor: actor.into(),
            event: event.map(str::to_owned),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewStatus {
    Pending,
    Approved,
    Rejected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewStoreStatus {
    Stored,
    Decided,
    Duplicate,
    Read,
}
pub struct ReviewStored {
    status: ReviewStoreStatus,
    request: ReviewRequest,
    created: i64,
    decision: Option<(ReviewDecisionRequest, i64)>,
    public_candidate: Option<String>,
}
impl ReviewStored {
    pub fn status(&self) -> ReviewStoreStatus {
        self.status
    }
    pub fn review_id(&self) -> &str {
        &self.request.id
    }
    pub fn operation_id(&self) -> &str {
        &self.request.operation
    }
    pub fn comparison_id(&self) -> &str {
        &self.request.comparison
    }
    pub fn candidate_version_id(&self) -> &str {
        &self.request.candidate
    }
    /// Public declared contract selected as the comparison right input, when read through the public API.
    pub fn public_candidate_id(&self) -> Option<&str> {
        self.public_candidate.as_deref()
    }
    pub fn expected_event_id(&self) -> Option<&str> {
        self.request.expected.as_deref()
    }
    pub fn creator_actor_id(&self) -> &str {
        &self.request.creator
    }
    pub fn created_micros(&self) -> i64 {
        self.created
    }
    /// Effective review revision, unrelated to a public contract revision or UUID.
    pub fn revision(&self) -> u64 {
        if self.decision.is_some() { 2 } else { 1 }
    }
    pub fn review_status(&self) -> ReviewStatus {
        match &self.decision {
            None => ReviewStatus::Pending,
            Some((d, _)) if d.event.is_some() => ReviewStatus::Approved,
            _ => ReviewStatus::Rejected,
        }
    }
    pub fn deciding_actor_id(&self) -> Option<&str> {
        self.decision.as_ref().map(|(d, _)| d.actor.as_str())
    }
    pub fn approval_event_id(&self) -> Option<&str> {
        self.decision.as_ref().and_then(|(d, _)| d.event.as_deref())
    }
    pub fn decided_micros(&self) -> Option<i64> {
        self.decision.as_ref().map(|(_, time)| *time)
    }
}
impl fmt::Debug for ReviewStored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReviewStored")
    }
}
enum Action<'a> {
    Create(&'a ReviewRequest),
    Read,
    Decide(&'a ReviewDecisionRequest),
    HumanCreate(&'a HumanReviewRequest),
    HumanDecide(&'a HumanReviewDecisionRequest),
    PublicCreate(&'a HumanReviewRequest),
    PublicRead,
    PublicDecide(&'a HumanReviewDecisionRequest),
}
/// Human request: actor attribution comes only from locked identity metadata.
pub struct HumanReviewRequest {
    operation: String,
    id: String,
    comparison: String,
    candidate: String,
    expected: Option<String>,
}
impl HumanReviewRequest {
    pub fn new(
        operation: &str,
        id: &str,
        comparison: &str,
        candidate: &str,
        expected: Option<&str>,
    ) -> Result<Self, Error> {
        if ![operation, id, comparison, candidate].into_iter().all(uuid)
            || expected.is_some_and(|id| !uuid(id))
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            operation: operation.into(),
            id: id.into(),
            comparison: comparison.into(),
            candidate: candidate.into(),
            expected: expected.map(str::to_owned),
        })
    }
}
pub struct HumanReviewDecisionRequest {
    operation: String,
    id: String,
    revision: u64,
    event: Option<String>,
}
impl HumanReviewDecisionRequest {
    pub fn approve(operation: &str, id: &str, revision: u64, event: &str) -> Result<Self, Error> {
        Self::new(operation, id, revision, Some(event))
    }
    pub fn reject(operation: &str, id: &str, revision: u64) -> Result<Self, Error> {
        Self::new(operation, id, revision, None)
    }
    fn new(operation: &str, id: &str, revision: u64, event: Option<&str>) -> Result<Self, Error> {
        if ![operation, id].into_iter().all(uuid)
            || event.is_some_and(|id| !uuid(id))
            || revision == 0
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            operation: operation.into(),
            id: id.into(),
            revision,
            event: event.map(str::to_owned),
        })
    }
}
impl ConnectedDatabase {
    pub async fn store_public_review_as_human_until(
        &mut self,
        identity: &contour_auth::VerifiedIdentity,
        scope: &DeclaredScope,
        request: &HumanReviewRequest,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
        self.review_transaction(
            scope,
            &request.operation,
            &request.id,
            Action::PublicCreate(request),
            Some(identity),
            deadline,
        )
        .await
    }
    pub async fn read_public_review_as_human_until(
        &mut self,
        identity: &contour_auth::VerifiedIdentity,
        scope: &DeclaredScope,
        operation: &str,
        id: &str,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
        self.review_transaction(
            scope,
            operation,
            id,
            Action::PublicRead,
            Some(identity),
            deadline,
        )
        .await
    }
    pub async fn decide_public_review_as_human_until(
        &mut self,
        identity: &contour_auth::VerifiedIdentity,
        scope: &DeclaredScope,
        request: &HumanReviewDecisionRequest,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
        self.review_transaction(
            scope,
            &request.operation,
            &request.id,
            Action::PublicDecide(request),
            Some(identity),
            deadline,
        )
        .await
    }
    pub async fn store_review_as_human_until(
        &mut self,
        identity: &contour_auth::VerifiedIdentity,
        scope: &DeclaredScope,
        request: &HumanReviewRequest,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
        self.review_transaction(
            scope,
            &request.operation,
            &request.id,
            Action::HumanCreate(request),
            Some(identity),
            deadline,
        )
        .await
    }
    pub async fn read_review_as_human_until(
        &mut self,
        identity: &contour_auth::VerifiedIdentity,
        scope: &DeclaredScope,
        operation: &str,
        id: &str,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
        self.review_transaction(scope, operation, id, Action::Read, Some(identity), deadline)
            .await
    }
    pub async fn decide_review_as_human_until(
        &mut self,
        identity: &contour_auth::VerifiedIdentity,
        scope: &DeclaredScope,
        request: &HumanReviewDecisionRequest,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
        self.review_transaction(
            scope,
            &request.operation,
            &request.id,
            Action::HumanDecide(request),
            Some(identity),
            deadline,
        )
        .await
    }
    pub async fn store_review(
        &mut self,
        scope: &DeclaredScope,
        r: &ReviewRequest,
    ) -> Result<ReviewStored, Error> {
        self.store_review_until(scope, r, Instant::now() + self.deadline)
            .await
    }
    pub async fn store_review_until(
        &mut self,
        scope: &DeclaredScope,
        r: &ReviewRequest,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
        self.review_transaction(
            scope,
            &r.operation,
            &r.id,
            Action::Create(r),
            None,
            deadline,
        )
        .await
    }
    pub async fn read_review(
        &mut self,
        scope: &DeclaredScope,
        operation: &str,
        id: &str,
    ) -> Result<ReviewStored, Error> {
        self.read_review_until(scope, operation, id, Instant::now() + self.deadline)
            .await
    }
    pub async fn read_review_until(
        &mut self,
        scope: &DeclaredScope,
        operation: &str,
        id: &str,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
        self.review_transaction(scope, operation, id, Action::Read, None, deadline)
            .await
    }
    pub async fn decide_review(
        &mut self,
        scope: &DeclaredScope,
        r: &ReviewDecisionRequest,
    ) -> Result<ReviewStored, Error> {
        self.decide_review_until(scope, r, Instant::now() + self.deadline)
            .await
    }
    pub async fn decide_review_until(
        &mut self,
        scope: &DeclaredScope,
        r: &ReviewDecisionRequest,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
        self.review_transaction(
            scope,
            &r.operation,
            &r.id,
            Action::Decide(r),
            None,
            deadline,
        )
        .await
    }
    async fn review_transaction(
        &mut self,
        scope: &DeclaredScope,
        operation: &str,
        id: &str,
        action: Action<'_>,
        identity: Option<&contour_auth::VerifiedIdentity>,
        deadline: Instant,
    ) -> Result<ReviewStored, Error> {
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
            let tx = if identity.is_none() && matches!(action, Action::Read) {
                client
                    .build_transaction()
                    .read_only(true)
                    .start()
                    .await
                    .map_err(database_error)?
            } else {
                begin(client).await?
            };
            let prepared = async {
                configure_tenant(
                    &tx,
                    &scope.ids[0],
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await?;
                let actor = if let Some(identity) = identity {
                    Some(
                        crate::human_authorization::authorize(
                            &tx,
                            identity,
                            [&scope.ids[0], &scope.ids[1], &scope.ids[2]],
                            !matches!(action, Action::Read | Action::PublicRead),
                        )
                        .await?,
                    )
                } else {
                    None
                };
                let result = match action {
                    Action::Create(r) => create(&tx, scope, r).await,
                    Action::Read => load(&tx, scope, operation, id, false).await,
                    Action::Decide(r) => decide(&tx, scope, r).await,
                    Action::HumanCreate(r) => {
                        let request = ReviewRequest::new(
                            &r.operation,
                            &r.id,
                            &r.comparison,
                            &r.candidate,
                            r.expected.as_deref(),
                            actor.as_deref().ok_or(Error::Forbidden)?,
                        )?;
                        create(&tx, scope, &request).await
                    }
                    Action::PublicCreate(r) => {
                        let (candidate, version) =
                            public_input(&tx, scope, &r.operation, &r.comparison).await?;
                        if candidate != r.candidate {
                            return Err(Error::Conflict);
                        }
                        let request = ReviewRequest::new(
                            &r.operation,
                            &r.id,
                            &r.comparison,
                            &version,
                            r.expected.as_deref(),
                            actor.as_deref().ok_or(Error::Forbidden)?,
                        )?;
                        let mut stored = create(&tx, scope, &request).await?;
                        stored.public_candidate = Some(candidate);
                        Ok(stored)
                    }
                    Action::PublicRead => public_load(&tx, scope, operation, id).await,
                    Action::PublicDecide(r) => {
                        let public = public_load(&tx, scope, operation, id).await?;
                        let request = ReviewDecisionRequest::new(
                            &r.operation,
                            &r.id,
                            r.revision,
                            actor.as_deref().ok_or(Error::Forbidden)?,
                            r.event.as_deref(),
                        )?;
                        let mut stored = decide(&tx, scope, &request).await?;
                        stored.public_candidate = public.public_candidate;
                        Ok(stored)
                    }
                    Action::HumanDecide(r) => {
                        let request = ReviewDecisionRequest::new(
                            &r.operation,
                            &r.id,
                            r.revision,
                            actor.as_deref().ok_or(Error::Forbidden)?,
                            r.event.as_deref(),
                        )?;
                        decide(&tx, scope, &request).await
                    }
                }?;
                if matches!(
                    result.status,
                    ReviewStoreStatus::Stored | ReviewStoreStatus::Decided
                ) {
                    tx.query_one("SELECT set_config('synchronous_commit','on',true)", &[])
                        .await
                        .map_err(database_error)?;
                }
                if let Some(identity) = identity {
                    crate::human_authorization::check_expiry(&tx, identity).await?;
                }
                check_deadline(deadline)?;
                Ok::<_, Error>(result)
            }
            .await;
            match prepared {
                Ok(stored)
                    if matches!(
                        stored.status,
                        ReviewStoreStatus::Stored | ReviewStoreStatus::Decided
                    ) =>
                {
                    committing = true;
                    tx.commit().await.map_err(|_| Error::OutcomeUnknown)?;
                    committed = Some(stored);
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(None)
                }
                result => {
                    tx.rollback().await.map_err(database_error)?;
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
async fn load(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    operation: &str,
    id: &str,
    lock: bool,
) -> Result<ReviewStored, Error> {
    let ids = &scope.ids;
    let query = format!(
        "SELECT comparison_id::text,candidate_version_id::text,expected_event_id::text,creator_actor_id::text,revision,floor(extract(epoch FROM created_at)*1000000)::bigint FROM contour.review_requests WHERE tenant_id=$1::text::uuid AND review_id=$2::text::uuid AND operation_id=$3::text::uuid AND project_id=$4::text::uuid AND service_id=$5::text::uuid AND environment_id=$6::text::uuid{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt(
            &query,
            &[&ids[0], &id, &operation, &ids[1], &ids[2], &ids[3]],
        )
        .await
        .map_err(database_error)?
        .ok_or(Error::NotFound)?;
    if row.try_get::<_, i64>(4).map_err(|_| Error::Corrupt)? != 1 {
        return Err(Error::Corrupt);
    }
    let request = ReviewRequest::new(
        operation,
        id,
        row.try_get(0).map_err(|_| Error::Corrupt)?,
        row.try_get(1).map_err(|_| Error::Corrupt)?,
        row.try_get(2).map_err(|_| Error::Corrupt)?,
        row.try_get(3).map_err(|_| Error::Corrupt)?,
    )
    .map_err(|_| Error::Corrupt)?;
    let decision=tx.query_opt("SELECT decision,expected_revision,revision,actor_id::text,approval_event_id::text,floor(extract(epoch FROM decided_at)*1000000)::bigint FROM contour.review_decisions WHERE tenant_id=$1::text::uuid AND review_id=$2::text::uuid",&[&ids[0],&id]).await.map_err(database_error)?;
    let decision = if let Some(d) = decision {
        let event: Option<&str> = d.try_get(4).map_err(|_| Error::Corrupt)?;
        let kind: &str = d.try_get(0).map_err(|_| Error::Corrupt)?;
        if !matches!((kind, event), ("approve", Some(_)) | ("reject", None))
            || d.try_get::<_, i64>(1).map_err(|_| Error::Corrupt)? != 1
            || d.try_get::<_, i64>(2).map_err(|_| Error::Corrupt)? != 2
        {
            return Err(Error::Corrupt);
        }
        Some((
            ReviewDecisionRequest::new(
                operation,
                id,
                1,
                d.try_get(3).map_err(|_| Error::Corrupt)?,
                event,
            )
            .map_err(|_| Error::Corrupt)?,
            d.try_get(5).map_err(|_| Error::Corrupt)?,
        ))
    } else {
        None
    };
    Ok(ReviewStored {
        status: ReviewStoreStatus::Read,
        request,
        created: row.try_get(5).map_err(|_| Error::Corrupt)?,
        decision,
        public_candidate: None,
    })
}
// Public provenance is derived only from the immutable right input of a v2 comparison.
async fn public_input(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    operation: &str,
    comparison: &str,
) -> Result<(String, String), Error> {
    let ids = &scope.ids;
    let row = tx.query_opt("SELECT i.public_input_id::text,i.version_id::text FROM contour.comparisons c JOIN contour.public_comparison_inputs i ON i.tenant_id=c.tenant_id AND i.comparison_id=c.comparison_id AND i.operation_id=c.operation_id AND i.project_id=c.project_id AND i.service_id=c.service_id AND i.environment_id=c.environment_id WHERE c.tenant_id=$1::text::uuid AND c.comparison_id=$2::text::uuid AND c.operation_id=$3::text::uuid AND c.project_id=$4::text::uuid AND c.service_id=$5::text::uuid AND c.environment_id=$6::text::uuid AND c.public_projection=2 AND c.right_kind='declared' AND i.side='right' AND i.input_kind='declared' AND i.public_input_id=i.declared_contract_id AND i.version_id=c.right_version_id", &[&ids[0], &comparison, &operation, &ids[1], &ids[2], &ids[3]]).await.map_err(database_error)?.ok_or(Error::NotFound)?;
    Ok((
        row.try_get(0).map_err(|_| Error::Corrupt)?,
        row.try_get(1).map_err(|_| Error::Corrupt)?,
    ))
}
async fn public_load(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    operation: &str,
    id: &str,
) -> Result<ReviewStored, Error> {
    let mut stored = load(tx, scope, operation, id, false).await?;
    let (candidate, version) =
        public_input(tx, scope, operation, &stored.request.comparison).await?;
    if version != stored.request.candidate {
        return Err(Error::Corrupt);
    }
    stored.public_candidate = Some(candidate);
    Ok(stored)
}
async fn create(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    r: &ReviewRequest,
) -> Result<ReviewStored, Error> {
    let ids = &scope.ids;
    let source=tx.query_opt("SELECT right_kind,right_version_id::text,left_kind,left_event_id::text FROM contour.comparisons WHERE tenant_id=$1::text::uuid AND comparison_id=$2::text::uuid AND operation_id=$3::text::uuid AND project_id=$4::text::uuid AND service_id=$5::text::uuid AND environment_id=$6::text::uuid",&[&ids[0],&r.comparison,&r.operation,&ids[1],&ids[2],&ids[3]]).await.map_err(database_error)?.ok_or(Error::NotFound)?;
    if source.try_get::<_, &str>(0).map_err(|_| Error::Corrupt)? != "declared"
        || source.try_get::<_, &str>(1).map_err(|_| Error::Corrupt)? != r.candidate
        || source
            .try_get::<_, Option<String>>(3)
            .map_err(|_| Error::Corrupt)?
            != r.expected
        || source.try_get::<_, &str>(2).map_err(|_| Error::Corrupt)?
            != if r.expected.is_some() {
                "approved"
            } else {
                "declared"
            }
    {
        return Err(Error::Conflict);
    }
    let inserted=tx.execute("INSERT INTO contour.review_requests(tenant_id,review_id,operation_id,project_id,service_id,environment_id,comparison_id,candidate_version_id,expected_event_id,creator_actor_id) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid,$10::text::uuid) ON CONFLICT DO NOTHING",&[&ids[0],&r.id,&r.operation,&ids[1],&ids[2],&ids[3],&r.comparison,&r.candidate,&r.expected,&r.creator]).await.map_err(database_error)?!=0;
    let mut stored = load(tx, scope, &r.operation, &r.id, false)
        .await
        .map_err(|e| {
            if e == Error::NotFound {
                Error::Conflict
            } else {
                e
            }
        })?;
    if stored.request != *r {
        return Err(Error::Conflict);
    }
    stored.status = if inserted {
        ReviewStoreStatus::Stored
    } else {
        ReviewStoreStatus::Duplicate
    };
    Ok(stored)
}
async fn decide(
    tx: &Transaction<'_>,
    scope: &DeclaredScope,
    r: &ReviewDecisionRequest,
) -> Result<ReviewStored, Error> {
    let mut stored = load(tx, scope, &r.operation, &r.id, true).await?;
    if let Some((decision, _)) = &stored.decision {
        if decision != r {
            return Err(Error::Conflict);
        }
        stored.status = ReviewStoreStatus::Duplicate;
        return Ok(stored);
    }
    if r.revision != 1 {
        return Err(Error::Conflict);
    }
    if r.event.is_some() && r.event == stored.request.expected {
        return Err(Error::Conflict);
    }
    let ids = &scope.ids;
    let params: [&(dyn tokio_postgres::types::ToSql + Sync); 5] =
        [&ids[0], &r.operation, &ids[1], &ids[2], &ids[3]];
    tx.execute("INSERT INTO contour.approval_heads(tenant_id,operation_id,project_id,service_id,environment_id) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid) ON CONFLICT DO NOTHING",&params).await.map_err(database_error)?;
    let head=tx.query_opt("SELECT current_event_id::text FROM contour.approval_heads WHERE tenant_id=$1::text::uuid AND operation_id=$2::text::uuid AND project_id=$3::text::uuid AND service_id=$4::text::uuid AND environment_id=$5::text::uuid FOR UPDATE",&params).await.map_err(database_error)?.ok_or(Error::Corrupt)?;
    if head
        .try_get::<_, Option<String>>(0)
        .map_err(|_| Error::Corrupt)?
        != stored.request.expected
    {
        return Err(Error::Conflict);
    }
    if let Some(event) = &r.event {
        // A fresh decision cannot borrow an event created by another transaction.
        if tx.execute("INSERT INTO contour.approval_events(tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,expected_event_id,actor_id) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid) ON CONFLICT DO NOTHING",&[&ids[0],event,&r.operation,&ids[1],&ids[2],&ids[3],&stored.request.candidate,&stored.request.expected,&r.actor]).await.map_err(database_error)?!=1{return Err(Error::Conflict);}
        if tx.execute("UPDATE contour.approval_heads SET current_event_id=$3::text::uuid WHERE tenant_id=$1::text::uuid AND operation_id=$2::text::uuid",&[&ids[0],&r.operation,event]).await.map_err(database_error)?!=1{return Err(Error::Corrupt);}
    }
    let kind = if r.event.is_some() {
        "approve"
    } else {
        "reject"
    };
    tx.execute("INSERT INTO contour.review_decisions(tenant_id,review_id,decision,expected_revision,actor_id,approval_event_id) VALUES($1::text::uuid,$2::text::uuid,$3,1,$4::text::uuid,$5::text::uuid)",&[&ids[0],&r.id,&kind,&r.actor,&r.event]).await.map_err(database_error)?;
    let mut stored = load(tx, scope, &r.operation, &r.id, false).await?;
    stored.status = ReviewStoreStatus::Decided;
    Ok(stored)
}

impl From<crate::human_authorization::HumanAuthorizationError> for ReviewStoreError {
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
