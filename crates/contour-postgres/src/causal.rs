//! Internal causal SQL bridge. Callers authenticate the peer and own the
//! configured binding; neither a leaf pin nor this module attests a producer.
//! Session authority is in-memory only; durable restart recovery is not provided.
//! The UUID501 profile and b0bc manifest are the existing fixed intent-only
//! enrollment, not qualification or attestation of any changed producer.
//! Database current-time observations have microsecond resolution. Canceling
//! an in-flight operation can leave an unknown commit outcome; retry only the
//! original issue or batch identity and exact content.
use crate::{
    AuthorityError, ConnectedDatabase,
    transaction::{
        CancellationGuard, begin, check_deadline, clock, configure_tenant, empty_context,
        time_from_micros,
    },
};
use contour_core::{
    AdmissionInputs, CaptureScope, CausalEventBatch, CausalGrantKeys, PolicyKeys, SourceAssignment,
    VerifiedCausalGrant, VerifiedPolicy,
};
use std::{fmt, time::Duration};
use time::{OffsetDateTime, UtcOffset};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Client, Error, Row};

const PROFILE: &str = "nodered_5_0_9_v1";
const ARTIFACT: &str = "b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510";
const ROLE_QUERY: &str = "SELECT current_user=session_user, COALESCE(session_user=(SELECT a.usename FROM pg_catalog.pg_stat_activity a WHERE a.pid=pg_catalog.pg_backend_pid()),false), EXISTS (SELECT 1 FROM pg_catalog.pg_roles u WHERE u.rolname=current_user AND NOT u.rolsuper AND NOT u.rolbypassrls), EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='contour_causal_issuer'), EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='contour_causal_inbox_writer'), EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=$1 AND pg_catalog.pg_has_role(current_user,r.oid,'USAGE')), NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname<>current_user AND r.rolname<>$1 AND pg_catalog.pg_has_role(current_user,r.oid,'MEMBER'))";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CausalError {
    Identity,
    Signature,
    Scope,
    Expired,
    InvalidBatch,
    Conflict,
    Corrupt,
    LogicalQuota,
    HistoryLimit,
    Busy,
    Database,
    Deadline,
    OutcomeUnknown,
}
impl fmt::Display for CausalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CausalError {}
impl From<AuthorityError> for CausalError {
    fn from(value: AuthorityError) -> Self {
        match value {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Identity => Self::Identity,
            _ => Self::Database,
        }
    }
}
fn db_error(error: Error) -> CausalError {
    let Some(db) = error.as_db_error() else {
        return CausalError::Database;
    };
    classify_database_error(db.code().code(), db.constraint(), db.message())
}
fn classify_database_error(code: &str, constraint: Option<&str>, message: &str) -> CausalError {
    match (code, constraint) {
        ("54000", Some("origin_logical_quota_exhausted")) => CausalError::LogicalQuota,
        ("54000", Some("causal_session_history_limit")) => CausalError::HistoryLimit,
        ("23505", None)
            if matches!(
                message,
                "nonce unavailable" | "causal batch conflict" | "causal fact conflict"
            ) =>
        {
            CausalError::Conflict
        }
        ("23514", None) if message == "stored causal batch corrupted" => CausalError::Corrupt,
        ("23514", _) => CausalError::Scope,
        ("40001", _) => CausalError::Busy,
        ("57014" | "55P03" | "25P03", _) => CausalError::Deadline,
        _ => CausalError::Database,
    }
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
/// Operator-configured mapping from a verified TLS leaf to the fixed registry
/// identity. This is syntax-checked configuration, not enrollment or attestation.
#[derive(Clone, PartialEq, Eq)]
pub struct CausalBinding {
    ids: [String; 10],
    peer: [u8; 32],
}
impl CausalBinding {
    /// IDs: tenant, runtime, collector, source, project, service, environment,
    /// deployment, instance, lifecycle. The pin is SHA-256 of the verified DER leaf.
    pub fn new(ids: [&str; 10], peer: [u8; 32]) -> Result<Self, CausalError> {
        if ids.iter().any(|s| !uuid(s)) {
            return Err(CausalError::Identity);
        }
        Ok(Self {
            ids: ids.map(str::to_owned),
            peer,
        })
    }
}
impl fmt::Debug for CausalBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalBinding")
    }
}
/// Trusted original request. A retry after unknown commit must use this exact
/// request and peer; it is never a generic nonce lookup.
#[derive(Clone)]
pub struct CausalIssue {
    binding: CausalBinding,
    nonce: String,
    ttl_micros: i64,
    grant: Vec<u8>,
    policy: Vec<u8>,
}
impl CausalIssue {
    pub fn new(
        binding: CausalBinding,
        nonce: &str,
        ttl: Duration,
        grant: &[u8],
        policy: &[u8],
    ) -> Result<Self, CausalError> {
        if !uuid(nonce) {
            return Err(CausalError::Identity);
        }
        let micros = ttl.as_micros();
        if micros == 0
            || micros > 900_000_000
            || ttl.subsec_nanos() % 1000 != 0
            || grant.is_empty()
            || grant.len() > 1_048_576
            || policy.is_empty()
            || policy.len() > 1_048_576
        {
            return Err(CausalError::Scope);
        }
        Ok(Self {
            binding,
            nonce: nonce.to_owned(),
            ttl_micros: micros as i64,
            grant: grant.to_vec(),
            policy: policy.to_vec(),
        })
    }
}
impl fmt::Debug for CausalIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalIssue")
    }
}
/// Created only after confirmed SQL commit. It retains the exact authenticated
/// envelopes and original input in memory; no durable journal is implemented.
pub struct CausalSession {
    issue: CausalIssue,
    epoch: u64,
    issued: OffsetDateTime,
    expires: OffsetDateTime,
    digest: [u8; 32],
}
impl CausalSession {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued
    }
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires
    }
}
impl fmt::Debug for CausalSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalSession")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct CausalReceipt {
    id: String,
    accepted: OffsetDateTime,
    duplicate: bool,
}
impl CausalReceipt {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn accepted_at(&self) -> OffsetDateTime {
        self.accepted
    }
    pub fn duplicate(&self) -> bool {
        self.duplicate
    }
}
impl fmt::Debug for CausalReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalReceipt")
    }
}

fn verify(
    issue: &CausalIssue,
    peer: &[u8; 32],
    grant_keys: &CausalGrantKeys,
    policy_keys: &PolicyKeys,
    now: OffsetDateTime,
) -> Result<(VerifiedCausalGrant, VerifiedPolicy), CausalError> {
    let ids = &issue.binding.ids;
    if peer != &issue.binding.peer {
        return Err(CausalError::Identity);
    }
    let grant = VerifiedCausalGrant::from_signed_json(&issue.grant, grant_keys, now).map_err(
        |e| match e {
            contour_core::CausalGrantError::Lease => CausalError::Expired,
            contour_core::CausalGrantError::Semantic => CausalError::Scope,
            _ => CausalError::Signature,
        },
    )?;
    grant
        .validate_capture_at(now)
        .map_err(|_| CausalError::Scope)?;
    if [
        grant.tenant_id(),
        grant.runtime_id(),
        grant.collector_id(),
        grant.source_id(),
        grant.instance_id(),
        grant.lifecycle_id(),
    ] != [
        ids[0].as_str(),
        ids[1].as_str(),
        ids[2].as_str(),
        ids[3].as_str(),
        ids[8].as_str(),
        ids[9].as_str(),
    ] || grant.causal_profile() != PROFILE
        || grant.profile_sha256() != ARTIFACT
    {
        return Err(CausalError::Identity);
    }
    let policy =
        VerifiedPolicy::from_signed_json(&issue.policy, policy_keys, &ids[0], &ids[2], now)
            .map_err(|e| match e {
                contour_core::PolicyError::Lease => CausalError::Expired,
                contour_core::PolicyError::Identity => CausalError::Identity,
                _ => CausalError::Signature,
            })?;
    policy
        .validate_capture_at(now)
        .map_err(|_| CausalError::Scope)?;
    let source = SourceAssignment::new(
        &ids[3],
        [&ids[0], &ids[2], &ids[4], &ids[5], &ids[6], &ids[7]],
        "runtime",
        &["http_json_v1"],
    )
    .map_err(|_| CausalError::Scope)?;
    let sources = [source];
    let input = AdmissionInputs::new([&ids[0], &ids[2]], &policy, &[], &sources)
        .map_err(|_| CausalError::Scope)?;
    input
        .check_capture_scope(
            &CaptureScope {
                source_id: &ids[3],
                workload: [&ids[4], &ids[5], &ids[6], &ids[7]],
                parser_profile: "http_json_v1",
                operation: "POST",
                route_template: "/run",
                request_header_names: &[],
                response_header_names: &[],
                query_parameter_names: &[],
            },
            now,
        )
        .map_err(|_| CausalError::Scope)?;
    Ok((grant, policy))
}
// Euclidean rounding handles pre-epoch instants as well as positive instants.
fn pg_time(value: OffsetDateTime, ceil: bool) -> Result<String, CausalError> {
    let n = value.unix_timestamp_nanos();
    let mut us = n.div_euclid(1000);
    if ceil && n.rem_euclid(1000) != 0 {
        us = us.checked_add(1).ok_or(CausalError::Expired)?;
    }
    let dt = OffsetDateTime::from_unix_timestamp_nanos(
        us.checked_mul(1000).ok_or(CausalError::Expired)?,
    )
    .map_err(|_| CausalError::Expired)?
    .to_offset(UtcOffset::UTC);
    if !(1..=9999).contains(&dt.year()) {
        return Err(CausalError::Expired);
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+00:00",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.microsecond()
    ))
}
async fn check_role(client: &Client, role: &str) -> Result<(), CausalError> {
    empty_context(client).await?;
    let row = client
        .query_one(ROLE_QUERY, &[&role])
        .await
        .map_err(db_error)?;
    let mut facts = [false; 7];
    for (index, fact) in facts.iter_mut().enumerate() {
        *fact = row.try_get(index).map_err(|_| CausalError::Database)?;
    }
    if !role_allowed(facts) {
        return Err(CausalError::Identity);
    }
    Ok(())
}
// All catalog checks must be present and true, including both role existence
// checks; no missing-role name is passed to pg_has_role.
fn role_allowed(facts: [bool; 7]) -> bool {
    facts.into_iter().all(|fact| fact)
}
fn parse_session(
    row: &Row,
    issue: &CausalIssue,
    digest: [u8; 32],
) -> Result<CausalSession, CausalError> {
    let epoch: String = row.try_get(0).map_err(|_| CausalError::Corrupt)?;
    let epoch = epoch.parse::<u64>().map_err(|_| CausalError::Corrupt)?;
    let issued = time_from_micros(row.try_get(1).map_err(|_| CausalError::Corrupt)?)?;
    let expires = time_from_micros(row.try_get(2).map_err(|_| CausalError::Corrupt)?)?;
    if epoch == 0 || expires <= issued || expires - issued > time::Duration::minutes(15) {
        return Err(CausalError::Corrupt);
    }
    Ok(CausalSession {
        issue: issue.clone(),
        epoch,
        issued,
        expires,
        digest,
    })
}
fn check_batch(
    session: &CausalSession,
    peer: &[u8; 32],
    bytes: &[u8],
) -> Result<CausalEventBatch, CausalError> {
    let ids = &session.issue.binding.ids;
    if *peer != session.issue.binding.peer {
        return Err(CausalError::Identity);
    }
    let batch = CausalEventBatch::from_wire_json(bytes).map_err(|_| CausalError::InvalidBatch)?;
    if batch
        .canonical_bytes()
        .map_err(|_| CausalError::InvalidBatch)?
        != bytes
    {
        return Err(CausalError::InvalidBatch);
    }
    if batch.tenant_id() != ids[0]
        || batch.runtime_id() != ids[1]
        || batch.session_epoch() != session.epoch
    {
        return Err(CausalError::Identity);
    }
    Ok(batch)
}
// Snapshot-only cryptographic/scope checks use the database's microsecond
// clock; live enrollment and revocation are checked by SQL20 under its locks.
fn checked_admission(
    session: &CausalSession,
    peer: &[u8; 32],
    bytes: &[u8],
    grant_keys: &CausalGrantKeys,
    policy_keys: &PolicyKeys,
    now: OffsetDateTime,
) -> Result<(), CausalError> {
    let (grant, _) = verify(&session.issue, peer, grant_keys, policy_keys, now)?;
    if now < session.issued || now >= session.expires || grant.payload_digest() != session.digest {
        return Err(CausalError::Expired);
    }
    let batch = check_batch(session, peer, bytes)?;
    if bytes.len() > grant.max_batch_bytes() as usize
        || batch.events().len() > grant.max_batch_events() as usize
    {
        return Err(CausalError::InvalidBatch);
    }
    Ok(())
}
fn receipt(row: &Row) -> Result<CausalReceipt, CausalError> {
    let id: String = row.try_get(0).map_err(|_| CausalError::Corrupt)?;
    if !uuid(&id) {
        return Err(CausalError::Corrupt);
    }
    Ok(CausalReceipt {
        id,
        accepted: time_from_micros(row.try_get(1).map_err(|_| CausalError::Corrupt)?)?,
        duplicate: row.try_get(2).map_err(|_| CausalError::Corrupt)?,
    })
}

const ISSUE_SQL: &str = "SELECT epoch::text,floor(extract(epoch FROM issued_at)*1000000)::bigint,floor(extract(epoch FROM expires_at)*1000000)::bigint FROM contour.issue_causal_session(ROW($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid,$10::text::uuid,$11::bytea,'nodered_5_0_9_v1',decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex'),$12::text::uuid,$13::text::numeric,$14::bytea,$15::text::timestamptz,$16::text::timestamptz,$17::text::numeric,$18::bytea,$19::text::timestamptz,$20::text::timestamptz,$21::bigint,$22::bigint,$23::bigint,$24::bigint,$25::bigint)::contour.causal_session_claim)";
const ACCEPT_SQL: &str = "SELECT receipt_id::text,floor(extract(epoch FROM accepted_at)*1000000)::bigint,duplicate FROM contour.accept_causal_batch($1::text::uuid,$2::text::uuid,$3::text::numeric,$4::bytea,$5::bytea,$6::bytea)";

/// Separate issuer connection. The peer, binding, nonce, and signing key sets
/// are trusted operator/server inputs, never request-supplied trust anchors.
/// Actual mTLS is outside this database bridge.
pub struct CausalIssuer {
    connection: ConnectedDatabase,
}
impl fmt::Debug for CausalIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalIssuer")
    }
}
impl CausalIssuer {
    pub fn new(connection: ConnectedDatabase) -> Self {
        Self { connection }
    }
    pub async fn issue(
        &mut self,
        request: &CausalIssue,
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
    ) -> Result<CausalSession, CausalError> {
        let deadline = Instant::now() + self.connection.deadline;
        self.issue_until(request, peer, grant_keys, policy_keys, deadline)
            .await
    }
    pub async fn issue_until(
        &mut self,
        request: &CausalIssue,
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<CausalSession, CausalError> {
        let deadline = deadline.min(Instant::now() + self.connection.deadline);
        check_deadline(deadline)?;
        if request.binding.peer != *peer {
            return Err(CausalError::Identity);
        }
        let mut guard = CancellationGuard::arm(&mut self.connection);
        let mut committing = false;
        let mut accepted = None;
        let work = async {
            let duration = guard.connection.deadline;
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CausalError::Database)?;
            check_role(client, "contour_causal_issuer").await?;
            let tx = begin(client).await?;
            let preparation = async {
                configure_tenant(&tx, &request.binding.ids[0], duration).await?;
                let now = clock(&tx).await?;
                let (grant, policy) = verify(request, peer, grant_keys, policy_keys, now)?;
                let g_start = pg_time(grant.issued_at(), true)?;
                let g_end = pg_time(grant.expires_at(), false)?;
                let p_start = pg_time(policy.issued_at(), true)?;
                let p_end = pg_time(policy.expires_at(), false)?;
                if g_start >= g_end || p_start >= p_end {
                    return Err(CausalError::Expired);
                }
                let revision = grant.revision().to_string();
                let p_revision = policy.revision().to_string();
                let digest = grant.payload_digest();
                let leaf = peer.as_slice();
                let hash = digest.as_slice();
                let envelope = request.policy.as_slice();
                let max_events =
                    i64::try_from(grant.max_batch_events()).map_err(|_| CausalError::Scope)?;
                let max_bytes =
                    i64::try_from(grant.max_batch_bytes()).map_err(|_| CausalError::Scope)?;
                let queue_bytes =
                    i64::try_from(grant.queue_bytes()).map_err(|_| CausalError::Scope)?;
                let queue_ttl =
                    i64::try_from(grant.queue_ttl_seconds()).map_err(|_| CausalError::Scope)?;
                let ids = &request.binding.ids;
                let params: [&(dyn tokio_postgres::types::ToSql + Sync); 25] = [
                    &ids[0],
                    &ids[1],
                    &ids[2],
                    &ids[3],
                    &ids[4],
                    &ids[5],
                    &ids[6],
                    &ids[7],
                    &ids[8],
                    &ids[9],
                    &leaf,
                    &request.nonce,
                    &revision,
                    &hash,
                    &g_start,
                    &g_end,
                    &p_revision,
                    &envelope,
                    &p_start,
                    &p_end,
                    &request.ttl_micros,
                    &max_events,
                    &max_bytes,
                    &queue_bytes,
                    &queue_ttl,
                ];
                let row = tx.query_one(ISSUE_SQL, &params).await.map_err(db_error)?;
                let result = parse_session(&row, request, digest)?;
                tx.query_one("SELECT set_config('synchronous_commit','on',true)", &[])
                    .await
                    .map_err(db_error)?;
                let final_now = clock(&tx).await?;
                let (again, pol_again) = verify(request, peer, grant_keys, policy_keys, final_now)?;
                if again.payload_digest() != digest
                    || result.issued > final_now
                    || result.issued < again.issued_at()
                    || result.issued < pol_again.issued_at()
                    || final_now >= result.expires
                    || result.expires > again.expires_at()
                    || result.expires > pol_again.expires_at()
                    || result.expires - result.issued
                        > time::Duration::microseconds(request.ttl_micros)
                {
                    return Err(CausalError::Expired);
                }
                check_deadline(deadline)?;
                Ok::<_, CausalError>(result)
            }
            .await;
            match preparation {
                Ok(session) => {
                    committing = true;
                    tx.commit().await.map_err(|_| CausalError::OutcomeUnknown)?;
                    accepted = Some(session);
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(())
                }
                Err(e) => {
                    tx.rollback().await.map_err(db_error)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    if e != CausalError::Deadline {
                        guard.confirm();
                    }
                    Err(e)
                }
            }
        };
        let result = timeout_at(deadline, work).await;
        if let Some(session) = accepted {
            return Ok(session);
        }
        match result {
            Ok(Ok(())) => Err(CausalError::Database),
            Ok(Err(e)) => Err(e),
            Err(_) if committing => Err(CausalError::OutcomeUnknown),
            Err(_) => Err(CausalError::Deadline),
        }
    }
}
/// Separate inbox connection; SQL rechecks session and authorization atomically
/// with the write. A verified peer pin and current operator-configured key sets
/// are supplied by the owning TLS server.
pub struct CausalInbox {
    connection: ConnectedDatabase,
}
impl fmt::Debug for CausalInbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalInbox")
    }
}
impl CausalInbox {
    pub fn new(connection: ConnectedDatabase) -> Self {
        Self { connection }
    }
    pub async fn accept(
        &mut self,
        session: &CausalSession,
        peer: &[u8; 32],
        bytes: &[u8],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
    ) -> Result<CausalReceipt, CausalError> {
        let deadline = Instant::now() + self.connection.deadline;
        self.accept_until(session, peer, bytes, grant_keys, policy_keys, deadline)
            .await
    }
    pub async fn accept_until(
        &mut self,
        session: &CausalSession,
        peer: &[u8; 32],
        bytes: &[u8],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<CausalReceipt, CausalError> {
        let deadline = deadline.min(Instant::now() + self.connection.deadline);
        check_deadline(deadline)?;
        let ids = &session.issue.binding.ids;
        if *peer != session.issue.binding.peer {
            return Err(CausalError::Identity);
        }
        if bytes.len() > contour_core::MAX_CAUSAL_EVENT_BATCH_BYTES {
            return Err(CausalError::InvalidBatch);
        }
        let mut guard = CancellationGuard::arm(&mut self.connection);
        let mut committing = false;
        let mut accepted = None;
        let work = async {
            let duration = guard.connection.deadline;
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CausalError::Database)?;
            check_role(client, "contour_causal_inbox_writer").await?;
            let tx = begin(client).await?;
            let preparation = async {
                configure_tenant(&tx, &ids[0], duration).await?;
                let now = clock(&tx).await?;
                checked_admission(session, peer, bytes, grant_keys, policy_keys, now)?;
                let epoch = session.epoch.to_string();
                let leaf = peer.as_slice();
                let digest = session.digest.as_slice();
                let row = tx
                    .query_one(
                        ACCEPT_SQL,
                        &[&ids[0], &ids[1], &epoch, &leaf, &digest, &bytes],
                    )
                    .await
                    .map_err(db_error)?;
                let result = receipt(&row)?;
                tx.query_one("SELECT set_config('synchronous_commit','on',true)", &[])
                    .await
                    .map_err(db_error)?;
                let final_now = clock(&tx).await?;
                let (again, _) = verify(&session.issue, peer, grant_keys, policy_keys, final_now)?;
                if final_now < session.issued
                    || final_now >= session.expires
                    || again.payload_digest() != session.digest
                {
                    return Err(CausalError::Expired);
                }
                check_deadline(deadline)?;
                Ok::<_, CausalError>(result)
            }
            .await;
            match preparation {
                Ok(receipt) => {
                    committing = true;
                    tx.commit().await.map_err(|_| CausalError::OutcomeUnknown)?;
                    accepted = Some(receipt);
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(())
                }
                Err(e) => {
                    tx.rollback().await.map_err(db_error)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    if e != CausalError::Deadline {
                        guard.confirm();
                    }
                    Err(e)
                }
            }
        };
        let result = timeout_at(deadline, work).await;
        if let Some(receipt) = accepted {
            return Ok(receipt);
        }
        match result {
            Ok(Ok(())) => Err(CausalError::Database),
            Ok(Err(e)) => Err(e),
            Err(_) if committing => Err(CausalError::OutcomeUnknown),
            Err(_) => Err(CausalError::Deadline),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contour_core::Timestamp;
    use serde_json::{Value, json};
    const ID: &str = "00000000-0000-4000-8000-000000000001";
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/causal_bridge.json")).unwrap()
    }
    fn bytes(v: &Value, name: &str) -> Vec<u8> {
        serde_json::to_vec(&v[name]).unwrap()
    }
    fn hex32(s: &str) -> [u8; 32] {
        let mut b = [0; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        b
    }
    fn keys(v: &Value) -> (CausalGrantKeys, PolicyKeys) {
        (
            CausalGrantKeys::new(&[("fixture", hex32(v["grant_public"].as_str().unwrap()))])
                .unwrap(),
            PolicyKeys::new(&[("fixture", hex32(v["policy_public"].as_str().unwrap()))]).unwrap(),
        )
    }
    fn binding() -> CausalBinding {
        CausalBinding::new([ID; 10], [3; 32]).unwrap()
    }
    fn request(v: &Value, grant: &str, policy: &str) -> CausalIssue {
        CausalIssue::new(
            binding(),
            ID,
            Duration::from_secs(60),
            &bytes(v, grant),
            &bytes(v, policy),
        )
        .unwrap()
    }
    fn now() -> OffsetDateTime {
        Timestamp::parse("2026-10-07T12:00:01Z").unwrap().instant()
    }
    fn session(request: CausalIssue) -> CausalSession {
        CausalSession {
            issue: request,
            epoch: u64::MAX,
            issued: now(),
            expires: now() + time::Duration::minutes(1),
            digest: [9; 32],
        }
    }
    #[test]
    fn signed_grant_policy_and_fixed_point_positive_control() {
        let v = fixture();
        let (g, p) = keys(&v);
        let r = request(&v, "grant", "policy");
        let (grant, policy) = verify(&r, &[3; 32], &g, &p, now()).unwrap();
        assert_eq!(grant.revision(), u64::MAX);
        assert_eq!(policy.revision(), u64::MAX);
        assert_eq!(grant.profile_sha256(), ARTIFACT);
        assert_eq!(format!("{r:?}"), "CausalIssue");
        assert_eq!(format!("{:?}", r.binding), "CausalBinding");
    }
    #[test]
    fn signed_rejections_are_independent_of_binding_and_lease() {
        let v = fixture();
        let (g, p) = keys(&v);
        for name in ["disabled_grant", "empty_queue", "wrong_profile_name"] {
            assert_eq!(
                verify(&request(&v, name, "policy"), &[3; 32], &g, &p, now()).unwrap_err(),
                CausalError::Scope
            );
        }
        for name in ["wrong_profile", "wrong_tenant", "wrong_collector"] {
            assert_eq!(
                verify(&request(&v, name, "policy"), &[3; 32], &g, &p, now()).unwrap_err(),
                CausalError::Identity
            );
        }
        for name in ["disabled_policy", "denied_route", "missing_post"] {
            assert_eq!(
                verify(&request(&v, "grant", name), &[3; 32], &g, &p, now()).unwrap_err(),
                CausalError::Scope
            );
        }
        let mut r = request(&v, "grant", "policy");
        r.grant.push(b' ');
        r.grant[10] ^= 1;
        assert_eq!(
            verify(&r, &[3; 32], &g, &p, now()).unwrap_err(),
            CausalError::Signature
        );
        assert_eq!(
            verify(
                &request(&v, "grant", "wrong_policy_tenant"),
                &[3; 32],
                &g,
                &p,
                now()
            )
            .unwrap_err(),
            CausalError::Identity
        );
        for index in [1, 3, 8, 9] {
            let mut mismatch = request(&v, "grant", "policy");
            mismatch.binding.ids[index] = "00000000-0000-4000-8000-000000000002".into();
            assert_eq!(
                verify(&mismatch, &[3; 32], &g, &p, now()).unwrap_err(),
                CausalError::Identity
            );
        }
        let mut wrong_policy = request(&v, "grant", "policy");
        wrong_policy.policy[10] ^= 1;
        assert_eq!(
            verify(&wrong_policy, &[3; 32], &g, &p, now()).unwrap_err(),
            CausalError::Signature
        );
        let other_policy =
            PolicyKeys::new(&[("fixture", hex32(v["grant_public"].as_str().unwrap()))]).unwrap();
        assert_eq!(
            verify(
                &request(&v, "grant", "policy"),
                &[3; 32],
                &g,
                &other_policy,
                now()
            )
            .unwrap_err(),
            CausalError::Signature
        );
        let other =
            CausalGrantKeys::new(&[("fixture", hex32(v["policy_public"].as_str().unwrap()))])
                .unwrap();
        assert_eq!(
            verify(&request(&v, "grant", "policy"), &[3; 32], &other, &p, now()).unwrap_err(),
            CausalError::Signature
        );
        assert_eq!(
            verify(&request(&v, "grant", "policy"), &[4; 32], &g, &p, now()).unwrap_err(),
            CausalError::Identity
        );
        let expired = Timestamp::parse("2026-10-07T12:10:00.000000999Z")
            .unwrap()
            .instant();
        assert_eq!(
            verify(&request(&v, "grant", "policy"), &[3; 32], &g, &p, expired).unwrap_err(),
            CausalError::Expired
        );
    }
    #[test]
    fn precision_rounds_conservatively_across_epoch() {
        let year_zero = time::Date::from_calendar_date(0, time::Month::January, 1)
            .unwrap()
            .midnight()
            .assume_utc();
        assert_eq!(pg_time(year_zero, false).unwrap_err(), CausalError::Expired);
        let pre = OffsetDateTime::from_unix_timestamp_nanos(-1).unwrap();
        assert_eq!(
            pg_time(pre, false).unwrap(),
            "1969-12-31T23:59:59.999999+00:00"
        );
        assert_eq!(
            pg_time(pre, true).unwrap(),
            "1970-01-01T00:00:00.000000+00:00"
        );
        let post = OffsetDateTime::from_unix_timestamp_nanos(1001).unwrap();
        assert_eq!(
            pg_time(post, false).unwrap(),
            "1970-01-01T00:00:00.000001+00:00"
        );
        assert_eq!(
            pg_time(post, true).unwrap(),
            "1970-01-01T00:00:00.000002+00:00"
        );
        let v = fixture();
        let (g, p) = keys(&v);
        let (grant, pol) =
            verify(&request(&v, "grant", "policy"), &[3; 32], &g, &p, now()).unwrap();
        assert_eq!(
            pg_time(grant.issued_at(), true).unwrap(),
            "2026-10-07T12:00:00.000001+00:00"
        );
        assert_eq!(
            pg_time(pol.expires_at(), false).unwrap(),
            "2026-10-07T12:10:00.000000+00:00"
        );
    }
    #[test]
    fn binding_nonce_ttl_and_data_are_bounded() {
        let v = fixture();
        let (g, p) = keys(&v);
        assert_eq!(
            CausalBinding::new(["bad"; 10], [0; 32]).unwrap_err(),
            CausalError::Identity
        );
        assert_eq!(
            CausalIssue::new(
                binding(),
                "bad",
                Duration::from_secs(1),
                &bytes(&v, "grant"),
                &bytes(&v, "policy")
            )
            .unwrap_err(),
            CausalError::Identity
        );
        for ttl in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_secs(901),
        ] {
            assert_eq!(
                CausalIssue::new(
                    binding(),
                    ID,
                    ttl,
                    &bytes(&v, "grant"),
                    &bytes(&v, "policy")
                )
                .unwrap_err(),
                CausalError::Scope
            );
        }
        let mut r = request(&v, "grant", "policy");
        r.binding.ids[5] = "00000000-0000-4000-8000-000000000002".into();
        assert_eq!(
            verify(&r, &[3; 32], &g, &p, now()).unwrap_err(),
            CausalError::Scope
        );
    }
    #[test]
    fn role_decision_requires_every_catalog_fact() {
        assert!(role_allowed([true; 7]));
        // current/session mismatch, authenticated-login mismatch, superuser or
        // bypass, either missing role, absent target membership, mixed membership.
        for i in 0..7 {
            let mut facts = [true; 7];
            facts[i] = false;
            assert!(!role_allowed(facts));
        }
    }
    #[test]
    fn authority_checks_precede_canonical_batch_parsing() {
        let v = fixture();
        let (g, p) = keys(&v);
        let r = request(&v, "grant", "policy");
        let digest = verify(&r, &[3; 32], &g, &p, now())
            .unwrap()
            .0
            .payload_digest();
        let mut s = session(r);
        s.digest = digest;
        let wrong =
            CausalGrantKeys::new(&[("fixture", hex32(v["policy_public"].as_str().unwrap()))])
                .unwrap();
        assert_eq!(
            checked_admission(&s, &[3; 32], b"not-json", &wrong, &p, now()).unwrap_err(),
            CausalError::Signature
        );
        assert_eq!(
            checked_admission(&s, &[3; 32], b"not-json", &g, &p, now()).unwrap_err(),
            CausalError::InvalidBatch
        );
        assert_eq!(
            checked_admission(&s, &[3; 32], b"not-json", &g, &p, s.expires).unwrap_err(),
            CausalError::Expired
        );
    }
    #[test]
    fn database_error_categories_require_the_exact_diagnostic() {
        assert_eq!(
            classify_database_error("54000", Some("origin_logical_quota_exhausted"), "ignored"),
            CausalError::LogicalQuota
        );
        assert_eq!(
            classify_database_error("54000", Some("causal_session_history_limit"), "ignored"),
            CausalError::HistoryLimit
        );
        assert_eq!(
            classify_database_error("54000", None, "origin_logical_quota_exhausted"),
            CausalError::Database
        );
        assert_eq!(
            classify_database_error("23514", Some("origin_logical_quota_exhausted"), "ignored"),
            CausalError::Scope
        );
        assert_eq!(
            classify_database_error("23514", None, "stored causal batch corrupted"),
            CausalError::Corrupt
        );
        assert_eq!(
            classify_database_error("23514", None, "other"),
            CausalError::Scope
        );
    }
    #[test]
    fn only_explicit_untagged_unique_conflicts_are_caller_conflicts() {
        for message in [
            "nonce unavailable",
            "causal batch conflict",
            "causal fact conflict",
        ] {
            assert_eq!(
                classify_database_error("23505", None, message),
                CausalError::Conflict
            );
            assert_eq!(
                classify_database_error("23505", Some("unrelated_unique_index"), message),
                CausalError::Database
            );
            assert_eq!(
                classify_database_error("23514", None, message),
                CausalError::Scope
            );
        }
        for (constraint, message) in [
            (None, "duplicate key value violates unique constraint"),
            (
                Some("causal_inbox_batches_receipt_id_key"),
                "duplicate key value violates unique constraint",
            ),
            (Some("unexpected_unique_index"), "causal batch conflict"),
            (None, "causal batch conflict with suffix"),
        ] {
            assert_eq!(
                classify_database_error("23505", constraint, message),
                CausalError::Database
            );
        }
    }
    #[test]
    fn corruption_diagnostic_is_exact_and_does_not_hide_bad_input() {
        assert_eq!(
            classify_database_error("23514", None, "stored causal batch corrupted"),
            CausalError::Corrupt
        );
        assert_eq!(
            classify_database_error(
                "23514",
                Some("unexpected_constraint"),
                "stored causal batch corrupted"
            ),
            CausalError::Scope
        );
        assert_eq!(
            classify_database_error("23514", None, "invalid causal envelope"),
            CausalError::Scope
        );
        for code in ["22021", "22P02", "22003"] {
            assert_eq!(
                classify_database_error(code, None, "stored causal batch corrupted"),
                CausalError::Database
            );
        }
        for (code, constraint) in [
            ("54000", None),
            ("54000", Some("other")),
            ("23514", Some("origin_logical_quota_exhausted")),
            ("22003", Some("causal_session_history_limit")),
        ] {
            assert_ne!(
                classify_database_error(code, constraint, "origin logical quota exhausted"),
                CausalError::LogicalQuota
            );
            assert_ne!(
                classify_database_error(code, constraint, "causal session history limit exhausted"),
                CausalError::HistoryLimit
            );
        }
    }
    #[test]
    fn microsecond_empty_window_is_not_widened() {
        let first = OffsetDateTime::from_unix_timestamp_nanos(1).unwrap();
        let last = OffsetDateTime::from_unix_timestamp_nanos(999).unwrap();
        assert!(pg_time(first, true).unwrap() >= pg_time(last, false).unwrap());
    }
    #[test]
    fn batch_requires_original_peer_epoch_and_exact_canonical_bytes() {
        let v = fixture();
        let mut r = request(&v, "grant", "policy");
        let saved = session(r.clone());
        let value = json!({"wire_version":1,"batch_id":ID,"tenant_id":ID,"runtime_id":ID,"session_epoch":u64::MAX,"first_seq":1,"last_seq":1,"events":[{"kind":"root","event_id":"11111111111111111111111111111111","seq":1,"root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]});
        let raw = serde_json::to_vec(&value).unwrap();
        let batch = CausalEventBatch::from_wire_json(&raw).unwrap();
        let canonical = batch.canonical_bytes().unwrap();
        assert!(check_batch(&saved, &[3; 32], &canonical).is_ok());
        assert!(matches!(
            check_batch(&saved, &[4; 32], &canonical),
            Err(CausalError::Identity)
        ));
        let mut other = session(r.clone());
        other.epoch = 1;
        assert!(matches!(
            check_batch(&other, &[3; 32], &canonical),
            Err(CausalError::Identity)
        ));
        let mut noncanonical = canonical.clone();
        noncanonical.push(b' ');
        assert!(matches!(
            check_batch(&saved, &[3; 32], &noncanonical),
            Err(CausalError::InvalidBatch)
        ));
        assert!(matches!(
            check_batch(&saved, &[3; 32], &vec![b' '; 1_048_577]),
            Err(CausalError::InvalidBatch)
        ));
        r.nonce = "changed-secret".into();
        r.grant.clear();
        assert_eq!(saved.issue.nonce, ID);
        assert!(!saved.issue.grant.is_empty());
        assert_eq!(format!("{saved:?}"), "CausalSession");
    }
}
