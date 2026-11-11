//! Internal causal SQL bridge. Callers authenticate the peer and own the
//! configured binding; neither a leaf pin nor this module attests a producer.
//! Session authority is in-memory only; request recovery requires a separate owner.
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
    AdmissionInputs, CaptureScope, CausalEventBatch, CausalGrantKeys, CausalMarkerScope,
    CausalMarkerVerifier, PolicyKeys, SourceAssignment, VerifiedCausalGrant, VerifiedPolicy,
};
use std::{fmt, time::Duration};
use time::{OffsetDateTime, UtcOffset};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Client, Error, Row};

const PROFILE: &str = "nodered_5_0_9_v1";
const ARTIFACT: &str = "b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510";
const WIRE_PROFILE: &str = "nodered_5_0_9_wire_v1";
const WIRE_ARTIFACT: &str = "a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e";

fn authorized_profile(name: &str, hash: &str) -> bool {
    matches!(
        (name, hash),
        (PROFILE, ARTIFACT) | (WIRE_PROFILE, WIRE_ARTIFACT)
    )
}

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
fn classify_issuer_error(code: &str, constraint: Option<&str>, message: &str) -> CausalError {
    if code == "40001" {
        return if constraint.is_none()
            && matches!(
                message,
                "origin gate busy" | "credential gate busy" | "collector gate busy"
            ) {
            CausalError::Busy
        } else {
            CausalError::Database
        };
    }
    classify_database_error(code, constraint, message)
}
fn issuer_sql_error(error: Error) -> CausalError {
    error.as_db_error().map_or(CausalError::Database, |db| {
        classify_issuer_error(db.code().code(), db.constraint(), db.message())
    })
}
fn classify_marker_binding_error(
    code: &str,
    constraint: Option<&str>,
    message: &str,
) -> CausalError {
    classify_issuer_error(code, constraint, message)
}
fn marker_binding_sql_error(error: Error) -> CausalError {
    error.as_db_error().map_or(CausalError::Database, |db| {
        classify_marker_binding_error(db.code().code(), db.constraint(), db.message())
    })
}
fn nonretry_error(error: Error) -> CausalError {
    match db_error(error) {
        CausalError::Busy => CausalError::Database,
        other => other,
    }
}
fn classify_database_error(code: &str, constraint: Option<&str>, message: &str) -> CausalError {
    match (code, constraint) {
        ("54000", Some("origin_logical_quota_exhausted")) => CausalError::LogicalQuota,
        ("54000", Some("causal_session_history_limit")) => CausalError::HistoryLimit,
        ("23505", None)
            if matches!(
                message,
                "nonce unavailable"
                    | "causal batch conflict"
                    | "causal fact conflict"
                    | "marker binding conflict"
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
    /// Canonical versioned encoding of inputs for the fixed intent-only v1 profile. Contains credentials;
    /// callers must protect it and must not treat it as session authority.
    pub fn original_bytes(&self) -> Vec<u8> {
        let mut out = b"CCI1".to_vec();
        for id in &self.binding.ids {
            out.extend_from_slice(id.as_bytes());
        }
        out.extend_from_slice(&self.binding.peer);
        out.extend_from_slice(self.nonce.as_bytes());
        out.extend_from_slice(&self.ttl_micros.to_be_bytes());
        for envelope in [&self.grant, &self.policy] {
            out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
            out.extend_from_slice(envelope);
        }
        out
    }
    /// Signature/scope preflight for an inert candidate proxy only. Local wall
    /// clock is not database time and this does not issue a session or authorize
    /// a producer, seed transfer, or permit.
    pub fn signature_preflight_503(
        &self,
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
    ) -> Result<(), CausalError> {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CausalError::Expired)?;
        let nanos = i128::try_from(duration.as_nanos()).map_err(|_| CausalError::Expired)?;
        let now =
            OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| CausalError::Expired)?;
        self.signature_preflight_503_at(peer, grant_keys, policy_keys, now)
    }
    fn signature_preflight_503_at(
        &self,
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
        now: OffsetDateTime,
    ) -> Result<(), CausalError> {
        let (grant, _) = verify(self, peer, grant_keys, policy_keys, now)?;
        if SessionProfile::from_verified(&grant)? != SessionProfile::Candidate503 {
            return Err(CausalError::Identity);
        }
        Ok(())
    }
    /// Parse only original request inputs, with no verification or session creation.
    pub fn from_original_bytes(bytes: &[u8]) -> Result<Self, CausalError> {
        const FIXED: usize = 4 + 10 * 36 + 32 + 36 + 8 + 8;
        if bytes.len() < FIXED || bytes.len() > FIXED + 2 * 1_048_576 || &bytes[..4] != b"CCI1" {
            return Err(CausalError::Corrupt);
        }
        let mut at = 4;
        fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], CausalError> {
            let end = at.checked_add(n).ok_or(CausalError::Corrupt)?;
            let result = bytes.get(*at..end).ok_or(CausalError::Corrupt)?;
            *at = end;
            Ok(result)
        }
        let mut ids = Vec::with_capacity(10);
        for _ in 0..10 {
            ids.push(
                std::str::from_utf8(take(bytes, &mut at, 36)?).map_err(|_| CausalError::Corrupt)?,
            );
        }
        let peer: [u8; 32] = take(bytes, &mut at, 32)?
            .try_into()
            .map_err(|_| CausalError::Corrupt)?;
        let nonce =
            std::str::from_utf8(take(bytes, &mut at, 36)?).map_err(|_| CausalError::Corrupt)?;
        let ttl = i64::from_be_bytes(
            take(bytes, &mut at, 8)?
                .try_into()
                .map_err(|_| CausalError::Corrupt)?,
        );
        let mut envelopes = Vec::with_capacity(2);
        for _ in 0..2 {
            let n = u32::from_be_bytes(
                take(bytes, &mut at, 4)?
                    .try_into()
                    .map_err(|_| CausalError::Corrupt)?,
            ) as usize;
            if n == 0 || n > 1_048_576 {
                return Err(CausalError::Corrupt);
            }
            envelopes.push(take(bytes, &mut at, n)?);
        }
        if at != bytes.len() || ttl <= 0 {
            return Err(CausalError::Corrupt);
        }
        let binding = CausalBinding::new(ids.try_into().map_err(|_| CausalError::Corrupt)?, peer)
            .map_err(|_| CausalError::Corrupt)?;
        let issue = Self::new(
            binding,
            nonce,
            Duration::from_micros(ttl as u64),
            envelopes[0],
            envelopes[1],
        )
        .map_err(|_| CausalError::Corrupt)?;
        if issue.original_bytes() != bytes {
            return Err(CausalError::Corrupt);
        }
        Ok(issue)
    }
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
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionProfile {
    Legacy501,
    Candidate503,
}
impl SessionProfile {
    fn from_verified(grant: &VerifiedCausalGrant) -> Result<Self, CausalError> {
        match (grant.causal_profile(), grant.profile_sha256()) {
            (PROFILE, ARTIFACT) => Ok(Self::Legacy501),
            (WIRE_PROFILE, WIRE_ARTIFACT) => Ok(Self::Candidate503),
            _ => Err(CausalError::Identity),
        }
    }
}

/// Created only after confirmed SQL commit. It retains the exact authenticated
/// envelopes and original input in memory; it cannot be deserialized from a journal.
pub struct CausalSession {
    issue: CausalIssue,
    profile: SessionProfile,
    epoch: u64,
    issued: OffsetDateTime,
    expires: OffsetDateTime,
    digest: [u8; 32],
    verified_until: Instant,
}
/// Borrowed candidate identity from an issued session. This is data for the
/// session's lifetime, not producer attestation or independent authority.
/// Check the current monotonic ceiling again at every use.
///
/// The view cannot be constructed by callers:
/// ```compile_fail
/// use contour_postgres::CausalWireProfile503;
/// let _view = CausalWireProfile503 { session: todo!() };
/// ```
/// It cannot outlive an immutable borrow of its session:
/// ```compile_fail
/// use contour_postgres::CausalSession;
/// fn cannot_mutate(session: &mut CausalSession) {
///     let view = session.wire_profile_503().unwrap();
///     let _mutable = &mut *session;
///     println!("{}", view.epoch());
/// }
/// ```
pub struct CausalWireProfile503<'a> {
    session: &'a CausalSession,
}
impl CausalWireProfile503<'_> {
    pub fn tenant_id(&self) -> &str {
        &self.session.issue.binding.ids[0]
    }
    pub fn runtime_id(&self) -> &str {
        &self.session.issue.binding.ids[1]
    }
    pub fn nonce(&self) -> &str {
        &self.session.issue.nonce
    }
    pub fn epoch(&self) -> u64 {
        self.session.epoch
    }
    pub fn profile_id(&self) -> &'static str {
        "00000000-0000-4000-8000-000000000503"
    }
    pub fn profile_name(&self) -> &'static str {
        WIRE_PROFILE
    }
    pub fn profile_sha256(&self) -> &'static str {
        WIRE_ARTIFACT
    }
    /// Current conservative monotonic ceiling; it can only tighten.
    pub fn verified_until(&self) -> Instant {
        self.session.verified_until
    }
    pub fn verified_remaining(&self) -> Duration {
        self.session.verified_remaining()
    }
}
impl CausalSession {
    /// Whether this session is permitted to enter the legacy intent-only path.
    pub fn is_legacy_intent_profile(&self) -> bool {
        self.profile == SessionProfile::Legacy501 && !self.verified_remaining().is_zero()
    }
    /// Candidate profile data tied to this live session, if still fresh.
    pub fn wire_profile_503(&self) -> Option<CausalWireProfile503<'_>> {
        (self.profile == SessionProfile::Candidate503 && !self.verified_remaining().is_zero())
            .then_some(CausalWireProfile503 { session: self })
    }
    /// Compare an operator-configured verified leaf pin without exposing the
    /// retained credential or constructing a session from request data.
    pub fn matches_peer(&self, peer: &[u8; 32]) -> bool {
        self.issue.binding.peer == *peer
    }
    /// Conservative remaining lifetime from the last verified database-clock check.
    pub fn verified_remaining(&self) -> Duration {
        self.verified_until
            .saturating_duration_since(Instant::now())
    }
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
    ] || !authorized_profile(grant.causal_profile(), grant.profile_sha256())
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
fn freshness_deadline(
    start: Instant,
    checked: OffsetDateTime,
    expires: OffsetDateTime,
    now: Instant,
) -> Result<Instant, CausalError> {
    let remaining = Duration::try_from(expires - checked).map_err(|_| CausalError::Expired)?;
    let deadline = start.checked_add(remaining).ok_or(CausalError::Expired)?;
    if deadline <= now {
        return Err(CausalError::Expired);
    }
    Ok(deadline)
}
fn claim_freshness(
    current: Instant,
    start: Instant,
    checked: OffsetDateTime,
    expires: OffsetDateTime,
    now: Instant,
) -> Result<Instant, CausalError> {
    let deadline = current.min(freshness_deadline(start, checked, expires, now)?);
    if deadline <= now {
        return Err(CausalError::Expired);
    }
    Ok(deadline)
}
fn commit_freshness(limit: Instant, now: Instant) -> Result<Instant, CausalError> {
    if now >= limit {
        Err(CausalError::Expired)
    } else {
        Ok(limit)
    }
}
fn parse_session(
    row: &Row,
    issue: &CausalIssue,
    digest: [u8; 32],
    profile: SessionProfile,
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
        profile,
        epoch,
        issued,
        expires,
        digest,
        verified_until: Instant::now(),
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
const ISSUE_SQL_WIRE: &str = "SELECT epoch::text,floor(extract(epoch FROM issued_at)*1000000)::bigint,floor(extract(epoch FROM expires_at)*1000000)::bigint FROM contour.issue_causal_session(ROW($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid,$10::text::uuid,$11::bytea,'nodered_5_0_9_wire_v1',decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex'),$12::text::uuid,$13::text::numeric,$14::bytea,$15::text::timestamptz,$16::text::timestamptz,$17::text::numeric,$18::bytea,$19::text::timestamptz,$20::text::timestamptz,$21::bigint,$22::bigint,$23::bigint,$24::bigint,$25::bigint)::contour.causal_session_claim)";
const ACCEPT_SQL: &str = "SELECT receipt_id::text,floor(extract(epoch FROM accepted_at)*1000000)::bigint,duplicate FROM contour.accept_causal_batch($1::text::uuid,$2::text::uuid,$3::text::numeric,$4::bytea,$5::bytea,$6::bytea)";

fn check_marker_inputs(
    session: &CausalSession,
    generation: &[u8; 32],
    product_credential_id: &str,
    product_leaf: &[u8; 32],
    public_key: &[u8; 32],
    peer: &[u8; 32],
) -> Result<(), CausalError> {
    if !uuid(product_credential_id)
        || *generation == [0; 32]
        || product_leaf == peer
        || !session.matches_peer(peer)
        || session.verified_remaining().is_zero()
    {
        return Err(CausalError::Scope);
    }
    let leaf_hex: String = product_leaf.iter().map(|b| format!("{b:02x}")).collect();
    let scope = CausalMarkerScope::new(
        &session.issue.binding.ids[0],
        &session.issue.binding.ids[1],
        session.epoch,
        &leaf_hex,
    )
    .map_err(|_| CausalError::Scope)?;
    CausalMarkerVerifier::new(*public_key, scope).map_err(|_| CausalError::Signature)?;
    Ok(())
}

/// Immutable public binding receipt. It does not grant future authority, attest
/// possession of a private key, or authorize a producer launch.
pub struct CausalMarkerBinding {
    public_key: [u8; 32],
    bound_at: OffsetDateTime,
}
impl CausalMarkerBinding {
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    pub fn bound_at(&self) -> OffsetDateTime {
        self.bound_at
    }
}
impl fmt::Debug for CausalMarkerBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalMarkerBinding")
    }
}

// An interrupted future must not leave its borrowed session usable.
struct MarkerSessionGuard<'a> {
    session: &'a mut CausalSession,
    succeeded: bool,
}
impl Drop for MarkerSessionGuard<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.session.verified_until = Instant::now();
        }
    }
}

/// Dedicated provisioner connection. The selected credential and public key
/// are trusted operator inputs; database state is rechecked under locks.
pub struct CausalMarkerBinder {
    connection: ConnectedDatabase,
}
impl fmt::Debug for CausalMarkerBinder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalMarkerBinder")
    }
}
impl CausalMarkerBinder {
    pub fn new(connection: ConnectedDatabase) -> Self {
        Self { connection }
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn bind(
        &mut self,
        session: &mut CausalSession,
        generation: &[u8; 32],
        product_credential_id: &str,
        product_leaf: &[u8; 32],
        public_key: &[u8; 32],
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
    ) -> Result<CausalMarkerBinding, CausalError> {
        let deadline = Instant::now() + self.connection.deadline;
        self.bind_until(
            session,
            generation,
            product_credential_id,
            product_leaf,
            public_key,
            peer,
            grant_keys,
            policy_keys,
            deadline,
        )
        .await
    }
    /// Bind within an absolute deadline. Commit ambiguity remains terminal;
    /// dropping this future invalidates the borrowed session.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind_until(
        &mut self,
        session: &mut CausalSession,
        generation: &[u8; 32],
        product_credential_id: &str,
        product_leaf: &[u8; 32],
        public_key: &[u8; 32],
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<CausalMarkerBinding, CausalError> {
        let deadline = deadline.min(Instant::now() + self.connection.deadline);
        let mut session_guard = MarkerSessionGuard {
            session,
            succeeded: false,
        };
        let result = self
            .bind_checked(
                session_guard.session,
                generation,
                product_credential_id,
                product_leaf,
                public_key,
                peer,
                grant_keys,
                policy_keys,
                deadline,
            )
            .await;
        session_guard.succeeded = result.is_ok();
        result
    }
    #[allow(clippy::too_many_arguments)]
    async fn bind_checked(
        &mut self,
        session: &mut CausalSession,
        generation: &[u8; 32],
        product_credential_id: &str,
        product_leaf: &[u8; 32],
        public_key: &[u8; 32],
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<CausalMarkerBinding, CausalError> {
        check_deadline(deadline)?;
        check_marker_inputs(
            session,
            generation,
            product_credential_id,
            product_leaf,
            public_key,
            peer,
        )?;
        let deadline = deadline.min(session.verified_until);
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(&mut self.connection);
        let mut committing = false;
        let mut tightened = None;
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CausalError::Database)?;
            check_role(client, "contour_causal_provisioner")
                .await
                .map_err(|_| CausalError::Database)?;
            let tx = begin(client).await?;
            let checked = async {
                let issue = &session.issue;
                configure_tenant(&tx, &issue.binding.ids[0], deadline.saturating_duration_since(Instant::now())).await?;
                let now = clock(&tx).await?;
                let (g, _) = verify(issue, peer, grant_keys, policy_keys, now)?;
                if g.payload_digest() != session.digest || now < session.issued || now >= session.expires || session.verified_remaining().is_zero() { return Err(CausalError::Expired); }
                let epoch = session.epoch.to_string();
                check_deadline(deadline)?;
                configure_tenant(&tx, &issue.binding.ids[0], deadline.saturating_duration_since(Instant::now())).await?;
                let row = tx.query_one("SELECT floor(extract(epoch FROM contour.bind_causal_marker_key($1::text::uuid,$2::text::uuid,$3::text::numeric,$4::text::uuid,$5::bytea,$6::text::uuid,$7::bytea,$8::bytea))*1000000)::bigint", &[&issue.binding.ids[0], &issue.binding.ids[1], &epoch, &issue.nonce, &&generation[..], &product_credential_id, &&product_leaf[..], &&public_key[..]]).await.map_err(marker_binding_sql_error)?;
                let bound_at = time_from_micros(row.try_get(0).map_err(|_| CausalError::Corrupt)?)?;
                let final_start = Instant::now();
                let final_now = clock(&tx).await?;
                let (again, _) = verify(issue, peer, grant_keys, policy_keys, final_now)?;
                if final_now < now || final_now < bound_at || final_now >= session.expires || again.payload_digest() != session.digest || session.verified_remaining().is_zero() { return Err(CausalError::Expired); }
                tightened = Some(claim_freshness(session.verified_until, final_start, final_now, session.expires, Instant::now())?);
                tx.query_one("SELECT set_config('synchronous_commit','on',true)", &[]).await.map_err(nonretry_error)?;
                check_deadline(deadline)?;
                Ok::<_, CausalError>(bound_at)
            }.await;
            match checked {
                Ok(bound_at) => {
                    committing = true;
                    tx.commit().await.map_err(|_| CausalError::OutcomeUnknown)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(bound_at)
                }
                Err(e) => {
                    tx.rollback().await.map_err(|_| CausalError::Database)?;
                    empty_context(client)
                        .await
                        .map_err(|_| CausalError::Database)?;
                    check_deadline(deadline)?;
                    if e != CausalError::Deadline {
                        guard.confirm();
                    }
                    Err(e)
                }
            }
        };
        let result = match timeout_at(deadline, work).await {
            Ok(Err(_)) if committing => Err(CausalError::OutcomeUnknown),
            Ok(result) => result,
            Err(_) if committing => Err(CausalError::OutcomeUnknown),
            Err(_) => Err(CausalError::Deadline),
        };
        let bound_at = result?;
        session.verified_until =
            commit_freshness(tightened.ok_or(CausalError::Expired)?, Instant::now())?;
        Ok(CausalMarkerBinding {
            public_key: *public_key,
            bound_at,
        })
    }
}

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
    /// Claim one privately generated child generation for this checked session.
    /// A lost COMMIT acknowledgement is OutcomeUnknown; only the same generation
    /// may be reconciled, and reconciliation is never permission to relaunch.
    pub async fn claim_generation(
        &mut self,
        session: &mut CausalSession,
        generation: &[u8; 32],
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
    ) -> Result<(), CausalError> {
        let deadline = Instant::now() + self.connection.deadline;
        self.claim_generation_until(session, generation, peer, grant_keys, policy_keys, deadline)
            .await
    }
    /// A single checked claim bounded by the caller's absolute deadline.
    pub async fn claim_generation_until(
        &mut self,
        session: &mut CausalSession,
        generation: &[u8; 32],
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<(), CausalError> {
        let deadline = deadline.min(Instant::now() + self.connection.deadline);
        check_deadline(deadline)?;
        if *generation == [0; 32]
            || !session.matches_peer(peer)
            || session.verified_remaining().is_zero()
        {
            return Err(CausalError::Expired);
        }
        let mut guard = CancellationGuard::arm(&mut self.connection);
        let mut committing = false;
        let mut tightened = None;
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CausalError::Database)?;
            check_role(client, "contour_causal_issuer")
                .await
                .map_err(|e| {
                    if e == CausalError::Busy {
                        CausalError::Database
                    } else {
                        e
                    }
                })?;
            let tx = begin(client).await?;
            let checked = async {
                let issue = &session.issue;
                check_deadline(deadline)?;
                let duration = deadline.saturating_duration_since(Instant::now());
                configure_tenant(&tx, &issue.binding.ids[0], duration).await?;
                let now = clock(&tx).await?;
                let (g, _) = verify(issue, peer, grant_keys, policy_keys, now)?;
                if g.payload_digest() != session.digest || now < session.issued || now >= session.expires || session.verified_remaining().is_zero() { return Err(CausalError::Expired); }
                let epoch = session.epoch.to_string();
                check_deadline(deadline)?;
                configure_tenant(&tx, &issue.binding.ids[0], deadline.saturating_duration_since(Instant::now())).await?;
                check_deadline(deadline)?;
                let row = tx.query_one("SELECT contour.claim_causal_generation($1::text::uuid,$2::text::uuid,$3::text::numeric,$4::text::uuid,$5::bytea)", &[&issue.binding.ids[0], &issue.binding.ids[1], &epoch, &issue.nonce, &&generation[..]]).await.map_err(issuer_sql_error)?;
                if !row.try_get::<_,bool>(0).map_err(|_| CausalError::Database)? { return Err(CausalError::Scope); }
                let final_start = Instant::now();
                let final_now = clock(&tx).await?;
                let (again, _) = verify(issue, peer, grant_keys, policy_keys, final_now)?;
                if final_now < now || final_now >= session.expires || again.payload_digest() != session.digest || session.verified_remaining().is_zero() { return Err(CausalError::Expired); }
                tightened = Some(claim_freshness(session.verified_until, final_start, final_now, session.expires, Instant::now())?);
                tx.query_one("SELECT set_config('synchronous_commit','on',true)", &[]).await.map_err(nonretry_error)?;
                check_deadline(deadline)?;
                Ok::<_,CausalError>(())
            }.await;
            match checked {
                Ok(()) => {
                    committing = true;
                    tx.commit().await.map_err(|_| CausalError::OutcomeUnknown)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(())
                }
                Err(e) => {
                    tx.rollback().await.map_err(|_| CausalError::Database)?;
                    empty_context(client)
                        .await
                        .map_err(|_| CausalError::Database)?;
                    check_deadline(deadline)?;
                    if e != CausalError::Deadline {
                        guard.confirm();
                    }
                    Err(e)
                }
            }
        };
        let result = match timeout_at(deadline, work).await {
            Ok(Err(_)) if committing => Err(CausalError::OutcomeUnknown),
            Ok(result) => result,
            Err(_) if committing => Err(CausalError::OutcomeUnknown),
            Err(_) => Err(CausalError::Deadline),
        };
        let final_result = result.and_then(|()| {
            commit_freshness(tightened.ok_or(CausalError::Expired)?, Instant::now())
        });
        match final_result {
            Ok(limit) => {
                session.verified_until = limit;
                Ok(())
            }
            Err(error) => {
                session.verified_until = Instant::now();
                Err(error)
            }
        }
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
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CausalError::Database)?;
            check_role(client, "contour_causal_issuer")
                .await
                .map_err(|e| {
                    if e == CausalError::Busy {
                        CausalError::Database
                    } else {
                        e
                    }
                })?;
            let tx = begin(client).await?;
            let preparation = async {
                check_deadline(deadline)?;
                let duration = deadline.saturating_duration_since(Instant::now());
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
                check_deadline(deadline)?;
                configure_tenant(
                    &tx,
                    &request.binding.ids[0],
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await?;
                check_deadline(deadline)?;
                let row = tx
                    .query_one(
                        if grant.causal_profile() == PROFILE {
                            ISSUE_SQL
                        } else {
                            ISSUE_SQL_WIRE
                        },
                        &params,
                    )
                    .await
                    .map_err(issuer_sql_error)?;
                let mut result = parse_session(
                    &row,
                    request,
                    digest,
                    SessionProfile::from_verified(&grant)?,
                )?;
                tx.query_one("SELECT set_config('synchronous_commit','on',true)", &[])
                    .await
                    .map_err(nonretry_error)?;
                let clock_start = Instant::now();
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
                result.verified_until =
                    freshness_deadline(clock_start, final_now, result.expires, Instant::now())?;
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
                    tx.rollback().await.map_err(|_| CausalError::Database)?;
                    empty_context(client)
                        .await
                        .map_err(|_| CausalError::Database)?;
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
    /// Return the owned connection to a bounded pool; cancellation/reuse state
    /// remains on the connection and is not reset by this transfer.
    pub fn into_database(self) -> ConnectedDatabase {
        self.connection
    }
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
            profile: SessionProfile::Legacy501,
            epoch: u64::MAX,
            issued: now(),
            expires: now() + time::Duration::minutes(1),
            digest: [9; 32],
            verified_until: Instant::now(),
        }
    }
    #[test]
    fn marker_session_guard_invalidates_on_drop_and_preserves_success() {
        let v = fixture();
        let mut s = session(request(&v, "grant", "policy"));
        s.verified_until = Instant::now() + Duration::from_secs(10);
        {
            let _pending = MarkerSessionGuard {
                session: &mut s,
                succeeded: false,
            };
        }
        assert!(s.verified_remaining().is_zero());
        s.verified_until = Instant::now() + Duration::from_secs(10);
        {
            let _complete = MarkerSessionGuard {
                session: &mut s,
                succeeded: true,
            };
        }
        assert!(!s.verified_remaining().is_zero());
    }

    #[test]
    fn marker_inputs_validate_real_key_and_exact_session_scope() {
        let v = fixture();
        let mut s = session(request(&v, "grant", "policy"));
        s.verified_until = Instant::now() + Duration::from_secs(10);
        let key = hex32(v["grant_public"].as_str().unwrap());
        assert_eq!(
            check_marker_inputs(&s, &[8; 32], ID, &[4; 32], &key, &[3; 32]),
            Ok(())
        );
        assert_eq!(
            check_marker_inputs(&s, &[0; 32], ID, &[4; 32], &key, &[3; 32]),
            Err(CausalError::Scope)
        );
        assert_eq!(
            check_marker_inputs(&s, &[8; 32], "invalid", &[4; 32], &key, &[3; 32]),
            Err(CausalError::Scope)
        );
        assert_eq!(
            check_marker_inputs(&s, &[8; 32], ID, &[3; 32], &key, &[3; 32]),
            Err(CausalError::Scope)
        );
        assert_eq!(
            check_marker_inputs(&s, &[8; 32], ID, &[4; 32], &[0; 32], &[3; 32]),
            Err(CausalError::Signature)
        );
        assert_eq!(
            check_marker_inputs(&s, &[8; 32], ID, &[4; 32], &key, &[2; 32]),
            Err(CausalError::Scope)
        );
        s.verified_until = Instant::now();
        assert_eq!(
            check_marker_inputs(&s, &[8; 32], ID, &[4; 32], &key, &[3; 32]),
            Err(CausalError::Scope)
        );
    }

    #[test]
    fn freshness_uses_query_start_and_rejects_late_or_expired() {
        let start = Instant::now();
        let checked = now();
        let expiry = checked + time::Duration::seconds(2);
        assert_eq!(
            freshness_deadline(start, checked, expiry, start + Duration::from_secs(1)),
            Ok(start + Duration::from_secs(2))
        );
        assert_eq!(
            freshness_deadline(start, checked, expiry, start + Duration::from_secs(2)),
            Err(CausalError::Expired)
        );
        assert_eq!(
            freshness_deadline(start, checked, checked, start),
            Err(CausalError::Expired)
        );
        assert_eq!(
            freshness_deadline(start, checked, checked - time::Duration::seconds(1), start),
            Err(CausalError::Expired)
        );
    }
    #[test]
    fn claim_tightens_after_forward_clock_jump_and_delayed_commit() {
        let start = Instant::now();
        let expiry = now() + time::Duration::minutes(1);
        let db_final = expiry - time::Duration::milliseconds(100);
        let original = start + Duration::from_secs(60);
        let tightened = claim_freshness(original, start, db_final, expiry, start).unwrap();
        assert_eq!(tightened, start + Duration::from_millis(100));
        assert_eq!(
            commit_freshness(tightened, start + Duration::from_millis(100)),
            Err(CausalError::Expired)
        );
        assert_eq!(
            claim_freshness(
                original,
                start,
                db_final,
                expiry,
                start + Duration::from_millis(100)
            ),
            Err(CausalError::Expired)
        );
    }
    #[test]
    fn original_codec_is_bounded_and_canonical() {
        let v = fixture();
        let issue = request(&v, "grant", "policy");
        let original = issue.original_bytes();
        assert_eq!(
            CausalIssue::from_original_bytes(&original)
                .unwrap()
                .original_bytes(),
            original
        );
        for bytes in [
            vec![],
            original[..original.len() - 1].to_vec(),
            [original.as_slice(), b"x"].concat(),
            [original.as_slice(), original.as_slice()].concat(),
            vec![0; 2_100_000],
        ] {
            assert!(CausalIssue::from_original_bytes(&bytes).is_err());
        }
        let mut bad = original.clone();
        bad[0] ^= 1;
        assert!(CausalIssue::from_original_bytes(&bad).is_err());
        let mut bad = original.clone();
        bad[4] = b'A';
        assert!(CausalIssue::from_original_bytes(&bad).is_err());
        let mut bad = original.clone();
        bad[440..444].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(CausalIssue::from_original_bytes(&bad).is_err());
    }
    #[test]
    fn candidate_view_borrows_identity_and_observes_current_ceiling() {
        let legacy = fixture();
        let candidate: Value =
            serde_json::from_str(include_str!("../tests/fixtures/causal_candidate_503.json"))
                .unwrap();
        let grant_keys = CausalGrantKeys::new(&[
            (
                "candidate-test",
                hex32(candidate["test_public_hex"].as_str().unwrap()),
            ),
            ("fixture", hex32(legacy["grant_public"].as_str().unwrap())),
        ])
        .unwrap();
        let (_, policy_keys) = keys(&legacy);
        let issue = CausalIssue::new(
            binding(),
            ID,
            Duration::from_secs(60),
            &bytes(&candidate, "candidate"),
            &bytes(&legacy, "policy"),
        )
        .unwrap();
        let (grant, _) = verify(&issue, &[3; 32], &grant_keys, &policy_keys, now()).unwrap();
        let mut s = session(issue);
        s.profile = SessionProfile::from_verified(&grant).unwrap();
        let ceiling = Instant::now() + Duration::from_secs(10);
        s.verified_until = ceiling;
        assert!(!s.is_legacy_intent_profile());
        {
            let view = s.wire_profile_503().unwrap();
            assert_eq!(
                (
                    view.tenant_id(),
                    view.runtime_id(),
                    view.nonce(),
                    view.epoch()
                ),
                (ID, ID, ID, u64::MAX)
            );
            assert_eq!(
                (
                    view.profile_id(),
                    view.profile_name(),
                    view.profile_sha256()
                ),
                (
                    "00000000-0000-4000-8000-000000000503",
                    WIRE_PROFILE,
                    WIRE_ARTIFACT
                )
            );
            assert_eq!(view.verified_until(), ceiling);
            assert!(!view.verified_remaining().is_zero());
        }
        let tightened = ceiling - Duration::from_secs(5);
        s.verified_until = tightened;
        assert_eq!(s.wire_profile_503().unwrap().verified_until(), tightened);
        s.verified_until = Instant::now();
        assert!(s.wire_profile_503().is_none());
        let candidate_issue = CausalIssue::new(
            binding(),
            ID,
            Duration::from_secs(60),
            &bytes(&candidate, "candidate"),
            &bytes(&legacy, "policy"),
        )
        .unwrap();
        assert!(
            candidate_issue
                .signature_preflight_503_at(&[3; 32], &grant_keys, &policy_keys, now())
                .is_ok()
        );
        assert!(
            candidate_issue
                .signature_preflight_503_at(&[9; 32], &grant_keys, &policy_keys, now())
                .is_err()
        );
        assert!(
            candidate_issue
                .signature_preflight_503_at(
                    &[3; 32],
                    &grant_keys,
                    &policy_keys,
                    now() + time::Duration::days(366)
                )
                .is_err()
        );
        let wrong_policy = CausalIssue::new(
            binding(),
            ID,
            Duration::from_secs(60),
            &bytes(&candidate, "candidate"),
            &bytes(&legacy, "wrong_policy_tenant"),
        )
        .unwrap();
        assert!(
            wrong_policy
                .signature_preflight_503_at(&[3; 32], &grant_keys, &policy_keys, now())
                .is_err()
        );
        let mut damaged = candidate["candidate"].clone();
        damaged["signature_base64url"] = json!("AAAA");
        let damaged = CausalIssue::new(
            binding(),
            ID,
            Duration::from_secs(60),
            &serde_json::to_vec(&damaged).unwrap(),
            &bytes(&legacy, "policy"),
        )
        .unwrap();
        assert!(
            damaged
                .signature_preflight_503_at(&[3; 32], &grant_keys, &policy_keys, now())
                .is_err()
        );
        let old_issue = request(&legacy, "grant", "policy");
        assert!(
            old_issue
                .signature_preflight_503_at(&[3; 32], &grant_keys, &policy_keys, now())
                .is_err()
        );
        let (old, _) = verify(&old_issue, &[3; 32], &grant_keys, &policy_keys, now()).unwrap();
        let mut old_session = session(old_issue);
        old_session.profile = SessionProfile::from_verified(&old).unwrap();
        old_session.verified_until = ceiling;
        assert!(old_session.wire_profile_503().is_none());
        assert!(old_session.is_legacy_intent_profile());
        old_session.verified_until = Instant::now();
        assert!(!old_session.is_legacy_intent_profile());
    }
    #[test]
    fn profile_authority_is_a_closed_pair_mapping() {
        assert!(authorized_profile(PROFILE, ARTIFACT));
        assert!(authorized_profile(WIRE_PROFILE, WIRE_ARTIFACT));
        assert!(!authorized_profile(PROFILE, WIRE_ARTIFACT));
        assert!(!authorized_profile(WIRE_PROFILE, ARTIFACT));
        assert!(!authorized_profile("nodered_5_0_9_v2", WIRE_ARTIFACT));
        assert!(!authorized_profile(WIRE_PROFILE, &"0".repeat(64)));
    }
    #[test]
    fn signed_candidate_passes_full_verification_and_rejects_scope_and_time_failures() {
        let legacy = fixture();
        let candidate: Value =
            serde_json::from_str(include_str!("../tests/fixtures/causal_candidate_503.json"))
                .unwrap();
        let grant_keys = CausalGrantKeys::new(&[
            (
                "candidate-test",
                hex32(candidate["test_public_hex"].as_str().unwrap()),
            ),
            ("fixture", hex32(legacy["grant_public"].as_str().unwrap())),
        ])
        .unwrap();
        let (_, policy_keys) = keys(&legacy);
        let make_request = |name: &str| {
            CausalIssue::new(
                binding(),
                ID,
                Duration::from_secs(60),
                &bytes(&candidate, name),
                &bytes(&legacy, "policy"),
            )
            .unwrap()
        };
        let good = make_request("candidate");
        let (grant, _) = verify(&good, &[3; 32], &grant_keys, &policy_keys, now()).unwrap();
        assert_eq!(
            (grant.causal_profile(), grant.profile_sha256()),
            (WIRE_PROFILE, WIRE_ARTIFACT)
        );
        for (name, error) in [
            ("wrong_tenant", CausalError::Identity),
            ("corrupt_scope", CausalError::Scope),
            ("disabled", CausalError::Scope),
            ("unknown_502", CausalError::Scope),
            ("cross_hash", CausalError::Scope),
            ("legacy_name_candidate_hash", CausalError::Identity),
        ] {
            assert_eq!(
                verify(
                    &make_request(name),
                    &[3; 32],
                    &grant_keys,
                    &policy_keys,
                    now()
                )
                .unwrap_err(),
                error,
                "{name}"
            );
        }
        assert_eq!(
            verify(&good, &[4; 32], &grant_keys, &policy_keys, now()).unwrap_err(),
            CausalError::Identity
        );
        for at in ["2026-10-07T12:00:00Z", "2026-10-07T12:10:00.000000999Z"] {
            assert_eq!(
                verify(
                    &good,
                    &[3; 32],
                    &grant_keys,
                    &policy_keys,
                    Timestamp::parse(at).unwrap().instant()
                )
                .unwrap_err(),
                CausalError::Expired
            );
        }
        let (legacy_only, _) = keys(&legacy);
        assert_eq!(
            verify(&good, &[3; 32], &legacy_only, &policy_keys, now()).unwrap_err(),
            CausalError::Signature
        );
        let mut disabled_policy = good.clone();
        disabled_policy.policy = bytes(&legacy, "disabled_policy");
        assert_eq!(
            verify(&disabled_policy, &[3; 32], &grant_keys, &policy_keys, now()).unwrap_err(),
            CausalError::Scope
        );
        let old = request(&legacy, "grant", "policy");
        assert!(verify(&old, &[3; 32], &grant_keys, &policy_keys, now()).is_ok());
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
    fn marker_binding_busy_requires_exact_gate_error() {
        for msg in [
            "origin gate busy",
            "credential gate busy",
            "collector gate busy",
        ] {
            assert_eq!(
                classify_marker_binding_error("40001", None, msg),
                CausalError::Busy
            );
            assert_eq!(
                classify_marker_binding_error("40001", Some("other"), msg),
                CausalError::Database
            );
        }
        for code in ["55P03", "57014", "25P03"] {
            assert_eq!(
                classify_marker_binding_error(code, None, "origin gate busy"),
                CausalError::Deadline
            );
        }
        assert_eq!(
            classify_marker_binding_error("23514", None, "origin gate busy"),
            CausalError::Scope
        );
        for msg in [
            "origin operation requires no prior advisory lock",
            "serialization failure",
            "origin gate busy ",
        ] {
            assert_eq!(
                classify_marker_binding_error("40001", None, msg),
                CausalError::Database
            );
        }
    }
    #[test]
    fn issuer_busy_requires_exact_gate_error() {
        for msg in [
            "origin gate busy",
            "credential gate busy",
            "collector gate busy",
        ] {
            assert_eq!(classify_issuer_error("40001", None, msg), CausalError::Busy);
            assert_eq!(
                classify_issuer_error("40001", Some("other"), msg),
                CausalError::Database
            );
            assert_eq!(
                classify_issuer_error("23514", None, msg),
                CausalError::Scope
            );
        }
        for msg in [
            "origin operation requires no prior advisory lock",
            "serialization failure",
            "origin gate busy ",
        ] {
            assert_eq!(
                classify_issuer_error("40001", None, msg),
                CausalError::Database
            );
        }
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
        assert!(saved.matches_peer(&[3; 32]));
        assert!(!saved.matches_peer(&[4; 32]));
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
