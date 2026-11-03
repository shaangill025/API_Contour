use crate::{
    ConnectedDatabase,
    transaction::{
        CancellationGuard, begin, check_deadline, clock, configure_context, database_error,
        empty_context,
    },
};
use contour_core::{
    AdmissionInputs, AuthorityRequest, Batch, BatchV2, PolicyKeys, SourceAssignment,
    UnsignedInteger, VerifiedPolicy, validate_admission, validate_admission_v2,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use time::OffsetDateTime;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Row, Transaction};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    Identity,
    Invalidated,
    Deadline,
    Database,
    Missing,
    Disabled,
    Revoked,
    Policy,
    Source,
    Admission,
    AuthorityTooLarge,
}
impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AuthorityError {}

// V2 witnesses are retained in the checked batch and never used as authority.
#[derive(Clone, Copy)]
enum BatchInput<'a> {
    V1(&'a Batch),
    V2(&'a BatchV2),
}
impl<'a> BatchInput<'a> {
    fn identity(self) -> [&'a str; 2] {
        match self {
            Self::V1(batch) => [batch.tenant_id(), batch.collector_id()],
            Self::V2(batch) => [batch.tenant_id(), batch.collector_id()],
        }
    }
    fn requests(self) -> Box<dyn Iterator<Item = AuthorityRequest<'a>> + 'a> {
        match self {
            Self::V1(batch) => Box::new(batch.authority_requests()),
            Self::V2(batch) => Box::new(batch.authority_requests()),
        }
    }
}
pub(crate) struct LoadedAuthority {
    policies: BTreeMap<u64, VerifiedPolicy>,
    current: u64,
    sources: Vec<SourceAssignment>,
}
impl LoadedAuthority {
    pub(crate) fn validate(
        &self,
        batch: &Batch,
        expected: [&str; 2],
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        self.validate_input(BatchInput::V1(batch), expected, now)
    }
    pub(crate) fn validate_v2(
        &self,
        batch: &BatchV2,
        expected: [&str; 2],
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        self.validate_input(BatchInput::V2(batch), expected, now)
    }
    fn validate_input(
        &self,
        batch: BatchInput<'_>,
        expected: [&str; 2],
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        let current = self
            .policies
            .get(&self.current)
            .ok_or(AuthorityError::Missing)?;
        let historical = batch
            .requests()
            .map(|request| request.revision())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|revision| self.policies.get(&revision).ok_or(AuthorityError::Missing))
            .collect::<Result<Vec<_>, _>>()?;
        let inputs = AdmissionInputs::new(expected, current, &historical, &self.sources)
            .map_err(|_| AuthorityError::Admission)?;
        match batch {
            BatchInput::V1(batch) => validate_admission(batch, &inputs, now),
            BatchInput::V2(batch) => validate_admission_v2(batch, &inputs, now),
        }
        .map_err(|_| AuthorityError::Admission)
    }
}
impl ConnectedDatabase {
    /// Validate the current authoritative snapshot, then rollback. Success is not
    /// authorization for any later write. The caller independently authenticates
    /// expected tenant/collector; this method never authenticates request identity.
    pub async fn validate_authority(
        &mut self,
        batch: &Batch,
        expected: [&str; 2],
        keys: &PolicyKeys,
    ) -> Result<(), AuthorityError> {
        self.validate_record_authority_input(BatchInput::V1(batch), expected, keys)
            .await
    }

    /// Validate only legacy signed record and destination authority for V2.
    /// Witnesses do not establish origin authority. Success cannot authorize a
    /// later write; an atomic V2 writer must acquire the origin gate before the
    /// collector lock and perform its own fresh validation through commit.
    /// The caller independently authenticates the expected tenant and collector.
    pub async fn validate_v2_record_authority(
        &mut self,
        batch: &BatchV2,
        expected: [&str; 2],
        keys: &PolicyKeys,
    ) -> Result<(), AuthorityError> {
        self.validate_record_authority_input(BatchInput::V2(batch), expected, keys)
            .await
    }

    async fn validate_record_authority_input(
        &mut self,
        batch: BatchInput<'_>,
        expected: [&str; 2],
        keys: &PolicyKeys,
    ) -> Result<(), AuthorityError> {
        if batch.identity() != expected {
            return Err(AuthorityError::Identity);
        }
        if self.client.is_none() {
            return Err(AuthorityError::Invalidated);
        }
        let deadline = Instant::now() + self.deadline;
        let mut guard = CancellationGuard::arm(self);
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(AuthorityError::Invalidated)?;
            let transaction = begin(client).await?;
            let result = async {
                configure_context(&transaction, expected, guard.connection.deadline).await?;
                let initial = clock(&transaction).await?;
                let loaded = match batch {
                    BatchInput::V1(_) => {
                        load_input(&transaction, batch, expected, keys, initial, deadline, None)
                            .await?
                    }
                    BatchInput::V2(batch) => {
                        load_staged_v2(&transaction, batch, expected, keys, initial, deadline, None)
                            .await?
                    }
                };
                let validate = |now| match batch {
                    BatchInput::V1(batch) => loaded.validate(batch, expected, now),
                    BatchInput::V2(batch) => loaded.validate_v2(batch, expected, now),
                };
                validate(clock(&transaction).await?)?;
                check_deadline(deadline)?;
                // Refresh every time-sensitive admission rule again before success.
                validate(clock(&transaction).await?)?;
                check_deadline(deadline)
            }
            .await;
            let rollback = transaction.rollback().await.map_err(database_error);
            rollback?;
            empty_context(client).await?;
            check_deadline(deadline)?;
            if result != Err(AuthorityError::Deadline) {
                guard.confirm();
            }
            result
        };
        match timeout_at(deadline, work).await {
            Ok(result) => result,
            Err(_) => Err(AuthorityError::Deadline),
        }
    }
}
fn revision(text: &str) -> Result<u64, AuthorityError> {
    UnsignedInteger::parse(text)
        .map(|value| value.get())
        .map_err(|_| AuthorityError::Policy)
}
fn budget(sizes: impl IntoIterator<Item = usize>) -> Result<(), AuthorityError> {
    let mut count = 0;
    let mut total = 0usize;
    for size in sizes {
        count += 1;
        total = total
            .checked_add(size)
            .ok_or(AuthorityError::AuthorityTooLarge)?;
        if count > 501 || !(1..=1_048_576).contains(&size) || total > 16 * 1_048_576 {
            return Err(AuthorityError::AuthorityTooLarge);
        }
    }
    Ok(())
}
// Scoped database state only; a returned revision is not signed authorization.
pub(crate) async fn current_revision(
    transaction: &Transaction<'_>,
    expected: [&str; 2],
) -> Result<u64, AuthorityError> {
    let row = transaction.query_opt("SELECT active_revision::numeric(20,0)::text,enabled,revoked_at IS NOT NULL FROM contour.collector_authorization WHERE tenant_id=$1::text::uuid AND collector_id=$2::text::uuid",&[&expected[0],&expected[1]]).await.map_err(database_error)?.ok_or(AuthorityError::Missing)?;
    if row
        .try_get::<_, bool>(2)
        .map_err(|_| AuthorityError::Database)?
    {
        return Err(AuthorityError::Revoked);
    }
    if !row
        .try_get::<_, bool>(1)
        .map_err(|_| AuthorityError::Database)?
    {
        return Err(AuthorityError::Disabled);
    }
    let current = revision(
        &row.try_get::<_, Option<String>>(0)
            .map_err(|_| AuthorityError::Database)?
            .ok_or(AuthorityError::Missing)?,
    )?;
    Ok(current)
}
// Callers still apply enabled/current-capture and record-scope checks after verification.
pub(crate) fn verify_policy(
    bytes: &[u8],
    keys: &PolicyKeys,
    expected: [&str; 2],
    row_revision: u64,
    at: OffsetDateTime,
    deadline: Instant,
) -> Result<VerifiedPolicy, AuthorityError> {
    check_deadline(deadline)?;
    let policy = VerifiedPolicy::from_signed_json(bytes, keys, expected[0], expected[1], at)
        .map_err(|_| AuthorityError::Policy)?;
    check_deadline(deadline)?;
    if policy.revision() != row_revision {
        return Err(AuthorityError::Policy);
    }
    Ok(policy)
}
pub(crate) struct StagedCurrent {
    pub(crate) policy: VerifiedPolicy,
    size: usize,
}
pub(crate) async fn stage_current(
    transaction: &Transaction<'_>,
    expected: [&str; 2],
    keys: &PolicyKeys,
    now: OffsetDateTime,
    deadline: Instant,
) -> Result<StagedCurrent, AuthorityError> {
    let current = current_revision(transaction, expected).await?.to_string();
    let (size, row) = current_envelope(transaction, expected, &current).await?;
    let policy = verify_policy(
        row.try_get(0).map_err(|_| AuthorityError::Database)?,
        keys,
        expected,
        revision(&current)?,
        now,
        deadline,
    )?;
    policy
        .validate_capture_at(now)
        .map_err(|_| AuthorityError::Admission)?;
    Ok(StagedCurrent { policy, size })
}
// Metadata is checked before fetch; Row lets existing consumers borrow unchanged
// bytes without an additional owned envelope copy.
pub(crate) async fn current_envelope(
    transaction: &Transaction<'_>,
    expected: [&str; 2],
    current: &str,
) -> Result<(usize, Row), AuthorityError> {
    let row = transaction.query_opt("SELECT octet_length(signed_envelope) FROM contour.policy_revisions WHERE tenant_id=$1::text::uuid AND collector_id=$2::text::uuid AND revision=$3::text::numeric", &[&expected[0], &expected[1], &current]).await.map_err(database_error)?.ok_or(AuthorityError::Missing)?;
    let size = usize::try_from(
        row.try_get::<_, i32>(0)
            .map_err(|_| AuthorityError::Database)?,
    )
    .map_err(|_| AuthorityError::Database)?;
    budget([size])?;
    let row = transaction.query_one("SELECT signed_envelope FROM contour.policy_revisions WHERE tenant_id=$1::text::uuid AND collector_id=$2::text::uuid AND revision=$3::text::numeric", &[&expected[0], &expected[1], &current]).await.map_err(database_error)?;
    let bytes: &[u8] = row.try_get(0).map_err(|_| AuthorityError::Database)?;
    if bytes.len() != size {
        return Err(AuthorityError::Policy);
    }
    Ok((size, row))
}
pub(crate) async fn load_staged(
    transaction: &Transaction<'_>,
    batch: &Batch,
    expected: [&str; 2],
    keys: &PolicyKeys,
    initial: OffsetDateTime,
    deadline: Instant,
    staged: Option<StagedCurrent>,
) -> Result<LoadedAuthority, AuthorityError> {
    load_input(
        transaction,
        BatchInput::V1(batch),
        expected,
        keys,
        initial,
        deadline,
        staged,
    )
    .await
}

// The caller must hold the required transaction locks through any subsequent write.
pub(crate) async fn load_staged_v2(
    transaction: &Transaction<'_>,
    batch: &BatchV2,
    expected: [&str; 2],
    keys: &PolicyKeys,
    initial: OffsetDateTime,
    deadline: Instant,
    staged: Option<StagedCurrent>,
) -> Result<LoadedAuthority, AuthorityError> {
    load_input(
        transaction,
        BatchInput::V2(batch),
        expected,
        keys,
        initial,
        deadline,
        staged,
    )
    .await
}

// This loader alone is not authorization for a later transaction or V2 write.
async fn load_input(
    transaction: &Transaction<'_>,
    batch: BatchInput<'_>,
    expected: [&str; 2],
    keys: &PolicyKeys,
    initial: OffsetDateTime,
    deadline: Instant,
    staged: Option<StagedCurrent>,
) -> Result<LoadedAuthority, AuthorityError> {
    let current = match &staged {
        Some(current) => current.policy.revision(),
        None => current_revision(transaction, expected).await?,
    };
    let mut requested = BTreeMap::new();
    let mut sources = BTreeSet::new();
    for request in batch.requests() {
        if request.revision() > current {
            return Err(AuthorityError::Policy);
        }
        requested
            .entry(request.revision())
            .or_insert(request.queued_at());
        sources.insert(request.source_id().to_owned());
    }
    requested.insert(current, initial);
    let revisions = requested.keys().map(u64::to_string).collect::<Vec<_>>();
    let metadata = transaction.query("SELECT revision::numeric(20,0)::text,octet_length(signed_envelope) FROM contour.policy_revisions WHERE tenant_id=$1::text::uuid AND collector_id=$2::text::uuid AND revision=ANY($3::text[]::numeric[])",&[&expected[0],&expected[1],&revisions]).await.map_err(database_error)?;
    if metadata.len() != requested.len() {
        return Err(AuthorityError::Missing);
    }
    let sizes = metadata
        .iter()
        .map(|row| {
            row.try_get::<_, i32>(1)
                .map_err(|_| AuthorityError::Database)
                .and_then(|size| usize::try_from(size).map_err(|_| AuthorityError::Database))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Validation has fetched nothing; submission has fetched only bounded current.
    // Both paths include current in this aggregate before fetching any remainder.
    budget(sizes)?;
    if let Some(staged) = &staged {
        let stored_size = metadata
            .iter()
            .find(|row| row.try_get::<_, String>(0).ok().as_deref() == Some(&current.to_string()))
            .ok_or(AuthorityError::Missing)?
            .try_get::<_, i32>(1)
            .map_err(|_| AuthorityError::Database)?;
        if usize::try_from(stored_size).ok() != Some(staged.size) {
            return Err(AuthorityError::Policy);
        }
    }
    let revisions = requested
        .keys()
        .filter(|revision| staged.is_none() || **revision != current)
        .map(u64::to_string)
        .collect::<Vec<_>>();
    let rows = transaction.query("SELECT revision::numeric(20,0)::text,signed_envelope FROM contour.policy_revisions WHERE tenant_id=$1::text::uuid AND collector_id=$2::text::uuid AND revision=ANY($3::text[]::numeric[])",&[&expected[0],&expected[1],&revisions]).await.map_err(database_error)?;
    let mut policies = BTreeMap::new();
    if let Some(staged) = staged {
        policies.insert(current, staged.policy);
    }
    for row in rows {
        check_deadline(deadline)?;
        let row_revision = revision(
            &row.try_get::<_, String>(0)
                .map_err(|_| AuthorityError::Database)?,
        )?;
        let at = *requested.get(&row_revision).ok_or(AuthorityError::Policy)?;
        let bytes: &[u8] = row.try_get(1).map_err(|_| AuthorityError::Database)?;
        let policy = verify_policy(bytes, keys, expected, row_revision, at, deadline)?;
        if policies.insert(row_revision, policy).is_some() {
            return Err(AuthorityError::Policy);
        }
    }
    if policies.len() != requested.len() {
        return Err(AuthorityError::Missing);
    }
    let source_ids = sources.into_iter().collect::<Vec<_>>();
    let rows=transaction.query("SELECT s.source_id::text,s.tenant_id::text,s.collector_id::text,s.project_id::text,s.service_id::text,s.environment_id::text,s.deployment_id::text,a.technique,a.parser_profiles FROM contour.sources s JOIN contour.source_authorization a USING(tenant_id,source_id,collector_id) WHERE s.tenant_id=$1::text::uuid AND s.collector_id=$2::text::uuid AND s.source_id=ANY($3::text[]::uuid[])",&[&expected[0],&expected[1],&source_ids]).await.map_err(database_error)?;
    if rows.len() != source_ids.len() {
        return Err(AuthorityError::Source);
    }
    let mut assignments = Vec::new();
    for row in rows {
        let mut tuple = Vec::new();
        for column in 0..7 {
            tuple.push(
                row.try_get::<_, String>(column)
                    .map_err(|_| AuthorityError::Source)?,
            );
        }
        let technique: &str = row.try_get(7).map_err(|_| AuthorityError::Source)?;
        let profiles: Vec<String> = row.try_get(8).map_err(|_| AuthorityError::Source)?;
        assignments.push(
            SourceAssignment::new(
                &tuple[0],
                [
                    &tuple[1], &tuple[2], &tuple[3], &tuple[4], &tuple[5], &tuple[6],
                ],
                technique,
                &profiles.iter().map(String::as_str).collect::<Vec<_>>(),
            )
            .map_err(|_| AuthorityError::Source)?,
        );
    }
    Ok(LoadedAuthority {
        policies,
        current,
        sources: assignments,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_helper_enforces_deadline_and_static_failures() {
        // Public verification key from RFC 8032, section 7.1, test 1.
        let public = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let keys = PolicyKeys::new(&[("unit", public)]).unwrap();
        let identity = ["00000000-0000-0000-0000-000000000001"; 2];
        assert_eq!(
            verify_policy(
                b"SYNTHETIC_SECRET",
                &keys,
                identity,
                1,
                OffsetDateTime::UNIX_EPOCH,
                Instant::now()
            )
            .unwrap_err(),
            AuthorityError::Deadline
        );
        let error = verify_policy(
            b"SYNTHETIC_SECRET",
            &keys,
            identity,
            1,
            OffsetDateTime::UNIX_EPOCH,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error, AuthorityError::Policy);
        assert_eq!(error.to_string(), "Policy");
    }
    #[test]
    fn v2_witnesses_preserve_record_authority_requests() {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/specification/fixtures/batches.json"
        ))
        .unwrap();
        let body = fixtures
            .as_array()
            .unwrap()
            .iter()
            .find(|fixture| fixture["id"] == "valid_structure")
            .unwrap()["body"]
            .clone();
        let v1 = Batch::from_wire_json(&serde_json::to_vec(&body).unwrap()).unwrap();
        let expected: Vec<_> = BatchInput::V1(&v1)
            .requests()
            .map(|request| {
                (
                    request.source_id().to_owned(),
                    request.revision(),
                    request.queued_at(),
                )
            })
            .collect();
        for witness in [
            serde_json::json!({"kind": "unattributed"}),
            serde_json::json!({"kind": "downstream_mtls_leaf_sha256_v1", "leaf_sha256": "ab".repeat(32)}),
        ] {
            let mut wire = body.clone();
            wire["wire_version"] = 2.into();
            wire["records"] = body["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|record| serde_json::json!({"record": record, "origin_witness": witness}))
                .collect::<Vec<_>>()
                .into();
            let v2 = BatchV2::from_wire_json(&serde_json::to_vec(&wire).unwrap()).unwrap();
            assert_eq!(
                BatchInput::V1(&v1).identity(),
                BatchInput::V2(&v2).identity()
            );
            let requests: Vec<_> = BatchInput::V2(&v2)
                .requests()
                .map(|request| {
                    (
                        request.source_id().to_owned(),
                        request.revision(),
                        request.queued_at(),
                    )
                })
                .collect();
            assert_eq!(requests, expected);
        }
    }
    #[test]
    fn aggregate_and_revision_boundaries() {
        assert_eq!(budget([1_048_576; 16]), Ok(()));
        assert_eq!(
            budget([1_048_576; 17]),
            Err(AuthorityError::AuthorityTooLarge)
        );
        assert_eq!(budget([0]), Err(AuthorityError::AuthorityTooLarge));
        assert_eq!(budget([1_048_577]), Err(AuthorityError::AuthorityTooLarge));
        assert_eq!(budget([1; 501]), Ok(()));
        assert_eq!(budget([1; 502]), Err(AuthorityError::AuthorityTooLarge));
        assert_eq!(revision("18446744073709551615"), Ok(u64::MAX));
        assert_eq!(revision("1.000"), Ok(1));
        assert!(revision("18446744073709551616").is_err());
    }
}
