//! Authenticated database snapshot for already operator-enrolled collectors.
use crate::{
    AuthorityError, ConnectedDatabase,
    authority::{current_envelope, current_revision, verify_policy},
    transaction::{
        CancellationGuard, begin, check_deadline, clock, configure_context, database_error,
        empty_context,
    },
};
use contour_core::{PolicyKeys, SourceAssignment, VerifiedPolicy};
use std::{collections::BTreeSet, fmt};
use time::OffsetDateTime;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

/// Checked request syntax, not authentication. The caller authenticates identity.
pub struct AuthorityReadRequest {
    identity: [String; 2],
    sources: Vec<String>,
}
impl fmt::Debug for AuthorityReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityReadRequest")
    }
}
impl AuthorityReadRequest {
    /// Validate all bounds before copying identifiers; available before DB contact.
    pub fn new(identity: [&str; 2], sources: &[&str]) -> Result<Self, AuthorityError> {
        if identity.iter().any(|id| !uuid(id)) {
            return Err(AuthorityError::Identity);
        }
        if sources.is_empty()
            || sources.len() > 500
            || sources.iter().any(|id| !uuid(id))
            || sources.iter().copied().collect::<BTreeSet<_>>().len() != sources.len()
        {
            return Err(AuthorityError::Source);
        }
        Ok(Self {
            identity: identity.map(str::to_owned),
            sources: sources.iter().map(|id| (*id).to_owned()).collect(),
        })
    }
    pub fn identity(&self) -> [&str; 2] {
        self.identity.each_ref().map(String::as_str)
    }
    pub fn source_ids(&self) -> &[String] {
        &self.sources
    }
}
fn uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

/// Owned DB-derived binding. Its shared projection checks syntax, not online grants.
pub struct AuthoritySource {
    tuple: [String; 7],
    technique: String,
    profiles: Vec<String>,
    checked: SourceAssignment,
}
impl fmt::Debug for AuthoritySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthoritySource")
    }
}
impl AuthoritySource {
    pub fn source_id(&self) -> &str {
        &self.tuple[0]
    }
    /// Tenant, collector, project, service, environment, deployment, in that order.
    pub fn identity(&self) -> [&str; 6] {
        std::array::from_fn(|index| self.tuple[index + 1].as_str())
    }
    pub fn technique(&self) -> &str {
        &self.technique
    }
    pub fn parser_profiles(&self) -> &[String] {
        &self.profiles
    }
    pub fn assignment(&self) -> &SourceAssignment {
        &self.checked
    }
}

/// Sealed server-side read result. Not enrollment or a reusable client online grant.
pub struct AuthorityRead {
    identity: [String; 2],
    checked_at: OffsetDateTime,
    envelope: Vec<u8>,
    policy: VerifiedPolicy,
    sources: Vec<AuthoritySource>,
}
impl fmt::Debug for AuthorityRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityRead")
    }
}
impl AuthorityRead {
    pub fn identity(&self) -> [&str; 2] {
        self.identity.each_ref().map(String::as_str)
    }
    /// Snapshot time inside the held lock, before rollback/response transit.
    /// Future clients must account elapsed cleanup/transit from request start;
    /// this is not a response-receipt grant and does not extend the signed lease.
    pub fn checked_at(&self) -> OffsetDateTime {
        self.checked_at
    }
    pub fn signed_envelope(&self) -> &[u8] {
        &self.envelope
    }
    pub fn policy(&self) -> &VerifiedPolicy {
        &self.policy
    }
    pub fn sources(&self) -> &[AuthoritySource] {
        &self.sources
    }
}

impl ConnectedDatabase {
    /// Read already enrolled authority. Caller identity is a trusted server boundary;
    /// future HTTP callers must derive it from verified certificates, not headers.
    pub async fn read_authority(
        &mut self,
        request: &AuthorityReadRequest,
        keys: &PolicyKeys,
    ) -> Result<AuthorityRead, AuthorityError> {
        let deadline = Instant::now() + self.deadline;
        self.read_authority_until(request, keys, deadline).await
    }
    /// Absolute caller deadline only shortens the configured budget.
    pub async fn read_authority_until(
        &mut self,
        request: &AuthorityReadRequest,
        keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<AuthorityRead, AuthorityError> {
        let deadline = deadline.min(Instant::now() + self.deadline);
        check_deadline(deadline)?;
        if self.client.is_none() {
            return Err(AuthorityError::Invalidated);
        }
        let expected = request.identity();
        let duration = self.deadline;
        let mut guard = CancellationGuard::arm(self);
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(AuthorityError::Invalidated)?;
            let transaction = begin(client).await?;
            let result = async {
                configure_context(&transaction, expected, duration).await?;
                let revision = current_revision(&transaction, expected).await?;
                let (size, row) =
                    current_envelope(&transaction, expected, &revision.to_string()).await?;
                let bytes: &[u8] = row.try_get(0).map_err(|_| AuthorityError::Database)?;
                let policy = verify_policy(
                    bytes,
                    keys,
                    expected,
                    revision,
                    clock(&transaction).await?,
                    deadline,
                )?;
                policy
                    .validate_capture_at(clock(&transaction).await?)
                    .map_err(|_| AuthorityError::Admission)?;
                let sources = sources(&transaction, request, size, deadline).await?;
                let checked_at = clock(&transaction).await?;
                policy
                    .validate_capture_at(checked_at)
                    .map_err(|_| AuthorityError::Admission)?;
                check_deadline(deadline)?;
                Ok(AuthorityRead {
                    identity: request.identity.clone(),
                    checked_at,
                    envelope: bytes.to_vec(),
                    policy,
                    sources,
                })
            }
            .await;
            transaction.rollback().await.map_err(database_error)?;
            empty_context(client).await?;
            check_deadline(deadline)?;
            if !matches!(result, Err(AuthorityError::Deadline)) {
                guard.confirm();
            }
            result
        };
        timeout_at(deadline, work)
            .await
            .map_err(|_| AuthorityError::Deadline)?
    }
}

// All six workload fields are joined, with explicit collector/tenant predicates.
const FROM: &str = " FROM contour.sources s JOIN contour.source_authorization a USING(tenant_id,source_id,collector_id) JOIN contour.workload_assignments w USING(tenant_id,collector_id,project_id,service_id,environment_id,deployment_id) WHERE s.tenant_id=$1::text::uuid AND s.collector_id=$2::text::uuid AND s.source_id=ANY($3::text[]::uuid[])";
async fn sources(
    transaction: &Transaction<'_>,
    request: &AuthorityReadRequest,
    envelope_size: usize,
    deadline: Instant,
) -> Result<Vec<AuthoritySource>, AuthorityError> {
    let expected = request.identity();
    let metadata = transaction.query(&format!("SELECT s.source_id::text,cardinality(a.parser_profiles),(SELECT sum(octet_length(p))::bigint FROM unnest(a.parser_profiles) p),(SELECT max(octet_length(p)) FROM unnest(a.parser_profiles) p),octet_length(a.technique){FROM}"), &[&expected[0],&expected[1],&request.sources]).await.map_err(database_error)?;
    if metadata.len() != request.sources.len() {
        return Err(AuthorityError::Source);
    }
    let mut total = envelope_size;
    for row in metadata {
        let count: i32 = row.try_get(1).map_err(|_| AuthorityError::Source)?;
        let profile_bytes: i64 = row.try_get(2).map_err(|_| AuthorityError::Source)?;
        let longest: i32 = row.try_get(3).map_err(|_| AuthorityError::Source)?;
        let technique: i32 = row.try_get(4).map_err(|_| AuthorityError::Source)?;
        if !(1..=128).contains(&count)
            || !(1..=64).contains(&longest)
            || !(1..=8192).contains(&profile_bytes)
            || !(1..=9).contains(&technique)
        {
            return Err(AuthorityError::AuthorityTooLarge);
        }
        // Metadata and checked projection each retain a copy. Logical byte charge,
        // not RSS: container/allocator/driver overhead is separately bounded by counts.
        total = total
            .checked_add(2 * (7 * 36 + technique as usize + profile_bytes as usize))
            .ok_or(AuthorityError::AuthorityTooLarge)?;
        if total > 16 * 1_048_576 {
            return Err(AuthorityError::AuthorityTooLarge);
        }
    }
    check_deadline(deadline)?;
    let rows = transaction.query(&format!("SELECT s.source_id::text,s.tenant_id::text,s.collector_id::text,s.project_id::text,s.service_id::text,s.environment_id::text,s.deployment_id::text,a.technique,a.parser_profiles{FROM} ORDER BY s.source_id"), &[&expected[0],&expected[1],&request.sources]).await.map_err(database_error)?;
    if rows.len() != request.sources.len() {
        return Err(AuthorityError::Source);
    }
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        check_deadline(deadline)?;
        let tuple: [String; 7] = (0..7)
            .map(|column| row.try_get(column).map_err(|_| AuthorityError::Source))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| AuthorityError::Source)?;
        if tuple[1] != expected[0]
            || tuple[2] != expected[1]
            || !request.sources.contains(&tuple[0])
        {
            return Err(AuthorityError::Source);
        }
        let technique: String = row.try_get(7).map_err(|_| AuthorityError::Source)?;
        let profiles: Vec<String> = row.try_get(8).map_err(|_| AuthorityError::Source)?;
        let checked = SourceAssignment::new(
            &tuple[0],
            std::array::from_fn(|index| tuple[index + 1].as_str()),
            &technique,
            &profiles.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .map_err(|_| AuthorityError::Source)?;
        result.push(AuthoritySource {
            tuple,
            technique,
            profiles,
            checked,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "00000000-0000-0000-0000-000000000001";
    #[test]
    fn request_bounds_identity_and_duplicates_precede_database_contact() {
        for sources in [
            Vec::new(),
            vec![ID; 501],
            vec![ID, ID],
            vec!["SYNTHETIC_SECRET"],
            vec!["AAAAAAAA-0000-0000-0000-000000000000"],
        ] {
            assert_eq!(
                AuthorityReadRequest::new([ID; 2], &sources).unwrap_err(),
                AuthorityError::Source
            );
        }
        assert_eq!(
            AuthorityReadRequest::new(["SYNTHETIC_SECRET", ID], &[ID]).unwrap_err(),
            AuthorityError::Identity
        );
        let ids = (0..500)
            .map(|number| format!("00000000-0000-0000-0000-{number:012x}"))
            .collect::<Vec<_>>();
        let request =
            AuthorityReadRequest::new([ID; 2], &ids.iter().map(String::as_str).collect::<Vec<_>>())
                .unwrap();
        assert_eq!(request.source_ids().len(), 500);
        assert_eq!(request.identity(), [ID; 2]);
        assert_eq!(format!("{request:?}"), "AuthorityReadRequest");
    }
}
