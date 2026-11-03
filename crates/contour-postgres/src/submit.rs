//! Atomic checked submission; callers independently authenticate expected identity.
use crate::{
    AuthorityError, ConnectedDatabase,
    authority::{load_staged, load_staged_v2, stage_current},
    transaction::{
        CancellationGuard, begin, check_deadline, clock, configure_context, configure_tenant,
        database_error, empty_context, time_from_micros,
    },
};
use contour_core::{Batch, BatchV2, OriginWitness, PolicyKeys};
use std::fmt;
use time::OffsetDateTime;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Row, Transaction};

#[derive(Clone, PartialEq, Eq)]
pub struct DurableReceipt {
    id: String,
    accepted_at: OffsetDateTime,
    status: ReceiptStatus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptStatus {
    Accepted,
    Duplicate,
}
impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
        }
    }
}
impl DurableReceipt {
    pub fn status(&self) -> ReceiptStatus {
        self.status
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn accepted_at(&self) -> OffsetDateTime {
        self.accepted_at
    }
}
impl fmt::Debug for DurableReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableReceipt").finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitError {
    Authority(AuthorityError),
    Batch,
    Conflict,
    Corrupt,
    /// The tenant's logical origin-proof storage quota is exhausted.
    LogicalQuota,
    OutcomeUnknown,
}
impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SubmitError {}
impl From<AuthorityError> for SubmitError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl ConnectedDatabase {
    /// Persist a checked batch or acknowledge its integrity-checked committed retry.
    /// Expected identity is independently authenticated by the caller. OutcomeUnknown
    /// requires retrying the same batch ID and content, never a replacement ID.
    pub async fn submit_batch(
        &mut self,
        batch: &Batch,
        expected: [&str; 2],
        keys: &PolicyKeys,
    ) -> Result<DurableReceipt, SubmitError> {
        let deadline = Instant::now() + self.deadline;
        self.submit_batch_until(batch, expected, keys, deadline)
            .await
    }
    /// Caller deadline can shorten the configured operation budget, never extend it.
    /// Known COMMIT latching and uncertainty remain inside this operation.
    pub async fn submit_batch_until(
        &mut self,
        batch: &Batch,
        expected: [&str; 2],
        keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<DurableReceipt, SubmitError> {
        let deadline = deadline.min(Instant::now() + self.deadline);
        if batch.tenant_id() != expected[0] || batch.collector_id() != expected[1] {
            return Err(AuthorityError::Identity.into());
        }
        if self.client.is_none() {
            return Err(AuthorityError::Invalidated.into());
        }
        let digest = batch
            .request_digest_bytes()
            .map_err(|_| SubmitError::Batch)?;
        let payload = batch.to_wire_json().map_err(|_| SubmitError::Batch)?;
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(self);
        let mut committing = false;
        let mut accepted = None;
        let work = async {
            let duration = guard.connection.deadline;
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(AuthorityError::Invalidated)?;
            let transaction = begin(client).await?;
            let preparation = async {
                configure_context(&transaction, expected, duration).await?;
                let current = stage_current(&transaction, expected, keys, clock(&transaction).await?, deadline).await?;
                if let Some(receipt) = duplicate(&transaction, batch, &digest, expected).await? {
                    current.policy.validate_capture_at(clock(&transaction).await?).map_err(|_| AuthorityError::Admission)?;
                    check_deadline(deadline)?;
                    return Ok((receipt, true));
                }
                let loaded = load_staged(&transaction, batch, expected, keys, clock(&transaction).await?, deadline, Some(current)).await?;
                loaded.validate(batch, expected, clock(&transaction).await?)?;
                let count = i32::try_from(batch.record_count()).map_err(|_| SubmitError::Batch)?;
                let row = transaction.query_one("INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,1,$5) RETURNING receipt_id::text,floor(extract(epoch FROM accepted_at)*1000000)::bigint", &[&expected[0], &expected[1], &batch.batch_id(), &digest.as_slice(), &count]).await.map_err(database_error)?;
                let receipt = receipt(&row, ReceiptStatus::Accepted)?;
                transaction.execute("INSERT INTO contour.ingestion_payloads(tenant_id,collector_id,batch_id,payload_format,checked_batch) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,1,$4)", &[&expected[0], &expected[1], &batch.batch_id(), &payload]).await.map_err(database_error)?;
                transaction.query_one("SELECT set_config('synchronous_commit','on',true)", &[]).await.map_err(database_error)?;
                loaded.validate(batch, expected, clock(&transaction).await?)?;
                check_deadline(deadline)?;
                Ok::<_, SubmitError>((receipt, false))
            }.await;
            match preparation {
                Ok((receipt, false)) => {
                    // No intervening await after confirmed COMMIT before latching acceptance.
                    committing = true;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| SubmitError::OutcomeUnknown)?;
                    accepted = Some(receipt.clone());
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(receipt)
                }
                result => {
                    transaction.rollback().await.map_err(database_error)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    if result != Err(SubmitError::Authority(AuthorityError::Deadline)) {
                        guard.confirm();
                    }
                    result.map(|(receipt, _)| receipt)
                }
            }
        };
        let result = timeout_at(deadline, work).await;
        // A known commit is not erased by subsequent deadline/context cleanup failure.
        if let Some(receipt) = accepted {
            return Ok(receipt);
        }
        match result {
            Ok(result) => result,
            Err(_) if committing => Err(SubmitError::OutcomeUnknown),
            Err(_) => Err(AuthorityError::Deadline.into()),
        }
    }
}
fn receipt(row: &Row, status: ReceiptStatus) -> Result<DurableReceipt, SubmitError> {
    let id: String = row.try_get(0).map_err(|_| SubmitError::Corrupt)?;
    if id.len() != 36
        || id.bytes().enumerate().any(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte != b'-'
            } else {
                !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte)
            }
        })
    {
        return Err(SubmitError::Corrupt);
    }
    let micros = row.try_get(1).map_err(|_| SubmitError::Corrupt)?;
    Ok(DurableReceipt {
        id,
        accepted_at: time_from_micros(micros)?,
        status,
    })
}
async fn duplicate(
    transaction: &Transaction<'_>,
    batch: &Batch,
    digest: &[u8; 32],
    expected: [&str; 2],
) -> Result<Option<DurableReceipt>, SubmitError> {
    // Metadata bounds precede fetching the potentially corrupted payload.
    let row = transaction.query_opt("SELECT b.receipt_id::text,floor(extract(epoch FROM b.accepted_at)*1000000)::bigint,b.request_digest,b.digest_version,b.record_count,p.payload_format,octet_length(p.checked_batch) FROM contour.ingestion_batches b LEFT JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE b.tenant_id=$1::text::uuid AND b.collector_id=$2::text::uuid AND b.batch_id=$3::text::uuid", &[&expected[0], &expected[1], &batch.batch_id()]).await.map_err(database_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_digest: &[u8] = row.try_get(2).map_err(|_| SubmitError::Corrupt)?;
    if row.try_get::<_, i16>(3).map_err(|_| SubmitError::Corrupt)? != 1 || stored_digest.len() != 32
    {
        return Err(SubmitError::Corrupt);
    }
    if stored_digest != digest {
        return Err(SubmitError::Conflict);
    }
    let count: i32 = row.try_get(4).map_err(|_| SubmitError::Corrupt)?;
    let format: Option<i16> = row.try_get(5).map_err(|_| SubmitError::Corrupt)?;
    let size: Option<i32> = row.try_get(6).map_err(|_| SubmitError::Corrupt)?;
    if format != Some(1) || !size.is_some_and(|size| (1..=1_048_576).contains(&size)) {
        return Err(SubmitError::Corrupt);
    }
    let payload = transaction.query_one("SELECT checked_batch FROM contour.ingestion_payloads WHERE tenant_id=$1::text::uuid AND collector_id=$2::text::uuid AND batch_id=$3::text::uuid", &[&expected[0], &expected[1], &batch.batch_id()]).await.map_err(database_error)?;
    let bytes: &[u8] = payload.try_get(0).map_err(|_| SubmitError::Corrupt)?;
    let stored = Batch::from_wire_json(bytes).map_err(|_| SubmitError::Corrupt)?;
    if stored.tenant_id() != expected[0]
        || stored.collector_id() != expected[1]
        || stored.batch_id() != batch.batch_id()
        || usize::try_from(count).ok() != Some(stored.record_count())
        || stored
            .request_digest_bytes()
            .map_err(|_| SubmitError::Corrupt)?
            != *digest
    {
        return Err(SubmitError::Corrupt);
    }
    Ok(Some(receipt(&row, ReceiptStatus::Duplicate)?))
}

/// An explicitly verified database session. Callers must independently authenticate
/// the collector principal and bind it to this operator-configured capability.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IngressCapability {
    Basic,
    Origin,
}

pub struct OriginIngress<'a> {
    database: &'a mut ConnectedDatabase,
}

pub struct V2Ingress<'a> {
    database: &'a mut ConnectedDatabase,
}
impl ConnectedDatabase {
    /// Verify the independent origin-ingress database role. The caller must bind
    /// this capability to an independently authenticated collector principal.
    pub async fn origin_ingress(&mut self) -> Result<OriginIngress<'_>, SubmitError> {
        let deadline = Instant::now() + self.deadline;
        let mut guard = CancellationGuard::arm(self);
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(AuthorityError::Invalidated)?;
            let row = client.query_one("SELECT session_user=current_user AND pg_has_role(current_user,'contour_origin_ingress','USAGE') AND NOT pg_has_role(current_user,'contour_v2_ingress','MEMBER') AND NOT pg_has_role(current_user,'contour_ingestion','MEMBER') AND NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user)", &[]).await.map_err(database_error)?;
            if !row
                .try_get::<_, bool>(0)
                .map_err(|_| AuthorityError::Database)?
            {
                return Err(AuthorityError::Identity);
            }
            empty_context(client).await?;
            guard.confirm();
            Ok(())
        };
        timeout_at(deadline, work)
            .await
            .map_err(|_| AuthorityError::Deadline)??;
        drop(guard);
        Ok(OriginIngress { database: self })
    }
    pub async fn v2_ingress(&mut self) -> Result<V2Ingress<'_>, SubmitError> {
        let deadline = Instant::now() + self.deadline;
        let mut guard = CancellationGuard::arm(self);
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(AuthorityError::Invalidated)?;
            let row = client.query_one("SELECT session_user=current_user AND pg_has_role(current_user,'contour_v2_ingress','USAGE') AND NOT pg_has_role(current_user,'contour_ingestion','MEMBER') AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='contour_origin_ingress' AND pg_has_role(current_user,oid,'MEMBER')) AND NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user)", &[]).await.map_err(database_error)?;
            let allowed: bool = row.try_get(0).map_err(|_| AuthorityError::Database)?;
            if !allowed {
                return Err(AuthorityError::Identity);
            }
            empty_context(client).await?;
            guard.confirm();
            Ok(())
        };
        timeout_at(deadline, work)
            .await
            .map_err(|_| AuthorityError::Deadline)??;
        drop(guard);
        Ok(V2Ingress { database: self })
    }
}

impl V2Ingress<'_> {
    pub async fn submit_batch_v2_until(
        &mut self,
        batch: &BatchV2,
        expected: [&str; 2],
        keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<DurableReceipt, SubmitError> {
        submit_v2(
            self.database,
            IngressCapability::Basic,
            batch,
            expected,
            keys,
            deadline,
        )
        .await
    }
}
impl OriginIngress<'_> {
    pub async fn submit_batch_v2_until(
        &mut self,
        batch: &BatchV2,
        expected: [&str; 2],
        keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<DurableReceipt, SubmitError> {
        submit_v2(
            self.database,
            IngressCapability::Origin,
            batch,
            expected,
            keys,
            deadline,
        )
        .await
    }
}
async fn submit_v2(
    database: &mut ConnectedDatabase,
    capability: IngressCapability,
    batch: &BatchV2,
    expected: [&str; 2],
    keys: &PolicyKeys,
    deadline: Instant,
) -> Result<DurableReceipt, SubmitError> {
    let deadline = deadline.min(Instant::now() + database.deadline);
    if batch.tenant_id() != expected[0] || batch.collector_id() != expected[1] {
        return Err(AuthorityError::Identity.into());
    }
    if database.client.is_none() {
        return Err(AuthorityError::Invalidated.into());
    }
    if capability == IngressCapability::Basic
        && batch
            .records()
            .iter()
            .any(|record| !matches!(record.origin_witness(), OriginWitness::Unattributed))
    {
        return Err(SubmitError::Batch);
    }
    let digest = batch
        .request_digest_bytes()
        .map_err(|_| SubmitError::Batch)?;
    let payload = match capability {
        IngressCapability::Basic => batch.to_wire_json(),
        IngressCapability::Origin => batch.to_canonical_wire_json(),
    }
    .map_err(|_| SubmitError::Batch)?;
    check_deadline(deadline)?;
    let mut guard = CancellationGuard::arm(database);
    let mut committing = false;
    let mut accepted = None;
    let work = async {
        let duration = guard.connection.deadline;
        let client = guard
            .connection
            .client
            .as_mut()
            .ok_or(AuthorityError::Invalidated)?;
        let transaction = begin(client).await?;
        let preparation = async {
                match capability {
                    IngressCapability::Basic => configure_context(&transaction, expected, duration).await?,
                    IngressCapability::Origin => {
                        configure_tenant(&transaction, expected[0], duration).await?;
                        transaction.query_one("SELECT contour.begin_origin_ingress($1::text::uuid,$2::text::uuid)", &[&expected[0], &expected[1]]).await.map_err(database_error)?;
                    }
                }
                let current = stage_current(&transaction, expected, keys, clock(&transaction).await?, deadline).await?;
                if let Some(receipt) = duplicate_v2(&transaction, batch, &digest, expected, capability).await? {
                    current.policy.validate_capture_at(clock(&transaction).await?).map_err(|_| AuthorityError::Admission)?;
                    check_deadline(deadline)?;
                    return Ok((receipt, true));
                }
                let loaded = load_staged_v2(&transaction, batch, expected, keys, clock(&transaction).await?, deadline, Some(current)).await?;
                loaded.validate_v2(batch, expected, clock(&transaction).await?)?;
                let count = i32::try_from(batch.record_count()).map_err(|_| SubmitError::Batch)?;
                let row = transaction.query_one("INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,2,$5) RETURNING receipt_id::text,floor(extract(epoch FROM accepted_at)*1000000)::bigint", &[&expected[0], &expected[1], &batch.batch_id(), &digest.as_slice(), &count]).await.map_err(database_error)?;
                let receipt = receipt(&row, ReceiptStatus::Accepted)?;
                transaction.execute("INSERT INTO contour.ingestion_payloads(tenant_id,collector_id,batch_id,payload_format,checked_batch) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,2,$4)", &[&expected[0], &expected[1], &batch.batch_id(), &payload]).await.map_err(database_error)?;
                for (observation, witness) in batch.operation_observations() {
                    let class = attribution_class(witness);
                    let parts = observation.key.components();
                    let revision = observation.policy_revision.to_string();
                    transaction.execute("INSERT INTO contour.ingestion_v2_metadata (tenant_id,collector_id,batch_id,record_id,digest_version,request_digest,accepted_at,source_id,project_id,service_id,environment_id,deployment_id,policy_revision,parser_profile,attribution_class) SELECT tenant_id,collector_id,batch_id,$4::text::uuid,2,request_digest,accepted_at,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid,$10::text::numeric,$11,$12 FROM contour.ingestion_batches WHERE tenant_id=$1::text::uuid AND collector_id=$2::text::uuid AND batch_id=$3::text::uuid", &[&expected[0], &expected[1], &batch.batch_id(), &observation.record_id, &observation.source_id, &parts[1], &parts[2], &parts[3], &observation.deployment_id, &revision, &observation.parser_profile, &class]).await.map_err(database_error)?;
                }
                if capability == IngressCapability::Origin {
                    let row = transaction.query_one("SELECT contour.write_origin_batch_proofs($1::text::uuid,$2::text::uuid,$3::text::uuid,$4)", &[&expected[0], &expected[1], &batch.batch_id(), &payload]).await.map_err(origin_write_error)?;
                    let count: i32 = row.try_get(0).map_err(|_| SubmitError::Corrupt)?;
                    if count != expected_proof_count(batch)? { return Err(SubmitError::Corrupt); }
                }
                transaction.query_one("SELECT set_config('synchronous_commit','on',true)", &[]).await.map_err(database_error)?;
                loaded.validate_v2(batch, expected, clock(&transaction).await?)?;
                check_deadline(deadline)?;
                Ok::<_, SubmitError>((receipt, false))
            }.await;
        match preparation {
            Ok((receipt, false)) => {
                // No intervening await after confirmed COMMIT before latching acceptance.
                committing = true;
                transaction
                    .commit()
                    .await
                    .map_err(|_| SubmitError::OutcomeUnknown)?;
                accepted = Some(receipt.clone());
                empty_context(client).await?;
                check_deadline(deadline)?;
                guard.confirm();
                Ok(receipt)
            }
            result => {
                transaction.rollback().await.map_err(database_error)?;
                empty_context(client).await?;
                check_deadline(deadline)?;
                if result != Err(SubmitError::Authority(AuthorityError::Deadline)) {
                    guard.confirm();
                }
                result.map(|(receipt, _)| receipt)
            }
        }
    };
    let result = timeout_at(deadline, work).await;
    // A known commit is not erased by subsequent deadline/context cleanup failure.
    if let Some(receipt) = accepted {
        return Ok(receipt);
    }
    match result {
        Ok(result) => result,
        Err(_) if committing => Err(SubmitError::OutcomeUnknown),
        Err(_) => Err(AuthorityError::Deadline.into()),
    }
}

async fn validate_submit_v2_metadata(
    transaction: &Transaction<'_>,
    batch: &BatchV2,
    expected: [&str; 2],
    batch_id: &str,
) -> Result<(), SubmitError> {
    // Inspect every row, including extras, and recheck bindings even if storage
    // constraints were bypassed by privileged repair.
    let rows = transaction.query("SELECT m.record_id::text,m.source_id::text,m.project_id::text,m.service_id::text,m.environment_id::text,m.deployment_id::text,CASE WHEN m.policy_revision BETWEEN 1 AND 18446744073709551615 AND m.policy_revision=trunc(m.policy_revision) THEN trunc(m.policy_revision)::text END,CASE WHEN octet_length(m.parser_profile) BETWEEN 1 AND 64 THEN m.parser_profile END,CASE WHEN octet_length(m.attribution_class) IN (12,18) THEN m.attribution_class END,(m.digest_version=2 AND m.request_digest=b.request_digest AND m.accepted_at=b.accepted_at AND isfinite(m.accepted_at)) FROM contour.ingestion_v2_metadata m JOIN contour.ingestion_batches b USING(tenant_id,collector_id,batch_id) WHERE m.tenant_id=$1::text::uuid AND m.collector_id=$2::text::uuid AND m.batch_id=$3::text::uuid LIMIT 501", &[&expected[0], &expected[1], &batch_id]).await.map_err(database_error)?;
    if rows.len() != batch.record_count() {
        return Err(SubmitError::Corrupt);
    }
    let mut by_record = std::collections::HashMap::with_capacity(rows.len());
    for row in &rows {
        let id: &str = row.try_get(0).map_err(|_| SubmitError::Corrupt)?;
        if by_record.insert(id, row).is_some() {
            return Err(SubmitError::Corrupt);
        }
    }
    for (observation, witness) in batch.operation_observations() {
        let row = by_record
            .remove(observation.record_id)
            .ok_or(SubmitError::Corrupt)?;
        let parts = observation.key.components();
        let expected_fields = [
            observation.source_id,
            parts[1],
            parts[2],
            parts[3],
            observation.deployment_id,
        ];
        for (index, value) in expected_fields.iter().enumerate() {
            if row
                .try_get::<_, &str>(index + 1)
                .map_err(|_| SubmitError::Corrupt)?
                != *value
            {
                return Err(SubmitError::Corrupt);
            }
        }
        if row
            .try_get::<_, &str>(6)
            .map_err(|_| SubmitError::Corrupt)?
            != observation.policy_revision.to_string()
            || row
                .try_get::<_, &str>(7)
                .map_err(|_| SubmitError::Corrupt)?
                != observation.parser_profile
            || row
                .try_get::<_, &str>(8)
                .map_err(|_| SubmitError::Corrupt)?
                != attribution_class(witness)
            || !row
                .try_get::<_, bool>(9)
                .map_err(|_| SubmitError::Corrupt)?
        {
            return Err(SubmitError::Corrupt);
        }
    }
    if !by_record.is_empty() {
        return Err(SubmitError::Corrupt);
    }
    Ok(())
}

async fn duplicate_v2(
    transaction: &Transaction<'_>,
    batch: &BatchV2,
    digest: &[u8; 32],
    expected: [&str; 2],
    capability: IngressCapability,
) -> Result<Option<DurableReceipt>, SubmitError> {
    let row = transaction.query_opt("SELECT b.receipt_id::text,floor(extract(epoch FROM b.accepted_at)*1000000)::bigint,b.digest_version,octet_length(b.request_digest),b.record_count,p.payload_format,octet_length(p.checked_batch) FROM contour.ingestion_batches b LEFT JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE b.tenant_id=$1::text::uuid AND b.collector_id=$2::text::uuid AND b.batch_id=$3::text::uuid", &[&expected[0], &expected[1], &batch.batch_id()]).await.map_err(database_error)?;
    let Some(row) = row else { return Ok(None) };
    let version: i16 = row.try_get(2).map_err(|_| SubmitError::Corrupt)?;
    let digest_size: i32 = row.try_get(3).map_err(|_| SubmitError::Corrupt)?;
    let count: i32 = row.try_get(4).map_err(|_| SubmitError::Corrupt)?;
    let format: Option<i16> = row.try_get(5).map_err(|_| SubmitError::Corrupt)?;
    let size: Option<i32> = row.try_get(6).map_err(|_| SubmitError::Corrupt)?;
    if !matches!(version, 1 | 2)
        || digest_size != 32
        || !(1..=500).contains(&count)
        || format != Some(version)
        || !size.is_some_and(|n| (1..=1_048_576).contains(&n))
    {
        return Err(SubmitError::Corrupt);
    }
    let stored = transaction.query_one("SELECT b.request_digest,p.checked_batch FROM contour.ingestion_batches b JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE b.tenant_id=$1::text::uuid AND b.collector_id=$2::text::uuid AND b.batch_id=$3::text::uuid AND octet_length(b.request_digest)=32 AND octet_length(p.checked_batch) BETWEEN 1 AND 1048576", &[&expected[0], &expected[1], &batch.batch_id()]).await.map_err(database_error)?;
    let stored_digest: &[u8] = stored.try_get(0).map_err(|_| SubmitError::Corrupt)?;
    let bytes: &[u8] = stored.try_get(1).map_err(|_| SubmitError::Corrupt)?;
    if version == 1 {
        let old = Batch::from_wire_json(bytes).map_err(|_| SubmitError::Corrupt)?;
        if old.tenant_id() != expected[0]
            || old.collector_id() != expected[1]
            || old.batch_id() != batch.batch_id()
            || old.record_count() != count as usize
            || old
                .request_digest_bytes()
                .map_err(|_| SubmitError::Corrupt)?
                .as_slice()
                != stored_digest
        {
            return Err(SubmitError::Corrupt);
        }
        return Err(SubmitError::Conflict);
    }
    let old = BatchV2::from_wire_json(bytes).map_err(|_| SubmitError::Corrupt)?;
    if old.tenant_id() != expected[0]
        || old.collector_id() != expected[1]
        || old.batch_id() != batch.batch_id()
        || old.record_count() != count as usize
        || old
            .request_digest_bytes()
            .map_err(|_| SubmitError::Corrupt)?
            .as_slice()
            != stored_digest
    {
        return Err(SubmitError::Corrupt);
    }
    // Basic V2 cannot authenticate stored fingerprint witnesses. Preserve its
    // corruption-before-conflict behavior without consulting origin proofs.
    if capability == IngressCapability::Basic
        && old
            .records()
            .iter()
            .any(|record| !matches!(record.origin_witness(), OriginWitness::Unattributed))
    {
        return Err(SubmitError::Corrupt);
    }
    validate_submit_v2_metadata(transaction, &old, expected, batch.batch_id()).await?;
    if capability == IngressCapability::Origin {
        let expected_proofs = expected_proof_count(&old)?;
        let requires_canonical = if expected_proofs == 0 {
            // Provenance is set by an owner trigger from the private ingress
            // capability, never from supplied input. The helper checks that an
            // unattributed batch has no retained proof, marker or projection.
            let row = transaction.query_one("SELECT contour.origin_retry_requires_canonical($1::text::uuid,$2::text::uuid,$3::text::uuid)", &[&expected[0], &expected[1], &batch.batch_id()]).await.map_err(origin_verify_error)?;
            row.try_get::<_, bool>(0)
                .map_err(|_| SubmitError::Corrupt)?
        } else {
            true
        };
        if requires_canonical {
            let canonical = old
                .to_canonical_wire_json()
                .map_err(|_| SubmitError::Corrupt)?;
            let proof = transaction.query_one("SELECT contour.verify_origin_batch_proofs($1::text::uuid,$2::text::uuid,$3::text::uuid,$4)", &[&expected[0], &expected[1], &batch.batch_id(), &canonical]).await.map_err(origin_verify_error)?;
            if proof
                .try_get::<_, i32>(0)
                .map_err(|_| SubmitError::Corrupt)?
                != expected_proofs
            {
                return Err(SubmitError::Corrupt);
            }
        }
    }
    if stored_digest != digest {
        return Err(SubmitError::Conflict);
    }
    Ok(Some(receipt(&row, ReceiptStatus::Duplicate)?))
}

fn attribution_class(witness: &OriginWitness) -> &'static str {
    match witness {
        OriginWitness::Unattributed => "unattributed",
        OriginWitness::DownstreamMtlsLeafSha256V1 { .. } => "verified_origin_v1",
    }
}
fn expected_proof_count(batch: &BatchV2) -> Result<i32, SubmitError> {
    i32::try_from(
        batch
            .operation_observations()
            .filter(|(_, witness)| !matches!(witness, OriginWitness::Unattributed))
            .count(),
    )
    .map_err(|_| SubmitError::Corrupt)
}

// Only the closed quota error from the fresh proof writer is an actionable
// capacity result. Other resource or database errors retain normal handling.
fn origin_write_error(error: tokio_postgres::Error) -> SubmitError {
    if error
        .as_db_error()
        .is_some_and(|db| is_origin_quota_error(db.code().code(), db.constraint()))
    {
        SubmitError::LogicalQuota
    } else {
        database_error(error).into()
    }
}
fn origin_verify_error(error: tokio_postgres::Error) -> SubmitError {
    if error.code().is_some_and(|code| code.code() == "23514") {
        SubmitError::Corrupt
    } else {
        database_error(error).into()
    }
}

fn is_origin_quota_error(code: &str, constraint: Option<&str>) -> bool {
    code == "54000" && constraint == Some("origin_logical_quota_exhausted")
}
#[cfg(test)]
mod origin_error_tests {
    use super::is_origin_quota_error;
    #[test]
    fn quota_requires_exact_sqlstate_and_constraint() {
        assert!(is_origin_quota_error(
            "54000",
            Some("origin_logical_quota_exhausted")
        ));
        assert!(!is_origin_quota_error("54000", None));
        assert!(!is_origin_quota_error("54000", Some("another_limit")));
        assert!(!is_origin_quota_error(
            "23514",
            Some("origin_logical_quota_exhausted")
        ));
    }
}
