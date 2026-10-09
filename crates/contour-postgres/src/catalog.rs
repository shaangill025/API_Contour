//! Atomic projection of accepted history. No caller payload or capture grant.
use crate::{
    AuthorityError, ConnectedDatabase,
    transaction::{
        CancellationGuard, begin, check_deadline, configure_tenant, database_error, empty_context,
    },
};
use contour_core::{Batch, OperationObservation};
use std::fmt;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogStatus {
    Processed,
    AlreadyProcessed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogError {
    Identity,
    NotFound,
    Corrupt,
    Collision,
    Database,
    Deadline,
    Invalidated,
    OutcomeUnknown,
}
impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CatalogError {}
impl From<AuthorityError> for CatalogError {
    fn from(error: AuthorityError) -> Self {
        match error {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Invalidated => Self::Invalidated,
            _ => Self::Database,
        }
    }
}
impl ConnectedDatabase {
    /// Process one committed inbox batch using a separately provisioned catalog-worker
    /// login. The operator supplies tenant/collector scope and batch ID. Accepted
    /// history is independent of current capture authorization or policy expiry.
    /// Retry the same ID after OutcomeUnknown; never substitute a new batch ID.
    pub async fn process_catalog_batch(
        &mut self,
        expected: [&str; 2],
        batch_id: &str,
    ) -> Result<CatalogStatus, CatalogError> {
        self.process_catalog_batch_until(expected, batch_id, Instant::now() + self.deadline)
            .await
    }
    /// An absolute caller deadline can shorten, but cannot extend, the connection budget.
    pub async fn process_catalog_batch_until(
        &mut self,
        expected: [&str; 2],
        batch_id: &str,
        deadline: Instant,
    ) -> Result<CatalogStatus, CatalogError> {
        if !expected.into_iter().chain([batch_id]).all(uuid) {
            return Err(CatalogError::Identity);
        }
        if self.client.is_none() {
            return Err(CatalogError::Invalidated);
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
                .ok_or(CatalogError::Invalidated)?;
            let transaction = begin(client).await?;
            let preparation = async {
                configure_tenant(&transaction, expected[0], deadline.saturating_duration_since(Instant::now())).await?;
                let batch = load(&transaction, expected, batch_id).await?;
                // The unique claim serializes concurrent consumers. A conflicting
                // INSERT can wait for another transaction, so inspect its committed
                // version in a separate READ COMMITTED statement with a fresh snapshot.
                let claim = transaction.execute("INSERT INTO contour.catalog_processed_batches(tenant_id,collector_id,batch_id,processor_version) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,1) ON CONFLICT DO NOTHING", &[&expected[0], &expected[1], &batch_id]).await.map_err(database_error)?;
                if claim == 0 {
                    let row = transaction.query_one("SELECT processor_version FROM contour.catalog_processed_batches WHERE tenant_id=$1::text::uuid AND collector_id=$2::text::uuid AND batch_id=$3::text::uuid", &[&expected[0], &expected[1], &batch_id]).await.map_err(database_error)?;
                    if row.try_get::<_, i16>(0).map_err(|_| CatalogError::Corrupt)? != 1 {
                        return Err(CatalogError::Corrupt);
                    }
                    return Ok(CatalogStatus::AlreadyProcessed);
                }
                for observation in batch.operation_observations() {
                    check_deadline(deadline)?;
                    store(&transaction, batch_id, observation).await?;
                }
                transaction.query_one("SELECT set_config('synchronous_commit','on',true)", &[]).await.map_err(database_error)?;
                check_deadline(deadline)?;
                Ok::<_, CatalogError>(CatalogStatus::Processed)
            }.await;
            match preparation {
                Ok(CatalogStatus::Processed) => {
                    committing = true;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| CatalogError::OutcomeUnknown)?;
                    // No await between the confirmed COMMIT and the outcome latch.
                    committed = Some(CatalogStatus::Processed);
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(CatalogStatus::Processed)
                }
                result => {
                    transaction.rollback().await.map_err(database_error)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    if result != Err(CatalogError::Deadline) {
                        guard.confirm();
                    }
                    result
                }
            }
        };
        let result = timeout_at(deadline, work).await;
        if let Some(status) = committed {
            return Ok(status);
        }
        match result {
            Ok(result) => result,
            Err(_) if committing => Err(CatalogError::OutcomeUnknown),
            Err(_) => Err(CatalogError::Deadline),
        }
    }
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
async fn load(
    transaction: &Transaction<'_>,
    expected: [&str; 2],
    batch_id: &str,
) -> Result<Batch, CatalogError> {
    // Metadata bounds precede retrieval of either bytea field, including a digest
    // damaged by privileged storage repair. Immutable inbox rows cannot change
    // between these statements through an application role.
    let row = transaction.query_opt("SELECT b.digest_version,octet_length(b.request_digest),b.record_count,p.payload_format,octet_length(p.checked_batch) FROM contour.ingestion_batches b LEFT JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE b.tenant_id=$1::text::uuid AND b.collector_id=$2::text::uuid AND b.batch_id=$3::text::uuid", &[&expected[0], &expected[1], &batch_id]).await.map_err(database_error)?.ok_or(CatalogError::NotFound)?;
    let version: i16 = row.try_get(0).map_err(|_| CatalogError::Corrupt)?;
    let digest_size: i32 = row.try_get(1).map_err(|_| CatalogError::Corrupt)?;
    let count: i32 = row.try_get(2).map_err(|_| CatalogError::Corrupt)?;
    let format: Option<i16> = row.try_get(3).map_err(|_| CatalogError::Corrupt)?;
    let size: Option<i32> = row.try_get(4).map_err(|_| CatalogError::Corrupt)?;
    if version != 1
        || digest_size != 32
        || !(1..=500).contains(&count)
        || format != Some(1)
        || !size.is_some_and(|size| (1..=1_048_576).contains(&size))
    {
        return Err(CatalogError::Corrupt);
    }
    let row = transaction.query_one("SELECT b.request_digest,p.checked_batch FROM contour.ingestion_batches b JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE b.tenant_id=$1::text::uuid AND b.collector_id=$2::text::uuid AND b.batch_id=$3::text::uuid AND octet_length(b.request_digest)=32 AND octet_length(p.checked_batch) BETWEEN 1 AND 1048576", &[&expected[0], &expected[1], &batch_id]).await.map_err(database_error)?;
    let digest: &[u8] = row.try_get(0).map_err(|_| CatalogError::Corrupt)?;
    let payload: &[u8] = row.try_get(1).map_err(|_| CatalogError::Corrupt)?;
    let batch = Batch::from_wire_json(payload).map_err(|_| CatalogError::Corrupt)?;
    if batch.tenant_id() != expected[0]
        || batch.collector_id() != expected[1]
        || batch.batch_id() != batch_id
        || batch.record_count() != count as usize
        || batch
            .request_digest_bytes()
            .map_err(|_| CatalogError::Corrupt)?
            .as_slice()
            != digest
    {
        return Err(CatalogError::Corrupt);
    }
    Ok(batch)
}
async fn store(
    transaction: &Transaction<'_>,
    batch_id: &str,
    observation: OperationObservation<'_>,
) -> Result<(), CatalogError> {
    let parts = observation.key.components();
    let key = observation
        .key
        .canonical_bytes()
        .map_err(|_| CatalogError::Corrupt)?;
    let hash = observation
        .key
        .fingerprint()
        .map_err(|_| CatalogError::Corrupt)?;
    transaction.execute("INSERT INTO contour.operations(tenant_id,operation_hash,identity_version,canonical_key,project_id,service_id,environment_id) VALUES($1::text::uuid,decode($2,'hex'),1,$3,$4::text::uuid,$5::text::uuid,$6::text::uuid) ON CONFLICT DO NOTHING", &[&parts[0], &hash, &key, &parts[1], &parts[2], &parts[3]]).await.map_err(database_error)?;
    let row = transaction.query_one("SELECT operation_id::text,canonical_key,project_id::text,service_id::text,environment_id::text FROM contour.operations WHERE tenant_id=$1::text::uuid AND identity_version=1 AND operation_hash=decode($2,'hex') AND octet_length(canonical_key) BETWEEN 1 AND 2048", &[&parts[0], &hash]).await.map_err(database_error)?;
    if row
        .try_get::<_, &[u8]>(1)
        .map_err(|_| CatalogError::Corrupt)?
        != key
        || row
            .try_get::<_, &str>(2)
            .map_err(|_| CatalogError::Corrupt)?
            != parts[1]
        || row
            .try_get::<_, &str>(3)
            .map_err(|_| CatalogError::Corrupt)?
            != parts[2]
        || row
            .try_get::<_, &str>(4)
            .map_err(|_| CatalogError::Corrupt)?
            != parts[3]
    {
        return Err(CatalogError::Collision);
    }
    let operation: &str = row.try_get(0).map_err(|_| CatalogError::Corrupt)?;
    let canonical = observation
        .structure
        .canonical_bytes()
        .map_err(|_| CatalogError::Corrupt)?;
    let structure_hash = observation
        .structure
        .fingerprint()
        .map_err(|_| CatalogError::Corrupt)?;
    let wire = observation
        .structure
        .to_wire_json()
        .map_err(|_| CatalogError::Corrupt)?;
    let revision = observation.policy_revision.to_string();
    let version = i16::from(observation.canonicalization_version);
    transaction.execute("INSERT INTO contour.variants(tenant_id,operation_id,collector_id,policy_revision,parser_profile,canonicalization_version,structure_hash,canonical_structure,structure_wire) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::numeric,$5,$6,decode($7,'hex'),$8,$9) ON CONFLICT DO NOTHING", &[&parts[0], &operation, &observation.collector_id, &revision, &observation.parser_profile, &version, &structure_hash, &canonical, &wire]).await.map_err(database_error)?;
    let row = transaction.query_one("SELECT variant_id::text,canonical_structure,structure_wire FROM contour.variants WHERE tenant_id=$1::text::uuid AND operation_id=$2::text::uuid AND collector_id=$3::text::uuid AND policy_revision=$4::text::numeric AND parser_profile=$5 AND canonicalization_version=$6 AND structure_hash=decode($7,'hex') AND octet_length(canonical_structure) BETWEEN 1 AND 65536 AND octet_length(structure_wire) BETWEEN 1 AND 1048576", &[&parts[0], &operation, &observation.collector_id, &revision, &observation.parser_profile, &version, &structure_hash]).await.map_err(database_error)?;
    if row
        .try_get::<_, &[u8]>(1)
        .map_err(|_| CatalogError::Corrupt)?
        != canonical
        || row
            .try_get::<_, &[u8]>(2)
            .map_err(|_| CatalogError::Corrupt)?
            != wire
    {
        return Err(CatalogError::Collision);
    }
    let variant: &str = row.try_get(0).map_err(|_| CatalogError::Corrupt)?;
    let count = observation.count.to_string();
    let numerator = observation.sample_numerator.to_string();
    let denominator = observation.sample_denominator.to_string();
    let status = observation.status_code.map(|value| value as i32);
    let request_names =
        serde_json::to_vec(observation.request_header_names).map_err(|_| CatalogError::Corrupt)?;
    let response_names =
        serde_json::to_vec(observation.response_header_names).map_err(|_| CatalogError::Corrupt)?;
    let query_names =
        serde_json::to_vec(observation.query_parameter_names).map_err(|_| CatalogError::Corrupt)?;
    transaction.execute("INSERT INTO contour.observation_windows(tenant_id,collector_id,batch_id,record_id,operation_id,variant_id,source_id,project_id,service_id,environment_id,deployment_id,observation_count,sample_numerator,sample_denominator,visibility,completeness,reasons,route_uncertain,status_code,first_seen,last_seen,queued_at,expires_at,request_header_names,response_header_names,query_parameter_names) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8::text::uuid,$9::text::uuid,$10::text::uuid,$11::text::uuid,$12::text::numeric,$13::text::numeric,$14::text::numeric,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)", &[&parts[0], &observation.collector_id, &batch_id, &observation.record_id, &operation, &variant, &observation.source_id, &parts[1], &parts[2], &parts[3], &observation.deployment_id, &count, &numerator, &denominator, &observation.visibility, &observation.completeness, &observation.reasons, &observation.route_uncertain, &status, &observation.first_seen.as_str(), &observation.last_seen.as_str(), &observation.queued_at.as_str(), &observation.expires_at.as_str(), &request_names, &response_names, &query_names]).await.map_err(database_error)?;
    Ok(())
}
