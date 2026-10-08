//! Atomic checked submission; callers independently authenticate expected identity.
use crate::{
    AuthorityError, ConnectedDatabase,
    authority::{load_staged, stage_current},
    transaction::{
        CancellationGuard, begin, check_deadline, clock, configure_context, database_error,
        empty_context, time_from_micros,
    },
};
use contour_core::{Batch, PolicyKeys};
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
        if batch.tenant_id() != expected[0] || batch.collector_id() != expected[1] {
            return Err(AuthorityError::Identity.into());
        }
        if self.client.is_none() {
            return Err(AuthorityError::Invalidated.into());
        }
        let deadline = Instant::now() + self.deadline;
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
