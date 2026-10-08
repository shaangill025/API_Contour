//! Private transaction mechanics; no public SQL or transaction escape.
use crate::{ConnectedDatabase, authority::AuthorityError};
use time::OffsetDateTime;
use tokio::time::Instant;
use tokio_postgres::{Client, Error, IsolationLevel, Transaction};

// Armed before BEGIN. Transaction locals drop first; queued rollback is not enough.
pub(crate) struct CancellationGuard<'a> {
    pub(crate) connection: &'a mut ConnectedDatabase,
    confirmed: bool,
}
impl Drop for CancellationGuard<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.connection.invalidate();
        }
    }
}
impl<'a> CancellationGuard<'a> {
    pub(crate) fn arm(connection: &'a mut ConnectedDatabase) -> Self {
        connection.reusable = false;
        Self {
            connection,
            confirmed: false,
        }
    }
    // Only call after confirmed transaction completion and checked context cleanup.
    pub(crate) fn confirm(&mut self) {
        self.confirmed = true;
        self.connection.reusable = true;
    }
}
pub(crate) async fn begin(client: &mut Client) -> Result<Transaction<'_>, AuthorityError> {
    client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(database_error)
}
pub(crate) async fn configure_context(
    transaction: &Transaction<'_>,
    expected: [&str; 2],
    timeout: std::time::Duration,
) -> Result<(), AuthorityError> {
    configure_tenant(transaction, expected[0], timeout).await?;
    // This is its own statement; authority reads must follow with a fresh snapshot.
    transaction
        .query_one(
            "SELECT contour.lock_collector($1::text::uuid,$2::text::uuid)",
            &[&expected[0], &expected[1]],
        )
        .await
        .map_err(database_error)?;
    Ok(())
}
pub(crate) async fn configure_tenant(
    transaction: &Transaction<'_>,
    tenant: &str,
    timeout: std::time::Duration,
) -> Result<(), AuthorityError> {
    let milliseconds = timeout.as_millis().max(1).to_string();
    transaction.query_one("SELECT set_config('apicontour.tenant_id',$1,true), set_config('statement_timeout',$2,true), set_config('lock_timeout',$2,true), set_config('idle_in_transaction_session_timeout',$2,true)", &[&tenant,&milliseconds]).await.map_err(database_error)?;
    Ok(())
}
pub(crate) async fn empty_context(client: &Client) -> Result<(), AuthorityError> {
    let context = client
        .query_one(
            "SELECT nullif(current_setting('apicontour.tenant_id',true),'') IS NULL",
            &[],
        )
        .await
        .map_err(database_error)?;
    if !context
        .try_get::<_, bool>(0)
        .map_err(|_| AuthorityError::Database)?
    {
        return Err(AuthorityError::Invalidated);
    }
    Ok(())
}
pub(crate) fn database_error(error: Error) -> AuthorityError {
    match error.code().map(|code| code.code()) {
        Some("57014" | "55P03" | "25P03") => AuthorityError::Deadline,
        _ => AuthorityError::Database,
    }
}
pub(crate) fn check_deadline(deadline: Instant) -> Result<(), AuthorityError> {
    if Instant::now() >= deadline {
        Err(AuthorityError::Deadline)
    } else {
        Ok(())
    }
}
pub(crate) async fn clock(transaction: &Transaction<'_>) -> Result<OffsetDateTime, AuthorityError> {
    let row = transaction
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
            &[],
        )
        .await
        .map_err(database_error)?;
    let micros: i64 = row.try_get(0).map_err(|_| AuthorityError::Database)?;
    time_from_micros(micros)
}
pub(crate) fn time_from_micros(micros: i64) -> Result<OffsetDateTime, AuthorityError> {
    let nanos = i128::from(micros)
        .checked_mul(1000)
        .ok_or(AuthorityError::Database)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| AuthorityError::Database)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn server_time_conversion_is_exact_and_checked() {
        assert_eq!(time_from_micros(0).unwrap(), OffsetDateTime::UNIX_EPOCH);
        assert_eq!(time_from_micros(-1).unwrap().unix_timestamp_nanos(), -1000);
        assert_eq!(
            time_from_micros(1_800_000_000_123_456)
                .unwrap()
                .unix_timestamp_nanos(),
            1_800_000_000_123_456_000
        );
        assert_eq!(time_from_micros(i64::MIN), Err(AuthorityError::Database));
        assert_eq!(time_from_micros(i64::MAX), Err(AuthorityError::Database));
    }
    #[test]
    fn absolute_deadline_bounds() {
        assert_eq!(
            check_deadline(Instant::now()),
            Err(AuthorityError::Deadline)
        );
        assert_eq!(
            check_deadline(Instant::now() + std::time::Duration::from_secs(1)),
            Ok(())
        );
    }
}
