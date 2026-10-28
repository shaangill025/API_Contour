//! Transaction-local authorization. Never expose a reusable authorization receipt.
use crate::AuthorityError;
#[derive(Clone, Copy)]
pub(crate) enum HumanAuthorizationError {
    Forbidden,
    Corrupt,
    Database,
    Deadline,
    Invalidated,
}
type Error = HumanAuthorizationError;
impl From<AuthorityError> for Error {
    fn from(value: AuthorityError) -> Self {
        match value {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Invalidated => Self::Invalidated,
            _ => Self::Database,
        }
    }
}
use crate::transaction::{clock, database_error};
use contour_auth::VerifiedIdentity;
use tokio_postgres::Transaction;

pub(crate) async fn check_expiry(
    tx: &Transaction<'_>,
    identity: &VerifiedIdentity,
) -> Result<(), Error> {
    let now = clock(tx).await?.unix_timestamp();
    if now < 0 || now as u64 >= identity.expires_at() {
        return Err(Error::Forbidden);
    }
    Ok(())
}

/// Lock order: identity, actor, tenant membership, project membership, service role.
/// SHARE conflicts with provisioning's non-key enabled updates; KEY SHARE does not.
/// The caller retains this transaction through the business commit or rollback.
pub(crate) async fn authorize(
    tx: &Transaction<'_>,
    identity: &VerifiedIdentity,
    scope: [&str; 3],
    write: bool,
) -> Result<String, Error> {
    check_expiry(tx, identity).await?;
    let row = tx.query_opt(
        "SELECT actor_id::text,enabled FROM contour.human_identities WHERE issuer=$1 AND subject=$2 FOR SHARE",
        &[&identity.issuer(), &identity.subject()],
    ).await.map_err(database_error)?.ok_or(Error::Forbidden)?;
    let actor: String = row.try_get(0).map_err(|_| Error::Corrupt)?;
    if !row.try_get::<_, bool>(1).map_err(|_| Error::Corrupt)? {
        return Err(Error::Forbidden);
    }
    for (sql, params) in [
        (
            "SELECT enabled FROM contour.human_actors WHERE actor_id=$1::text::uuid FOR SHARE",
            vec![&actor],
        ),
        (
            "SELECT enabled FROM contour.human_tenant_memberships WHERE actor_id=$1::text::uuid AND tenant_id=$2::text::uuid FOR SHARE",
            vec![&actor, &scope[0].to_owned()],
        ),
        (
            "SELECT enabled FROM contour.human_project_memberships WHERE actor_id=$1::text::uuid AND tenant_id=$2::text::uuid AND project_id=$3::text::uuid FOR SHARE",
            vec![&actor, &scope[0].to_owned(), &scope[1].to_owned()],
        ),
    ] {
        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| *p as _).collect();
        let row = tx
            .query_opt(sql, &params)
            .await
            .map_err(database_error)?
            .ok_or(Error::Forbidden)?;
        if !row.try_get::<_, bool>(0).map_err(|_| Error::Corrupt)? {
            return Err(Error::Forbidden);
        }
    }
    let roles = if write {
        vec!["service_owner"]
    } else {
        vec!["service_owner", "viewer"]
    };
    let rows = tx.query(
        "SELECT enabled FROM contour.human_service_roles WHERE actor_id=$1::text::uuid AND tenant_id=$2::text::uuid AND project_id=$3::text::uuid AND service_id=$4::text::uuid AND role=ANY($5::text[]) ORDER BY role FOR SHARE",
        &[&actor, &scope[0], &scope[1], &scope[2], &roles],
    ).await.map_err(database_error)?;
    let mut enabled = false;
    for row in rows {
        enabled |= row.try_get::<_, bool>(0).map_err(|_| Error::Corrupt)?;
    }
    if !enabled {
        return Err(Error::Forbidden);
    }
    // A token can expire while any of the preceding row locks is waiting.
    check_expiry(tx, identity).await?;
    Ok(actor)
}
