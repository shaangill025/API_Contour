//! SQL28 data snapshot reader. This does not authenticate a peer or grant authority.
use crate::{
    AuthorityError, ConnectedDatabase,
    transaction::{
        CancellationGuard, begin, check_deadline, clock, configure_tenant, empty_context,
        time_from_micros,
    },
};
use contour_core::ReceiverEnrollment;
use std::fmt;
use time::OffsetDateTime;
use tokio::time::{Instant, timeout_at};

const ROLE: &str = "contour_causal_receiver_reader";
const ROLE_QUERY: &str = "SELECT current_user=session_user, COALESCE(session_user=(SELECT a.usename FROM pg_catalog.pg_stat_activity a WHERE a.pid=pg_catalog.pg_backend_pid()),false), EXISTS (SELECT 1 FROM pg_catalog.pg_roles u WHERE u.rolname=current_user AND NOT u.rolsuper AND NOT u.rolbypassrls), EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=$1), EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=$1 AND pg_catalog.pg_has_role(current_user,r.oid,'USAGE')), NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname<>current_user AND r.rolname<>$1 AND pg_catalog.pg_has_role(current_user,r.oid,'MEMBER'))";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CausalReceiverReadError {
    Identity,
    Unavailable,
    Corrupt,
    Expired,
    Database,
    Deadline,
    OutcomeUnknown,
}
impl fmt::Display for CausalReceiverReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CausalReceiverReadError {}
impl From<AuthorityError> for CausalReceiverReadError {
    fn from(value: AuthorityError) -> Self {
        match value {
            AuthorityError::Deadline => Self::Deadline,
            _ => Self::Database,
        }
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
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Caller-configured selector; it is not a verified TLS identity.
pub struct CausalReceiverSelector {
    tenant: String,
    runtime: String,
    epoch: u64,
    generation: String,
    leaf: [u8; 32],
}
impl CausalReceiverSelector {
    pub fn new(
        tenant: &str,
        runtime: &str,
        epoch: u64,
        generation: &str,
        leaf: [u8; 32],
    ) -> Result<Self, CausalReceiverReadError> {
        if !uuid(tenant)
            || !uuid(runtime)
            || epoch == 0
            || !hex(generation, 32)
            || generation.bytes().all(|b| b == b'0')
        {
            return Err(CausalReceiverReadError::Identity);
        }
        Ok(Self {
            tenant: tenant.into(),
            runtime: runtime.into(),
            epoch,
            generation: generation.into(),
            leaf,
        })
    }
}
/// An immutable stale-able observation, not a session, permit, or launch proof.
pub struct CausalReceiverObservation {
    metadata: ReceiverEnrollment,
    verified_until: Instant,
}
impl CausalReceiverObservation {
    pub fn metadata(&self) -> &ReceiverEnrollment {
        &self.metadata
    }
    pub fn verified_until(&self) -> Instant {
        self.verified_until
    }
}
impl fmt::Debug for CausalReceiverObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalReceiverObservation")
    }
}
pub struct CausalReceiverReader {
    connection: ConnectedDatabase,
}
impl CausalReceiverReader {
    pub fn new(connection: ConnectedDatabase) -> Self {
        Self { connection }
    }
    pub async fn read_until(
        &mut self,
        selector: &CausalReceiverSelector,
        deadline: Instant,
    ) -> Result<CausalReceiverObservation, CausalReceiverReadError> {
        let deadline = deadline.min(Instant::now() + self.connection.deadline);
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(&mut self.connection);
        let mut committing = false;
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CausalReceiverReadError::Database)?;
            empty_context(client).await?;
            let row = client
                .query_one(ROLE_QUERY, &[&ROLE])
                .await
                .map_err(|_| CausalReceiverReadError::Database)?;
            let mut facts = [false; 6];
            for (i, v) in facts.iter_mut().enumerate() {
                *v = row
                    .try_get(i)
                    .map_err(|_| CausalReceiverReadError::Database)?;
            }
            if !role_allowed(facts) {
                return Err(CausalReceiverReadError::Identity);
            }
            let tx = begin(client).await?;
            let checked=async {
    configure_tenant(&tx,&selector.tenant,deadline.saturating_duration_since(Instant::now())).await?;
    let initial=clock(&tx).await?; check_deadline(deadline)?;
    let epoch=selector.epoch.to_string();
    let row=tx.query_one("SELECT credential_id::text, CASE WHEN octet_length(metadata) BETWEEN 1 AND 4096 THEN metadata END, CASE WHEN octet_length(commitment)=32 THEN commitment END, floor(extract(epoch FROM expires_at)*1000000)::bigint FROM contour.current_causal_receiver($1::text::uuid,$2::text::uuid,$3::text::numeric,$4::text,$5::bytea)",&[&selector.tenant,&selector.runtime,&epoch,&selector.generation,&&selector.leaf[..]]).await.map_err(|_|CausalReceiverReadError::Unavailable)?;
    let credential:String=row.try_get(0).map_err(|_|CausalReceiverReadError::Corrupt)?;
    let body:Vec<u8>=row.try_get(1).map_err(|_|CausalReceiverReadError::Corrupt)?;
    let commitment:Vec<u8>=row.try_get(2).map_err(|_|CausalReceiverReadError::Corrupt)?;
    let expires=time_from_micros(row.try_get(3).map_err(|_|CausalReceiverReadError::Corrupt)?)?;
    let metadata=validate_row(selector,&credential,&body,&commitment,expires)?;
    tx.query_one("SELECT set_config('synchronous_commit','on',true)",&[]).await.map_err(|_|CausalReceiverReadError::Database)?;
    let start=Instant::now();let final_now=clock(&tx).await?;
    let remaining=freshness(initial,final_now,metadata.issued_at().instant(),expires)?;
    let verified_until=start.checked_add(remaining).ok_or(CausalReceiverReadError::Expired)?.min(deadline);
    if Instant::now()>=verified_until {return Err(CausalReceiverReadError::Expired);}
    Ok::<_,CausalReceiverReadError>(CausalReceiverObservation{metadata,verified_until})
   }.await;
            match checked {
                Ok(observation) => {
                    committing = true;
                    tx.commit()
                        .await
                        .map_err(|_| CausalReceiverReadError::OutcomeUnknown)?;
                    empty_context(client)
                        .await
                        .map_err(|_| CausalReceiverReadError::OutcomeUnknown)?;
                    check_deadline(deadline)
                        .map_err(|_| CausalReceiverReadError::OutcomeUnknown)?;
                    if Instant::now() >= observation.verified_until {
                        return Err(CausalReceiverReadError::OutcomeUnknown);
                    }
                    guard.confirm();
                    Ok(observation)
                }
                Err(error) => {
                    tx.rollback()
                        .await
                        .map_err(|_| CausalReceiverReadError::Database)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Err(error)
                }
            }
        };
        match timeout_at(deadline, work).await {
            Ok(result) => result,
            Err(_) if committing => Err(CausalReceiverReadError::OutcomeUnknown),
            Err(_) => Err(CausalReceiverReadError::Deadline),
        }
    }
}
fn validate_row(
    selector: &CausalReceiverSelector,
    credential: &str,
    body: &[u8],
    commitment: &[u8],
    expires: OffsetDateTime,
) -> Result<ReceiverEnrollment, CausalReceiverReadError> {
    if body.is_empty() || body.len() > 4096 {
        return Err(CausalReceiverReadError::Corrupt);
    }
    let digest: [u8; 32] = commitment
        .try_into()
        .map_err(|_| CausalReceiverReadError::Corrupt)?;
    let metadata =
        ReceiverEnrollment::decode(body, &digest).map_err(|_| CausalReceiverReadError::Corrupt)?;
    let leaf = selector
        .leaf
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if metadata.tenant_id() != selector.tenant
        || metadata.runtime_id() != selector.runtime
        || metadata.session_epoch() != selector.epoch
        || metadata.enrollment_generation() != selector.generation
        || metadata.evidence_leaf_sha256() != leaf
        || metadata.evidence_credential_id() != credential
        || metadata.expires_at().instant() != expires
    {
        return Err(CausalReceiverReadError::Corrupt);
    }
    Ok(metadata)
}
fn role_allowed(facts: [bool; 6]) -> bool {
    facts.into_iter().all(|fact| fact)
}
fn freshness(
    initial: OffsetDateTime,
    final_now: OffsetDateTime,
    issued: OffsetDateTime,
    expires: OffsetDateTime,
) -> Result<std::time::Duration, CausalReceiverReadError> {
    if final_now < initial || issued > final_now || final_now >= expires {
        return Err(CausalReceiverReadError::Expired);
    }
    (expires - final_now)
        .try_into()
        .map_err(|_| CausalReceiverReadError::Expired)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn vector_row_requires_exact_scope_and_representation() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/specification/fixtures/receiver-enrollment-v1.json"
        ))
        .unwrap();
        let b = &fixture["body"];
        let text = |name: &str| b[name].as_str().unwrap();
        let body = fixture["canonical_utf8"].as_str().unwrap().as_bytes();
        let digest = unhex(fixture["commitment_sha256"].as_str().unwrap());
        let expires = contour_core::Timestamp::parse(text("expires_at"))
            .unwrap()
            .instant();
        let leaf: [u8; 32] = unhex(text("evidence_leaf_sha256")).try_into().unwrap();
        let selector = CausalReceiverSelector::new(
            text("tenant_id"),
            text("runtime_id"),
            1,
            text("enrollment_generation"),
            leaf,
        )
        .unwrap();
        let credential = text("evidence_credential_id");
        assert!(validate_row(&selector, credential, body, &digest, expires).is_ok());
        let mut wrong = CausalReceiverSelector::new(
            text("tenant_id"),
            text("runtime_id"),
            1,
            text("enrollment_generation"),
            leaf,
        )
        .unwrap();
        wrong.tenant = "00000000-0000-4000-8000-000000000009".into();
        assert!(validate_row(&wrong, credential, body, &digest, expires).is_err());
        wrong.tenant = selector.tenant.clone();
        wrong.runtime = "00000000-0000-4000-8000-000000000009".into();
        assert!(validate_row(&wrong, credential, body, &digest, expires).is_err());
        wrong.runtime = selector.runtime.clone();
        wrong.epoch = 2;
        assert!(validate_row(&wrong, credential, body, &digest, expires).is_err());
        wrong.epoch = 1;
        wrong.generation = "1".repeat(32);
        assert!(validate_row(&wrong, credential, body, &digest, expires).is_err());
        wrong.generation = selector.generation.clone();
        wrong.leaf = [3; 32];
        assert!(validate_row(&wrong, credential, body, &digest, expires).is_err());
        assert!(
            validate_row(
                &selector,
                "00000000-0000-4000-8000-000000000009",
                body,
                &digest,
                expires
            )
            .is_err()
        );
        assert!(
            validate_row(
                &selector,
                credential,
                body,
                &digest,
                expires + time::Duration::microseconds(1)
            )
            .is_err()
        );
        let mut bad_digest = digest.clone();
        bad_digest[0] ^= 1;
        assert!(validate_row(&selector, credential, body, &bad_digest, expires).is_err());
        assert!(validate_row(&selector, credential, body, &digest[..31], expires).is_err());
        assert!(validate_row(&selector, credential, &vec![b' '; 4097], &digest, expires).is_err());
        let mut padded = body.to_vec();
        padded.push(b' ');
        let matching_noncanonical =
            unhex("4594e7046699357a8bb7899fd9e780296bbee8be0462a45662394e218cb19bb2");
        assert!(
            validate_row(
                &selector,
                credential,
                &padded,
                &matching_noncanonical,
                expires
            )
            .is_err()
        );
    }
    #[test]
    fn selector_rejects_bad_and_zero() {
        let id = "00000000-0000-4000-8000-000000000001";
        let g = "1234567890abcdef1234567890abcdef";
        assert!(CausalReceiverSelector::new(id, id, 1, g, [1; 32]).is_ok());
        assert!(CausalReceiverSelector::new("bad", id, 1, g, [1; 32]).is_err());
        assert!(CausalReceiverSelector::new(id, id, 0, g, [1; 32]).is_err());
        assert!(CausalReceiverSelector::new(id, id, 1, &"0".repeat(32), [1; 32]).is_err());
        assert!(
            CausalReceiverSelector::new(id, id, 1, &format!("{}\\n", &g[..31]), [1; 32]).is_err()
        );
    }
    #[test]
    fn every_role_fact_is_required() {
        assert!(role_allowed([true; 6]));
        for i in 0..6 {
            let mut facts = [true; 6];
            facts[i] = false;
            assert!(!role_allowed(facts));
        }
    }
    #[test]
    fn clock_rollback_and_expiry_fail() {
        let t = OffsetDateTime::UNIX_EPOCH;
        let s = time::Duration::seconds(1);
        assert!(freshness(t, t + s, t, t + 2 * s).is_ok());
        assert!(freshness(t + s, t, t, t + 2 * s).is_err());
        assert!(freshness(t, t + s, t + 2 * s, t + 3 * s).is_err());
        assert!(freshness(t, t + s, t, t + s).is_err());
    }
}
