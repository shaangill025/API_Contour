//! SQL30 gateway data snapshot reader. This does not authenticate a peer or grant authority.
use crate::{
    AuthorityError, ConnectedDatabase,
    transaction::{
        CancellationGuard, begin, check_deadline, clock, configure_tenant, empty_context,
        time_from_micros,
    },
};
use contour_core::GatewayEnrollment;
use std::fmt;
use time::OffsetDateTime;
use tokio::time::{Instant, timeout_at};

const ROLE: &str = "contour_causal_gateway_reader";
const ROLE_QUERY: &str = "SELECT current_user=session_user, COALESCE(session_user=(SELECT a.usename FROM pg_catalog.pg_stat_activity a WHERE a.pid=pg_catalog.pg_backend_pid()),false), EXISTS (SELECT 1 FROM pg_catalog.pg_roles u WHERE u.rolname=current_user AND NOT u.rolsuper AND NOT u.rolbypassrls), EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=$1), EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=$1 AND pg_catalog.pg_has_role(current_user,r.oid,'USAGE')), NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname<>current_user AND r.rolname<>$1 AND pg_catalog.pg_has_role(current_user,r.oid,'MEMBER'))";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CausalGatewayReadError {
    Identity,
    Unavailable,
    Corrupt,
    Expired,
    Database,
    Deadline,
    OutcomeUnknown,
}
impl fmt::Display for CausalGatewayReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CausalGatewayReadError {}
impl From<AuthorityError> for CausalGatewayReadError {
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
pub struct CausalGatewaySelector {
    tenant: String,
    gateway: String,
    generation: String,
    leaf: [u8; 32],
}
impl CausalGatewaySelector {
    pub fn new(
        tenant: &str,
        gateway: &str,
        generation: &str,
        leaf: [u8; 32],
    ) -> Result<Self, CausalGatewayReadError> {
        if !uuid(tenant)
            || !uuid(gateway)
            || !hex(generation, 32)
            || generation.bytes().all(|b| b == b'0')
        {
            return Err(CausalGatewayReadError::Identity);
        }
        Ok(Self {
            tenant: tenant.into(),
            gateway: gateway.into(),
            generation: generation.into(),
            leaf,
        })
    }
}
/// An immutable stale-able observation, not a session, permit, or launch proof.
pub struct CausalGatewayObservation {
    metadata: GatewayEnrollment,
    verified_until: Instant,
}
impl CausalGatewayObservation {
    pub fn metadata(&self) -> &GatewayEnrollment {
        &self.metadata
    }
    pub fn verified_until(&self) -> Instant {
        self.verified_until
    }
}
impl fmt::Debug for CausalGatewayObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalGatewayObservation")
    }
}
pub struct CausalGatewayReader {
    connection: ConnectedDatabase,
}
impl CausalGatewayReader {
    pub fn new(connection: ConnectedDatabase) -> Self {
        Self { connection }
    }
    pub async fn read_until(
        &mut self,
        selector: &CausalGatewaySelector,
        deadline: Instant,
    ) -> Result<CausalGatewayObservation, CausalGatewayReadError> {
        let deadline = deadline.min(Instant::now() + self.connection.deadline);
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(&mut self.connection);
        let mut committing = false;
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CausalGatewayReadError::Database)?;
            empty_context(client).await?;
            let row = client
                .query_one(ROLE_QUERY, &[&ROLE])
                .await
                .map_err(|_| CausalGatewayReadError::Database)?;
            let mut facts = [false; 6];
            for (i, v) in facts.iter_mut().enumerate() {
                *v = row
                    .try_get(i)
                    .map_err(|_| CausalGatewayReadError::Database)?;
            }
            if !role_allowed(facts) {
                return Err(CausalGatewayReadError::Identity);
            }
            let tx = begin(client).await?;
            let checked=async {
    configure_tenant(&tx,&selector.tenant,deadline.saturating_duration_since(Instant::now())).await?;
    let initial=clock(&tx).await?; check_deadline(deadline)?;
    let row=tx.query_one("SELECT CASE WHEN octet_length(metadata) BETWEEN 1 AND 4096 THEN metadata END, CASE WHEN octet_length(metadata_sha256)=32 THEN metadata_sha256 END, floor(extract(epoch FROM issued_at)*1000000)::bigint, floor(extract(epoch FROM expires_at)*1000000)::bigint FROM contour.current_causal_gateway($1::text::uuid,$2::text::uuid,$3::text,$4::bytea)",&[&selector.tenant,&selector.gateway,&selector.generation,&&selector.leaf[..]]).await.map_err(|_|CausalGatewayReadError::Unavailable)?;
    let body:Vec<u8>=row.try_get(0).map_err(|_|CausalGatewayReadError::Corrupt)?;
    let digest:Vec<u8>=row.try_get(1).map_err(|_|CausalGatewayReadError::Corrupt)?;
    let issued=time_from_micros(row.try_get(2).map_err(|_|CausalGatewayReadError::Corrupt)?)?;
    let expires=time_from_micros(row.try_get(3).map_err(|_|CausalGatewayReadError::Corrupt)?)?;
    let metadata=validate_row(selector,&body,&digest,issued,expires)?;
    tx.query_one("SELECT set_config('synchronous_commit','on',true)",&[]).await.map_err(|_|CausalGatewayReadError::Database)?;
    let start=Instant::now();let final_now=clock(&tx).await?;
    let remaining=freshness(initial,final_now,metadata.issued_at(),expires)?;
    let verified_until=start.checked_add(remaining).ok_or(CausalGatewayReadError::Expired)?.min(deadline);
    if Instant::now()>=verified_until {return Err(CausalGatewayReadError::Expired);}
    Ok::<_,CausalGatewayReadError>(CausalGatewayObservation{metadata,verified_until})
   }.await;
            match checked {
                Ok(observation) => {
                    committing = true;
                    tx.commit()
                        .await
                        .map_err(|_| CausalGatewayReadError::OutcomeUnknown)?;
                    empty_context(client)
                        .await
                        .map_err(|_| CausalGatewayReadError::OutcomeUnknown)?;
                    check_deadline(deadline).map_err(|_| CausalGatewayReadError::OutcomeUnknown)?;
                    if Instant::now() >= observation.verified_until {
                        return Err(CausalGatewayReadError::OutcomeUnknown);
                    }
                    guard.confirm();
                    Ok(observation)
                }
                Err(error) => {
                    tx.rollback()
                        .await
                        .map_err(|_| CausalGatewayReadError::Database)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Err(error)
                }
            }
        };
        match timeout_at(deadline, work).await {
            Ok(result) => result,
            Err(_) if committing => Err(CausalGatewayReadError::OutcomeUnknown),
            Err(_) => Err(CausalGatewayReadError::Deadline),
        }
    }
}
fn validate_row(
    selector: &CausalGatewaySelector,
    body: &[u8],
    digest: &[u8],
    issued: OffsetDateTime,
    expires: OffsetDateTime,
) -> Result<GatewayEnrollment, CausalGatewayReadError> {
    let data = GatewayEnrollment::decode(body).map_err(|_| CausalGatewayReadError::Corrupt)?;
    let leaf = selector
        .leaf
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if data.metadata_sha256().as_slice() != digest
        || data.tenant_id() != selector.tenant
        || data.gateway_id() != selector.gateway
        || data.generation() != selector.generation
        || data.backend_client_leaf() != leaf
        || data.issued_at() != issued
        || data.expires_at() != expires
    {
        return Err(CausalGatewayReadError::Corrupt);
    }
    Ok(data)
}
fn role_allowed(facts: [bool; 6]) -> bool {
    facts.into_iter().all(|fact| fact)
}
fn freshness(
    initial: OffsetDateTime,
    final_now: OffsetDateTime,
    issued: OffsetDateTime,
    expires: OffsetDateTime,
) -> Result<std::time::Duration, CausalGatewayReadError> {
    if final_now < initial || issued > final_now || final_now >= expires {
        return Err(CausalGatewayReadError::Expired);
    }
    (expires - final_now)
        .try_into()
        .map_err(|_| CausalGatewayReadError::Expired)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selector_and_role_checks_are_closed() {
        let id = "00000000-0000-4000-8000-000000000001";
        let generation = "123456789abcdef0123456789abcdef0";
        assert!(CausalGatewaySelector::new(id, id, generation, [0x33; 32]).is_ok());
        assert!(CausalGatewaySelector::new(id, id, &"0".repeat(32), [0x33; 32]).is_err());
        assert!(CausalGatewaySelector::new("invalid", id, generation, [0x33; 32]).is_err());
        assert!(role_allowed([true; 6]));
        for i in 0..6 {
            let mut x = [true; 6];
            x[i] = false;
            assert!(!role_allowed(x));
        }
    }
    #[test]
    fn vector_requires_exact_scope_digest_and_times() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/specification/fixtures/gateway-enrollment-v1.json"
        ))
        .unwrap();
        let body = v["canonical_utf8"].as_str().unwrap().as_bytes();
        let data = GatewayEnrollment::decode(body).unwrap();
        let id = data.tenant_id();
        let mut s = CausalGatewaySelector::new(id, id, data.generation(), [0x33; 32]).unwrap();
        let hash = data.metadata_sha256();
        let issued = data.issued_at();
        let expires = data.expires_at();
        assert!(validate_row(&s, body, &hash, issued, expires).is_ok());
        s.leaf = [0x34; 32];
        assert!(validate_row(&s, body, &hash, issued, expires).is_err());
        s.leaf = [0x33; 32];
        let mut wrong = hash;
        wrong[0] ^= 1;
        assert!(validate_row(&s, body, &wrong, issued, expires).is_err());
        assert!(
            validate_row(
                &s,
                body,
                &hash,
                issued,
                expires + time::Duration::microseconds(1)
            )
            .is_err()
        );
        assert!(freshness(issued, issued, issued, expires).is_ok());
        assert!(freshness(issued, expires, issued, expires).is_err());
    }
}
