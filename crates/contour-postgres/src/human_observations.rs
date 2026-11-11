//! Human-authorized immutable observation history, separate from the operator reader.
use crate::{
    AuthorityError, ConnectedDatabase, DeclaredScope,
    catalog_reader::{self, CatalogReadError, CatalogReadScope},
    declared_store::uuid,
    transaction::{
        CancellationGuard, begin, check_deadline, configure_tenant, database_error, empty_context,
    },
};
use contour_auth::VerifiedIdentity;
use serde_json::{Value, json};
use std::fmt;
use tokio::time::{Instant, timeout_at};

const MAX_PAGE_BYTES: usize = 1_048_576;
const METADATA: &str = "SELECT w.variant_id::text,w.source_id::text,w.batch_id::text,w.record_id::text,w.collector_id::text,(octet_length(v.canonical_structure) BETWEEN 1 AND 65536 AND octet_length(v.structure_wire) BETWEEN 1 AND 65536 AND octet_length(v.structure_hash)=32 AND v.canonicalization_version=1 AND octet_length(v.parser_profile) BETWEEN 1 AND 64 AND octet_length(v.policy_revision::text) BETWEEN 1 AND 20 AND octet_length(w.observation_count::text) BETWEEN 1 AND 10 AND octet_length(w.sample_numerator::text) BETWEEN 1 AND 7 AND octet_length(w.sample_denominator::text) BETWEEN 1 AND 7 AND octet_length(w.visibility) BETWEEN 1 AND 16 AND octet_length(w.completeness) BETWEEN 1 AND 16 AND cardinality(w.reasons)<=8 AND octet_length(w.reasons::text)<=128 AND octet_length(w.first_seen) BETWEEN 20 AND 35 AND octet_length(w.last_seen) BETWEEN 20 AND 35 AND octet_length(w.queued_at) BETWEEN 20 AND 35 AND octet_length(w.expires_at) BETWEEN 20 AND 35 AND octet_length(w.request_header_names) BETWEEN 2 AND 49537 AND octet_length(w.response_header_names) BETWEEN 2 AND 49537 AND octet_length(w.query_parameter_names) BETWEEN 2 AND 49537) FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id) WHERE w.tenant_id=$1::text::uuid AND w.project_id=$2::text::uuid AND w.service_id=$3::text::uuid AND w.environment_id=$4::text::uuid AND w.operation_id=$5::text::uuid AND w.observation_id=$6::text::uuid";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HumanObservationError {
    Scope,
    Limit,
    Forbidden,
    NotFound,
    Corrupt,
    Database,
    Deadline,
    Invalidated,
}
impl fmt::Display for HumanObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for HumanObservationError {}
impl From<AuthorityError> for HumanObservationError {
    fn from(e: AuthorityError) -> Self {
        match e {
            AuthorityError::Deadline => Self::Deadline,
            AuthorityError::Invalidated => Self::Invalidated,
            _ => Self::Database,
        }
    }
}
impl From<crate::human_authorization::HumanAuthorizationError> for HumanObservationError {
    fn from(e: crate::human_authorization::HumanAuthorizationError) -> Self {
        use crate::human_authorization::HumanAuthorizationError as H;
        match e {
            H::Forbidden => Self::Forbidden,
            H::Corrupt => Self::Corrupt,
            H::Database => Self::Database,
            H::Deadline => Self::Deadline,
            H::Invalidated => Self::Invalidated,
        }
    }
}
impl From<CatalogReadError> for HumanObservationError {
    fn from(e: CatalogReadError) -> Self {
        match e {
            CatalogReadError::Scope | CatalogReadError::Cursor => Self::Scope,
            CatalogReadError::Limit => Self::Limit,
            CatalogReadError::NotFound => Self::NotFound,
            CatalogReadError::Corrupt => Self::Corrupt,
            CatalogReadError::Database => Self::Database,
            CatalogReadError::Deadline => Self::Deadline,
            CatalogReadError::Invalidated => Self::Invalidated,
        }
    }
}

pub struct HumanObservationPage {
    pub items: Vec<Value>,
    pub next_cursor: Option<String>,
}
#[derive(Clone, Copy)]
enum Selection<'a> {
    Page(u16, Option<&'a str>),
    Detail(&'a str),
}
impl ConnectedDatabase {
    pub async fn list_observations_as_human_until(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        operation: &str,
        limit: u16,
        cursor: Option<&str>,
        deadline: Instant,
    ) -> Result<HumanObservationPage, HumanObservationError> {
        if !uuid(operation) || cursor.is_some_and(|v| !uuid(v)) {
            return Err(HumanObservationError::Scope);
        }
        if !(1..=50).contains(&limit) {
            return Err(HumanObservationError::Limit);
        }
        self.human_observations_transaction(
            identity,
            scope,
            operation,
            Selection::Page(limit, cursor),
            deadline,
        )
        .await
    }
    pub async fn read_observation_as_human_until(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        operation: &str,
        id: &str,
        deadline: Instant,
    ) -> Result<Value, HumanObservationError> {
        if !uuid(operation) || !uuid(id) {
            return Err(HumanObservationError::Scope);
        }
        self.human_observations_transaction(
            identity,
            scope,
            operation,
            Selection::Detail(id),
            deadline,
        )
        .await?
        .items
        .into_iter()
        .next()
        .ok_or(HumanObservationError::NotFound)
    }
    async fn human_observations_transaction(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        operation: &str,
        selection: Selection<'_>,
        deadline: Instant,
    ) -> Result<HumanObservationPage, HumanObservationError> {
        if self.client.is_none() {
            return Err(HumanObservationError::Invalidated);
        }
        let deadline = deadline.min(Instant::now() + self.deadline);
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(self);
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(HumanObservationError::Invalidated)?;
            let tx = begin(client).await?;
            let result=async {
                let ids=&scope.ids;
                configure_tenant(&tx,&ids[0],deadline.saturating_duration_since(Instant::now())).await?;
                crate::human_authorization::authorize(&tx,identity,[&ids[0],&ids[1],&ids[2]],false).await?;
                let operator_scope=CatalogReadScope::new([&ids[0],&ids[1],&ids[2],operation])?;
                let parts=catalog_reader::operation(&tx,&operator_scope).await?;
                if parts[3]!=ids[3] {return Err(HumanObservationError::NotFound)}
                if let Selection::Page(_,Some(cursor))=selection {
                    let row=tx.query_opt("SELECT 1 FROM contour.observation_windows WHERE tenant_id=$1::text::uuid AND project_id=$2::text::uuid AND service_id=$3::text::uuid AND environment_id=$4::text::uuid AND operation_id=$5::text::uuid AND observation_id=$6::text::uuid",&[&ids[0],&ids[1],&ids[2],&ids[3],&operation,&cursor]).await.map_err(database_error)?;
                    if row.is_none() {return Err(HumanObservationError::Scope)}
                }
                let (rows,limit)=match selection {
                    Selection::Detail(id)=>(vec![id.to_owned()],1usize),
                    Selection::Page(limit,cursor)=>{
                        let rows=tx.query("SELECT observation_id::text FROM contour.observation_windows WHERE tenant_id=$1::text::uuid AND project_id=$2::text::uuid AND service_id=$3::text::uuid AND environment_id=$4::text::uuid AND operation_id=$5::text::uuid AND ($6::text IS NULL OR observation_id>$6::text::uuid) ORDER BY observation_id LIMIT $7",&[&ids[0],&ids[1],&ids[2],&ids[3],&operation,&cursor,&(i64::from(limit)+1)]).await.map_err(database_error)?;
                        (rows.iter().map(|r|r.try_get::<_,String>(0).map_err(|_|HumanObservationError::Corrupt)).collect::<Result<Vec<_>,_>>()?,usize::from(limit))
                    }
                };
                let statement=tx.prepare(catalog_reader::EVIDENCE_SQL).await.map_err(database_error)?;
                let mut items=Vec::new();let mut bytes=0usize;let mut more=rows.len()>limit;
                for id in rows.into_iter().take(limit) {
                    check_deadline(deadline)?;
                    let metadata=tx.query_opt(METADATA,&[&ids[0],&ids[1],&ids[2],&ids[3],&operation,&id]).await.map_err(database_error)?.ok_or(HumanObservationError::NotFound)?;
                    if !metadata.try_get::<_,bool>(5).map_err(|_|HumanObservationError::Corrupt)? {return Err(HumanObservationError::Corrupt)}
                    let evidence=catalog_reader::evidence(&tx,&statement,&operator_scope,&parts,&metadata).await?;
                    let item=project_evidence(&evidence,&parts,&id,operation)?;let len=serde_json::to_vec(&item).map_err(|_|HumanObservationError::Corrupt)?.len()+1;
                    if bytes+len+512>MAX_PAGE_BYTES {if items.is_empty(){return Err(HumanObservationError::Limit)} more=true;break}
                    bytes+=len;items.push(item);
                }
                let next_cursor=if more {Some(items.last().and_then(|v|v.get("id")).and_then(Value::as_str).ok_or(HumanObservationError::Corrupt)?.to_owned())} else {None};
                crate::human_authorization::check_expiry(&tx,identity).await?;check_deadline(deadline)?;
                Ok(HumanObservationPage{items,next_cursor})
            }.await;
            tx.rollback().await.map_err(database_error)?;
            empty_context(client).await?;
            check_deadline(deadline)?;
            if !matches!(result, Err(HumanObservationError::Deadline)) {
                guard.confirm()
            };
            result
        };
        timeout_at(deadline, work)
            .await
            .map_err(|_| HumanObservationError::Deadline)?
    }
}

fn project_evidence(
    evidence: &Value,
    parts: &[String; 8],
    id: &str,
    operation: &str,
) -> Result<Value, HumanObservationError> {
    let record = evidence
        .get("record")
        .and_then(Value::as_object)
        .ok_or(HumanObservationError::Corrupt)?;
    let mut out = serde_json::Map::new();
    for key in [
        "structure",
        "visibility",
        "completeness",
        "reasons",
        "route_uncertain",
        "first_seen",
        "last_seen",
        "queued_at",
        "expires_at",
        "sample_numerator",
        "sample_denominator",
        "count",
        "parser_profile",
        "status_code",
    ] {
        out.insert(
            key.to_owned(),
            record
                .get(key)
                .ok_or(HumanObservationError::Corrupt)?
                .clone(),
        );
    }
    let fingerprint = evidence
        .get("structure_fingerprint")
        .and_then(Value::as_str)
        .ok_or(HumanObservationError::Corrupt)?;
    out.insert("structure_fingerprint".into(), json!(fingerprint));
    let revision = record
        .get("policy_revision")
        .and_then(Value::as_u64)
        .ok_or(HumanObservationError::Corrupt)?;
    out.insert("policy_revision".into(), json!(revision.to_string()));
    for (key, value) in [
        ("protocol", &parts[4]),
        ("direction", &parts[5]),
        ("operation", &parts[6]),
        ("route_template", &parts[7]),
    ] {
        out.insert(key.into(), json!(value));
    }
    out.insert("id".into(), json!(id));
    out.insert("operation_id".into(), json!(operation));
    out.insert("canonicalization_version".into(), json!(1));
    out.insert("origin_evidence".into(), json!("unavailable"));
    Ok(Value::Object(out))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_keeps_exact_evidence_and_never_emits_unchecked_fields() {
        let record = json!({"structure":{"kind":"string"},"visibility":"structure","completeness":"partial","reasons":["limit"],"route_uncertain":true,"status_code":null,"first_seen":"first","last_seen":"last","queued_at":"queued","expires_at":"expires","sample_numerator":1,"sample_denominator":3,"count":4,"parser_profile":"fixed","policy_revision":u64::MAX,"request_header_names":["private"],"origin":"forged"});
        let parts = std::array::from_fn(|i| format!("part-{i}"));
        let value = project_evidence(
            &json!({"record":record,"structure_fingerprint":"checked-fingerprint","collector_id":"private"}),
            &parts,
            "observation",
            "operation",
        )
        .unwrap();
        assert_eq!(value["origin_evidence"], "unavailable");
        assert_eq!(value["policy_revision"], u64::MAX.to_string());
        assert_eq!(value["sample_denominator"], 3);
        assert_eq!(value["direction"], "part-5");
        assert_eq!(value["status_code"], Value::Null);
        assert_eq!(value["structure_fingerprint"], "checked-fingerprint");
        let mut response = record.clone();
        response["status_code"] = json!(201);
        assert_eq!(
            project_evidence(
                &json!({"record":response,"structure_fingerprint":"checked-fingerprint"}),
                &parts,
                "x",
                "y"
            )
            .unwrap()["status_code"],
            201
        );
        assert!(project_evidence(&json!({"record":record}), &parts, "x", "y").is_err());
        assert!(value.get("collector_id").is_none());
        assert!(value.get("request_header_names").is_none());
        assert!(value.get("origin").is_none());
        assert!(project_evidence(&json!({"record":{}}), &parts, "x", "y").is_err());
    }
}
