//! Human access to already committed historical causal connections.
use crate::{
    ConnectedDatabase, DeclaredScope,
    declared_store::uuid,
    human_observations::HumanObservationError as Error,
    transaction::{
        CancellationGuard, begin, check_deadline, configure_tenant, database_error, empty_context,
    },
};
use contour_auth::VerifiedIdentity;
use serde_json::Value;
use tokio::time::{Instant, timeout_at};

/// Selection only; authorization and validation remain inside the reader.
pub struct HumanCausalConnectionQuery<'a> {
    pub operation: &'a str,
    pub observation: &'a str,
    pub limit: u16,
    pub cursor: Option<&'a str>,
}

pub struct HumanCausalConnectionPage {
    pub items: Vec<Value>,
    pub next_cursor: Option<String>,
}

fn id128(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn cursor_parts(cursor: &str) -> Option<(&str, &str, &str)> {
    let mut parts = cursor.split('.');
    let gateway = parts.next()?;
    let generation = parts.next()?;
    let handle = parts.next()?;
    if parts.next().is_some() || !uuid(gateway) || !id128(generation) || !id128(handle) {
        return None;
    }
    Some((gateway, generation, handle))
}

const MAX_WIRE_BYTES: usize = 65_536;
const ENDPOINT_KEYS: [&str; 8] = [
    "project_id",
    "service_id",
    "environment_id",
    "deployment_id",
    "instance_id",
    "batch_id",
    "event_id",
    "receipt_id",
];

fn utc_time(value: &str) -> Option<time::PrimitiveDateTime> {
    let b = value.as_bytes();
    if b.len() != 27
        || !b.is_ascii()
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[26] != b'Z'
    {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let mut n = 0u32;
        for &c in &b[range] {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + u32::from(c - b'0');
        }
        Some(n)
    };
    let year = i32::try_from(digits(0..4)?).ok()?;
    if year == 0 {
        return None;
    }
    let month = time::Month::try_from(u8::try_from(digits(5..7)?).ok()?).ok()?;
    let day = u8::try_from(digits(8..10)?).ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let clock = time::Time::from_hms_micro(
        u8::try_from(digits(11..13)?).ok()?,
        u8::try_from(digits(14..16)?).ok()?,
        u8::try_from(digits(17..19)?).ok()?,
        digits(20..26)?,
    )
    .ok()?;
    Some(time::PrimitiveDateTime::new(date, clock))
}

fn decode_page(wire: &str, limit: u16) -> Result<HumanCausalConnectionPage, Error> {
    if wire.len() > MAX_WIRE_BYTES {
        return Err(Error::Corrupt);
    }
    let mut data: Value = serde_json::from_str(wire).map_err(|_| Error::Corrupt)?;
    let object = data.as_object_mut().ok_or(Error::Corrupt)?;
    if object.len() != 2 {
        return Err(Error::Corrupt);
    }
    let cursor = match object.remove("next_cursor") {
        Some(Value::Null) => None,
        Some(Value::String(value)) if cursor_parts(&value).is_some() => Some(value),
        _ => return Err(Error::Corrupt),
    };
    let items = match object.remove("items") {
        Some(Value::Array(items)) => items,
        _ => return Err(Error::Corrupt),
    };
    if items.len() > usize::from(limit) || (cursor.is_some() && items.is_empty()) {
        return Err(Error::Corrupt);
    }
    for item in &items {
        let fields = item.as_object().ok_or(Error::Corrupt)?;
        if fields.len() != 4 {
            return Err(Error::Corrupt);
        }
        let resolved = fields
            .get("resolved_at")
            .and_then(Value::as_str)
            .and_then(utc_time)
            .ok_or(Error::Corrupt)?;
        let expires = fields
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(utc_time)
            .ok_or(Error::Corrupt)?;
        if expires - resolved != time::Duration::days(30) {
            return Err(Error::Corrupt);
        }
        for name in ["producer", "receiver"] {
            let endpoint = fields
                .get(name)
                .and_then(Value::as_object)
                .ok_or(Error::Corrupt)?;
            if endpoint.len() != ENDPOINT_KEYS.len()
                || ENDPOINT_KEYS.iter().any(|key| {
                    !endpoint
                        .get(*key)
                        .and_then(Value::as_str)
                        .is_some_and(|value| {
                            if *key == "event_id" {
                                id128(value)
                            } else {
                                uuid(value)
                            }
                        })
                })
            {
                return Err(Error::Corrupt);
            }
        }
    }
    Ok(HumanCausalConnectionPage {
        items,
        next_cursor: cursor,
    })
}

impl ConnectedDatabase {
    pub async fn list_observation_connections_as_human_until(
        &mut self,
        identity: &VerifiedIdentity,
        scope: &DeclaredScope,
        query: HumanCausalConnectionQuery<'_>,
        deadline: Instant,
    ) -> Result<HumanCausalConnectionPage, Error> {
        let HumanCausalConnectionQuery {
            operation,
            observation,
            limit,
            cursor,
        } = query;
        if !uuid(operation)
            || !uuid(observation)
            || cursor.is_some_and(|v| cursor_parts(v).is_none())
        {
            return Err(Error::Scope);
        }
        if !(1..=50).contains(&limit) {
            return Err(Error::Limit);
        }
        if self.client.is_none() {
            return Err(Error::Invalidated);
        }
        let deadline = deadline.min(Instant::now() + self.deadline);
        check_deadline(deadline)?;
        let mut guard = CancellationGuard::arm(self);
        let work = async {
            let client = guard.connection.client.as_mut().ok_or(Error::Invalidated)?;
            let tx = begin(client).await?;
            let result = async {
                let ids = &scope.ids;
                configure_tenant(&tx, &ids[0], deadline.saturating_duration_since(Instant::now())).await?;
                crate::human_authorization::check_expiry(&tx, identity).await?;
                let (gateway, generation, handle) = cursor.and_then(cursor_parts).map_or((None,None,None), |(a,b,c)| (Some(a),Some(b),Some(c)));
                let row = tx.query_one(
                    "SELECT contour.human_causal_connections($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7,$8,$9::text::uuid,$10,$11,$12)::text",
                    &[&ids[0],&ids[1],&ids[2],&ids[3],&operation,&observation,&identity.issuer(),&identity.subject(),&gateway,&generation,&handle,&i32::from(limit)]
                ).await.map_err(|e| match e.code().map(|c| c.code()) { Some("42501") => Error::Forbidden, _ => Error::from(database_error(e)) })?;
                let wire: &str = row.try_get(0).map_err(|_| Error::Corrupt)?;
                let page = decode_page(wire, limit)?;
                crate::human_authorization::check_expiry(&tx, identity).await?;
                check_deadline(deadline)?;
                Ok(page)
            }.await;
            tx.rollback().await.map_err(database_error)?;
            empty_context(client).await?;
            check_deadline(deadline)?;
            if !matches!(result, Err(Error::Deadline)) {
                guard.confirm();
            }
            result
        };
        timeout_at(deadline, work)
            .await
            .map_err(|_| Error::Deadline)?
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_WIRE_BYTES, cursor_parts, decode_page};
    use serde_json::json;
    #[test]
    fn page_rejects_unchecked_fields_and_bad_values() {
        let id = "00000000-0000-4000-8000-000000000000";
        let endpoint = json!({"project_id":id,"service_id":id,"environment_id":id,"deployment_id":id,"instance_id":id,"batch_id":id,"event_id":"31".repeat(16),"receipt_id":id});
        let item = json!({"resolved_at":"2026-01-01T00:00:00.000000Z","expires_at":"2026-01-31T00:00:00.000000Z","producer":endpoint,"receiver":endpoint});
        let page = json!({"items":[item],"next_cursor":null});
        assert!(decode_page(&page.to_string(), 1).is_ok());
        let mut changed = page.clone();
        changed["items"][0]["producer"]["credential_id"] = json!(id);
        assert!(decode_page(&changed.to_string(), 1).is_err());
        let mut changed = page.clone();
        changed["items"][0]["receiver"]["event_id"] = json!("not-a-uuid");
        assert!(decode_page(&changed.to_string(), 1).is_err());
        for invalid in [
            json!(id),
            json!("AB".repeat(16)),
            json!("a".repeat(31)),
            json!(123),
        ] {
            let mut changed = page.clone();
            changed["items"][0]["receiver"]["event_id"] = invalid;
            assert!(decode_page(&changed.to_string(), 1).is_err());
        }
        let mut changed = page.clone();
        changed["items"][0]["expires_at"] = json!("2026-01-32T00:00:00.000000Z");
        assert!(decode_page(&changed.to_string(), 1).is_err());
        let mut changed = page.clone();
        changed["items"][0]["resolved_at"] = json!("2026-01-02T00:00:00.000000Z");
        assert!(decode_page(&changed.to_string(), 1).is_err());
        let mut changed = page.clone();
        changed["next_cursor"] = json!("broken");
        assert!(decode_page(&changed.to_string(), 1).is_err());
        assert!(decode_page(&" ".repeat(MAX_WIRE_BYTES + 1), 1).is_err());
        assert!(decode_page(&page.to_string(), 0).is_err());
    }
    #[test]
    fn cursor_requires_a_complete_canonical_key() {
        let valid = "00000000-0000-4000-8000-000000000000.0123456789abcdef0123456789abcdef.0123456789abcdef0123456789abcdef";
        assert!(cursor_parts(valid).is_some());
        for bad in [
            "",
            "00000000-0000-4000-8000-000000000000",
            &valid.to_uppercase(),
            &format!("{valid}.x"),
            &valid[..valid.len() - 1],
        ] {
            assert!(cursor_parts(bad).is_none());
        }
    }
}
