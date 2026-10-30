//! Checked reply data only; this does not authenticate transport or establish online authority.
use crate::{PolicyKeys, SourceAssignment, Timestamp, UnsignedInteger, VerifiedPolicy};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::{collections::BTreeSet, fmt, time::Duration};
use time::OffsetDateTime;

/// Maximum encoded reply size, matching the native bounded exchange.
pub const MAX_AUTHORITY_REPLY_BYTES: usize = 8 * 1024 * 1024;
/// Safe rejection categories, mapped by the native adapter to its existing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityReplyError {
    Size,
    Invalid,
    Deadline,
}
/// Checked data, not proof of authenticated transport, enrollment, revocation or online authority.
pub struct CheckedAuthorityReply {
    pub policy: VerifiedPolicy,
    pub sources: Vec<SourceAssignment>,
    pub envelope_bytes: usize,
    pub lease: Duration,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    wire_version: UnsignedInteger,
    challenge: String,
    tenant_id: String,
    collector_id: String,
    checked_at: Timestamp,
    signed_policy: Box<RawValue>,
    #[serde(deserialize_with = "source_list")]
    sources: Vec<Source>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    source_id: String,
    project_id: String,
    service_id: String,
    environment_id: String,
    deployment_id: String,
    technique: String,
    #[serde(deserialize_with = "profile_list")]
    parser_profiles: Vec<Profile>,
}
struct Profile(String);
impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Text;
        impl serde::de::Visitor<'_> for Text {
            type Value = Profile;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("profile of at most 64 bytes")
            }
            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Profile, E> {
                if text.len() > 64 {
                    return Err(E::custom("profile bound"));
                }
                Ok(Profile(text.to_owned()))
            }
        }
        d.deserialize_str(Text)
    }
}
fn bounded_list<'de, D, T, const N: usize>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct List<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for List<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded list")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut values = Vec::new();
            while values.len() < N {
                match seq.next_element()? {
                    Some(value) => values.push(value),
                    None => return Ok(values),
                }
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("list bound"));
            }
            Ok(values)
        }
    }
    d.deserialize_seq(List::<T, N>(std::marker::PhantomData))
}
fn source_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Source>, D::Error> {
    bounded_list::<D, Source, 500>(d)
}
fn profile_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Profile>, D::Error> {
    bounded_list::<D, Profile, 128>(d)
}

/// Validate a bounded reply against explicit expectations and trusted policy keys/time.
pub fn check_authority_reply(
    bytes: &[u8],
    challenge: &str,
    tenant: &str,
    collector: &str,
    source_ids: &[String],
    keys: &PolicyKeys,
    now: OffsetDateTime,
) -> Result<CheckedAuthorityReply, AuthorityReplyError> {
    use AuthorityReplyError::{Deadline, Invalid, Size};
    if bytes.len() > MAX_AUTHORITY_REPLY_BYTES {
        return Err(Size);
    }
    let reply: Reply = serde_json::from_slice(bytes).map_err(|_| Invalid)?;
    if reply.wire_version.get() != 1
        || reply.challenge != challenge
        || reply.tenant_id != tenant
        || reply.collector_id != collector
        || reply.sources.len() != source_ids.len()
    {
        return Err(Invalid);
    }
    let actual = reply
        .sources
        .iter()
        .map(|s| s.source_id.as_str())
        .collect::<BTreeSet<_>>();
    if actual.len() != source_ids.len() || actual != source_ids.iter().map(String::as_str).collect()
    {
        return Err(Invalid);
    }
    let raw = reply.signed_policy.get().as_bytes();
    let policy =
        VerifiedPolicy::from_signed_json(raw, keys, tenant, collector, now).map_err(|_| Invalid)?;
    policy
        .validate_capture_at(reply.checked_at.instant())
        .map_err(|_| Invalid)?;
    let lease = Duration::try_from(policy.expires_at() - reply.checked_at.instant())
        .map_err(|_| Deadline)?
        .min(Duration::from_secs(900));
    let sources = reply
        .sources
        .iter()
        .map(|s| {
            SourceAssignment::new(
                &s.source_id,
                [
                    tenant,
                    collector,
                    &s.project_id,
                    &s.service_id,
                    &s.environment_id,
                    &s.deployment_id,
                ],
                &s.technique,
                &s.parser_profiles
                    .iter()
                    .map(|p| p.0.as_str())
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CheckedAuthorityReply {
        policy,
        sources,
        envelope_bytes: raw.len(),
        lease,
    })
}
