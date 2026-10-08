//! Wire representation for an already enrolled collector's current snapshot.
use contour_core::UnsignedInteger;
use contour_postgres::{AuthorityRead, AuthorityReadRequest};
use serde::{
    Deserialize, Serialize,
    de::{self, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use std::io::{self, Write};
use time::format_description::well_known::Rfc3339;

pub(crate) const REQUEST_LIMIT: usize = 32_768;
const RESPONSE_LIMIT: usize = 8 * 1_048_576;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    wire_version: UnsignedInteger,
    challenge: String,
    #[serde(deserialize_with = "source_ids")]
    source_ids: Vec<String>,
}

fn source_ids<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Vec<String>, D::Error> {
    struct SourceIds;
    impl<'de> Visitor<'de> for SourceIds {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded source identifier list")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element::<String>()? {
                if values.len() == 500 || value.len() != 36 {
                    return Err(de::Error::custom("source identifier bound"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    decoder.deserialize_seq(SourceIds)
}

pub(crate) fn decode(
    bytes: &[u8],
    identity: [&str; 2],
) -> Result<(String, AuthorityReadRequest), ()> {
    if bytes.len() > REQUEST_LIMIT {
        return Err(());
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| ())?;
    if request.wire_version.get() != 1
        || request.challenge.len() != 64
        || !request
            .challenge
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let checked = AuthorityReadRequest::new(
        identity,
        &request
            .source_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
    .map_err(|_| ())?;
    Ok((request.challenge, checked))
}

#[derive(Serialize)]
struct Source<'a> {
    source_id: &'a str,
    project_id: &'a str,
    service_id: &'a str,
    environment_id: &'a str,
    deployment_id: &'a str,
    technique: &'a str,
    parser_profiles: &'a [String],
}

#[derive(Serialize)]
struct Response<'a> {
    wire_version: u8,
    challenge: &'a str,
    tenant_id: &'a str,
    collector_id: &'a str,
    checked_at: String,
    signed_policy: &'a RawValue,
    sources: Vec<Source<'a>>,
}

pub(crate) fn encode(read: &AuthorityRead, challenge: &str) -> Result<Vec<u8>, ()> {
    let identity = read.identity();
    let response = Response {
        wire_version: 1,
        challenge,
        tenant_id: identity[0],
        collector_id: identity[1],
        checked_at: read.checked_at().format(&Rfc3339).map_err(|_| ())?,
        // Keep the signed payload, signature and envelope fields unchanged.
        signed_policy: serde_json::from_slice(read.signed_envelope()).map_err(|_| ())?,
        sources: read
            .sources()
            .iter()
            .map(|source| {
                let scope = source.identity();
                Source {
                    source_id: source.source_id(),
                    project_id: scope[2],
                    service_id: scope[3],
                    environment_id: scope[4],
                    deployment_id: scope[5],
                    technique: source.technique(),
                    parser_profiles: source.parser_profiles(),
                }
            })
            .collect(),
    };
    let mut output = BoundedOutput(Vec::new());
    serde_json::to_writer(&mut output, &response).map_err(|_| ())?;
    Ok(output.0)
}

struct BoundedOutput(Vec<u8>);
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let needed = self
            .0
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= RESPONSE_LIMIT)
            .ok_or_else(|| io::Error::other("authority response limit"))?;
        if needed > self.0.capacity() {
            let target = needed
                .max(self.0.capacity().max(4096).saturating_mul(2))
                .min(RESPONSE_LIMIT);
            self.0
                .try_reserve_exact(target - self.0.len())
                .map_err(|_| io::Error::other("authority response capacity"))?;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
