//! Private online grant. Parsing a response alone cannot construct live authority.
use crate::*;
use contour_core::{PolicyKeys, SourceAssignment, UnsignedInteger, VerifiedPolicy};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, value::RawValue};
use std::collections::BTreeSet;

pub(crate) const HISTORY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) struct LiveAuthority {
    pub(crate) sources: Vec<SourceAssignment>,
    pub(crate) deadline: Instant,
}
pub(crate) struct Refresh {
    pub(crate) live: LiveAuthority,
    pub(crate) policy: VerifiedPolicy,
    pub(crate) envelope_bytes: usize,
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
impl DeliveryClient {
    pub(crate) async fn refresh_authority(
        &mut self,
        source_ids: &[String],
        keys: &PolicyKeys,
    ) -> Result<Refresh, DeliveryError> {
        let started = Instant::now();
        let deadline = started + self.deadline;
        let mut entropy = [0; 32];
        SystemRandom::new()
            .fill(&mut entropy)
            .map_err(|_| DeliveryError::Configuration)?;
        let challenge = entropy
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let bytes = serde_json::to_vec(
            &json!({"wire_version":1,"challenge":challenge,"source_ids":source_ids}),
        )
        .map_err(|_| DeliveryError::Configuration)?;
        if bytes.len() > 32768 {
            return Err(DeliveryError::ResponseLimit);
        }
        let work = async {
            let socket = TcpStream::connect(self.address)
                .await
                .map_err(|_| DeliveryError::Transport)?;
            let stream = self
                .tls
                .connect(
                    ServerName::try_from(self.host.clone())
                        .map_err(|_| DeliveryError::Configuration)?,
                    socket,
                )
                .await
                .map_err(|_| DeliveryError::Transport)?;
            if stream.get_ref().1.alpn_protocol() != Some(b"http/1.1".as_slice()) {
                return Err(DeliveryError::Transport);
            }
            let mut builder = http1::Builder::new();
            builder
                .max_headers(32)
                .max_header_size(16384)
                .max_buf_size(16384);
            let (mut sender, connection) = builder
                .handshake(TokioIo::new(stream))
                .await
                .map_err(|_| DeliveryError::Transport)?;
            let host = if self.host.contains(':') {
                format!("[{}]:{}", self.host, self.address.port())
            } else {
                format!("{}:{}", self.host, self.address.port())
            };
            let request = Request::post("/v1/collector-authority")
                .header("Host", host)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Connection", "close")
                .body(Full::new(Bytes::from(bytes)))
                .map_err(|_| DeliveryError::Configuration)?;
            let mut driver = Driver {
                future: Box::pin(connection),
                done: false,
            };
            let response = driver
                .step(sender.send_request(request))
                .await?
                .map_err(|_| DeliveryError::Transport)?;
            if response.status().as_u16() != 200 {
                return Err(DeliveryError::Rejected {
                    status: response.status().as_u16(),
                    retry_after: retry_after(response.headers()),
                });
            }
            if response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                != Some("application/json")
                || response.headers().contains_key("content-encoding")
            {
                return Err(DeliveryError::Receipt);
            }
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = driver.step(body.frame()).await? {
                let data = frame
                    .map_err(|_| DeliveryError::Transport)?
                    .into_data()
                    .map_err(|_| DeliveryError::Receipt)?;
                if data.len() > HISTORY_BYTES - bytes.len() {
                    return Err(DeliveryError::ResponseLimit);
                }
                let needed = bytes.len() + data.len();
                if needed > bytes.capacity() {
                    let target = needed
                        .max(bytes.capacity().max(4096).saturating_mul(2))
                        .min(HISTORY_BYTES);
                    bytes
                        .try_reserve_exact(target - bytes.len())
                        .map_err(|_| DeliveryError::ResponseLimit)?;
                }
                bytes.extend_from_slice(&data);
            }
            let reply: Reply =
                serde_json::from_slice(&bytes).map_err(|_| DeliveryError::Receipt)?;
            if reply.wire_version.get() != 1
                || reply.challenge != challenge
                || reply.tenant_id != self.identity[0]
                || reply.collector_id != self.identity[1]
                || reply.sources.len() != source_ids.len()
            {
                return Err(DeliveryError::Receipt);
            }
            let actual = reply
                .sources
                .iter()
                .map(|s| s.source_id.as_str())
                .collect::<BTreeSet<_>>();
            if actual.len() != source_ids.len()
                || actual != source_ids.iter().map(String::as_str).collect()
            {
                return Err(DeliveryError::Receipt);
            }
            let raw = reply.signed_policy.get().as_bytes();
            let policy = VerifiedPolicy::from_signed_json(
                raw,
                keys,
                &self.identity[0],
                &self.identity[1],
                OffsetDateTime::now_utc(),
            )
            .map_err(|_| DeliveryError::Receipt)?;
            policy
                .validate_capture_at(reply.checked_at.instant())
                .map_err(|_| DeliveryError::Receipt)?;
            let lease = Duration::try_from(policy.expires_at() - reply.checked_at.instant())
                .map_err(|_| DeliveryError::Deadline)?
                .min(Duration::from_secs(900));
            let lease_deadline = started.checked_add(lease).ok_or(DeliveryError::Deadline)?;
            let sources = reply
                .sources
                .iter()
                .map(|s| {
                    SourceAssignment::new(
                        &s.source_id,
                        [
                            &self.identity[0],
                            &self.identity[1],
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
                    .map_err(|_| DeliveryError::Receipt)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if Instant::now() >= lease_deadline {
                return Err(DeliveryError::Deadline);
            }
            Ok(Refresh {
                live: LiveAuthority {
                    sources,
                    deadline: lease_deadline,
                },
                policy,
                envelope_bytes: raw.len(),
            })
        };
        let result = timeout_at(deadline, work)
            .await
            .map_err(|_| DeliveryError::Deadline)??;
        if Instant::now() >= deadline || Instant::now() >= result.live.deadline {
            return Err(DeliveryError::Deadline);
        }
        result
            .policy
            .validate_capture_at(OffsetDateTime::now_utc())
            .map_err(|_| DeliveryError::Deadline)?;
        Ok(result)
    }
}
