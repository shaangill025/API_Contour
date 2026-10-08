//! Private online grant. Parsing a response alone cannot construct live authority.
use crate::*;
use contour_core::{PolicyKeys, SourceAssignment, VerifiedPolicy};
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
    wire_version: u8,
    challenge: String,
    tenant_id: String,
    collector_id: String,
    checked_at: Timestamp,
    signed_policy: Box<RawValue>,
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
    parser_profiles: Vec<String>,
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
                bytes.extend_from_slice(&data);
            }
            let reply: Reply =
                serde_json::from_slice(&bytes).map_err(|_| DeliveryError::Receipt)?;
            if reply.wire_version != 1
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
                            .map(String::as_str)
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
