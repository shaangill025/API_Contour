//! Private online grant. Parsing a response alone cannot construct live authority.
use crate::*;
use contour_core::{
    AuthorityReplyError, PolicyKeys, SourceAssignment, VerifiedPolicy, check_authority_reply,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;

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
            let checked = check_authority_reply(
                &bytes,
                &challenge,
                &self.identity[0],
                &self.identity[1],
                source_ids,
                keys,
                OffsetDateTime::now_utc(),
            )
            .map_err(|error| match error {
                AuthorityReplyError::Size => DeliveryError::ResponseLimit,
                AuthorityReplyError::Invalid => DeliveryError::Receipt,
                AuthorityReplyError::Deadline => DeliveryError::Deadline,
            })?;
            let lease_deadline = started
                .checked_add(checked.lease)
                .ok_or(DeliveryError::Deadline)?;
            if Instant::now() >= lease_deadline {
                return Err(DeliveryError::Deadline);
            }
            Ok(Refresh {
                live: LiveAuthority {
                    sources: checked.sources,
                    deadline: lease_deadline,
                },
                policy: checked.policy,
                envelope_bytes: checked.envelope_bytes,
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
