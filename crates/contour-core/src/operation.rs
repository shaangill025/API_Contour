//! Stable operation identity is a projection, never proof of authorization.
use crate::{Error, Shape, Timestamp, Writer};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_OPERATION_BYTES: usize = 2048;
/// Exact tuple: tenant, project, service, environment, protocol, direction,
/// operation and sanitized template. No aliases or Unicode normalization in v1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OperationKey<'a> {
    pub(crate) components: [&'a str; 8],
}
impl fmt::Debug for OperationKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationKey")
    }
}
impl<'a> OperationKey<'a> {
    pub fn components(&self) -> [&'a str; 8] {
        self.components
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new(MAX_OPERATION_BYTES);
        writer.push(b"[")?;
        for (index, part) in self.components.iter().enumerate() {
            if index != 0 {
                writer.push(b",")?;
            }
            writer.string(part)?;
        }
        writer.push(b"]")?;
        Ok(writer.bytes)
    }
    /// A deterministic key, not a credential, assignment check or caller digest.
    pub fn fingerprint(&self) -> Result<String, Error> {
        let canonical = self.canonical_bytes()?;
        let mut hash = Sha256::new();
        hash.update(b"apicontour/operation/1\n");
        hash.update(canonical);
        Ok(format!("{:x}", hash.finalize()))
    }
}
/// Borrowed provenance must remain separate from stable operation identity.
/// Syntax checks do not establish safe attribution or policy approval.
#[non_exhaustive]
pub struct OperationObservation<'a> {
    pub key: OperationKey<'a>,
    pub deployment_id: &'a str,
    pub collector_id: &'a str,
    pub source_id: &'a str,
    pub parser_profile: &'a str,
    pub policy_revision: u64,
    pub visibility: &'a str,
    pub route_uncertain: bool,
    pub record_id: &'a str,
    pub canonicalization_version: u8,
    pub structure: &'a Shape,
    pub completeness: &'a str,
    pub reasons: &'a [String],
    /// Locally observed interactions for this source; never unique total traffic.
    pub count: u64,
    pub first_seen: &'a Timestamp,
    pub last_seen: &'a Timestamp,
    pub sample_numerator: u64,
    pub sample_denominator: u64,
    pub status_code: Option<u64>,
    pub request_header_names: &'a [String],
    pub response_header_names: &'a [String],
    pub query_parameter_names: &'a [String],
    pub queued_at: &'a Timestamp,
    pub expires_at: &'a Timestamp,
}
impl fmt::Debug for OperationObservation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationObservation")
    }
}
