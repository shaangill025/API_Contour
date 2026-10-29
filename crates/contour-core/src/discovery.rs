//! In-memory capture descriptors, not an ingest or persistence contract.
//!
//! Syntax checks do not establish enrollment, authorization, lifecycle validity,
//! destination approval, or causal proof. Callers must establish those separately
//! from trusted evidence and enforce policy before inspecting or exporting data.

use crate::policy::uuid;
use std::fmt;

pub const MAX_CAUSAL_LINKS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    InvalidIdentity,
    TooManyLinks,
}
impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DiscoveryError {}

/// Identifiers are platform-assigned references, not arbitrary labels, addresses,
/// process IDs, or trace headers. The instance ID identifies a lifecycle, so a
/// replacement or restart must receive a distinct ID from the trusted issuer.
#[derive(Clone, PartialEq, Eq)]
pub struct WorkloadIdentity {
    ids: [String; 6],
}
impl WorkloadIdentity {
    /// Order: tenant, project, service, environment, deployment, instance lifecycle.
    pub fn new(ids: [&str; 6]) -> Result<Self, DiscoveryError> {
        if ids.iter().any(|id| !uuid(id)) {
            return Err(DiscoveryError::InvalidIdentity);
        }
        Ok(Self {
            ids: ids.map(str::to_owned),
        })
    }
    pub fn tenant(&self) -> &str {
        &self.ids[0]
    }
    pub fn project(&self) -> &str {
        &self.ids[1]
    }
    pub fn service(&self) -> &str {
        &self.ids[2]
    }
    pub fn environment(&self) -> &str {
        &self.ids[3]
    }
    pub fn deployment(&self) -> &str {
        &self.ids[4]
    }
    pub fn instance(&self) -> &str {
        &self.ids[5]
    }
}
impl fmt::Debug for WorkloadIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WorkloadIdentity")
    }
}

/// A collector is distinct from the workload it observes; no assignment is implied.
#[derive(Clone, PartialEq, Eq)]
pub struct CollectorIdentity(String);
impl CollectorIdentity {
    pub fn new(id: &str) -> Result<Self, DiscoveryError> {
        if !uuid(id) {
            return Err(DiscoveryError::InvalidIdentity);
        }
        Ok(Self(id.to_owned()))
    }
    pub fn id(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for CollectorIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CollectorIdentity")
    }
}

/// Service reference within the workload's tenant and project. The caller must
/// verify that the reference is approved in that scope; construction cannot do so.
#[derive(Clone, PartialEq, Eq)]
pub struct DestinationService(String);
impl DestinationService {
    pub fn new(service_id: &str) -> Result<Self, DiscoveryError> {
        if !uuid(service_id) {
            return Err(DiscoveryError::InvalidIdentity);
        }
        Ok(Self(service_id.to_owned()))
    }
    pub fn id(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for DestinationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DestinationService")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapturePoint {
    Host,
    Runtime,
    Gateway,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsLeg {
    ClientToGateway,
    GatewayToUpstream,
    Endpoint,
    None,
    Unknown,
}

/// Claims about how an observation was obtained, not proof that TLS was validated.
/// Capture point describes the observer and TLS leg describes the traffic: a host
/// or runtime observer can observe a gateway leg, so combinations are not restricted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureProvenance {
    pub point: CapturePoint,
    pub tls_leg: TlsLeg,
}

/// An untrusted assertion, never a verification result or proof. A downstream
/// verifier must independently establish evidence before treating a claimed
/// verified link as verified. Trace headers, timing and socket adjacency alone
/// cannot establish causality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CausalClassificationClaim {
    VerifiedClaimed,
    InferredClaimed,
    MissingClaimed,
}

/// References to separately retained events, never raw trace context or baggage.
/// This is not a validated causal graph: self-links, repeated pairs, and cycles
/// are representable claims and require downstream assessment.
#[derive(Clone, PartialEq, Eq)]
pub struct CausalLink {
    from_event: String,
    to_event: String,
    claim: CausalClassificationClaim,
}
impl CausalLink {
    pub fn new(
        from_event: &str,
        to_event: &str,
        claim: CausalClassificationClaim,
    ) -> Result<Self, DiscoveryError> {
        if !uuid(from_event) || !uuid(to_event) {
            return Err(DiscoveryError::InvalidIdentity);
        }
        Ok(Self {
            from_event: from_event.to_owned(),
            to_event: to_event.to_owned(),
            claim,
        })
    }
    pub fn from_event(&self) -> &str {
        &self.from_event
    }
    pub fn to_event(&self) -> &str {
        &self.to_event
    }
    pub fn claim(&self) -> CausalClassificationClaim {
        self.claim
    }
}
impl fmt::Debug for CausalLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalLink")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CausalLinks(Vec<CausalLink>);
impl CausalLinks {
    pub fn new(links: Vec<CausalLink>) -> Result<Self, DiscoveryError> {
        if links.len() > MAX_CAUSAL_LINKS {
            return Err(DiscoveryError::TooManyLinks);
        }
        Ok(Self(links))
    }
    pub fn links(&self) -> &[CausalLink] {
        &self.0
    }
}
impl fmt::Debug for CausalLinks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalLinks")
    }
}
