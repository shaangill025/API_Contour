use crate::{
    Batch, Node, Shape, VerifiedPolicy,
    policy::{profile, uuid},
};
use std::{collections::BTreeMap, fmt};
use time::{Duration, OffsetDateTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Inputs,
    Identity,
    Time,
    Revision,
    Source,
    Scope,
    Route,
    Retention,
    Structure,
}
impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AdmissionError {}

/// Checked assignment syntax, not proof of authentication or enrollment.
pub struct SourceAssignment {
    source_id: String,
    identity: [String; 6],
    technique: String,
    parsers: Vec<String>,
}
impl fmt::Debug for SourceAssignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceAssignment")
    }
}
impl SourceAssignment {
    /// Identity order: tenant, collector, project, service, environment, deployment.
    pub fn new(
        source_id: &str,
        identity: [&str; 6],
        technique: &str,
        parsers: &[&str],
    ) -> Result<Self, AdmissionError> {
        if !uuid(source_id)
            || identity.iter().any(|id| !uuid(id))
            || ![
                "gateway",
                "ebpf",
                "browser",
                "android",
                "ios",
                "cloud",
                "messaging",
                "runtime",
            ]
            .contains(&technique)
            || parsers.is_empty()
            || parsers.len() > 128
            || parsers.iter().any(|name| !profile(name))
            || parsers
                .iter()
                .enumerate()
                .any(|(i, name)| parsers[..i].contains(name))
        {
            return Err(AdmissionError::Inputs);
        }
        Ok(Self {
            source_id: source_id.to_owned(),
            identity: identity.map(str::to_owned),
            technique: technique.to_owned(),
            parsers: parsers.iter().map(|name| (*name).to_owned()).collect(),
        })
    }
}

/// Caller-supplied authoritative snapshot, never deserialized from a batch.
/// Caller must authenticate, reject revocation and recheck at commit time.
pub struct AdmissionInputs<'a> {
    pub(crate) identity: [&'a str; 2],
    pub(crate) current: &'a VerifiedPolicy,
    historical: BTreeMap<u64, &'a VerifiedPolicy>,
    sources: BTreeMap<&'a str, &'a SourceAssignment>,
}
impl fmt::Debug for AdmissionInputs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdmissionInputs")
    }
}
impl<'a> AdmissionInputs<'a> {
    pub fn new(
        identity: [&'a str; 2],
        current: &'a VerifiedPolicy,
        historical: &[&'a VerifiedPolicy],
        sources: &'a [SourceAssignment],
    ) -> Result<Self, AdmissionError> {
        if identity.iter().any(|id| !uuid(id)) || historical.len() > 500 || sources.len() > 500 {
            return Err(AdmissionError::Inputs);
        }
        let matches = |policy: &VerifiedPolicy| {
            policy.tenant_id() == identity[0] && policy.collector_id() == identity[1]
        };
        if !matches(current) {
            return Err(AdmissionError::Identity);
        }
        let mut policies = BTreeMap::new();
        for policy in historical {
            if !matches(policy) {
                return Err(AdmissionError::Identity);
            }
            if policy.revision() > current.revision()
                || policies.insert(policy.revision(), *policy).is_some()
                || (policy.revision() == current.revision() && !policy.same_content(current))
            {
                return Err(AdmissionError::Revision);
            }
        }
        // Validate every denial rule, including policies not used by this batch.
        for policy in std::iter::once(current).chain(historical.iter().copied()) {
            for rule in policy.denied_templates() {
                route(rule)?;
            }
        }
        let mut assignments = BTreeMap::new();
        for source in sources {
            if source.identity[0] != identity[0] || source.identity[1] != identity[1] {
                return Err(AdmissionError::Identity);
            }
            if assignments
                .insert(source.source_id.as_str(), source)
                .is_some()
            {
                return Err(AdmissionError::Inputs);
            }
        }
        Ok(Self {
            identity,
            current,
            historical: policies,
            sources: assignments,
        })
    }
}

/// Pure validation only: no revocation, persistence, queue purge or transaction.
pub fn validate_admission(
    batch: &Batch,
    inputs: &AdmissionInputs<'_>,
    now: OffsetDateTime,
) -> Result<(), AdmissionError> {
    if batch.tenant_id() != inputs.identity[0] || batch.collector_id() != inputs.identity[1] {
        return Err(AdmissionError::Identity);
    }
    batch.validate_at(now).map_err(|_| AdmissionError::Time)?;
    inputs
        .current
        .validate_capture_at(now)
        .map_err(|_| AdmissionError::Time)?;
    for record in batch.records() {
        validate_record(
            record,
            inputs,
            record.queued_at.instant(),
            record.expires_at.instant(),
            now,
        )?;
    }
    Ok(())
}
pub(crate) fn validate_record(
    record: &crate::batch::Record,
    inputs: &AdmissionInputs<'_>,
    queued: OffsetDateTime,
    expires: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), AdmissionError> {
    inputs
        .current
        .validate_capture_at(now)
        .map_err(|_| AdmissionError::Time)?;
    if expires <= now {
        return Err(AdmissionError::Time);
    }
    let historical = inputs
        .historical
        .get(&record.policy_revision.get())
        .ok_or(AdmissionError::Revision)?;
    historical
        .validate_capture_at(queued)
        .map_err(|_| AdmissionError::Time)?;
    let source = inputs
        .sources
        .get(record.source_id.as_str())
        .ok_or(AdmissionError::Source)?;
    if source.identity.iter().map(String::as_str).ne([
        inputs.identity[0],
        inputs.identity[1],
        &record.project_id,
        &record.service_id,
        &record.environment_id,
        &record.deployment_id,
    ]) || !source
        .parsers
        .iter()
        .any(|name| name == &record.parser_profile)
    {
        return Err(AdmissionError::Source);
    }
    let segments = route(&record.route_template)?;
    for policy in [*historical, inputs.current] {
        if !policy.approves(
            &record.service_id,
            &source.technique,
            &record.parser_profile,
        ) || !policy.approves_name(&record.operation)
            || [
                &record.request_header_names.0,
                &record.response_header_names.0,
                &record.query_parameter_names.0,
            ]
            .iter()
            .any(|names| names.iter().any(|name| !policy.approves_name(name)))
            || record.structure.0.depth() > policy.depth_limit()
            || !approved_shape(&record.structure.0, policy)
        {
            return Err(AdmissionError::Scope);
        }
        if segments
            .iter()
            .any(|segment| !placeholder(segment) && !policy.approves_segment(segment))
        {
            return Err(AdmissionError::Route);
        }
        for denied in policy.denied_templates() {
            let denied = route(denied)?;
            if denied.len() == segments.len()
                && denied
                    .iter()
                    .zip(&segments)
                    .all(|(a, b)| a == b || placeholder(a) || placeholder(b))
            {
                return Err(AdmissionError::Route);
            }
        }
        let ttl = Duration::seconds(policy.ttl() as i64);
        if expires - queued > ttl {
            return Err(AdmissionError::Retention);
        }
    }
    // Recompute locally; an eventual persistence consumer must bind dimensions too.
    record
        .structure
        .0
        .fingerprint()
        .map_err(|_| AdmissionError::Structure)?;
    Ok(())
}
fn approved_shape(shape: &Shape, policy: &VerifiedPolicy) -> bool {
    match &shape.node {
        Node::Object(fields, additional) => {
            fields
                .iter()
                .all(|(name, child)| policy.approves_name(name) && approved_shape(child, policy))
                && additional
                    .as_deref()
                    .is_none_or(|child| approved_shape(child, policy))
        }
        Node::Array(items) => approved_shape(items, policy),
        Node::Union(children) => children.iter().all(|child| approved_shape(child, policy)),
        Node::Primitive(_) | Node::Unknown(_) => true,
    }
}
fn placeholder(segment: &str) -> bool {
    matches!(segment, "{segment}" | "{id}")
}
fn route(text: &str) -> Result<Vec<&str>, AdmissionError> {
    if text.is_empty()
        || text.chars().count() > 256
        || !text.starts_with('/')
        || text
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '\\' | '%' | '?' | '#' | ':'))
    {
        return Err(AdmissionError::Route);
    }
    if text == "/" {
        return Ok(Vec::new());
    }
    let segments = text[1..].split('/').collect::<Vec<_>>();
    if segments.iter().any(|segment| {
        segment.is_empty()
            || matches!(*segment, "." | "..")
            || (segment.contains(['{', '}']) && !placeholder(segment))
    }) {
        return Err(AdmissionError::Route);
    }
    Ok(segments)
}
