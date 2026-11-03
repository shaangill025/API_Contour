//! Data-only causal event encoding. Checked syntax conveys no authority or admission.
use crate::{
    BatchError,
    batch::{self, Bounded},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const MAX_CAUSAL_EVENTS: usize = 500;
pub const MAX_CAUSAL_EVENT_BATCH_BYTES: usize = 1_048_576;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    wire_version: u64,
    batch_id: String,
    tenant_id: String,
    runtime_id: String,
    session_epoch: u64,
    first_seq: u64,
    last_seq: u64,
    events: Bounded<EventKind, MAX_CAUSAL_EVENTS>,
}

/// A closed, untrusted causal observation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum EventKind {
    Root {
        event_id: String,
        seq: u64,
        root: String,
    },
    Delivery {
        event_id: String,
        seq: u64,
        root: String,
        activity: String,
        parent: String,
    },
    Attempt {
        event_id: String,
        seq: u64,
        root: String,
        activity: String,
        attempt: String,
        marker_digest: String,
    },
    Loss {
        event_id: String,
        seq: u64,
        first_missing_seq: u64,
        last_missing_seq: u64,
        reason: LossReason,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossReason {
    Overflow,
    Expired,
    Canceled,
    GuardInvalidated,
    DispatchMissing,
    Restart,
    Unsupported,
}

pub struct CausalEvent(EventKind);

/// Borrowed, checked event data; these identifiers remain untrusted claims.
#[derive(Debug, PartialEq, Eq)]
pub enum CausalEventKind<'a> {
    Root {
        root: &'a str,
    },
    Delivery {
        root: &'a str,
        activity: &'a str,
        parent: &'a str,
    },
    Attempt {
        root: &'a str,
        activity: &'a str,
        attempt: &'a str,
        marker_digest: &'a str,
    },
    Loss {
        first_missing_seq: u64,
        last_missing_seq: u64,
        reason: LossReason,
    },
}

impl CausalEvent {
    pub fn kind(&self) -> CausalEventKind<'_> {
        match &self.0 {
            EventKind::Root { root, .. } => CausalEventKind::Root { root },
            EventKind::Delivery {
                root,
                activity,
                parent,
                ..
            } => CausalEventKind::Delivery {
                root,
                activity,
                parent,
            },
            EventKind::Attempt {
                root,
                activity,
                attempt,
                marker_digest,
                ..
            } => CausalEventKind::Attempt {
                root,
                activity,
                attempt,
                marker_digest,
            },
            EventKind::Loss {
                first_missing_seq,
                last_missing_seq,
                reason,
                ..
            } => CausalEventKind::Loss {
                first_missing_seq: *first_missing_seq,
                last_missing_seq: *last_missing_seq,
                reason: *reason,
            },
        }
    }

    pub fn event_id(&self) -> &str {
        match &self.0 {
            EventKind::Root { event_id, .. }
            | EventKind::Delivery { event_id, .. }
            | EventKind::Attempt { event_id, .. }
            | EventKind::Loss { event_id, .. } => event_id,
        }
    }
    pub fn seq(&self) -> u64 {
        match &self.0 {
            EventKind::Root { seq, .. }
            | EventKind::Delivery { seq, .. }
            | EventKind::Attempt { seq, .. }
            | EventKind::Loss { seq, .. } => *seq,
        }
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BatchError> {
        batch::canonical_encode(&self.0)
    }
    pub fn digest_bytes(&self) -> Result<[u8; 32], BatchError> {
        batch::canonical_digest(&self.0, b"apicontour/causal-event/1\n")
    }
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A syntactically and semantically checked batch, not an admitted batch.
pub struct CausalEventBatch {
    envelope: Envelope,
    events: Vec<CausalEvent>,
}
impl CausalEventBatch {
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, BatchError> {
        if bytes.len() > MAX_CAUSAL_EVENT_BATCH_BYTES {
            return Err(BatchError::Size);
        }
        let mut e: Envelope = serde_json::from_slice(bytes).map_err(|_| BatchError::Invalid)?;
        if e.wire_version != 1
            || e.session_epoch == 0
            || e.events.0.is_empty()
            || [&e.batch_id, &e.tenant_id, &e.runtime_id]
                .iter()
                .any(|id| !batch::uuid(id))
        {
            return Err(BatchError::Semantic);
        }
        let events: Vec<CausalEvent> = std::mem::take(&mut e.events.0)
            .into_iter()
            .map(CausalEvent)
            .collect();
        if e.first_seq != events[0].seq() || e.last_seq != events.last().unwrap().seq() {
            return Err(BatchError::Semantic);
        }
        let mut ids = HashSet::new();
        let mut roots = HashSet::new();
        let mut activities = HashMap::new();
        let mut activity_roots = HashMap::new();
        let mut attempts = HashMap::new();
        let mut previous = 0;
        for event in &events {
            if event.seq() <= previous
                || !hex(event.event_id(), 32)
                || !ids.insert(event.event_id())
            {
                return Err(BatchError::Semantic);
            }
            previous = event.seq();
            match &event.0 {
                EventKind::Root { root, .. } => {
                    if !hex(root, 32) || !roots.insert(root) {
                        return Err(BatchError::Semantic);
                    }
                }
                EventKind::Delivery {
                    root,
                    activity,
                    parent,
                    ..
                } => {
                    if ![root, activity, parent].iter().all(|v| hex(v, 32))
                        || activity_roots
                            .insert(activity, root)
                            .is_some_and(|old| old != root)
                        || activities
                            .insert(activity, (root, parent))
                            .is_some_and(|old| old != (root, parent))
                    {
                        return Err(BatchError::Semantic);
                    }
                }
                EventKind::Attempt {
                    root,
                    activity,
                    attempt,
                    marker_digest,
                    ..
                } => {
                    if ![root, activity, attempt].iter().all(|v| hex(v, 32))
                        || !hex(marker_digest, 64)
                        || activity_roots
                            .insert(activity, root)
                            .is_some_and(|old| old != root)
                        || attempts
                            .insert(attempt, (root, activity, marker_digest))
                            .is_some_and(|old| old != (root, activity, marker_digest))
                    {
                        return Err(BatchError::Semantic);
                    }
                }
                EventKind::Loss {
                    first_missing_seq,
                    last_missing_seq,
                    ..
                } => {
                    let (a, b) = (*first_missing_seq, *last_missing_seq);
                    if a == 0
                        || a > b
                        || b >= event.seq()
                        || events.iter().any(|other| (a..=b).contains(&other.seq()))
                    {
                        return Err(BatchError::Semantic);
                    }
                }
            }
        }
        // Root identifiers also name their boundary activities. Resolve only
        // contradictions visible in this batch; missing references are allowed.
        for event in &events {
            match &event.0 {
                EventKind::Delivery {
                    activity, parent, ..
                } if activity == parent || roots.contains(activity) => {
                    return Err(BatchError::Semantic);
                }
                EventKind::Attempt { root, activity, .. }
                    if roots.contains(activity) && activity != root =>
                {
                    return Err(BatchError::Semantic);
                }
                _ => {}
            }
        }
        e.events.0 = events.iter().map(|event| event.0.clone()).collect();
        let result = Self {
            envelope: e,
            events,
        };
        result.canonical_bytes()?;
        Ok(result)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BatchError> {
        batch::canonical_encode(&self.envelope)
    }
    pub fn digest_bytes(&self) -> Result<[u8; 32], BatchError> {
        batch::canonical_digest(&self.envelope, b"apicontour/causal-events/1\n")
    }
    pub fn events(&self) -> &[CausalEvent] {
        &self.events
    }
    pub fn batch_id(&self) -> &str {
        &self.envelope.batch_id
    }
    pub fn tenant_id(&self) -> &str {
        &self.envelope.tenant_id
    }
    pub fn runtime_id(&self) -> &str {
        &self.envelope.runtime_id
    }
    pub fn session_epoch(&self) -> u64 {
        self.envelope.session_epoch
    }
    pub fn first_seq(&self) -> u64 {
        self.envelope.first_seq
    }
    pub fn last_seq(&self) -> u64 {
        self.envelope.last_seq
    }
}
