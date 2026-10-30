//! Owner-private bounded raw fragments. No payload leaves this module except
//! through the existing signed structural extractor.
use super::{CollectorOwner, OwnerError};
use contour_core::{AdmissionInputs, CaptureScope, Observation, RecordDraft, RecordMetadata};
use std::collections::BTreeMap;
use time::OffsetDateTime;

const MAX_STREAMS: usize = 16;
const MAX_RAW: usize = 1024 * 1024;
const MAX_BODY: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaptureId(u64);
struct Stream {
    source: String,
    workload: [String; 4],
    profile: String,
    operation: String,
    route: String,
    bytes: Vec<u8>,
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}
impl Stream {
    fn scope(&self) -> CaptureScope<'_> {
        CaptureScope {
            source_id: &self.source,
            workload: self.workload.each_ref().map(String::as_str),
            parser_profile: &self.profile,
            operation: &self.operation,
            route_template: &self.route,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        }
    }
}
#[derive(Default)]
pub(crate) struct Streams {
    next: u64,
    total: usize,
    entries: BTreeMap<CaptureId, Stream>,
}
impl Streams {
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.total = 0;
    }
    fn remove(&mut self, id: CaptureId) -> Option<Stream> {
        let stream = self.entries.remove(&id)?;
        self.total = self.total.saturating_sub(stream.bytes.len());
        Some(stream)
    }
}
impl CollectorOwner {
    /// Reserve a private stream under the current live scope. The returned token
    /// identifies storage only; it does not confer authority on later calls.
    pub fn begin_capture(&mut self, scope: &CaptureScope<'_>) -> Result<CaptureId, OwnerError> {
        self.guard()?;
        if !scope.request_header_names.is_empty()
            || !scope.response_header_names.is_empty()
            || !scope.query_parameter_names.is_empty()
            || self.streams.entries.len() >= MAX_STREAMS
        {
            return Err(OwnerError::Paused);
        }
        let limit = self.check_stream_scope(scope)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| OwnerError::Paused)?;
        self.guard()?;
        self.streams.next = self.streams.next.checked_add(1).ok_or(OwnerError::Paused)?;
        let id = CaptureId(self.streams.next);
        self.streams.entries.insert(
            id,
            Stream {
                source: scope.source_id.to_owned(),
                workload: scope.workload.map(str::to_owned),
                profile: scope.parser_profile.to_owned(),
                operation: scope.operation.to_owned(),
                route: scope.route_template.to_owned(),
                bytes,
            },
        );
        Ok(id)
    }
    fn check_stream_scope(&self, scope: &CaptureScope<'_>) -> Result<usize, OwnerError> {
        let live = self.live.as_ref().ok_or(OwnerError::Paused)?;
        let current = &self.policies.last().ok_or(OwnerError::Paused)?.policy;
        let refs = self.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            current,
            &refs,
            &live.sources,
        )
        .map_err(|e| OwnerError::Queue(crate::QueueError::Admission(e)))?;
        inputs
            .check_capture_scope(scope, OffsetDateTime::now_utc())
            .map_err(|e| OwnerError::Queue(crate::QueueError::Admission(e)))?;
        Ok(current.inspection_bytes().min(MAX_BODY))
    }
    /// Copy only while the owner holds a current scoped grant. The source slice
    /// is the unmodified application frame; it is never retained or cloned.
    pub fn capture_fragment(&mut self, id: CaptureId, bytes: &[u8]) -> Result<(), OwnerError> {
        self.capture_fragment_inner(id, bytes, || {})
    }
    pub(super) fn capture_fragment_inner(
        &mut self,
        id: CaptureId,
        bytes: &[u8],
        before_copy: impl FnOnce(),
    ) -> Result<(), OwnerError> {
        if self.guard().is_err() {
            self.streams.clear();
            return Err(OwnerError::Paused);
        }
        let stream = self.streams.remove(id).ok_or(OwnerError::Paused)?;
        let limit = self.check_stream_scope(&stream.scope())?;
        if bytes.len() > limit.saturating_sub(stream.bytes.len())
            || bytes.len() > MAX_RAW.saturating_sub(self.streams.total + stream.bytes.len())
        {
            return Err(OwnerError::Paused);
        }
        let mut stream = stream;
        stream
            .bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| OwnerError::Paused)?;
        before_copy();
        stream.bytes.extend_from_slice(bytes);
        if self.guard().is_err() {
            self.streams.clear();
            return Err(OwnerError::Paused);
        }
        self.streams.total += stream.bytes.len();
        self.streams.entries.insert(id, stream);
        Ok(())
    }
    pub fn cancel_capture(&mut self, id: CaptureId) {
        self.streams.remove(id);
    }
    pub fn finish_capture(&mut self, id: CaptureId) -> Result<(u64, Observation), OwnerError> {
        if self.guard().is_err() {
            self.streams.clear();
            return Err(OwnerError::Paused);
        }
        let stream = self.streams.remove(id).ok_or(OwnerError::Paused)?;
        self.inspect_json(&stream.scope(), &stream.bytes)
    }
    pub(super) fn finish_and_admit(
        &mut self,
        id: CaptureId,
        mut metadata: RecordMetadata<'_>,
    ) -> Result<(), OwnerError> {
        self.guard()?;
        let stream = self.streams.remove(id).ok_or(OwnerError::Paused)?;
        if metadata.source_id != stream.source
            || metadata.workload != stream.workload.each_ref().map(String::as_str)
            || metadata.parser_profile != stream.profile
            || metadata.operation != stream.operation
            || metadata.route_template != stream.route
            || !metadata.request_header_names.is_empty()
            || !metadata.response_header_names.is_empty()
            || !metadata.query_parameter_names.is_empty()
        {
            return Err(OwnerError::Paused);
        }
        let (revision, observation) = self.inspect_json(&stream.scope(), &stream.bytes)?;
        if observation.completeness == contour_core::Completeness::Unavailable
            || observation
                .reasons
                .contains(&contour_core::ObservationReason::Malformed)
        {
            return Err(OwnerError::Paused);
        }
        metadata.policy_revision = revision;
        let draft =
            RecordDraft::from_observation(metadata, observation).map_err(|_| OwnerError::Paused)?;
        self.admit(draft)
    }
}
