//! Versioned structural capture attachment. Descriptors convey no authority.
//!
//! The owner must retain the pool and continue its `poll_authority` maintenance
//! while detachment is pending, and retry `detach` until it succeeds. The native
//! owner schedules maintenance at 100 ms intervals; scheduling is not a hard
//! reclamation deadline. Dropping an attachment revokes it and queues cleanup,
//! but does not acknowledge reclamation or secure erasure.
use crate::{CollectorPool, OwnerError, PoolCapture};
use contour_core::{CaptureScope, OriginWitness, RecordMetadata};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterDescriptor {
    pub version: u8,
    pub origin_v2: bool,
}

/// Opaque storage handle, bound to one attachment and pool generation.
#[derive(Clone, Copy, Debug)]
pub struct AdapterCapture {
    pub(crate) attachment: u64,
    pub(crate) capture: PoolCapture,
}

pub struct StructuralAdapter {
    pub(crate) pool: Arc<CollectorPool>,
    pub(crate) id: u64,
    pub(crate) active: AtomicBool,
    pub(crate) sequences: [AtomicU64; 8],
}
impl StructuralAdapter {
    pub fn attach(pool: Arc<CollectorPool>) -> Result<Arc<Self>, OwnerError> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| OwnerError::Paused)?;
        Ok(Arc::new(Self {
            pool,
            id,
            active: AtomicBool::new(true),
            sequences: std::array::from_fn(|_| AtomicU64::new(0)),
        }))
    }
    pub fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            version: 1,
            origin_v2: self.pool.is_origin_v2(),
        }
    }
    pub fn try_begin(
        &self,
        scope: &CaptureScope<'_>,
        witness: Option<&OriginWitness>,
    ) -> Result<AdapterCapture, OwnerError> {
        self.pool
            .adapter_begin(self, scope, witness)
            .map(|capture| AdapterCapture {
                attachment: self.id,
                capture,
            })
    }
    pub fn try_fragment(&self, token: AdapterCapture, bytes: &[u8]) -> Result<(), OwnerError> {
        if token.attachment != self.id {
            return Err(OwnerError::Paused);
        }
        self.pool.adapter_fragment(self, token.capture, bytes)
    }
    pub fn try_finish(
        &self,
        token: AdapterCapture,
        metadata: RecordMetadata<'_>,
    ) -> Result<(), OwnerError> {
        if token.attachment != self.id {
            return Err(OwnerError::Paused);
        }
        self.pool.adapter_finish(self, token.capture, metadata)
    }
    pub fn try_cancel(&self, token: AdapterCapture) {
        if token.attachment == self.id {
            self.pool.try_cancel(token.capture);
        }
    }
    /// On success, no later callback can inspect or admit and this attachment's
    /// in-flight streams are cancelled. A busy gate returns `Paused` after
    /// revocation; retain the owner, continue maintenance, and retry until
    /// success to establish that cancellation drained.
    /// An already-running callback can finish before successful detachment.
    pub fn detach(&self) -> Result<(), OwnerError> {
        self.pool.detach_adapter(self)
    }
}
impl Drop for StructuralAdapter {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}
