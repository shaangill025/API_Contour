//! Exclusive role-specific slots. Uncertain connections are never reused.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::{
    CausalError, CausalReceipt, CausalReceiverEventInbox504, CausalReceiverSession504,
    ConnectedDatabase, DatabaseSettings, ReceiverEvidencePeer, ReceiverFactInbox,
    ReceiverFactReceipt, ReceiverFactRequest, ReceiverFactSelectors, TrustedCa,
};
use std::sync::{Arc, Mutex};
use tokio::{sync::oneshot, task::JoinHandle, time::Instant};

struct Slot {
    used: bool,
    release_after_job: bool,
    job: Option<JoinHandle<()>>,
    connection: Option<ConnectedDatabase>,
}
impl Slot {
    fn settle(&mut self) {
        if self.release_after_job && self.idle() {
            self.used = false;
            self.release_after_job = false;
        }
    }
    fn idle(&self) -> bool {
        self.job.as_ref().is_none_or(JoinHandle::is_finished)
    }
    fn available(&self) -> bool {
        self.idle()
            && (!self.used
                || self
                    .connection
                    .as_ref()
                    .is_some_and(ConnectedDatabase::is_reusable))
    }
    fn needs_reaping(&self) -> bool {
        self.idle() && self.used && self.connection.as_ref().is_some_and(|c| !c.is_reusable())
    }
}
struct Ledger {
    slots: Vec<Slot>,
    started: bool,
    closed: bool,
}
pub(crate) struct Pool {
    settings: Arc<DatabaseSettings>,
    trust: Arc<TrustedCa>,
    keys: Arc<PolicyKeys>,
    ledger: Arc<Mutex<Ledger>>,
}
pub(crate) enum Job {
    Event(
        Arc<CausalReceiverSession504>,
        ReceiverEvidencePeer,
        Vec<u8>,
        Arc<CausalGrantKeys>,
        oneshot::Sender<Result<CausalReceipt, CausalError>>,
    ),
    Fact(
        Arc<CausalReceiverSession504>,
        ReceiverEvidencePeer,
        Arc<ReceiverFactSelectors>,
        Vec<u8>,
        Arc<CausalGrantKeys>,
        oneshot::Sender<Result<ReceiverFactReceipt, CausalError>>,
    ),
}
impl Pool {
    pub fn new(
        settings: DatabaseSettings,
        trust: TrustedCa,
        keys: Arc<PolicyKeys>,
        capacity: usize,
    ) -> Self {
        Self {
            settings: Arc::new(settings),
            trust: Arc::new(trust),
            keys,
            ledger: Arc::new(Mutex::new(Ledger {
                slots: (0..capacity)
                    .map(|_| Slot {
                        used: false,
                        release_after_job: false,
                        job: None,
                        connection: None,
                    })
                    .collect(),
                started: false,
                closed: false,
            })),
        }
    }
    pub fn begin(&self) -> Result<(), ()> {
        let mut l = self.ledger.lock().map_err(|_| ())?;
        if l.started || l.closed {
            return Err(());
        }
        l.started = true;
        Ok(())
    }
    pub fn start(&self, job: Job, deadline: Instant) -> Result<(), ()> {
        if Instant::now() >= deadline {
            return Err(());
        }
        let mut l = self.ledger.lock().map_err(|_| ())?;
        if l.closed || !l.started {
            return Err(());
        }
        for slot in &mut l.slots {
            slot.settle();
        }
        let available = l.slots.iter().position(Slot::available);
        let Some(i) = available else {
            // Reap one dead idle connection under this request's absolute deadline.
            // The request is rejected; only a later request can claim the slot.
            if let Some(i) = l.slots.iter().position(Slot::needs_reaping) {
                let slot = &mut l.slots[i];
                slot.job.take();
                let connection = slot.connection.take().ok_or(())?;
                let owner = Arc::downgrade(&self.ledger);
                slot.job = Some(tokio::spawn(async move {
                    let terminated = connection.terminate_until(deadline).await.is_ok();
                    if terminated {
                        if let Some(owner) = owner.upgrade() {
                            if let Ok(mut ledger) = owner.lock() {
                                if !ledger.closed {
                                    ledger.slots[i].release_after_job = true;
                                }
                            }
                        }
                    }
                }));
            }
            return Err(());
        };
        let s = &mut l.slots[i];
        s.job.take();
        s.used = true;
        s.release_after_job = false;
        let existing = s.connection.take();
        let settings = self.settings.clone();
        let trust = self.trust.clone();
        let keys = self.keys.clone();
        let owner = Arc::downgrade(&self.ledger);
        s.job = Some(tokio::spawn(async move {
            let connected = match existing {
                Some(c) => Ok(c),
                None => settings.connect_single_until(&trust, deadline).await,
            };
            let (connection, outcome): (Option<ConnectedDatabase>, Box<dyn FnOnce() + Send>) =
                match job {
                    Job::Event(session, peer, bytes, grants, reply) => match connected {
                        Ok(c) => {
                            let mut inbox = CausalReceiverEventInbox504::new(c);
                            let result = inbox
                                .accept_peer_until(
                                    &session, &peer, &bytes, &grants, &keys, deadline,
                                )
                                .await;
                            (
                                Some(inbox.into_database()),
                                Box::new(move || {
                                    let _ = reply.send(result);
                                }),
                            )
                        }
                        Err(_) => (
                            None,
                            Box::new(move || {
                                let _ = reply.send(Err(CausalError::Database));
                            }),
                        ),
                    },
                    Job::Fact(session, peer, selectors, bytes, grants, reply) => match connected {
                        Ok(c) => {
                            let mut inbox = ReceiverFactInbox::new(c);
                            let result = inbox
                                .accept_until(
                                    &session,
                                    &peer,
                                    ReceiverFactRequest {
                                        selectors: &selectors,
                                        canonical_fact: &bytes,
                                    },
                                    &grants,
                                    &keys,
                                    deadline,
                                )
                                .await;
                            (
                                Some(inbox.into_database()),
                                Box::new(move || {
                                    let _ = reply.send(result);
                                }),
                            )
                        }
                        Err(_) => (
                            None,
                            Box::new(move || {
                                let _ = reply.send(Err(CausalError::Database));
                            }),
                        ),
                    },
                };
            // A returned connect error has no spawned driver. An established but
            // non-reusable session must finish its local driver before recycling.
            // No job or transaction is ever retried here.
            let (mut connection, fresh) = match connection {
                None => (None, true),
                Some(c) if c.is_reusable() => (Some(c), false),
                Some(c) => (None, c.terminate_until(deadline).await.is_ok()),
            };
            if let Some(owner) = owner.upgrade() {
                if let Ok(mut l) = owner.lock() {
                    if !l.closed {
                        l.slots[i].connection = connection.take();
                        if fresh {
                            l.slots[i].release_after_job = true;
                        }
                    }
                }
            }
            // If ownership could not be returned, Drop aborts the connection;
            // the closed or poisoned ledger never offers the slot again.
            drop(connection);
            outcome();
        }));
        Ok(())
    }
    pub fn seal(&self) {
        if let Ok(mut l) = self.ledger.lock() {
            l.closed = true;
            for s in &mut l.slots {
                s.used = true;
                s.release_after_job = false;
                if let Some(j) = &s.job {
                    j.abort();
                }
                s.connection.take();
            }
        }
    }
    pub async fn shutdown(&self) {
        let (jobs, connections) = {
            let Ok(mut l) = self.ledger.lock() else {
                return;
            };
            l.closed = true;
            let mut jobs = Vec::new();
            let mut connections = Vec::new();
            for s in &mut l.slots {
                s.used = true;
                s.release_after_job = false;
                if let Some(j) = s.job.take() {
                    j.abort();
                    jobs.push(j);
                }
                if let Some(c) = s.connection.take() {
                    connections.push(c);
                }
            }
            (jobs, connections)
        };
        for j in jobs {
            let _ = j.await;
        }
        for c in connections {
            let _ = c.close().await;
        }
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        if let Ok(mut l) = self.ledger.lock() {
            l.closed = true;
            for s in &mut l.slots {
                if let Some(j) = &s.job {
                    j.abort();
                }
                s.connection.take();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fresh_mark_does_not_release_a_running_slot() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (release, waiting) = oneshot::channel::<()>();
                let task = tokio::spawn(async move {
                    let _ = waiting.await;
                });
                // A connect failure or completed reaper may mark fresh before its
                // enclosing job has returned, but another job must not overlap it.
                let mut slot = Slot {
                    used: true,
                    release_after_job: true,
                    job: Some(task),
                    connection: None,
                };
                slot.settle();
                assert!(slot.used);
                assert!(!slot.available());
                release.send(()).unwrap();
                slot.job.as_mut().unwrap().await.unwrap();
                slot.settle();
                assert!(slot.available());
            });
    }

    #[test]
    fn failed_or_cancelled_cleanup_stays_quarantined() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let task = tokio::spawn(std::future::pending::<()>());
                let mut slot = Slot {
                    used: true,
                    release_after_job: false,
                    job: Some(task),
                    connection: None,
                };
                assert!(!slot.available());
                assert!(!slot.needs_reaping());
                slot.job.as_ref().unwrap().abort();
                let _ = slot.job.as_mut().unwrap().await;
                assert!(!slot.available());
                assert!(!slot.needs_reaping());
                // Elapsed time alone does not establish termination or free a slot.
                tokio::time::sleep(Duration::from_millis(1)).await;
                assert!(!slot.available());
            });
    }
}
