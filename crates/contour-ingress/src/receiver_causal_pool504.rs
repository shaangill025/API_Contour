//! Exclusive role-specific slots. Once a connection is uncertain its slot is never reused.
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
    job: Option<JoinHandle<()>>,
    connection: Option<ConnectedDatabase>,
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
        let i = l
            .slots
            .iter()
            .position(|s| {
                s.job.as_ref().is_none_or(|j| j.is_finished())
                    && (!s.used
                        || s.connection
                            .as_ref()
                            .is_some_and(ConnectedDatabase::is_reusable))
            })
            .ok_or(())?;
        let s = &mut l.slots[i];
        s.job.take();
        s.used = true;
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
            let mut connection = connection;
            if let Some(owner) = owner.upgrade() {
                if let Ok(mut l) = owner.lock() {
                    if !l.closed {
                        l.slots[i].connection = connection.take();
                    }
                }
            }
            if let Some(c) = connection {
                let _ = c.close().await;
            }
            outcome();
        }));
        Ok(())
    }
    pub fn seal(&self) {
        if let Ok(mut l) = self.ledger.lock() {
            l.closed = true;
            for s in &mut l.slots {
                s.used = true;
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
