//! Fixed slots bound potentially live sessions across receiver cancellation.
use contour_core::{Batch, PolicyKeys};
use contour_postgres::{
    AuthorityError, AuthorityRead, AuthorityReadRequest, ConnectedDatabase, DatabaseSettings,
    DurableReceipt, SubmitError, TrustedCa,
};
use std::sync::{Arc, Mutex};
use tokio::{
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseCapacity {
    pub capacity: usize,
    pub running: usize,
    pub reusable: usize,
    pub quarantined: usize,
    pub closed: bool,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum PoolError {
    Capacity,
    Closed,
}
enum Job {
    Submit(
        Batch,
        [String; 2],
        oneshot::Sender<Result<DurableReceipt, SubmitError>>,
    ),
    Authority(
        AuthorityReadRequest,
        oneshot::Sender<Result<AuthorityRead, AuthorityError>>,
    ),
}
enum Outcome {
    Submit(
        oneshot::Sender<Result<DurableReceipt, SubmitError>>,
        Result<DurableReceipt, SubmitError>,
    ),
    Authority(
        oneshot::Sender<Result<AuthorityRead, AuthorityError>>,
        Box<Result<AuthorityRead, AuthorityError>>,
    ),
}
impl Outcome {
    fn send(self) {
        match self {
            Self::Submit(reply, result) => {
                let _ = reply.send(result);
            }
            Self::Authority(reply, result) => {
                let _ = reply.send(*result);
            }
        }
    }
}
struct Slot {
    used: bool,
    job: Option<JoinHandle<()>>,
    session: Option<ConnectedDatabase>,
}
impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(job) = &self.job {
            job.abort();
        }
    }
}
struct Ledger {
    slots: Vec<Slot>,
    closed: bool,
    started: bool,
}
pub(crate) struct Serving<'a>(&'a DatabasePool);
impl Drop for Serving<'_> {
    fn drop(&mut self) {
        self.0.seal();
    }
}
pub(crate) struct DatabasePool {
    settings: Arc<DatabaseSettings>,
    trust: Arc<TrustedCa>,
    keys: Arc<PolicyKeys>,
    ledger: Arc<Mutex<Ledger>>,
}
impl DatabasePool {
    pub(crate) fn new(
        settings: DatabaseSettings,
        trust: TrustedCa,
        keys: PolicyKeys,
        capacity: usize,
    ) -> Self {
        Self {
            settings: Arc::new(settings),
            trust: Arc::new(trust),
            keys: Arc::new(keys),
            ledger: Arc::new(Mutex::new(Ledger {
                slots: (0..capacity)
                    .map(|_| Slot {
                        used: false,
                        job: None,
                        session: None,
                    })
                    .collect(),
                closed: false,
                started: false,
            })),
        }
    }
    pub(crate) fn serving(&self) -> Result<Serving<'_>, PoolError> {
        let mut ledger = self.ledger.lock().map_err(|_| PoolError::Closed)?;
        if ledger.closed || ledger.started {
            return Err(PoolError::Closed);
        }
        ledger.started = true;
        Ok(Serving(self))
    }
    fn seal(&self) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.closed = true;
            for slot in &mut ledger.slots {
                slot.used = true;
                if let Some(job) = &slot.job {
                    job.abort();
                }
                slot.session.take(); // Local owners close; remote slots remain charged.
            }
        }
    }
    pub(crate) fn capacity(&self) -> DatabaseCapacity {
        let Ok(ledger) = self.ledger.lock() else {
            return DatabaseCapacity {
                capacity: 0,
                running: 0,
                reusable: 0,
                quarantined: 0,
                closed: true,
            };
        };
        let running = ledger
            .slots
            .iter()
            .filter(|slot| slot.job.as_ref().is_some_and(|job| !job.is_finished()))
            .count();
        let reusable = ledger
            .slots
            .iter()
            .filter(|slot| {
                slot.job.as_ref().is_none_or(|job| job.is_finished())
                    && slot
                        .session
                        .as_ref()
                        .is_some_and(ConnectedDatabase::is_reusable)
            })
            .count();
        let quarantined = ledger
            .slots
            .iter()
            .filter(|slot| {
                slot.used
                    && slot.job.as_ref().is_none_or(|job| job.is_finished())
                    && !slot
                        .session
                        .as_ref()
                        .is_some_and(ConnectedDatabase::is_reusable)
            })
            .count();
        DatabaseCapacity {
            capacity: ledger.slots.len(),
            running,
            reusable,
            quarantined,
            closed: ledger.closed,
        }
    }
    pub(crate) fn submit(
        &self,
        batch: Batch,
        identity: [String; 2],
        deadline: Instant,
    ) -> Result<oneshot::Receiver<Result<DurableReceipt, SubmitError>>, PoolError> {
        let (reply, receive) = oneshot::channel();
        self.start(Job::Submit(batch, identity, reply), deadline)?;
        Ok(receive)
    }
    pub(crate) fn read_authority(
        &self,
        request: AuthorityReadRequest,
        deadline: Instant,
    ) -> Result<oneshot::Receiver<Result<AuthorityRead, AuthorityError>>, PoolError> {
        let (reply, receive) = oneshot::channel();
        self.start(Job::Authority(request, reply), deadline)?;
        Ok(receive)
    }
    fn start(&self, job: Job, deadline: Instant) -> Result<(), PoolError> {
        if Instant::now() >= deadline {
            return Err(PoolError::Capacity);
        }
        let mut ledger = self.ledger.lock().map_err(|_| PoolError::Closed)?;
        if ledger.closed {
            return Err(PoolError::Closed);
        }
        let selected = ledger
            .slots
            .iter()
            .position(|slot| {
                if slot.job.as_ref().is_some_and(|job| !job.is_finished()) {
                    return false;
                }
                !slot.used
                    || slot
                        .session
                        .as_ref()
                        .is_some_and(ConnectedDatabase::is_reusable)
            })
            .ok_or(PoolError::Capacity)?;
        let slot = &mut ledger.slots[selected];
        slot.job.take();
        slot.used = true; // Before any connect/DNS poll; never reset on uncertainty.
        let existing = slot.session.take();
        let settings = self.settings.clone();
        let trust = self.trust.clone();
        let keys = self.keys.clone();
        let owner = Arc::downgrade(&self.ledger); // No job/ledger ownership cycle.
        slot.job = Some(tokio::spawn(async move {
            let mut connected = match existing {
                Some(session) => Ok(session),
                None => settings.connect_single_until(&trust, deadline).await,
            };
            let outcome = match job {
                Job::Submit(batch, identity, reply) => {
                    let result = match &mut connected {
                        Ok(session) => {
                            session
                                .submit_batch_until(
                                    &batch,
                                    [&identity[0], &identity[1]],
                                    &keys,
                                    deadline,
                                )
                                .await
                        }
                        Err(_) => Err(AuthorityError::Database.into()),
                    };
                    Outcome::Submit(reply, result)
                }
                Job::Authority(request, reply) => {
                    let result = match &mut connected {
                        Ok(session) => {
                            session
                                .read_authority_until(&request, &keys, deadline)
                                .await
                        }
                        Err(_) => Err(AuthorityError::Database),
                    };
                    Outcome::Authority(reply, Box::new(result))
                }
            };
            let mut returned = connected.ok();
            if let Some(owner) = owner.upgrade() {
                if let Ok(mut ledger) = owner.lock() {
                    if !ledger.closed {
                        ledger.slots[selected].session = returned.take();
                    }
                }
            }
            if let Some(session) = returned {
                let _ = session.close().await;
            }
            outcome.send();
        }));
        Ok(())
    }
    /// Seal without replacing sessions. Abort/join jobs and close idle owners.
    pub(crate) async fn shutdown(&self) {
        let (jobs, sessions) = {
            let Ok(mut ledger) = self.ledger.lock() else {
                return;
            };
            ledger.closed = true;
            let mut jobs = Vec::new();
            let mut sessions = Vec::new();
            for slot in &mut ledger.slots {
                slot.used = true;
                if let Some(job) = slot.job.take() {
                    job.abort();
                    jobs.push(job);
                }
                if let Some(session) = slot.session.take() {
                    sessions.push(session);
                }
            }
            (jobs, sessions)
        };
        for job in jobs {
            let _ = job.await;
        }
        let mut closing = JoinSet::new();
        for session in sessions {
            closing.spawn(async move {
                let _ = session.close().await;
            });
        }
        while closing.join_next().await.is_some() {}
    }
}
