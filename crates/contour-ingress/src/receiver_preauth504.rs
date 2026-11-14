//! One-use pre-permit proof on the existing authenticated receiver listener.
use contour_postgres::ReceiverEvidencePeer;
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::{Arc, Mutex};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};

struct Pending {
    challenge: [u8; 32],
    owner: [u8; 32],
    cid: [u8; 32],
    leaf: [u8; 32],
    deadline: Instant,
    reply: oneshot::Sender<ReceiverPossession504>,
}
struct Ledger {
    active: bool,
    closed: bool,
    pending: Vec<Pending>,
}
/// A shared handle to this server's pending-only preauthentication ledger.
#[derive(Clone)]
pub struct ReceiverPreauth504(Arc<Mutex<Ledger>>);
/// A one-use possession proof. It cannot be created from caller-provided pins.
/// ```compile_fail
/// use contour_ingress::ReceiverPossession504;
/// let _ = ReceiverPossession504 { owner: [0;32], cid: [0;32], challenge: [0;32] };
/// ```
/// ```compile_fail
/// use contour_ingress::ReceiverPossession504;
/// fn duplicate(p: &ReceiverPossession504) -> ReceiverPossession504 { p.clone() }
/// ```
pub struct ReceiverPossession504 {
    broker: ReceiverPreauth504,
    owner: [u8; 32],
    cid: [u8; 32],
    challenge: [u8; 32],
    deadline: Instant,
}
pub(crate) struct Ticket {
    broker: ReceiverPreauth504,
    challenge: [u8; 32],
    receiver: oneshot::Receiver<ReceiverPossession504>,
    deadline: Instant,
}
impl ReceiverPreauth504 {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(Ledger {
            active: false,
            closed: false,
            pending: Vec::new(),
        })))
    }
    pub(crate) fn activate(&self) -> Result<(), ()> {
        let mut l = self.0.lock().map_err(|_| ())?;
        if l.active || l.closed {
            return Err(());
        }
        l.active = true;
        Ok(())
    }
    pub(crate) fn is_active(&self) -> bool {
        self.0.lock().is_ok_and(|l| l.active && !l.closed)
    }
    pub(crate) fn seal(&self) {
        if let Ok(mut l) = self.0.lock() {
            l.active = false;
            l.closed = true;
            l.pending.clear();
        }
    }
    pub(crate) fn register(
        &self,
        owner: [u8; 32],
        cid: [u8; 32],
        leaf: [u8; 32],
        deadline: Instant,
    ) -> Result<Ticket, ()> {
        if [owner, cid, leaf].contains(&[0; 32]) || Instant::now() >= deadline {
            return Err(());
        }
        let mut challenge = [0; 32];
        SystemRandom::new().fill(&mut challenge).map_err(|_| ())?;
        let mut l = self.0.lock().map_err(|_| ())?;
        l.pending
            .retain(|p| p.deadline > Instant::now() && !p.reply.is_closed());
        if !l.active
            || l.closed
            || l.pending.len() >= 128
            || l.pending.iter().any(|p| p.challenge == challenge)
        {
            return Err(());
        }
        let (reply, receiver) = oneshot::channel();
        l.pending.push(Pending {
            challenge,
            owner,
            cid,
            leaf,
            deadline,
            reply,
        });
        Ok(Ticket {
            broker: self.clone(),
            challenge,
            receiver,
            deadline,
        })
    }
    pub(crate) fn accept(&self, bytes: &[u8], peer: &ReceiverEvidencePeer) -> bool {
        if bytes.len() != 64
            || !bytes
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return false;
        }
        let mut token = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let Ok(s) = std::str::from_utf8(pair) else {
                return false;
            };
            let Ok(v) = u8::from_str_radix(s, 16) else {
                return false;
            };
            token[i] = v;
        }
        let Ok(mut l) = self.0.lock() else {
            return false;
        };
        if !l.active || l.closed {
            return false;
        }
        let Some(i) = l.pending.iter().position(|p| p.challenge == token) else {
            return false;
        };
        // Consume even on a wrong peer or expiry; failures never leave a live challenge.
        let pending = l.pending.swap_remove(i);
        if Instant::now() >= pending.deadline || !peer.matches_pin(&pending.leaf) {
            return false;
        }
        pending
            .reply
            .send(ReceiverPossession504 {
                broker: self.clone(),
                owner: pending.owner,
                cid: pending.cid,
                challenge: pending.challenge,
                deadline: pending.deadline,
            })
            .is_ok()
    }
}
impl Ticket {
    pub(crate) fn challenge(&self) -> String {
        self.challenge.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub(crate) async fn receive(mut self) -> Result<ReceiverPossession504, ()> {
        let proof = timeout_at(self.deadline, &mut self.receiver)
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if Instant::now() >= self.deadline || proof.challenge != self.challenge {
            return Err(());
        }
        Ok(proof)
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut l) = self.broker.0.lock() {
            l.pending.retain(|p| p.challenge != self.challenge);
        }
    }
}
impl ReceiverPossession504 {
    pub(crate) fn consume(
        self,
        broker: &ReceiverPreauth504,
        owner: [u8; 32],
        cid: [u8; 32],
        deadline: Instant,
    ) -> Result<(), ()> {
        let l = broker.0.lock().map_err(|_| ())?;
        if !l.active
            || l.closed
            || !Arc::ptr_eq(&broker.0, &self.broker.0)
            || self.owner != owner
            || self.cid != cid
            || self.deadline != deadline
            || Instant::now() >= deadline
        {
            Err(())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn pending_capacity_drop_expiry_and_shutdown_are_fail_closed() {
        let broker = ReceiverPreauth504::new();
        let future = Instant::now() + Duration::from_secs(10);
        assert!(broker.register([1; 32], [2; 32], [3; 32], future).is_err());
        broker.activate().unwrap();
        assert!(
            broker
                .register([1; 32], [2; 32], [3; 32], Instant::now())
                .is_err()
        );
        let mut tickets = Vec::new();
        for _ in 0..128 {
            tickets.push(broker.register([1; 32], [2; 32], [3; 32], future).unwrap());
        }
        assert!(broker.register([1; 32], [2; 32], [3; 32], future).is_err());
        tickets.pop();
        assert!(broker.register([1; 32], [2; 32], [3; 32], future).is_ok());
        broker.seal();
        assert!(broker.register([1; 32], [2; 32], [3; 32], future).is_err());
        assert!(broker.0.lock().unwrap().pending.is_empty());
        assert!(broker.activate().is_err());
    }
    #[test]
    fn consumed_proof_is_bound_to_owner_instance_broker_and_deadline() {
        let broker = ReceiverPreauth504::new();
        broker.activate().unwrap();
        let other = ReceiverPreauth504::new();
        other.activate().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let proof = |owner, cid, deadline| ReceiverPossession504 {
            broker: broker.clone(),
            owner,
            cid,
            challenge: [4; 32],
            deadline,
        };
        assert!(
            proof([1; 32], [2; 32], deadline)
                .consume(&broker, [1; 32], [2; 32], deadline)
                .is_ok()
        );
        assert!(
            proof([1; 32], [2; 32], deadline)
                .consume(&broker, [9; 32], [2; 32], deadline)
                .is_err()
        );
        assert!(
            proof([1; 32], [2; 32], deadline)
                .consume(&broker, [1; 32], [9; 32], deadline)
                .is_err()
        );
        assert!(
            proof([1; 32], [2; 32], deadline)
                .consume(&other, [1; 32], [2; 32], deadline)
                .is_err()
        );
        assert!(
            proof([1; 32], [2; 32], deadline)
                .consume(&broker, [1; 32], [2; 32], deadline + Duration::from_secs(1))
                .is_err()
        );
        broker.seal();
        assert!(
            proof([1; 32], [2; 32], deadline)
                .consume(&broker, [1; 32], [2; 32], deadline)
                .is_err()
        );
    }
    #[test]
    fn challenge_is_not_accepted_from_arbitrary_unsealed_data() {
        let broker = ReceiverPreauth504::new();
        broker.activate().unwrap();
        let ticket = broker
            .register(
                [1; 32],
                [2; 32],
                [3; 32],
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let value = ticket.challenge();
        assert_eq!(value.len(), 64);
        assert!(
            value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(broker.0.lock().unwrap().pending.len(), 1);
        drop(ticket);
        assert!(broker.0.lock().unwrap().pending.is_empty());
    }
}

#[cfg(test)]
mod tls_tests;
