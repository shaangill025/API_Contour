//! Bounded host-side CBP1 frame and correlation checks. This is not a launch
//! capability, peer attestation, lease extension, or Docker ownership proof.
const MAX: usize = 16_424;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolError;
#[derive(Debug, PartialEq, Eq)]
pub enum RelayEvent {
    Hello { pid: u32, start: u64 },
    Spawned { pid: u32, start: u64 },
    Request(Box<[u8; 108]>),
    Ready,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Hello,
    Spawn,
    Running,
    Failed,
}
/// One checked relay sequence; the caller must discard it on EOF, timeout or
/// any partial write. A complete response write must be explicitly confirmed.
pub struct RelayCodec {
    phase: Phase,
    initial_sent: bool,
    bootstrap_transferred: bool,
    challenge: [u8; 32],
    generation: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
    buffer: Vec<u8>,
    pending: Option<Box<[u8; 108]>>,
    writing: bool,
    ready: bool,
    counter: u64,
    previous: [u8; 32],
}
impl RelayCodec {
    pub fn new(
        challenge: [u8; 32],
        generation: [u8; 32],
        identity: [u8; 32],
        epoch: u64,
    ) -> Result<Self, ProtocolError> {
        if challenge == [0; 32] || generation == [0; 32] || identity == [0; 32] || epoch == 0 {
            return Err(ProtocolError);
        }
        Ok(Self {
            phase: Phase::Hello,
            initial_sent: false,
            bootstrap_transferred: false,
            challenge,
            generation,
            identity,
            epoch,
            buffer: Vec::new(),
            pending: None,
            writing: false,
            ready: false,
            counter: 0,
            previous: [0; 32],
        })
    }
    pub fn initial_frame(&mut self) -> Result<Vec<u8>, ProtocolError> {
        if self.phase != Phase::Hello || self.initial_sent {
            return Err(ProtocolError);
        }
        self.initial_sent = true;
        encode(b'I', &self.challenge)
    }
    /// Call only after the complete one-shot bootstrap write was confirmed.
    /// On a partial or uncertain write the caller must discard this codec.
    pub fn bootstrap_transferred(&mut self) -> Result<(), ProtocolError> {
        if self.phase != Phase::Spawn || self.bootstrap_transferred {
            self.phase = Phase::Failed;
            return Err(ProtocolError);
        }
        self.bootstrap_transferred = true;
        Ok(())
    }
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<RelayEvent>, ProtocolError> {
        let result = self.push_checked(data);
        if result.is_err() {
            self.phase = Phase::Failed;
            self.buffer.fill(0);
            self.buffer.clear();
        }
        result
    }
    fn push_checked(&mut self, data: &[u8]) -> Result<Vec<RelayEvent>, ProtocolError> {
        if self.phase == Phase::Failed || data.len() > MAX + 9 - self.buffer.len() {
            return Err(ProtocolError);
        }
        self.buffer.extend_from_slice(data);
        let mut events = Vec::new();
        while self.buffer.len() >= 9 {
            if &self.buffer[..4] != b"CBP1" {
                return Err(ProtocolError);
            }
            let len = u32::from_be_bytes(self.buffer[5..9].try_into().map_err(|_| ProtocolError)?)
                as usize;
            if len > MAX {
                return Err(ProtocolError);
            }
            if self.buffer.len() < 9 + len {
                break;
            }
            let ty = self.buffer[4];
            let body = self.buffer[9..9 + len].to_vec();
            self.buffer.drain(..9 + len);
            match (self.phase, ty, body.len()) {
                (Phase::Hello, b'H', 44) => {
                    if !self.initial_sent || body[..32] != self.challenge {
                        return Err(ProtocolError);
                    }
                    let (pid, start) = pid(&body[32..])?;
                    self.phase = Phase::Spawn;
                    events.push(RelayEvent::Hello { pid, start });
                }
                (Phase::Spawn, b'S', 12) => {
                    if !self.bootstrap_transferred {
                        return Err(ProtocolError);
                    }
                    let (pid, start) = pid(&body)?;
                    self.phase = Phase::Running;
                    events.push(RelayEvent::Spawned { pid, start });
                }
                (Phase::Running, b'Q', 108) => {
                    if self.pending.is_some()
                        || self.writing
                        || &body[..4] != b"CQP1"
                        || body[4..36] != self.generation
                        || body[36..68] != self.identity
                    {
                        return Err(ProtocolError);
                    }
                    let count =
                        u64::from_be_bytes(body[68..76].try_into().map_err(|_| ProtocolError)?);
                    let challenge: [u8; 32] =
                        body[76..108].try_into().map_err(|_| ProtocolError)?;
                    if Some(count) != self.counter.checked_add(1)
                        || challenge == [0; 32]
                        || challenge == self.previous
                    {
                        return Err(ProtocolError);
                    }
                    self.counter = count;
                    self.previous = challenge;
                    let q: Box<[u8; 108]> = Box::new(body.try_into().map_err(|_| ProtocolError)?);
                    events.push(RelayEvent::Request(q.clone()));
                    self.pending = Some(q);
                }
                (Phase::Running, b'Y', 76) => {
                    if self.ready
                        || self.counter == 0
                        || self.pending.is_some()
                        || self.writing
                        || &body[..4] != b"CLR1"
                        || body[4..36] != self.generation
                        || body[36..68] != self.identity
                        || u64::from_be_bytes(body[68..76].try_into().map_err(|_| ProtocolError)?)
                            != self.epoch
                    {
                        return Err(ProtocolError);
                    }
                    self.ready = true;
                    events.push(RelayEvent::Ready);
                }
                _ => return Err(ProtocolError),
            }
        }
        Ok(events)
    }
    fn begin_reply(&mut self, response: &[u8; 120]) -> Result<Vec<u8>, ProtocolError> {
        let result = self.begin_reply_checked(response);
        if result.is_err() {
            self.phase = Phase::Failed;
            self.pending = None;
        }
        result
    }
    fn begin_reply_checked(&mut self, response: &[u8; 120]) -> Result<Vec<u8>, ProtocolError> {
        let q = self.pending.as_ref().ok_or(ProtocolError)?;
        if self.phase != Phase::Running
            || self.writing
            || &response[..4] != b"CRP1"
            || response[4..108] != q[4..108]
            || u64::from_be_bytes(response[108..116].try_into().map_err(|_| ProtocolError)?)
                != self.epoch
        {
            return Err(ProtocolError);
        }
        let ttl = u32::from_be_bytes(response[116..120].try_into().map_err(|_| ProtocolError)?);
        if !(1..=1000).contains(&ttl) {
            return Err(ProtocolError);
        }
        self.writing = true;
        encode(b'R', response)
    }
    fn finish_reply(&mut self) -> Result<(), ProtocolError> {
        if self.phase != Phase::Running || !self.writing || self.pending.is_none() {
            self.phase = Phase::Failed;
            return Err(ProtocolError);
        }
        self.pending = None;
        self.writing = false;
        Ok(())
    }
    /// Forward one exact checked CRP response under the caller's retained
    /// deadline. A timeout, partial write, error or cancellation is terminal.
    pub async fn write_reply<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        response: &[u8; 120],
        deadline: tokio::time::Instant,
    ) -> Result<(), ProtocolError> {
        use tokio::io::AsyncWriteExt;
        if tokio::time::Instant::now() >= deadline {
            self.phase = Phase::Failed;
            return Err(ProtocolError);
        }
        let frame = self.begin_reply(response)?;
        struct Guard<'a> {
            codec: &'a mut RelayCodec,
            complete: bool,
        }
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                if !self.complete {
                    self.codec.phase = Phase::Failed;
                    self.codec.pending = None;
                }
            }
        }
        let mut guard = Guard {
            codec: self,
            complete: false,
        };
        tokio::time::timeout_at(deadline, async {
            writer.write_all(&frame).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| ProtocolError)?
        .map_err(|_| ProtocolError)?;
        guard.codec.finish_reply()?;
        guard.complete = true;
        Ok(())
    }
    pub fn end(&mut self) -> Result<(), ProtocolError> {
        self.phase = Phase::Failed;
        if self.buffer.is_empty() {
            Ok(())
        } else {
            self.buffer.fill(0);
            self.buffer.clear();
            Err(ProtocolError)
        }
    }
}
fn pid(body: &[u8]) -> Result<(u32, u64), ProtocolError> {
    let p = u32::from_be_bytes(body[..4].try_into().map_err(|_| ProtocolError)?);
    let s = u64::from_be_bytes(body[4..12].try_into().map_err(|_| ProtocolError)?);
    if p == 0 || s == 0 {
        Err(ProtocolError)
    } else {
        Ok((p, s))
    }
}
fn encode(kind: u8, body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() > MAX {
        return Err(ProtocolError);
    }
    let mut out = Vec::with_capacity(9 + body.len());
    out.extend_from_slice(b"CBP1");
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready() -> RelayCodec {
        let mut c = RelayCodec::new([1; 32], [2; 32], [3; 32], 9).unwrap();
        c.initial_frame().unwrap();
        let mut h = [0u8; 44];
        h[..32].fill(1);
        h[35] = 1;
        h[43] = 2;
        assert!(matches!(
            c.push(&encode(b'H', &h).unwrap()).unwrap()[0],
            RelayEvent::Hello { .. }
        ));
        c.bootstrap_transferred().unwrap();
        let mut s = [0u8; 12];
        s[3] = 1;
        s[11] = 2;
        assert!(matches!(
            c.push(&encode(b'S', &s).unwrap()).unwrap()[0],
            RelayEvent::Spawned { .. }
        ));
        c
    }
    fn request() -> [u8; 108] {
        let mut q = [0; 108];
        q[..4].copy_from_slice(b"CQP1");
        q[4..36].fill(2);
        q[36..68].fill(3);
        q[75] = 1;
        q[76..].fill(4);
        q
    }
    #[test]
    fn fragmentation_and_one_outstanding_request() {
        let mut c = ready();
        let q = request();
        let frame = encode(b'Q', &q).unwrap();
        let mut events = vec![];
        for byte in frame {
            events.extend(c.push(&[byte]).unwrap());
        }
        assert!(matches!(&events[..], [RelayEvent::Request(_)]));
        assert!(c.push(&encode(b'Q', &q).unwrap()).is_err());
    }
    #[test]
    fn reply_must_match_epoch_ttl_and_be_completed_before_next_request() {
        let mut c = ready();
        let q = request();
        c.push(&encode(b'Q', &q).unwrap()).unwrap();
        let mut r = [0; 120];
        r[..4].copy_from_slice(b"CRP1");
        r[4..108].copy_from_slice(&q[4..]);
        r[115] = 9;
        r[118..].copy_from_slice(&500u16.to_be_bytes());
        assert!(c.begin_reply(&r).is_ok());
        assert!(c.finish_reply().is_ok());
        assert!(c.finish_reply().is_err());
    }
    #[test]
    fn timed_out_or_partial_response_write_is_terminal() {
        use std::{
            io,
            pin::Pin,
            task::{Context, Poll},
        };
        struct Pending;
        impl tokio::io::AsyncWrite for Pending {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut c = ready();
            let q = request();
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            let mut r = [0; 120];
            r[..4].copy_from_slice(b"CRP1");
            r[4..108].copy_from_slice(&q[4..]);
            r[115] = 9;
            r[118..].copy_from_slice(&500u16.to_be_bytes());
            let mut sink = Pending;
            assert!(
                c.write_reply(
                    &mut sink,
                    &r,
                    tokio::time::Instant::now() + std::time::Duration::from_millis(5)
                )
                .await
                .is_err()
            );
            assert!(c.push(&[]).is_err());
        });
    }
    #[test]
    fn duplex_reply_is_exact_and_partial_write_never_retries() {
        use std::{
            io,
            pin::Pin,
            task::{Context, Poll},
        };
        use tokio::io::AsyncReadExt;
        struct Partial(bool);
        impl tokio::io::AsyncWrite for Partial {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                if !self.0 {
                    self.0 = true;
                    Poll::Ready(Ok(bytes.len().min(3)))
                } else {
                    Poll::Ready(Err(io::Error::other("controlled")))
                }
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let q = request();
            let mut r = [0; 120];
            r[..4].copy_from_slice(b"CRP1");
            r[4..108].copy_from_slice(&q[4..]);
            r[115] = 9;
            r[118..].copy_from_slice(&500u16.to_be_bytes());
            let mut c = ready();
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            let (mut a, mut b) = tokio::io::duplex(256);
            c.write_reply(
                &mut a,
                &r,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
            let mut observed = [0; 129];
            b.read_exact(&mut observed).await.unwrap();
            assert_eq!(observed, encode(b'R', &r).unwrap().as_slice());
            let mut c = ready();
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            let mut fail = Partial(false);
            assert!(
                c.write_reply(
                    &mut fail,
                    &r,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(1)
                )
                .await
                .is_err()
            );
            assert!(c.push(&[]).is_err());
        });
    }
    #[test]
    fn failed_response_flush_is_terminal() {
        use std::{
            io,
            pin::Pin,
            task::{Context, Poll},
        };
        struct FlushFailure;
        impl tokio::io::AsyncWrite for FlushFailure {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Err(io::Error::other("controlled")))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut c = ready();
            let q = request();
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            let mut r = [0; 120];
            r[..4].copy_from_slice(b"CRP1");
            r[4..108].copy_from_slice(&q[4..]);
            r[115] = 9;
            r[118..].copy_from_slice(&500u16.to_be_bytes());
            assert!(
                c.write_reply(
                    &mut FlushFailure,
                    &r,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(1)
                )
                .await
                .is_err()
            );
            assert!(c.push(&[]).is_err());
        });
    }
    #[test]
    fn dropping_pending_response_future_fails_closed() {
        use std::{
            future::Future,
            io,
            pin::Pin,
            task::{Context, Poll},
        };
        struct Pending;
        impl tokio::io::AsyncWrite for Pending {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut c = ready();
            let q = request();
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            let mut r = [0; 120];
            r[..4].copy_from_slice(b"CRP1");
            r[4..108].copy_from_slice(&q[4..]);
            r[115] = 9;
            r[118..].copy_from_slice(&500u16.to_be_bytes());
            let mut sink = Pending;
            let mut f = Box::pin(c.write_reply(
                &mut sink,
                &r,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            ));
            std::future::poll_fn(|cx| {
                assert!(matches!(f.as_mut().poll(cx), Poll::Pending));
                Poll::Ready(())
            })
            .await;
            drop(f);
            assert!(c.push(&[]).is_err());
        });
    }
    #[test]
    fn phase_order_and_ready_require_a_completed_permit() {
        let mut h = [0u8; 44];
        h[..32].fill(1);
        h[35] = 1;
        h[43] = 2;
        let mut c = RelayCodec::new([1; 32], [2; 32], [3; 32], 9).unwrap();
        assert!(c.push(&encode(b'H', &h).unwrap()).is_err());
        let mut c = RelayCodec::new([1; 32], [2; 32], [3; 32], 9).unwrap();
        assert!(c.initial_frame().is_ok());
        assert!(c.initial_frame().is_err());
        c.push(&encode(b'H', &h).unwrap()).unwrap();
        let mut spawn = [0u8; 12];
        spawn[3] = 1;
        spawn[11] = 2;
        assert!(c.push(&encode(b'S', &spawn).unwrap()).is_err());
        let mut c = ready();
        let mut status = [0u8; 76];
        status[..4].copy_from_slice(b"CLR1");
        status[4..36].fill(2);
        status[36..68].fill(3);
        status[75] = 9;
        assert!(c.push(&encode(b'Y', &status).unwrap()).is_err());
    }
    #[test]
    fn wrong_reply_or_replayed_ready_is_terminal() {
        let mut c = ready();
        let q = request();
        c.push(&encode(b'Q', &q).unwrap()).unwrap();
        let mut reply = [0u8; 120];
        reply[..4].copy_from_slice(b"CRP1");
        assert!(c.begin_reply(&reply).is_err());
        assert!(c.push(&[]).is_err());
        let mut c = ready();
        let q = request();
        c.push(&encode(b'Q', &q).unwrap()).unwrap();
        let mut reply = [0u8; 120];
        reply[..4].copy_from_slice(b"CRP1");
        reply[4..108].copy_from_slice(&q[4..]);
        reply[115] = 9;
        reply[119] = 1;
        c.begin_reply(&reply).unwrap();
        c.finish_reply().unwrap();
        let mut status = [0u8; 76];
        status[..4].copy_from_slice(b"CLR1");
        status[4..36].fill(2);
        status[36..68].fill(3);
        status[75] = 9;
        assert_eq!(
            c.push(&encode(b'Y', &status).unwrap()).unwrap(),
            vec![RelayEvent::Ready]
        );
        assert!(c.push(&encode(b'Y', &status).unwrap()).is_err());
    }
    #[test]
    fn malformed_or_trailing_eof_fails() {
        let mut c = ready();
        assert!(c.push(b"CBP1Q\0\0").unwrap().is_empty());
        assert!(c.end().is_err());
        let mut c = ready();
        assert!(c.push(b"\xc3BP1Q\0\0\0\0").is_err());
    }
}
