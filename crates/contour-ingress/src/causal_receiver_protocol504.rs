//! Data-only post-hello CBP2 framing and correlation checks. Construction and
//! successful checks do not establish authority, peer identity, or a lease.
const MAX: usize = 16_424;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverProtocolError504;
#[derive(Debug, PartialEq, Eq)]
pub enum ReceiverRelayEvent504 {
    Spawned { pid: u32, start: u64 },
    Request(Box<[u8; 140]>),
    Ready,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Spawn,
    Running,
    Failed,
}
/// One checked relay sequence; the caller must discard it on EOF, timeout or
/// any partial write. A complete response write must be explicitly confirmed.
pub struct ReceiverRelayCodec504 {
    phase: Phase,
    bootstrap_transferred: bool,
    enrollment: [u8; 32],
    generation: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
    buffer: Vec<u8>,
    pending: Option<Box<[u8; 140]>>,
    writing: bool,
    ready: bool,
    counter: u64,
    previous: [u8; 32],
}
impl ReceiverRelayCodec504 {
    /// Construct after the caller has separately verified the hello. The supplied
    /// values are data, not proof of that verification or launch authority.
    pub fn new(
        generation: [u8; 32],
        identity: [u8; 32],
        epoch: u64,
        enrollment: [u8; 32],
    ) -> Result<Self, ReceiverProtocolError504> {
        if generation == [0; 32] || identity == [0; 32] || enrollment == [0; 32] || epoch == 0 {
            return Err(ReceiverProtocolError504);
        }
        Ok(Self {
            phase: Phase::Spawn,
            bootstrap_transferred: false,
            enrollment,
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
    /// Send one CLB2 bootstrap frame containing caller-supplied checked descriptor
    /// bytes and seed. This validates framing only and does not establish authority.
    /// Any timeout, cancellation, write or flush error permanently fails the codec.
    pub async fn write_bootstrap<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        descriptor: &[u8],
        seed: &[u8; 32],
        deadline: tokio::time::Instant,
    ) -> Result<(), ReceiverProtocolError504> {
        use tokio::io::AsyncWriteExt;
        if self.phase != Phase::Spawn
            || self.bootstrap_transferred
            || descriptor.is_empty()
            || descriptor.len() > 16_384
            || tokio::time::Instant::now() >= deadline
        {
            self.phase = Phase::Failed;
            return Err(ReceiverProtocolError504);
        }
        let mut body = Vec::with_capacity(8 + descriptor.len() + 32);
        body.extend_from_slice(b"CLB2");
        body.extend_from_slice(&(descriptor.len() as u32).to_be_bytes());
        body.extend_from_slice(descriptor);
        body.extend_from_slice(seed);
        struct EraseFrame(Vec<u8>);
        impl Drop for EraseFrame {
            fn drop(&mut self) {
                self.0.fill(0);
            }
        }
        let frame = EraseFrame(encode(b'B', &body)?);
        body.fill(0);
        struct Guard<'a>(&'a mut ReceiverRelayCodec504, bool);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                if !self.1 {
                    self.0.phase = Phase::Failed;
                }
            }
        }
        let mut guard = Guard(self, false);
        tokio::time::timeout_at(deadline, async {
            writer.write_all(&frame.0).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| ReceiverProtocolError504)?
        .map_err(|_| ReceiverProtocolError504)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(ReceiverProtocolError504);
        }
        guard.0.bootstrap_transferred = true;
        guard.1 = true;
        Ok(())
    }
    pub fn push(
        &mut self,
        data: &[u8],
    ) -> Result<Vec<ReceiverRelayEvent504>, ReceiverProtocolError504> {
        let result = self.push_checked(data);
        if result.is_err() {
            self.phase = Phase::Failed;
            self.buffer.fill(0);
            self.buffer.clear();
        }
        result
    }
    fn push_checked(
        &mut self,
        data: &[u8],
    ) -> Result<Vec<ReceiverRelayEvent504>, ReceiverProtocolError504> {
        if self.phase == Phase::Failed
            || (self.phase == Phase::Spawn && !self.bootstrap_transferred && !data.is_empty())
            || data.len() > MAX + 9 - self.buffer.len()
        {
            return Err(ReceiverProtocolError504);
        }
        self.buffer.extend_from_slice(data);
        let mut events = Vec::new();
        while self.buffer.len() >= 9 {
            if &self.buffer[..4] != b"CBP2" {
                return Err(ReceiverProtocolError504);
            }
            let len = u32::from_be_bytes(
                self.buffer[5..9]
                    .try_into()
                    .map_err(|_| ReceiverProtocolError504)?,
            ) as usize;
            if len > MAX {
                return Err(ReceiverProtocolError504);
            }
            if self.buffer.len() < 9 + len {
                break;
            }
            let ty = self.buffer[4];
            let body = self.buffer[9..9 + len].to_vec();
            self.buffer.drain(..9 + len);
            match (self.phase, ty, body.len()) {
                (Phase::Spawn, b'S', 12) => {
                    if !self.bootstrap_transferred {
                        return Err(ReceiverProtocolError504);
                    }
                    let (pid, start) = pid(&body)?;
                    self.phase = Phase::Running;
                    events.push(ReceiverRelayEvent504::Spawned { pid, start });
                }
                (Phase::Running, b'Q', 140) => {
                    if self.pending.is_some()
                        || self.writing
                        || &body[..4] != b"CQP2"
                        || body[4..36] != self.generation
                        || body[36..68] != self.identity
                        || body[108..140] != self.enrollment
                    {
                        return Err(ReceiverProtocolError504);
                    }
                    let count = u64::from_be_bytes(
                        body[68..76]
                            .try_into()
                            .map_err(|_| ReceiverProtocolError504)?,
                    );
                    let challenge: [u8; 32] = body[76..108]
                        .try_into()
                        .map_err(|_| ReceiverProtocolError504)?;
                    if Some(count) != self.counter.checked_add(1)
                        || challenge == [0; 32]
                        || challenge == self.previous
                    {
                        return Err(ReceiverProtocolError504);
                    }
                    self.counter = count;
                    self.previous = challenge;
                    let q: Box<[u8; 140]> =
                        Box::new(body.try_into().map_err(|_| ReceiverProtocolError504)?);
                    events.push(ReceiverRelayEvent504::Request(q.clone()));
                    self.pending = Some(q);
                }
                (Phase::Running, b'Y', 76) => {
                    if self.ready
                        || self.counter == 0
                        || self.pending.is_some()
                        || self.writing
                        || &body[..4] != b"CLR2"
                        || body[4..36] != self.generation
                        || body[36..68] != self.identity
                        || u64::from_be_bytes(
                            body[68..76]
                                .try_into()
                                .map_err(|_| ReceiverProtocolError504)?,
                        ) != self.epoch
                    {
                        return Err(ReceiverProtocolError504);
                    }
                    self.ready = true;
                    events.push(ReceiverRelayEvent504::Ready);
                }
                _ => return Err(ReceiverProtocolError504),
            }
        }
        if !self.buffer.is_empty() {
            let prefix = &self.buffer;
            let magic_len = prefix.len().min(4);
            if prefix[..magic_len] != b"CBP2"[..magic_len] {
                return Err(ReceiverProtocolError504);
            }
            if prefix.len() > 4 {
                let expected = match (self.phase, prefix[4]) {
                    (Phase::Spawn, b'S') => 12u32,
                    (Phase::Running, b'Q') => 140u32,
                    (Phase::Running, b'Y') if !self.ready => 76u32,
                    _ => return Err(ReceiverProtocolError504),
                }
                .to_be_bytes();
                let available = (prefix.len() - 5).min(4);
                if prefix[5..5 + available] != expected[..available] {
                    return Err(ReceiverProtocolError504);
                }
            }
        }
        // A request is the only outstanding child message until its reply is
        // fully written. Even a partial next header is therefore premature.
        if self.pending.is_some() && !self.buffer.is_empty() {
            return Err(ReceiverProtocolError504);
        }
        Ok(events)
    }
    fn begin_reply(&mut self, response: &[u8; 152]) -> Result<Vec<u8>, ReceiverProtocolError504> {
        let result = self.begin_reply_checked(response);
        if result.is_err() {
            self.phase = Phase::Failed;
            self.pending = None;
        }
        result
    }
    fn begin_reply_checked(
        &mut self,
        response: &[u8; 152],
    ) -> Result<Vec<u8>, ReceiverProtocolError504> {
        let q = self.pending.as_ref().ok_or(ReceiverProtocolError504)?;
        if self.phase != Phase::Running
            || self.writing
            || !self.buffer.is_empty()
            || &response[..4] != b"CRP2"
            || response[4..140] != q[4..140]
            || u64::from_be_bytes(
                response[140..148]
                    .try_into()
                    .map_err(|_| ReceiverProtocolError504)?,
            ) != self.epoch
        {
            return Err(ReceiverProtocolError504);
        }
        let ttl = u32::from_be_bytes(
            response[148..152]
                .try_into()
                .map_err(|_| ReceiverProtocolError504)?,
        );
        if !(1..=1000).contains(&ttl) {
            return Err(ReceiverProtocolError504);
        }
        self.writing = true;
        encode(b'R', response)
    }
    fn finish_reply(&mut self) -> Result<(), ReceiverProtocolError504> {
        if self.phase != Phase::Running || !self.writing || self.pending.is_none() {
            self.phase = Phase::Failed;
            return Err(ReceiverProtocolError504);
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
        response: &[u8; 152],
        deadline: tokio::time::Instant,
    ) -> Result<(), ReceiverProtocolError504> {
        use tokio::io::AsyncWriteExt;
        if tokio::time::Instant::now() >= deadline {
            self.phase = Phase::Failed;
            return Err(ReceiverProtocolError504);
        }
        let frame = self.begin_reply(response)?;
        struct Guard<'a> {
            codec: &'a mut ReceiverRelayCodec504,
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
        .map_err(|_| ReceiverProtocolError504)?
        .map_err(|_| ReceiverProtocolError504)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(ReceiverProtocolError504);
        }
        guard.codec.finish_reply()?;
        guard.complete = true;
        Ok(())
    }
    pub fn end(&mut self) -> Result<(), ReceiverProtocolError504> {
        self.phase = Phase::Failed;
        if self.buffer.is_empty() {
            Ok(())
        } else {
            self.buffer.fill(0);
            self.buffer.clear();
            Err(ReceiverProtocolError504)
        }
    }
}
fn pid(body: &[u8]) -> Result<(u32, u64), ReceiverProtocolError504> {
    let p = u32::from_be_bytes(body[..4].try_into().map_err(|_| ReceiverProtocolError504)?);
    let s = u64::from_be_bytes(
        body[4..12]
            .try_into()
            .map_err(|_| ReceiverProtocolError504)?,
    );
    if p == 0 || s == 0 {
        Err(ReceiverProtocolError504)
    } else {
        Ok((p, s))
    }
}
fn encode(kind: u8, body: &[u8]) -> Result<Vec<u8>, ReceiverProtocolError504> {
    if body.len() > MAX {
        return Err(ReceiverProtocolError504);
    }
    let mut out = Vec::with_capacity(9 + body.len());
    out.extend_from_slice(b"CBP2");
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        io,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::AsyncReadExt;

    fn codec() -> ReceiverRelayCodec504 {
        ReceiverRelayCodec504::new([2; 32], [3; 32], 9, [5; 32]).unwrap()
    }
    fn spawn() -> Vec<u8> {
        let mut b = [0; 12];
        b[3] = 1;
        b[11] = 2;
        encode(b'S', &b).unwrap()
    }
    fn request(n: u64, challenge: u8) -> [u8; 140] {
        let mut q = [0; 140];
        q[..4].copy_from_slice(b"CQP2");
        q[4..36].fill(2);
        q[36..68].fill(3);
        q[68..76].copy_from_slice(&n.to_be_bytes());
        q[76..108].fill(challenge);
        q[108..].fill(5);
        q
    }
    fn reply(q: &[u8; 140]) -> [u8; 152] {
        let mut r = [0; 152];
        r[..4].copy_from_slice(b"CRP2");
        r[4..140].copy_from_slice(&q[4..]);
        r[140..148].copy_from_slice(&9u64.to_be_bytes());
        r[148..].copy_from_slice(&1000u32.to_be_bytes());
        r
    }
    fn ready_frame() -> Vec<u8> {
        let mut y = [0; 76];
        y[..4].copy_from_slice(b"CLR2");
        y[4..36].fill(2);
        y[36..68].fill(3);
        y[68..].copy_from_slice(&9u64.to_be_bytes());
        encode(b'Y', &y).unwrap()
    }
    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }
    async fn started() -> ReceiverRelayCodec504 {
        let mut c = codec();
        let mut out = Vec::new();
        c.write_bootstrap(
            &mut out,
            b"descriptor",
            &[7; 32],
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(&out[..9], b"CBP2B\0\0\x002");
        c.push(&spawn()).unwrap();
        c
    }
    #[test]
    fn bootstrap_spawn_and_fragmented_request() {
        rt().block_on(async {
            let mut c = codec();
            assert!(c.push(&spawn()).is_err());
            let mut c = started().await;
            let q = request(1, 4);
            let mut events = Vec::new();
            for b in encode(b'Q', &q).unwrap() {
                events.extend(c.push(&[b]).unwrap());
            }
            assert_eq!(events, vec![ReceiverRelayEvent504::Request(Box::new(q))]);
            assert!(c.push(&encode(b'Q', &q).unwrap()).is_err());
        });
    }
    #[test]
    fn coalesced_spawn_request_and_early_reply() {
        rt().block_on(async {
            let mut c = codec();
            c.write_bootstrap(
                &mut Vec::new(),
                b"descriptor",
                &[7; 32],
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
            let q = request(1, 4);
            let mut frames = spawn();
            frames.extend_from_slice(&encode(b'Q', &q).unwrap());
            assert_eq!(
                c.push(&frames).unwrap(),
                vec![
                    ReceiverRelayEvent504::Spawned { pid: 1, start: 2 },
                    ReceiverRelayEvent504::Request(Box::new(q))
                ]
            );
            let mut early = started().await;
            assert!(
                early
                    .write_reply(
                        &mut Vec::new(),
                        &reply(&q),
                        tokio::time::Instant::now() + Duration::from_secs(1)
                    )
                    .await
                    .is_err()
            );
            assert!(early.push(&[]).is_err());
        });
    }
    #[test]
    fn request_with_partial_next_frame_never_writes_a_reply() {
        rt().block_on(async {
            let q = request(1, 4);
            let next = ready_frame();
            for size in 1..=8 {
                let mut c = started().await;
                let mut data = encode(b'Q', &q).unwrap();
                data.extend_from_slice(&next[..size]);
                assert!(c.push(&data).is_err());
                let mut output = Vec::new();
                assert!(
                    c.write_reply(
                        &mut output,
                        &reply(&q),
                        tokio::time::Instant::now() + Duration::from_secs(1)
                    )
                    .await
                    .is_err()
                );
                assert!(output.is_empty());
                assert!(c.push(&next[size..]).is_err());
            }
            let mut c = codec();
            assert!(c.push(&spawn()[..1]).is_err());
            let mut output = Vec::new();
            assert!(
                c.write_bootstrap(
                    &mut output,
                    b"descriptor",
                    &[7; 32],
                    tokio::time::Instant::now() + Duration::from_secs(1)
                )
                .await
                .is_err()
            );
            assert!(output.is_empty());
        });
    }
    #[test]
    fn ready_rejects_bad_partial_headers_but_allows_fragmented_next_request() {
        rt().block_on(async {
            for size in 1..=8 {
                let mut c = started().await;
                let q = request(1, 4);
                c.push(&encode(b'Q', &q).unwrap()).unwrap();
                c.write_reply(
                    &mut Vec::new(),
                    &reply(&q),
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .unwrap();
                let mut header = encode(b'Q', &request(2, 6)).unwrap();
                header[size - 1] ^= 0xff;
                let mut data = ready_frame();
                data.extend_from_slice(&header[..size]);
                assert!(c.push(&data).is_err());
            }
            let mut c = started().await;
            let q = request(1, 4);
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            c.write_reply(
                &mut Vec::new(),
                &reply(&q),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
            let next = encode(b'Q', &request(2, 6)).unwrap();
            let mut data = ready_frame();
            data.extend_from_slice(&next[..8]);
            assert_eq!(c.push(&data).unwrap(), vec![ReceiverRelayEvent504::Ready]);
            assert_eq!(
                c.push(&next[8..]).unwrap(),
                vec![ReceiverRelayEvent504::Request(Box::new(request(2, 6)))]
            );
        });
    }
    #[test]
    fn scoped_sequence_ready_and_duplicate() {
        rt().block_on(async {
            let mut c = started().await;
            let q = request(1, 4);
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            let (mut a, mut b) = tokio::io::duplex(256);
            let r = reply(&q);
            c.write_reply(
                &mut a,
                &r,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
            let mut got = [0; 161];
            b.read_exact(&mut got).await.unwrap();
            assert_eq!(got.as_slice(), encode(b'R', &r).unwrap());
            assert_eq!(
                c.push(&ready_frame()).unwrap(),
                vec![ReceiverRelayEvent504::Ready]
            );
            assert!(c.push(&ready_frame()).is_err());
            let mut c = started().await;
            let mut q = request(1, 4);
            q[108] ^= 1;
            assert!(c.push(&encode(b'Q', &q).unwrap()).is_err());
            let mut c = started().await;
            assert!(c.push(&ready_frame()).is_err());
            let mut c = started().await;
            let q = request(1, 4);
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            let mut r = reply(&q);
            r[151] = 0;
            r[150] = 0;
            assert!(
                c.write_reply(
                    &mut Vec::new(),
                    &r,
                    tokio::time::Instant::now() + Duration::from_secs(1)
                )
                .await
                .is_err()
            );
        });
    }
    #[test]
    fn framing_counter_challenge_and_eof_fail_closed() {
        rt().block_on(async {
            let mut c = started().await;
            let mut both = spawn();
            both.extend_from_slice(&encode(b'Q', &request(1, 4)).unwrap());
            assert!(c.push(&both).is_err());
            let mut c = started().await;
            let mut f = encode(b'Q', &request(1, 4)).unwrap();
            f.extend_from_slice(b"trailerxx");
            assert!(c.push(&f).is_err());
            let mut c = started().await;
            assert!(c.push(b"CBP2Q\0\0").unwrap().is_empty());
            assert!(c.end().is_err());
            assert!(c.push(&[]).is_err());
            let mut c = started().await;
            assert!(c.push(&encode(b'Q', &request(2, 4)).unwrap()).is_err());
            let mut c = started().await;
            assert!(c.push(&encode(b'Q', &request(1, 0)).unwrap()).is_err());
            let mut c = started().await;
            let q = request(1, 4);
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            c.write_reply(
                &mut Vec::new(),
                &reply(&q),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
            assert!(c.push(&encode(b'Q', &request(2, 4)).unwrap()).is_err());
        });
    }
    struct Partial(bool);
    impl tokio::io::AsyncWrite for Partial {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.0 {
                self.0 = true;
                Poll::Ready(Ok(b.len().min(3)))
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
    struct Late;
    impl tokio::io::AsyncWrite for Late {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            std::thread::sleep(Duration::from_millis(10));
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[test]
    fn writes_completing_after_deadline_are_terminal() {
        rt().block_on(async {
            let mut c = codec();
            assert!(
                c.write_bootstrap(
                    &mut Late,
                    b"descriptor",
                    &[7; 32],
                    tokio::time::Instant::now() + Duration::from_millis(1)
                )
                .await
                .is_err()
            );
            assert!(c.push(&[]).is_err());
            let mut c = started().await;
            let q = request(1, 4);
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            assert!(
                c.write_reply(
                    &mut Late,
                    &reply(&q),
                    tokio::time::Instant::now() + Duration::from_millis(1)
                )
                .await
                .is_err()
            );
            assert!(c.push(&[]).is_err());
        });
    }
    #[test]
    fn writes_fail_terminal_on_error_deadline_and_cancellation() {
        rt().block_on(async {
            let mut c = codec();
            assert!(
                c.write_bootstrap(
                    &mut Partial(false),
                    b"d",
                    &[1; 32],
                    tokio::time::Instant::now() + Duration::from_secs(1)
                )
                .await
                .is_err()
            );
            assert!(c.push(&[]).is_err());
            let mut c = started().await;
            let q = request(1, 4);
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            assert!(
                c.write_reply(
                    &mut Pending,
                    &reply(&q),
                    tokio::time::Instant::now() + Duration::from_millis(1)
                )
                .await
                .is_err()
            );
            assert!(c.push(&[]).is_err());
            let mut c = started().await;
            let q = request(1, 4);
            c.push(&encode(b'Q', &q).unwrap()).unwrap();
            let r = reply(&q);
            let mut sink = Pending;
            let mut future = Box::pin(c.write_reply(
                &mut sink,
                &r,
                tokio::time::Instant::now() + Duration::from_secs(1),
            ));
            std::future::poll_fn(|cx| {
                assert!(future.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(future);
            assert!(c.push(&[]).is_err());
        });
    }
}
