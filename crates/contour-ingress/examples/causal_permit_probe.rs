//! Synthetic owned control-boundary probe. Never use real credentials.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_ingress::{CausalIssueOwner, CausalPermitOwner};
use contour_postgres::{
    CausalBinding, CausalError, CausalIssue, CausalIssuer, DatabaseSettings, TrustedCa,
};
use std::{
    env,
    fs::File,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const CHILD: &str = r#"
'use strict';
const fs=require('fs'),crypto=require('crypto'),permitModule=require(process.argv[2]),markerModule=require(process.argv[3]);
const fd=Number(process.argv[1]),boot=Buffer.alloc(64);let off=0;while(off<64){const n=fs.readSync(fd,boot,off,64-off,null);if(!n)throw Error('bootstrap');off+=n;}
const p=permitModule.create({fd,generation:boot.subarray(0,32),identity:boot.subarray(32)});
p.ready.then(()=>{const a=p.authority();if(!a)throw Error('permit');const signer=markerModule.createMarkerSigner(crypto.randomBytes(32));let closed=0;
const wrapped=p.bind({producer:{close(){closed++;}},exporter:{close(){closed++;}},signer});
const payload={tenant_id:process.argv[4],runtime_id:process.argv[5],session_epoch:a.epoch,product_leaf_sha256:'11'.repeat(32),root:'aa'.repeat(16),activity:'bb'.repeat(16),attempt:'cc'.repeat(16)};
wrapped.sign(payload);process.stdout.write('ACTIVE\n');
const timer=setInterval(()=>{try{wrapped.sign(payload);}catch(_){clearInterval(timer);if(p.authority()!==undefined||closed!==2)throw Error('invalidation');try{wrapped.sign(payload);throw Error('signed after invalidation');}catch(e){if(e.message==='signed after invalidation')throw e;}process.stdout.write('STOPPED\n');}},10);
},()=>{throw Error('no permit');});
"#;
const EXPECTED: &[u8] = b"ACTIVE\nSTOPPED\n";
struct ChildProtocol {
    bytes: Vec<u8>,
}
impl ChildProtocol {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }
    fn feed(&mut self, data: &[u8]) -> Result<u8, &'static str> {
        let before = self.bytes.len();
        if data.len() > EXPECTED.len().saturating_sub(before) {
            return Err("output");
        }
        self.bytes.extend_from_slice(data);
        if !EXPECTED.starts_with(&self.bytes) {
            return Err("output");
        }
        let mut markers = 0;
        if before < 7 && self.bytes.len() >= 7 {
            markers |= 1;
        }
        if before < EXPECTED.len() && self.bytes.len() == EXPECTED.len() {
            markers |= 2;
        }
        Ok(markers)
    }
    fn eof(&self) -> Result<(), &'static str> {
        if self.bytes == EXPECTED {
            Ok(())
        } else {
            Err("output")
        }
    }
}
enum ChildEvent {
    Output(Vec<u8>),
    OutputEof,
    ErrorData,
    ErrorEof,
    Failure,
    ControlStop,
    ControlFailure,
}
fn control_reader(
    fd: i32,
    tx: tokio::sync::mpsc::Sender<ChildEvent>,
    done: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut input = Vec::with_capacity(5);
        while !done.load(Ordering::Acquire) {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd points to one valid pollfd for the duration of the call.
            let ready = unsafe { libc::poll(&mut pfd, 1, 100) };
            if ready < 0 {
                let _ = tx.blocking_send(ChildEvent::ControlFailure);
                return;
            }
            if ready == 0 {
                continue;
            }
            let mut byte = [0u8; 1];
            // SAFETY: byte is a valid writable one-byte buffer and fd stays open until join.
            let received = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
            match received {
                0 if input.is_empty() => {
                    let _ = tx.blocking_send(ChildEvent::ControlStop);
                    return;
                }
                1 => {
                    input.push(byte[0]);
                    if !b"STOP\n".starts_with(&input) {
                        let _ = tx.blocking_send(ChildEvent::ControlFailure);
                        return;
                    }
                    if input == b"STOP\n" {
                        let _ = tx.blocking_send(ChildEvent::ControlStop);
                        return;
                    }
                }
                _ => {
                    let _ = tx.blocking_send(ChildEvent::ControlFailure);
                    return;
                }
            }
        }
    })
}
fn drain<R: Read + Send + 'static>(
    mut stream: R,
    error: bool,
    tx: tokio::sync::mpsc::Sender<ChildEvent>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut bytes = [0u8; 32];
        loop {
            let event = match stream.read(&mut bytes) {
                Ok(0) => {
                    if error {
                        ChildEvent::ErrorEof
                    } else {
                        ChildEvent::OutputEof
                    }
                }
                Ok(_) if error => ChildEvent::ErrorData,
                Ok(n) => ChildEvent::Output(bytes[..n].to_vec()),
                Err(_) => ChildEvent::Failure,
            };
            let terminal = matches!(
                event,
                ChildEvent::OutputEof
                    | ChildEvent::ErrorEof
                    | ChildEvent::ErrorData
                    | ChildEvent::Failure
            );
            if tx.blocking_send(event).is_err() || terminal {
                return;
            }
        }
    })
}
fn read(p: &str) -> Result<Vec<u8>, &'static str> {
    let mut v = Vec::new();
    File::open(p)
        .map_err(|_| "input")?
        .take(1_048_577)
        .read_to_end(&mut v)
        .map_err(|_| "input")?;
    if v.len() > 1_048_576 {
        return Err("input");
    }
    Ok(v)
}
fn run() -> Result<(), &'static str> {
    let a: Vec<_> = env::args().skip(1).collect();
    if a.len() != 27 {
        return Err("arguments");
    }
    let mut peer = [0u8; 32];
    if a[11].len() != 64 || !a[11].is_ascii() {
        return Err("peer");
    }
    for (i, b) in peer.iter_mut().enumerate() {
        *b = u8::from_str_radix(&a[11][2 * i..2 * i + 2], 16).map_err(|_| "peer")?;
    }
    let ids: [&str; 10] = std::array::from_fn(|i| a[12 + i].as_str());
    let binding = CausalBinding::new(ids, peer).map_err(|_| "binding")?;
    let issue = CausalIssue::new(
        binding,
        &a[22],
        Duration::from_secs(if a[24] == "expiry" { 3 } else { 300 }),
        &read(&a[8])?,
        &read(&a[9])?,
    )
    .map_err(|_| "issue")?;
    let owner = CausalIssueOwner::prepare(Path::new(&a[23]), issue, [1; 32], [3; 32])
        .map_err(|_| "owner")?;
    let g: [u8; 32] = read(&a[6])?.try_into().map_err(|_| "key")?;
    let p: [u8; 32] = read(&a[7])?.try_into().map_err(|_| "key")?;
    let grants = CausalGrantKeys::new(&[("fixture", g)]).map_err(|_| "key")?;
    let policies = PolicyKeys::new(&[("fixture", p)]).map_err(|_| "key")?;
    let trust = TrustedCa::from_pem(&read(&a[3])?).map_err(|_| "trust")?;
    let password = env::var("CONTOUR_CAUSAL_ISSUER_PASSWORD").map_err(|_| "password")?;
    let settings = DatabaseSettings::new(
        &a[0],
        a[1].parse().map_err(|_| "port")?,
        &a[2],
        &a[4],
        password.as_bytes(),
        Duration::from_secs(5),
    )
    .map_err(|_| "settings")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime")?
        .block_on(async {
            let conn = settings.connect(&trust).await.map_err(|_| "connect")?;
            let mut issuer = CausalIssuer::new(conn);
            if a[24] == "claim-busy" {
                let mut owner = owner;
                let generation = [7u8; 32];
                let mut original = owner
                    .issue(&mut issuer, &peer, &grants, &policies)
                    .await
                    .map_err(|_| "issue")?;
                let epoch = original.epoch();
                println!("ISSUED");
                std::io::stdout().flush().map_err(|_| "output")?;
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|_| "control")?;
                if line != "GO\n" {
                    return Err("control");
                }
                if issuer
                    .claim_generation_until(
                        &mut original,
                        &generation,
                        &peer,
                        &grants,
                        &policies,
                        tokio::time::Instant::now() + Duration::from_secs(2),
                    )
                    .await
                    != Err(CausalError::Busy)
                    || !original.verified_remaining().is_zero()
                {
                    return Err("claim");
                }
                println!("CLAIM_BUSY");
                std::io::stdout().flush().map_err(|_| "output")?;
                line.clear();
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|_| "control")?;
                if line != "GO\n" {
                    return Err("control");
                }
                let mut fresh = owner
                    .issue(&mut issuer, &peer, &grants, &policies)
                    .await
                    .map_err(|_| "issue")?;
                if fresh.epoch() != epoch {
                    return Err("epoch");
                }
                issuer
                    .claim_generation_until(
                        &mut fresh,
                        &generation,
                        &peer,
                        &grants,
                        &policies,
                        tokio::time::Instant::now() + Duration::from_secs(2),
                    )
                    .await
                    .map_err(|_| "claim")?;
                println!("CLAIM_OK");
                std::io::stdout().flush().map_err(|_| "output")?;
                return Ok(());
            }
            let (parent, child) = UnixStream::pair().map_err(|_| "pair")?;
            let mut bootstrap = parent.try_clone().map_err(|_| "pair")?;
            let identity = [5u8; 32];
            let permit = match CausalPermitOwner::claim(
                owner,
                parent,
                identity,
                &mut issuer,
                &peer,
                &grants,
                &policies,
            )
            .await
            {
                Ok(v) => v,
                Err(_) => {
                    println!("CLAIM_REJECTED");
                    return Ok(());
                }
            };
            if a[24] == "claim-only" {
                println!("CLAIMED");
                std::io::stdout().flush().map_err(|_| "output")?;
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|_| "control")?;
                if line != "GO\n" {
                    return Err("control");
                }
                return Ok(());
            }
            bootstrap
                .write_all(&permit.generation())
                .and_then(|_| bootstrap.write_all(&identity))
                .map_err(|_| "bootstrap")?;
            drop(bootstrap);
            let fd = child.as_raw_fd();
            let mut command = Command::new("node");
            command
                .arg("-e")
                .arg(CHILD)
                .arg(fd.to_string())
                .arg(&a[25])
                .arg(&a[26])
                .arg(&a[12])
                .arg(&a[13])
                .env_remove("CONTOUR_CAUSAL_ISSUER_PASSWORD")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // SAFETY: only async-signal-safe fcntl is used between fork and exec; the
            // inherited descriptor belongs exclusively to this child endpoint.
            unsafe {
                command.pre_exec(move || {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut process = command.spawn().map_err(|_| "spawn")?;
            drop(child);
            let stdout = process.stdout.take().ok_or("output")?;
            let stderr = process.stderr.take().ok_or("output")?;
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            let out_reader = drain(stdout, false, tx.clone());
            let err_reader = drain(stderr, true, tx.clone());
            let control_done = Arc::new(AtomicBool::new(false));
            let control = control_reader(libc::STDIN_FILENO, tx.clone(), Arc::clone(&control_done));
            drop(tx);
            let serving =
                tokio::spawn(
                    async move { permit.serve(&mut issuer, &peer, &grants, &policies).await },
                );
            let result = async {
                let mut protocol = ChildProtocol::new();
                let mut out_eof = false;
                let mut err_eof = false;
                let output_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                while !(out_eof && err_eof) {
                    let event = tokio::time::timeout_at(output_deadline, rx.recv())
                        .await
                        .map_err(|_| "deadline")?
                        .ok_or("output")?;
                    match event {
                        ChildEvent::Output(bytes) => {
                            let markers = protocol.feed(&bytes)?;
                            if markers & 1 != 0 {
                                println!("ACTIVE");
                                std::io::stdout().flush().map_err(|_| "output")?;
                                if a[24] == "eof" {
                                    serving.abort();
                                }
                            }
                            if markers & 2 != 0 {
                                println!("STOPPED");
                                std::io::stdout().flush().map_err(|_| "output")?;
                            }
                        }
                        ChildEvent::OutputEof => {
                            protocol.eof()?;
                            out_eof = true;
                        }
                        ChildEvent::ErrorEof => err_eof = true,
                        ChildEvent::ErrorData | ChildEvent::Failure => return Err("output"),
                        ChildEvent::ControlStop => serving.abort(),
                        ChildEvent::ControlFailure => return Err("control"),
                    }
                }
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if let Some(status) = process.try_wait().map_err(|_| "wait")? {
                        if !status.success() {
                            return Err("child");
                        }
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err("deadline");
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(())
            }
            .await;
            serving.abort();
            control_done.store(true, Ordering::Release);
            if result.is_err() {
                let _ = process.kill();
                let _ = process.wait();
            }
            drop(rx);
            let out_join = out_reader.join();
            let err_join = err_reader.join();
            let control_join = control.join();
            if out_join.is_err() || err_join.is_err() || control_join.is_err() {
                return Err("output");
            }
            result
        })
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_control_stop_eof_and_invalid_input_are_distinct() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (data, expected) in [
            (b"STOP\n".as_slice(), true),
            (b"".as_slice(), true),
            (b"BAD\n".as_slice(), false),
        ] {
            let mut fds = [-1; 2];
            // SAFETY: fds has space for the two descriptors returned by pipe.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let (tx, mut rx) = tokio::sync::mpsc::channel(2);
            let done = Arc::new(AtomicBool::new(false));
            let thread = control_reader(fds[0], tx, done);
            if !data.is_empty() {
                // SAFETY: data is valid for the requested write length.
                assert_eq!(
                    unsafe { libc::write(fds[1], data.as_ptr().cast(), data.len()) },
                    data.len() as isize
                );
            }
            // SAFETY: the write descriptor is owned by this test.
            unsafe {
                libc::close(fds[1]);
            }
            let event = rt.block_on(rx.recv()).unwrap();
            assert_eq!(matches!(event, ChildEvent::ControlStop), expected);
            if !expected {
                assert!(matches!(event, ChildEvent::ControlFailure));
            }
            thread.join().unwrap();
            // SAFETY: the reader has finished and this test owns the descriptor.
            unsafe {
                libc::close(fds[0]);
            }
        }
    }
    #[test]
    fn stderr_data_is_not_treated_as_clean_eof() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let reader = drain(std::io::Cursor::new(b"private-error".to_vec()), true, tx);
        assert!(matches!(
            rt.block_on(rx.recv()),
            Some(ChildEvent::ErrorData)
        ));
        reader.join().unwrap();
    }
    #[test]
    fn complete_protocol_rejects_trailing_partial_and_oversized_output() {
        let mut p = ChildProtocol::new();
        assert_eq!(p.feed(b"ACT"), Ok(0));
        assert_eq!(p.feed(b"IVE\nSTOPPED\n"), Ok(3));
        assert!(p.eof().is_ok());
        assert!(p.feed(b"x").is_err());
        let mut p = ChildProtocol::new();
        assert!(p.feed(&[b'x'; 64]).is_err());
        let mut p = ChildProtocol::new();
        assert_eq!(p.feed(b"ACTIVE\n"), Ok(1));
        assert!(p.eof().is_err());
        let mut p = ChildProtocol::new();
        assert!(p.feed(b"ACTIVE\nBAD\n").is_err());
    }
}
