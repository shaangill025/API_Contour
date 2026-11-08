//! Durable, fail-closed local create intent. This record is correlation data,
//! not a launch capability or proof that Docker performed any operation.
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    ffi::CString,
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    Unsafe,
    Busy,
    Existing,
    Io,
    Timeout,
    OutputLimit,
    Exit,
    CleanupUnknown,
}

/// An exclusively held, durable record. Dropping it releases the local lock;
/// the record remains and cannot be automatically adopted or overwritten.
pub struct OwnedCreateIntent {
    _lock: File,
    _directory: File,
}

fn open_at(
    dir: &File,
    name: &std::ffi::CStr,
    flags: i32,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    // SAFETY: dir and name remain valid throughout openat; File owns the returned descriptor.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn private_directory(path: &Path) -> Result<File, ProcessError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.ends_with(b"/")
        || bytes
            .split(|b| *b == b'/')
            .skip(1)
            .any(|p| p.is_empty() || p == b"." || p == b"..")
    {
        return Err(ProcessError::Unsafe);
    }
    // SAFETY: fixed, NUL-terminated path; File owns the returned descriptor.
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ProcessError::Io);
    }
    let mut dir = unsafe { File::from_raw_fd(fd) };
    for part in path.components().skip(1) {
        let Component::Normal(name) = part else {
            return Err(ProcessError::Unsafe);
        };
        let name = CString::new(name.as_bytes()).map_err(|_| ProcessError::Unsafe)?;
        dir = open_at(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map_err(|_| ProcessError::Unsafe)?;
    }
    let m = dir.metadata().map_err(|_| ProcessError::Io)?;
    // SAFETY: geteuid has no arguments.
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
        return Err(ProcessError::Unsafe);
    }
    Ok(dir)
}
fn private_file(file: &File) -> Result<(), ProcessError> {
    let m = file.metadata().map_err(|_| ProcessError::Io)?;
    // SAFETY: geteuid has no arguments.
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o600
    {
        return Err(ProcessError::Unsafe);
    }
    Ok(())
}
impl OwnedCreateIntent {
    /// Prepare and fsync an immutable intent before any future create. Inputs
    /// are expected identities, not observations or authorization. Existing or
    /// partially written records always fail closed and require operator review.
    pub fn prepare(
        directory: &Path,
        image_id: [u8; 32],
        network_id: [u8; 32],
        deployment_digest: [u8; 32],
        policy: &DockerPolicy,
    ) -> Result<Self, ProcessError> {
        policy.revalidate()?;
        Self::prepare_record(
            directory,
            image_id,
            network_id,
            deployment_digest,
            policy.digest,
        )
    }
    fn prepare_record(
        directory: &Path,
        image_id: [u8; 32],
        network_id: [u8; 32],
        deployment_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<Self, ProcessError> {
        if image_id == [0; 32]
            || network_id == [0; 32]
            || deployment_digest == [0; 32]
            || policy_digest == [0; 32]
        {
            return Err(ProcessError::Unsafe);
        }
        let dir = private_directory(directory)?;
        let lock = open_at(
            &dir,
            c"create.lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|_| ProcessError::Io)?;
        private_file(&lock)?;
        // SAFETY: the fd is valid and held for the returned owner's lifetime.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(ProcessError::Busy);
        }
        let mut token = [0; 32];
        SystemRandom::new()
            .fill(&mut token)
            .map_err(|_| ProcessError::Io)?;
        let mut file = match open_at(
            &dir,
            c"create.intent",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
            0o600,
        ) {
            Ok(file) => file,
            Err(error) => {
                return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                    ProcessError::Existing
                } else {
                    ProcessError::Io
                });
            }
        };
        private_file(&file)?;
        file.write_all(b"apicontour/local-create-intent/1\n")
            .and_then(|_| file.write_all(&token))
            .and_then(|_| file.write_all(&image_id))
            .and_then(|_| file.write_all(&network_id))
            .and_then(|_| file.write_all(&deployment_digest))
            .and_then(|_| file.write_all(&policy_digest))
            .and_then(|_| file.sync_all())
            .and_then(|_| dir.sync_all())
            .map_err(|_| ProcessError::Io)?;
        Ok(Self {
            _lock: lock,
            _directory: dir,
        })
    }
}

use sha2::{Digest, Sha256};
use std::{
    io::{ErrorKind, Read},
    os::unix::{fs::FileTypeExt, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_STDOUT: usize = 262_144;
const MAX_STDERR: usize = 16_384;
const PRELAUNCH_MAX: Duration = Duration::from_secs(600);
const APPROVED_IMAGE: &str = "docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963";

/// Explicit, operator-selected local CLI policy. This is data, not deployment
/// inspection or authority. Only an explicitly selected Unix daemon is supported.
pub struct DockerPolicy {
    binary: PathBuf,
    socket: PathBuf,
    config: PathBuf,
    binary_identity: Identity,
    socket_identity: Identity,
    config_identity: Identity,
    executable_hash: [u8; 32],
    digest: [u8; 32],
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl Identity {
    fn from(m: &std::fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            nlink: m.nlink(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
// Component-safe path resolution. The last component may be a socket; parent
// directories must be controlled by root or the operator and not group writable.
fn checked_path(path: &Path) -> Result<std::fs::Metadata, ProcessError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.ends_with(b"/")
        || bytes
            .split(|b| *b == b'/')
            .skip(1)
            .any(|p| p.is_empty() || p == b"." || p == b"..")
    {
        return Err(ProcessError::Unsafe);
    }
    let parts: Vec<_> = path.components().skip(1).collect();
    if parts.is_empty() {
        return Err(ProcessError::Unsafe);
    }
    // SAFETY: fixed NUL-terminated root path.
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ProcessError::Io);
    }
    let mut dir = unsafe { File::from_raw_fd(fd) };
    for part in &parts[..parts.len() - 1] {
        let Component::Normal(name) = part else {
            return Err(ProcessError::Unsafe);
        };
        let name = CString::new(name.as_bytes()).map_err(|_| ProcessError::Unsafe)?;
        dir = open_at(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map_err(|_| ProcessError::Unsafe)?;
        let m = dir.metadata().map_err(|_| ProcessError::Io)?;
        // SAFETY: geteuid has no arguments.
        if (m.uid() != 0 && m.uid() != unsafe { libc::geteuid() }) || m.mode() & 0o022 != 0 {
            return Err(ProcessError::Unsafe);
        }
    }
    let Component::Normal(last) = parts.last().ok_or(ProcessError::Unsafe)? else {
        return Err(ProcessError::Unsafe);
    };
    let name = CString::new(last.as_bytes()).map_err(|_| ProcessError::Unsafe)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: retained parent fd, valid name and writable stat buffer.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(ProcessError::Unsafe);
    }
    let m = std::fs::symlink_metadata(path).map_err(|_| ProcessError::Unsafe)?;
    if m.file_type().is_symlink()
        || m.dev() != st.st_dev as u64
        || m.ino() != st.st_ino as u64
        || m.mode() != st.st_mode as u32
        || m.uid() != st.st_uid
        || m.nlink() != st.st_nlink as u64
    {
        return Err(ProcessError::Unsafe);
    }
    Ok(m)
}

fn hash_executable(path: &Path) -> Result<([u8; 32], Identity), ProcessError> {
    let m = checked_path(path)?;
    // SAFETY: geteuid has no arguments.
    if !m.is_file()
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > 134_217_728
        || m.mode() & 0o022 != 0
        || m.mode() & 0o111 == 0
        || (m.uid() != 0 && m.uid() != unsafe { libc::geteuid() })
    {
        return Err(ProcessError::Unsafe);
    }
    let mut options = std::fs::OpenOptions::new();
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ProcessError::Io)?;
    if Identity::from(&file.metadata().map_err(|_| ProcessError::Io)?) != Identity::from(&m) {
        return Err(ProcessError::Unsafe);
    }
    let mut h = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|_| ProcessError::Io)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > m.len() {
            return Err(ProcessError::Unsafe);
        }
        h.update(&buf[..n]);
    }
    if count != m.len()
        || Identity::from(&file.metadata().map_err(|_| ProcessError::Io)?) != Identity::from(&m)
        || Identity::from(&checked_path(path)?) != Identity::from(&m)
    {
        return Err(ProcessError::Unsafe);
    }
    Ok((h.finalize().into(), Identity::from(&m)))
}
impl DockerPolicy {
    /// The digest is supplied by the operator's approved local executable
    /// receipt; the image and command recipes remain fixed by this module.
    pub fn new(
        binary: &Path,
        socket: &Path,
        config: &Path,
        expected_binary_sha256: [u8; 32],
    ) -> Result<Self, ProcessError> {
        if !socket
            .as_os_str()
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'/' | b'.' | b'_' | b'-'))
        {
            return Err(ProcessError::Unsafe);
        }
        let (hash, binary_identity) = hash_executable(binary)?;
        if hash != expected_binary_sha256 {
            return Err(ProcessError::Unsafe);
        }
        let sm = checked_path(socket)?;
        if !sm.file_type().is_socket() {
            return Err(ProcessError::Unsafe);
        }
        let cm = checked_path(config)?;
        // SAFETY: geteuid has no arguments.
        if !cm.is_dir()
            || cm.uid() != unsafe { libc::geteuid() }
            || cm.mode() & 0o7777 != 0o700
            || std::fs::read_dir(config)
                .map_err(|_| ProcessError::Io)?
                .next()
                .is_some()
        {
            return Err(ProcessError::Unsafe);
        }
        let mut h = Sha256::new();
        h.update(b"apicontour/docker-cli-policy/1\n");
        for part in [
            binary.as_os_str().as_bytes(),
            socket.as_os_str().as_bytes(),
            config.as_os_str().as_bytes(),
            hash.as_slice(),
        ] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        for id in [binary_identity, Identity::from(&sm), Identity::from(&cm)] {
            h.update(id.dev.to_be_bytes());
            h.update(id.ino.to_be_bytes());
            h.update(id.mode.to_be_bytes());
            h.update(id.uid.to_be_bytes());
            h.update(id.nlink.to_be_bytes());
        }
        Ok(Self {
            binary: binary.to_owned(),
            socket: socket.to_owned(),
            config: config.to_owned(),
            binary_identity,
            socket_identity: Identity::from(&sm),
            config_identity: Identity::from(&cm),
            executable_hash: hash,
            digest: h.finalize().into(),
        })
    }
    fn revalidate(&self) -> Result<(), ProcessError> {
        let (hash, identity) = hash_executable(&self.binary)?;
        if hash != self.executable_hash
            || identity != self.binary_identity
            || Identity::from(&checked_path(&self.socket)?) != self.socket_identity
            || Identity::from(&checked_path(&self.config)?) != self.config_identity
            || std::fs::read_dir(&self.config)
                .map_err(|_| ProcessError::Io)?
                .next()
                .is_some()
        {
            return Err(ProcessError::Unsafe);
        }
        Ok(())
    }
    /// Read-only fixed recipes. Results are untrusted CLI bytes and cannot mint
    /// an inspected deployment. CLI exit is not remote completion evidence.
    /// Synchronous filesystem validation cannot be interrupted by this deadline;
    /// an independent supervisor must bound the entire public setup to 600 seconds.
    pub fn inspect(
        &self,
        recipe: DockerInspect,
        deadline: Instant,
    ) -> Result<LocalProcess, ProcessError> {
        check_deadline(deadline)?;
        self.revalidate()?;
        check_deadline(deadline)?;
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .env("LC_ALL", "C")
            .arg("--host")
            .arg(format!("unix://{}", self.socket.to_string_lossy()))
            .arg("--config")
            .arg(&self.config);
        match recipe {
            DockerInspect::Daemon => {
                cmd.args(["info", "--format", "{{json .}}"]);
            }
            DockerInspect::Image => {
                cmd.args(["image", "inspect", APPROVED_IMAGE]);
            }
            DockerInspect::Container(id) => {
                cmd.args(["container", "inspect", &hex(&id)]);
            }
            DockerInspect::Network(id) => {
                cmd.args(["network", "inspect", &hex(&id)]);
            }
        }
        launch(cmd, deadline)
    }
}
fn check_deadline(deadline: Instant) -> Result<(), ProcessError> {
    let now = Instant::now();
    if deadline <= now || deadline.duration_since(now) > PRELAUNCH_MAX {
        Err(ProcessError::Unsafe)
    } else {
        Ok(())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// Closed read-only command selection; identifiers are fixed 32-byte values.
pub enum DockerInspect {
    Daemon,
    Image,
    Container([u8; 32]),
    Network([u8; 32]),
}
/// Retained local cleanup state; it does not describe a remote process.
#[derive(Clone)]
pub struct LocalCleanup(Arc<AtomicU8>);
impl LocalCleanup {
    /// None means cleanup is still pending; false means it could not be proved.
    pub fn result(&self) -> Option<bool> {
        match self.0.load(Ordering::Acquire) {
            1 => Some(true),
            2 => Some(false),
            _ => None,
        }
    }
}
/// Dropping this handle cancels only the owned local CLI process group.
pub struct LocalProcess {
    cancel: Arc<AtomicBool>,
    cleanup: LocalCleanup,
    result: tokio::sync::oneshot::Receiver<Result<Vec<u8>, ProcessError>>,
}
impl LocalProcess {
    pub fn cleanup(&self) -> LocalCleanup {
        self.cleanup.clone()
    }
    pub async fn wait(mut self) -> Result<Vec<u8>, ProcessError> {
        (&mut self.result)
            .await
            .unwrap_or(Err(ProcessError::CleanupUnknown))
    }
}
impl Drop for LocalProcess {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}
fn nonblocking(fd: i32) -> Result<(), ProcessError> {
    // SAFETY: valid owned pipe descriptor; fcntl does not retain pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err(ProcessError::Io)
    } else {
        Ok(())
    }
}
// Emergency guard for a local child if worker creation fails. It never signals
// remote resources. Failure to prove reaping is not reported as success.
struct SpawnGuard(Option<Child>);
impl Drop for SpawnGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        let pid = child.id() as i32;
        // SAFETY: this is our unreaped setsid child; only signal its group
        // when the live leader still confirms that group identity.
        if unsafe { libc::getpgid(pid) } == pid {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => return,
            }
        }
        let _ = std::thread::Builder::new()
            .name("contour-local-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            });
    }
}
fn launch(mut cmd: Command, deadline: Instant) -> Result<LocalProcess, ProcessError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setsid is async-signal-safe and does not access parent memory.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut guard = SpawnGuard(Some(cmd.spawn().map_err(|_| ProcessError::Io)?));
    let child = guard.0.as_mut().ok_or(ProcessError::Io)?;
    let stdout = child.stdout.take().ok_or(ProcessError::Io)?;
    let stderr = child.stderr.take().ok_or(ProcessError::Io)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let cleanup = LocalCleanup(Arc::new(AtomicU8::new(0)));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cancel_worker = cancel.clone();
    let cleanup_worker = cleanup.clone();
    std::thread::Builder::new()
        .name("contour-local-cli".into())
        .spawn(move || {
            let Some(child) = guard.0.take() else {
                return;
            };
            let (result, clean) = drive(child, stdout, stderr, deadline, &cancel_worker);
            cleanup_worker
                .0
                .store(if clean { 1 } else { 2 }, Ordering::Release);
            let _ = tx.send(if clean {
                result
            } else {
                Err(ProcessError::CleanupUnknown)
            });
        })
        .map_err(|_| ProcessError::CleanupUnknown)?;
    Ok(LocalProcess {
        cancel,
        cleanup,
        result: rx,
    })
}
fn read_bounded<R: Read>(
    reader: &mut R,
    output: &mut Vec<u8>,
    cap: usize,
) -> Result<bool, ProcessError> {
    let mut b = [0u8; 8192];
    loop {
        match reader.read(&mut b) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if n > cap.saturating_sub(output.len()) {
                    return Err(ProcessError::OutputLimit);
                }
                output.extend_from_slice(&b[..n]);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(ProcessError::Io),
        }
    }
}
fn drive(
    mut child: Child,
    mut stdout: impl Read + AsRawFd,
    mut stderr: impl Read + AsRawFd,
    deadline: Instant,
    cancel: &AtomicBool,
) -> (Result<Vec<u8>, ProcessError>, bool) {
    let pid = child.id() as i32;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut result =
        if nonblocking(stdout.as_raw_fd()).is_err() || nonblocking(stderr.as_raw_fd()).is_err() {
            Err(ProcessError::Io)
        } else {
            Ok(())
        };
    let mut out_eof = false;
    let mut err_eof = false;
    let mut exited = false;
    while result.is_ok() {
        if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            result = Err(ProcessError::Timeout);
            break;
        }
        if !out_eof {
            match read_bounded(&mut stdout, &mut out, MAX_STDOUT) {
                Ok(v) => out_eof = v,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        if !err_eof {
            match read_bounded(&mut stderr, &mut err, MAX_STDERR) {
                Ok(v) => err_eof = v,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        // WNOWAIT preserves the leader PID until the exact group is stopped.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: info is writable and PID is the owned unreaped child.
        if unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            result = Err(ProcessError::Io);
            break;
        }
        if info.si_signo != 0 {
            exited = true;
        }
        if exited && out_eof && err_eof {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // Even on pipe errors or cancellation, observe a completed leader without
    // reaping it before deciding how to stop its group.
    if !exited {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } == 0
            && info.si_signo != 0
        {
            exited = true;
        }
    }
    // Verify the unreaped leader still identifies the group immediately before
    // signaling. Never signal a group after reaping its leader.
    // SAFETY: pid identifies our unreaped child, kill targets its own session.
    let owned = unsafe { libc::getpgid(pid) } == pid || exited;
    // An exited leader can already have no process group. With its PID still
    // unreaped, ESRCH proves there is no remaining group to signal.
    let already_absent = unsafe { libc::kill(-pid, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    let kill_result = if owned && !already_absent {
        unsafe { libc::kill(-pid, libc::SIGKILL) }
    } else {
        0
    };
    let kill_errno = if kill_result != 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    let signaled =
        already_absent || (owned && (kill_result == 0 || kill_errno == Some(libc::ESRCH)));
    if !exited {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } == 0
            && info.si_signo != 0
        {
            exited = true;
        }
    }
    let stop = Instant::now() + Duration::from_secs(2);
    let mut status = None;
    while Instant::now() < stop {
        match child.try_wait() {
            Ok(Some(s)) => {
                status = Some(s);
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => break,
        }
    }
    // If reaping failed, keep a dedicated reaper rather than dropping the child.
    // The cleanup receipt remains unknown and cannot be used as success.
    if status.is_none() {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        return (Err(ProcessError::CleanupUnknown), false);
    }
    // SAFETY: signal zero only probes the already-owned group; it sends no signal.
    let absent = unsafe { libc::kill(-pid, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    // An already-observed exited leader plus post-reap ESRCH also proves
    // group absence on Darwin, where killing a zombie-only group returns EPERM.
    let clean = absent && (signaled || exited);
    let response = match result {
        Err(e) => Err(e),
        Ok(()) if !status.unwrap().success() || !err.is_empty() => Err(ProcessError::Exit),
        Ok(()) => Ok(out),
    };
    (response, clean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn dir() -> std::path::PathBuf {
        let mut random = [0u8; 16];
        SystemRandom::new().fill(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("contour-intent-{name}"));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn durable_exclusive_intent_never_adopts() {
        let p = dir();
        let owner =
            OwnedCreateIntent::prepare_record(&p, [1; 32], [2; 32], [3; 32], [4; 32]).unwrap();
        assert!(matches!(
            OwnedCreateIntent::prepare_record(&p, [1; 32], [2; 32], [3; 32], [4; 32]),
            Err(ProcessError::Busy)
        ));
        let record = std::fs::read(p.join("create.intent")).unwrap();
        assert_eq!(&record[record.len() - 32..], &[4; 32]);
        drop(owner);
        assert!(matches!(
            OwnedCreateIntent::prepare_record(&p, [1; 32], [2; 32], [3; 32], [4; 32]),
            Err(ProcessError::Existing)
        ));
        assert_eq!(record, std::fs::read(p.join("create.intent")).unwrap());
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn symlink_ancestor_and_unsafe_lock_fail() {
        let p = dir();
        let alias = p.with_extension("alias");
        symlink(&p, &alias).unwrap();
        assert!(matches!(
            OwnedCreateIntent::prepare_record(&alias, [1; 32], [2; 32], [3; 32], [4; 32]),
            Err(ProcessError::Unsafe)
        ));
        symlink("other", p.join("create.lock")).unwrap();
        assert!(OwnedCreateIntent::prepare_record(&p, [1; 32], [2; 32], [3; 32], [4; 32]).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn subprocess_fixture() {
        let Ok(mode) = std::env::var("CONTOUR_PROCESS_TEST_MODE") else {
            return;
        };
        match mode.as_str() {
            "ok" => {
                print!("controlled-output");
                std::io::stdout().flush().unwrap();
            }
            "flood_out" => {
                let _ = std::io::stdout().write_all(&vec![b'x'; MAX_STDOUT + 1]);
            }
            "flood_err" => {
                let _ = std::io::stderr().write_all(&vec![b'x'; MAX_STDERR + 1]);
            }
            "partial" => {
                print!("partial");
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "stall" => std::thread::sleep(Duration::from_secs(30)),
            "fail" => std::process::exit(17),
            "warning" => {
                eprint!("warning");
                std::io::stderr().flush().unwrap();
            }
            "descendant" => {
                let mut child = fixture_command("stall").spawn().unwrap();
                let _ = child.wait();
            }
            _ => std::process::exit(71),
        }
        std::process::exit(0);
    }
    fn fixture_command(mode: &str) -> Command {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.env_clear()
            .env("CONTOUR_PROCESS_TEST_MODE", mode)
            .args([
                "--exact",
                "causal_launch_process::tests::subprocess_fixture",
                "--nocapture",
            ]);
        cmd
    }
    fn run_mode(mode: &str, duration: Duration) -> (Result<Vec<u8>, ProcessError>, Option<bool>) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let process = launch(fixture_command(mode), Instant::now() + duration).unwrap();
            let cleanup = process.cleanup();
            let result = tokio::time::timeout(Duration::from_secs(5), process.wait())
                .await
                .unwrap();
            (result, cleanup.result())
        })
    }
    #[test]
    fn owned_process_bounds_output_and_time() {
        let (ok, clean) = run_mode("ok", Duration::from_secs(2));
        assert!(ok.unwrap().windows(17).any(|x| x == b"controlled-output"));
        assert_eq!(clean, Some(true));
        for mode in ["flood_out", "flood_err"] {
            let (r, c) = run_mode(mode, Duration::from_secs(2));
            assert_eq!(r, Err(ProcessError::OutputLimit));
            assert_eq!(c, Some(true));
        }
        let (warning, clean) = run_mode("warning", Duration::from_secs(2));
        assert_eq!(warning, Err(ProcessError::Exit));
        assert_eq!(clean, Some(true));
        let (failed, clean) = run_mode("fail", Duration::from_secs(2));
        assert_eq!(failed, Err(ProcessError::Exit));
        assert_eq!(clean, Some(true));
        let (r, c) = run_mode("partial", Duration::from_millis(100));
        assert_eq!(r, Err(ProcessError::Timeout));
        assert_eq!(c, Some(true));
    }
    #[test]
    fn dropping_handle_cancels_and_reaps_owned_group() {
        let process = launch(
            fixture_command("stall"),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        let cleanup = process.cleanup();
        drop(process);
        let end = Instant::now() + Duration::from_secs(4);
        while cleanup.result().is_none() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(cleanup.result(), Some(true));
    }
    #[test]
    fn cancellation_does_not_claim_cleanup_when_descendants_remain() {
        let process = launch(
            fixture_command("descendant"),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        let cleanup = process.cleanup();
        std::thread::sleep(Duration::from_millis(150));
        drop(process);
        let end = Instant::now() + Duration::from_secs(4);
        while cleanup.result().is_none() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(cleanup.result(), Some(true));
    }
    #[test]
    fn cancelling_wait_future_reaps_the_owned_process() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let process = launch(
            fixture_command("stall"),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        let cleanup = process.cleanup();
        runtime.block_on(async {
            assert!(
                tokio::time::timeout(Duration::from_millis(30), process.wait())
                    .await
                    .is_err()
            );
        });
        let end = Instant::now() + Duration::from_secs(4);
        while cleanup.result().is_none() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(cleanup.result(), Some(true));
    }
    #[test]
    fn malformed_paths_and_non_socket_daemons_are_refused() {
        let p = dir();
        assert!(matches!(
            checked_path(Path::new("relative")),
            Err(ProcessError::Unsafe)
        ));
        assert!(matches!(
            checked_path(Path::new("/tmp/../tmp")),
            Err(ProcessError::Unsafe)
        ));
        let alias = p.with_extension("link");
        symlink(&p, &alias).unwrap();
        assert!(matches!(checked_path(&alias), Err(ProcessError::Unsafe)));
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn existing_record_and_ancestor_alias_are_never_adopted() {
        let p = dir();
        let child = p.join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = p.with_extension("ancestor");
        symlink(&p, &alias).unwrap();
        assert!(matches!(
            OwnedCreateIntent::prepare_record(
                &alias.join("child"),
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32]
            ),
            Err(ProcessError::Unsafe)
        ));
        std::fs::write(child.join("create.intent"), b"incomplete prior record").unwrap();
        assert!(matches!(
            OwnedCreateIntent::prepare_record(&child, [1; 32], [2; 32], [3; 32], [4; 32]),
            Err(ProcessError::Existing)
        ));
        assert_eq!(
            std::fs::read(child.join("create.intent")).unwrap(),
            b"incomplete prior record"
        );
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn deadline_rejects_expired_and_excessive_bounds() {
        assert_eq!(check_deadline(Instant::now()), Err(ProcessError::Unsafe));
        assert_eq!(
            check_deadline(Instant::now() + Duration::from_secs(601)),
            Err(ProcessError::Unsafe)
        );
        assert_eq!(
            check_deadline(Instant::now() + Duration::from_secs(1)),
            Ok(())
        );
    }
}
