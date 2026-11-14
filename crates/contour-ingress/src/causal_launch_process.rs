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
    token: [u8; 32],
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
    pub(crate) fn token(&self) -> [u8; 32] {
        self.token
    }
    pub(crate) fn record_cid(&self, cid: [u8; 32]) -> Result<(), ProcessError> {
        if cid == [0; 32] {
            return Err(ProcessError::Unsafe);
        }
        let mut file = open_at(
            &self._directory,
            c"create.cid",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|_| ProcessError::Io)?;
        private_file(&file)?;
        file.write_all(b"CCI-CID1\n")
            .and_then(|_| file.write_all(&cid))
            .and_then(|_| file.sync_all())
            .and_then(|_| self._directory.sync_all())
            .map_err(|_| ProcessError::Io)
    }
    pub(crate) fn record_start(&self, cid: [u8; 32]) -> Result<(), ProcessError> {
        let mut receipt = open_at(
            &self._directory,
            c"create.cid",
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )
        .map_err(|_| ProcessError::Unsafe)?;
        private_file(&receipt)?;
        let mut exact = [0u8; 41];
        receipt
            .read_exact(&mut exact)
            .map_err(|_| ProcessError::Io)?;
        let mut extra = [0u8; 1];
        if receipt.read(&mut extra).map_err(|_| ProcessError::Io)? != 0
            || &exact[..9] != b"CCI-CID1\n"
            || exact[9..] != cid
        {
            return Err(ProcessError::Unsafe);
        }
        let mut file = open_at(
            &self._directory,
            c"create.start",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|_| ProcessError::Io)?;
        private_file(&file)?;
        file.write_all(b"CCI-START1\n")
            .and_then(|_| file.write_all(&cid))
            .and_then(|_| file.sync_all())
            .and_then(|_| self._directory.sync_all())
            .map_err(|_| ProcessError::Io)
    }
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
            token,
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

// Fixed, bounded in-container PID-namespace inspection. This never uses the
// host Docker-init PID as the proxy PID and contains no caller-supplied code.
const PROXY_PROC_SCRIPT: &str = r#"'use strict';const f=require('node:fs');const [p,t]=process.argv.slice(1);if(!/^[1-9][0-9]{0,9}$/.test(p)||!/^[1-9][0-9]{0,19}$/.test(t))throw Error('input');function read(path){const fd=f.openSync(path,f.constants.O_RDONLY|f.constants.O_NOFOLLOW),b=Buffer.alloc(8193);let n=0;try{for(;;){const r=f.readSync(fd,b,n,b.length-n,null);if(r===0)break;n+=r;if(n===b.length)throw Error('bound');}}finally{f.closeSync(fd);}if(n===0)throw Error('empty');return b.subarray(0,n);}const base='/proc/'+p+'/';const s=read(base+'stat').toString('utf8');const i=s.lastIndexOf(') ');if(i<0)throw Error('stat');const fields=s.slice(i+2).split(' ');if(fields[1]!=='1'||fields[19]!==t)throw Error('identity');const status=read(base+'status').toString('utf8');const m=/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);if(!m||m.slice(1).some(x=>x!=='1000'))throw Error('uid');const c=read(base+'cmdline');if(!c.equals(Buffer.from('/usr/local/bin/node\0/adapter/live-integration/private-launch-proxy.js\0')))throw Error('cmd');process.stdout.write('OK '+p+' '+t+'\n');"#;

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
pub(crate) struct Identity {
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
    pub(crate) fn same_object(&self, other: &Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.mode == other.mode
            && self.uid == other.uid
    }
    pub(crate) fn from(m: &std::fs::Metadata) -> Self {
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
pub(crate) fn checked_path(path: &Path) -> Result<std::fs::Metadata, ProcessError> {
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
    // libc's device and mode types differ on Linux and Darwin.
    #[cfg(target_os = "linux")]
    let (device, inode, mode) = (st.st_dev, st.st_ino, st.st_mode);
    #[cfg(target_os = "macos")]
    let (device, inode, mode) = (st.st_dev as u64, st.st_ino, st.st_mode as u32);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let (device, inode, mode) = (st.st_dev as u64, st.st_ino as u64, st.st_mode as u32);
    if m.file_type().is_symlink()
        || m.dev() != device
        || m.ino() != inode
        || m.mode() != mode
        || m.uid() != st.st_uid
        // Link counts are u32 on Linux ARM and u64 on Linux x86_64;
        // Darwin uses u16. Widen both sides without truncation on any target.
        || u128::from(m.nlink()) != u128::from(st.st_nlink)
    {
        return Err(ProcessError::Unsafe);
    }
    Ok(m)
}

pub(crate) fn hash_executable(path: &Path) -> Result<([u8; 32], Identity), ProcessError> {
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
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
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
    let hash: [u8; 32] = h
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| ProcessError::Unsafe)?;
    Ok((hash, Identity::from(&m)))
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
pub(crate) struct FixedCreateSpec<'a> {
    pub(crate) network: &'a str,
    pub(crate) owner: [u8; 32],
    pub(crate) mounts: Vec<(&'a str, &'a str)>,
}
impl DockerPolicy {
    // Fixed 504 image recipes; results are untrusted process output, not evidence.
    pub(crate) fn receiver_image_inspect(
        &self,
        image: [u8; 32],
        arm64: bool,
        deadline: Instant,
    ) -> Result<LocalProcess, ProcessError> {
        check_deadline(deadline)?;
        self.revalidate()?;
        check_deadline(deadline)?;
        let mut cmd = Command::new(&self.binary);
        let image = format!("sha256:{}", hex(&image));
        cmd.env_clear()
            .env("LC_ALL", "C")
            .arg("--host")
            .arg(format!("unix://{}", self.socket.to_string_lossy()))
            .arg("--config")
            .arg(&self.config)
            .args([
                "image",
                "inspect",
                "--platform",
                if arm64 { "linux/arm64" } else { "linux/amd64" },
                &image,
            ]);
        launch(cmd, deadline)
    }
    pub(crate) fn receiver_image_save(
        &self,
        stage: &crate::causal_receiver_image::ImageStage,
        deadline: Instant,
    ) -> Result<LocalProcess, ProcessError> {
        const DONOR: &str = "docker.io/library/node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5";
        const MAX_ARCHIVE: libc::rlim_t = 1024 * 1024 * 1024;
        check_deadline(deadline)?;
        stage.revalidate(false).map_err(|_| ProcessError::Unsafe)?;
        self.revalidate()?;
        check_deadline(deadline)?;
        let mut cmd = Command::new(&self.binary);
        let image = format!("sha256:{}", hex(&stage.image()));
        cmd.env_clear()
            .env("LC_ALL", "C")
            .arg("--host")
            .arg(format!("unix://{}", self.socket.to_string_lossy()))
            .arg("--config")
            .arg(&self.config)
            .args([
                "image",
                "save",
                "--platform",
                if stage.arm64() {
                    "linux/arm64"
                } else {
                    "linux/amd64"
                },
                "--output",
            ])
            .arg(stage.archive_path())
            .args([DONOR, APPROVED_IMAGE, &image]);
        // SAFETY: setrlimit is async-signal-safe and changes only the owned child.
        unsafe {
            cmd.pre_exec(|| {
                libc::umask(0o077);
                let limit = libc::rlimit {
                    rlim_cur: MAX_ARCHIVE,
                    rlim_max: MAX_ARCHIVE,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        launch(cmd, deadline)
    }
    pub(crate) fn receiver_revalidate(&self) -> Result<(), ProcessError> {
        self.revalidate()
    }

    pub(crate) fn daemon_endpoint(&self) -> String {
        format!("unix://{}", self.socket.to_string_lossy())
    }
    pub(crate) fn policy_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) async fn verify_proxy_process(
        &self,
        cid: [u8; 32],
        pid: u32,
        start: u64,
        deadline: Instant,
    ) -> Result<(), ProcessError> {
        check_deadline(deadline)?;
        self.revalidate()?;
        check_deadline(deadline)?;
        if cid == [0; 32] || pid == 0 || start == 0 {
            return Err(ProcessError::Unsafe);
        }
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .env("LC_ALL", "C")
            .arg("--host")
            .arg(format!("unix://{}", self.socket.to_string_lossy()))
            .arg("--config")
            .arg(&self.config)
            .args([
                "exec",
                &hex(&cid),
                "/usr/local/bin/node",
                "-e",
                PROXY_PROC_SCRIPT,
                "--",
                &pid.to_string(),
                &start.to_string(),
            ]);
        let bytes = launch(cmd, deadline)?.wait().await?;
        if bytes != format!("OK {pid} {start}\n").as_bytes() {
            return Err(ProcessError::Unsafe);
        }
        check_deadline(deadline)?;
        self.revalidate()?;
        check_deadline(deadline)
    }
    pub(crate) async fn verify_receiver_proxy_process(
        &self,
        cid: [u8; 32],
        pid: u32,
        start: u64,
        deadline: Instant,
    ) -> Result<(), ProcessError> {
        check_deadline(deadline)?;
        self.revalidate()?;
        if cid == [0; 32] || pid == 0 || start == 0 {
            return Err(ProcessError::Unsafe);
        }
        let script = PROXY_PROC_SCRIPT.replace(
            "/adapter/live-integration/private-launch-proxy.js",
            "/adapter/receiver-integration/private-launch-proxy-504.js",
        );
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .env("LC_ALL", "C")
            .arg("--host")
            .arg(format!("unix://{}", self.socket.to_string_lossy()))
            .arg("--config")
            .arg(&self.config)
            .args([
                "exec",
                &hex(&cid),
                "/usr/local/bin/node",
                "-e",
                &script,
                "--",
                &pid.to_string(),
                &start.to_string(),
            ]);
        let bytes = launch(cmd, deadline)?.wait().await?;
        if bytes != format!("OK {pid} {start}\n").as_bytes() {
            return Err(ProcessError::Unsafe);
        }
        check_deadline(deadline)?;
        self.revalidate()?;
        check_deadline(deadline)
    }
    pub(crate) fn create_inert(
        &self,
        spec: &FixedCreateSpec<'_>,
        deadline: Instant,
    ) -> Result<LocalProcess, ProcessError> {
        check_deadline(deadline)?;
        self.revalidate()?;
        check_deadline(deadline)?;
        let cmd = self.fixed_create_command(spec)?;
        launch(cmd, deadline)
    }
    fn fixed_create_command(&self, spec: &FixedCreateSpec<'_>) -> Result<Command, ProcessError> {
        if spec.owner == [0; 32]
            || spec.network.is_empty()
            || spec.network.len() > 128
            || !spec
                .network
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            || spec.mounts.len() != 11
        {
            return Err(ProcessError::Unsafe);
        }
        let targets = [
            "/adapter/causal-codec.js",
            "/adapter/error-integration",
            "/adapter/live-integration",
            "/data/flows.json",
            "/run/apicontour/live/ca.pem",
            "/run/apicontour/live/export.key",
            "/run/apicontour/live/export.pem",
            "/run/apicontour/live/product.key",
            "/run/apicontour/live/product.pem",
            "/run/apicontour/live/server.key",
            "/run/apicontour/live/server.pem",
        ];
        if spec.mounts.iter().map(|m| m.1).ne(targets)
            || spec.mounts.iter().any(|(p, _)| {
                !p.starts_with('/')
                    || !p.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-')
                    })
            })
        {
            return Err(ProcessError::Unsafe);
        }
        let owner = hex(&spec.owner);
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .env("LC_ALL", "C")
            .arg("--host")
            .arg(format!("unix://{}", self.socket.to_string_lossy()))
            .arg("--config")
            .arg(&self.config);
        cmd.args([
            "create",
            "--pull",
            "never",
            "--name",
            &format!("contour-causal-{owner}"),
            "--label",
            &format!("org.apicontour.causal.owner={owner}"),
            "--interactive",
            "--attach",
            "stdin",
            "--attach",
            "stdout",
            "--init",
            "--hostname",
            "causal-live",
            "--user",
            "1000:1000",
            "--workdir",
            "/data",
            "--network",
            spec.network,
            "--network-alias",
            "causal-node",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--log-driver",
            "none",
            "--memory",
            "536870912",
            "--cpus",
            "1",
            "--pids-limit",
            "128",
            "--tmpfs",
            "/data:rw,nosuid,nodev,noexec,size=16m,mode=1777",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
            "--entrypoint",
            "/usr/local/bin/node",
        ]);
        for value in [
            "FLOWS=flows.json",
            "HOME=/data",
            "HOSTNAME=causal-live",
            "LANG=C.UTF-8",
            "NODE_PATH=/usr/src/node-red/node_modules",
            "NODE_RED_VERSION=v5.0.9",
            "NODE_VERSION=24.22.1",
            "PATH=/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ=UTC",
            "YARN_VERSION=1.22.22",
        ] {
            cmd.arg("--env").arg(value);
        }
        for (source, dest) in &spec.mounts {
            cmd.arg("--mount").arg(format!(
                "type=bind,src={source},dst={dest},readonly,bind-propagation=rprivate"
            ));
        }
        cmd.args([
            APPROVED_IMAGE,
            "/adapter/live-integration/private-launch-proxy.js",
        ]);
        Ok(cmd)
    }
}
pub(crate) struct FixedReceiverCreateSpec<'a> {
    pub network: &'a str,
    pub owner: [u8; 32],
    pub image: [u8; 32],
    pub arm64: bool,
    pub mounts: Vec<(&'a str, &'a str)>,
}
impl DockerPolicy {
    pub(crate) fn create_receiver_inert(
        &self,
        spec: &FixedReceiverCreateSpec<'_>,
        deadline: Instant,
    ) -> Result<LocalProcess, ProcessError> {
        check_deadline(deadline)?;
        self.revalidate()?;
        if spec.owner == [0; 32]
            || spec.image == [0; 32]
            || spec.network.is_empty()
            || spec.network.len() > 128
            || !spec
                .network
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(ProcessError::Unsafe);
        }
        let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../collectors/nodered/receiver-integration/manifest-504.json"
        ))
        .map_err(|_| ProcessError::Unsafe)?;
        let mut targets: Vec<String> = manifest
            .get("files")
            .and_then(|v| v.as_object())
            .ok_or(ProcessError::Unsafe)?
            .keys()
            .cloned()
            .collect();
        targets.extend(
            [
                "/adapter/receiver-integration/manifest-504.json",
                "/adapter/receiver-integration/artifact-504.json",
                "/adapter/live-integration/tree-arm64.json",
                "/adapter/live-integration/tree-x64.json",
                "/data/flows.json",
                "/run/apicontour/live/product.pem",
                "/run/apicontour/live/product.key",
                "/run/apicontour/live/export.pem",
                "/run/apicontour/live/export.key",
                "/run/apicontour/live/server.pem",
                "/run/apicontour/live/server.key",
                "/run/apicontour/live/evidence.pem",
                "/run/apicontour/live/evidence.key",
                "/run/apicontour/live/ca.pem",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        targets.sort();
        let mut actual: Vec<_> = spec.mounts.iter().map(|(_, d)| (*d).to_owned()).collect();
        actual.sort();
        if targets.len() != 38
            || actual != targets
            || spec.mounts.iter().any(|(p, _)| {
                !p.starts_with('/')
                    || !p.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-')
                    })
            })
        {
            return Err(ProcessError::Unsafe);
        }
        let owner = hex(&spec.owner);
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .env("LC_ALL", "C")
            .arg("--host")
            .arg(format!("unix://{}", self.socket.to_string_lossy()))
            .arg("--config")
            .arg(&self.config);
        cmd.args([
            "create",
            "--pull",
            "never",
            "--platform",
            if spec.arm64 {
                "linux/arm64"
            } else {
                "linux/amd64"
            },
            "--name",
            &format!("contour-causal-{owner}"),
            "--label",
            &format!("org.apicontour.causal.owner={owner}"),
            "--interactive",
            "--attach",
            "stdin",
            "--attach",
            "stdout",
            "--init",
            "--hostname",
            "causal-live",
            "--user",
            "1000:1000",
            "--workdir",
            "/data",
            "--network",
            spec.network,
            "--network-alias",
            "causal-node",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--log-driver",
            "none",
            "--memory",
            "536870912",
            "--cpus",
            "1",
            "--cgroupns",
            "private",
            "--shm-size",
            "64m",
            "--pids-limit",
            "128",
            "--tmpfs",
            "/data:rw,nosuid,nodev,noexec,size=16m,mode=1777",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
            "--entrypoint",
            "/usr/local/bin/node",
        ]);
        for value in [
            "FLOWS=flows.json",
            "HOME=/data",
            "HOSTNAME=causal-live",
            "LANG=C.UTF-8",
            "NODE_PATH=/usr/src/node-red/node_modules",
            "NODE_RED_VERSION=v5.0.9",
            "NODE_VERSION=24.22.3",
            "PATH=/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ=UTC",
            "UV_USE_IO_URING=0",
            "YARN_VERSION=1.22.22",
        ] {
            cmd.arg("--env").arg(value);
        }
        for (source, dest) in &spec.mounts {
            cmd.arg("--mount").arg(format!(
                "type=bind,src={source},dst={dest},readonly,bind-propagation=rprivate"
            ));
        }
        cmd.arg(format!("sha256:{}", hex(&spec.image)))
            .arg("/adapter/receiver-integration/private-launch-proxy-504.js");
        check_deadline(deadline)?;
        launch(cmd, deadline)
    }
}
/// A fixed-recipe observation produced only by this module's local CLI worker.
/// The bytes remain untrusted until a closed Docker projection is validated.
pub(crate) struct ActualDockerObservation {
    recipe: DockerInspect,
    policy_digest: [u8; 32],
    observed_at: Instant,
    bytes: Vec<u8>,
}
impl ActualDockerObservation {
    #[cfg(test)]
    pub(crate) fn fake(recipe: DockerInspect, policy_digest: [u8; 32], bytes: Vec<u8>) -> Self {
        Self {
            recipe,
            policy_digest,
            observed_at: Instant::now(),
            bytes,
        }
    }
    pub(crate) fn observed_at(&self) -> Instant {
        self.observed_at
    }
    pub(crate) fn recipe(&self) -> DockerInspect {
        self.recipe
    }
    pub(crate) fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl DockerPolicy {
    pub(crate) async fn observe(
        &self,
        recipe: DockerInspect,
        deadline: Instant,
    ) -> Result<ActualDockerObservation, ProcessError> {
        let process = self.inspect(recipe, deadline)?;
        let bytes = process.wait().await?;
        check_deadline(deadline)?;
        self.revalidate()?;
        check_deadline(deadline)?;
        Ok(ActualDockerObservation {
            recipe,
            policy_digest: self.digest,
            observed_at: Instant::now(),
            bytes,
        })
    }
}
pub(crate) fn check_deadline(deadline: Instant) -> Result<(), ProcessError> {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
// Probe only within the original stop window; EPERM or a live group is not
// absence. A signal-zero observation never sends a signal to a reused group.
fn group_absent_until(
    stop: Instant,
    mut probe: impl FnMut() -> Option<i32>,
    mut now: impl FnMut() -> Instant,
    mut sleep: impl FnMut(Duration),
) -> (bool, Option<i32>) {
    let mut last = None;
    loop {
        if now() >= stop {
            return (false, last);
        }
        last = probe();
        let checked = now();
        if checked >= stop {
            return (false, last);
        }
        match last {
            Some(libc::ESRCH) => return (true, last),
            None | Some(libc::EPERM) => {
                sleep(Duration::from_millis(5).min(stop.duration_since(checked)));
            }
            _ => return (false, last),
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
pub(crate) fn launch(cmd: Command, deadline: Instant) -> Result<LocalProcess, ProcessError> {
    launch_input(cmd, deadline, None)
}
fn launch_input(
    mut cmd: Command,
    deadline: Instant,
    input: Option<&[u8]>,
) -> Result<LocalProcess, ProcessError> {
    if input.is_some_and(|bytes| bytes.len() != 64) {
        return Err(ProcessError::Unsafe);
    }
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
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
    if let Some(bytes) = input {
        let mut stdin = child.stdin.take().ok_or(ProcessError::Io)?;
        stdin.write_all(bytes).map_err(|_| ProcessError::Io)?;
        drop(stdin);
        check_deadline(deadline)?;
    }
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
    let (absent, _probe_errno) = group_absent_until(
        stop,
        || {
            // SAFETY: signal zero only observes the group; it sends no signal.
            if unsafe { libc::kill(-pid, 0) } == 0 {
                None
            } else {
                std::io::Error::last_os_error().raw_os_error()
            }
        },
        Instant::now,
        std::thread::sleep,
    );
    #[cfg(test)]
    if !absent || !(signaled || exited) {
        // Restrict diagnostic output to predicates and allowlisted errno values.
        let safe_errno = |value| match value {
            Some(libc::ESRCH) => "ESRCH",
            Some(libc::EPERM) => "EPERM",
            None => "none",
            _ => "other",
        };
        eprintln!(
            "cleanup diagnostic: owned={owned} already_absent={already_absent} signaled={signaled} exited={exited} absent={absent} kill_errno={} probe_errno={}",
            safe_errno(kill_errno),
            safe_errno(_probe_errno)
        );
    }
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

/// Private local CLI attach supervisor. Cancellation signals only its own local
/// setsid group; it never signals or deletes the remote container.
pub(crate) struct LocalAttached {
    stream: Option<tokio::net::UnixStream>,
    cancel: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    cleanup: LocalCleanup,
}
impl LocalAttached {
    pub(crate) fn take_stream(&mut self) -> Result<tokio::net::UnixStream, ProcessError> {
        self.stream.take().ok_or(ProcessError::Unsafe)
    }
    pub(crate) fn activate(&self) {
        self.active.store(true, Ordering::Release);
    }
    pub(crate) fn cleanup(&self) -> LocalCleanup {
        self.cleanup.clone()
    }
}
impl Drop for LocalAttached {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}
// Fixed internal collector request; only the challenge arrives on private stdin.
const RECEIVER_PREAUTH_SCRIPT: &str = r#"'use strict';const fs=require('node:fs'),https=require('node:https');const b=fs.readFileSync(0);if(b.length!==64||!/^[0-9a-f]{64}$/.test(b.toString('ascii')))process.exit(2);const dir='/run/apicontour/live/';const q=https.request({hostname:'causal-ingress',port:8443,path:'/v1/receiver-preauth',method:'POST',servername:'causal-ingress',ca:fs.readFileSync(dir+'ca.pem'),cert:fs.readFileSync(dir+'export.pem'),key:fs.readFileSync(dir+'export.key'),rejectUnauthorized:true,agent:false,headers:{'content-type':'application/json','content-length':'64'}},r=>{let n=0;r.on('data',x=>{n+=x.length;if(n>512)q.destroy()});r.on('end',()=>{if(r.statusCode!==200)process.exit(2);process.stdout.write('OK\n')})});q.setTimeout(5000,()=>q.destroy());q.on('error',()=>process.exit(2));q.end(b);"#;
impl DockerPolicy {
    pub(crate) async fn receiver_preauth_exec(
        &self,
        cid: [u8; 32],
        challenge: &str,
        deadline: Instant,
    ) -> Result<(), ProcessError> {
        check_deadline(deadline)?;
        self.revalidate()?;
        if cid == [0; 32]
            || challenge.len() != 64
            || !challenge
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ProcessError::Unsafe);
        }
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .env("LC_ALL", "C")
            .arg("--host")
            .arg(format!("unix://{}", self.socket.to_string_lossy()))
            .arg("--config")
            .arg(&self.config)
            .args([
                "exec",
                "-i",
                &hex(&cid),
                "/usr/local/bin/node",
                "-e",
                RECEIVER_PREAUTH_SCRIPT,
            ]);
        let bytes = launch_input(cmd, deadline, Some(challenge.as_bytes()))?
            .wait()
            .await?;
        if bytes != b"OK\n" {
            return Err(ProcessError::Unsafe);
        }
        check_deadline(deadline)?;
        self.revalidate()?;
        check_deadline(deadline)
    }
}
impl DockerPolicy {
    /// Start exactly one already-owned CID. The fixed start command is never
    /// used to retry an ambiguous create/start outcome.
    pub(crate) fn start_attached(
        &self,
        cid: [u8; 32],
        deadline: Instant,
    ) -> Result<LocalAttached, ProcessError> {
        check_deadline(deadline)?;
        self.revalidate()?;
        check_deadline(deadline)?;
        if cid == [0; 32] {
            return Err(ProcessError::Unsafe);
        }
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .env("LC_ALL", "C")
            .arg("--host")
            .arg(format!("unix://{}", self.socket.to_string_lossy()))
            .arg("--config")
            .arg(&self.config)
            .args(["start", "-a", "-i", &hex(&cid)]);
        launch_attached(cmd, deadline)
    }
}
fn launch_attached(mut cmd: Command, deadline: Instant) -> Result<LocalAttached, ProcessError> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setsid is async-signal-safe and creates a private local group.
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
    let input = child.stdin.take().ok_or(ProcessError::Io)?;
    let output = child.stdout.take().ok_or(ProcessError::Io)?;
    let errors = child.stderr.take().ok_or(ProcessError::Io)?;
    let (host, bridge) = std::os::unix::net::UnixStream::pair().map_err(|_| ProcessError::Io)?;
    host.set_nonblocking(true).map_err(|_| ProcessError::Io)?;
    bridge.set_nonblocking(true).map_err(|_| ProcessError::Io)?;
    let stream = tokio::net::UnixStream::from_std(host).map_err(|_| ProcessError::Io)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicBool::new(false));
    let cleanup = LocalCleanup(Arc::new(AtomicU8::new(0)));
    let cancel_worker = cancel.clone();
    let active_worker = active.clone();
    let cleanup_worker = cleanup.clone();
    std::thread::Builder::new()
        .name("contour-local-attach".into())
        .spawn(move || {
            let Some(child) = guard.0.take() else {
                cleanup_worker.0.store(2, Ordering::Release);
                return;
            };
            let clean = drive_attached(
                child,
                input,
                output,
                errors,
                bridge,
                (deadline, &cancel_worker, &active_worker),
            );
            cleanup_worker
                .0
                .store(if clean { 1 } else { 2 }, Ordering::Release);
        })
        .map_err(|_| ProcessError::CleanupUnknown)?;
    Ok(LocalAttached {
        stream: Some(stream),
        cancel,
        active,
        cleanup,
    })
}
fn transfer_read<R: Read>(reader: &mut R, buffer: &mut Vec<u8>) -> Result<bool, ProcessError> {
    if buffer.len() >= 32768 {
        return Ok(false);
    }
    let mut bytes = [0u8; 8192];
    let cap = (32768 - buffer.len()).min(bytes.len());
    match reader.read(&mut bytes[..cap]) {
        Ok(0) => Err(ProcessError::Io),
        Ok(n) => {
            buffer.extend_from_slice(&bytes[..n]);
            Ok(true)
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => Ok(false),
        Err(_) => Err(ProcessError::Io),
    }
}
fn transfer_write<W: Write>(writer: &mut W, buffer: &mut Vec<u8>) -> Result<bool, ProcessError> {
    if buffer.is_empty() {
        return Ok(false);
    }
    match writer.write(buffer) {
        Ok(0) => Err(ProcessError::Io),
        Ok(n) => {
            buffer.drain(..n);
            Ok(true)
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => Ok(false),
        Err(_) => Err(ProcessError::Io),
    }
}
fn drive_attached(
    mut child: Child,
    mut input: impl Write + AsRawFd,
    mut output: impl Read + AsRawFd,
    mut errors: impl Read + AsRawFd,
    mut bridge: std::os::unix::net::UnixStream,
    controls: (Instant, &AtomicBool, &AtomicBool),
) -> bool {
    let (deadline, cancel, active) = controls;
    let pid = child.id() as i32;
    if [
        input.as_raw_fd(),
        output.as_raw_fd(),
        errors.as_raw_fd(),
        bridge.as_raw_fd(),
    ]
    .into_iter()
    .any(|fd| nonblocking(fd).is_err())
    {
        cancel.store(true, Ordering::Release);
    }
    let mut incoming = Vec::new();
    let mut outgoing = Vec::new();
    let mut stalled = Instant::now();
    let mut exited = false;
    loop {
        if cancel.load(Ordering::Acquire)
            || (!active.load(Ordering::Acquire) && Instant::now() >= deadline)
        {
            break;
        }
        let mut progress = false;
        match transfer_read(&mut bridge, &mut incoming) {
            Ok(v) => progress |= v,
            Err(_) => break,
        }
        match transfer_write(&mut input, &mut incoming) {
            Ok(v) => progress |= v,
            Err(_) => break,
        }
        match transfer_read(&mut output, &mut outgoing) {
            Ok(v) => progress |= v,
            Err(_) => break,
        }
        match transfer_write(&mut bridge, &mut outgoing) {
            Ok(v) => progress |= v,
            Err(_) => break,
        }
        let mut byte = [0u8; 1];
        match errors.read(&mut byte) {
            Ok(0) => {}
            Ok(_) => break,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(_) => break,
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: owned child is deliberately unreaped until cleanup.
        if unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            break;
        }
        if info.si_signo != 0 {
            exited = true;
            break;
        }
        if progress {
            stalled = Instant::now();
        } else if (!incoming.is_empty() || !outgoing.is_empty())
            && stalled.elapsed() >= Duration::from_secs(2)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(input);
    drop(output);
    drop(errors);
    drop(bridge);
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
    // SAFETY: only signal the owned group while its leader remains unreaped.
    let owned = unsafe { libc::getpgid(pid) } == pid || exited;
    let already_absent = unsafe { libc::kill(-pid, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    let killed = if owned && !already_absent {
        (unsafe { libc::kill(-pid, libc::SIGKILL) }) == 0
    } else {
        already_absent
    };
    let until = Instant::now() + Duration::from_secs(2);
    let mut reaped = false;
    while Instant::now() < until {
        match child.try_wait() {
            Ok(Some(_)) => {
                reaped = true;
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => break,
        }
    }
    if !reaped {
        let _ = std::thread::Builder::new()
            .name("contour-attach-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            });
        return false;
    }
    // SAFETY: signal zero only probes group existence.
    let absent = unsafe { libc::kill(-pid, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    absent && (killed || exited)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn group_absence_requires_fresh_esrch_inside_original_window() {
        use std::cell::Cell;
        fn run(sequence: &[Option<i32>], budget: Duration) -> ((bool, Option<i32>), usize) {
            let start = Instant::now();
            let elapsed = Cell::new(Duration::ZERO);
            let calls = Cell::new(0usize);
            let outcome = group_absent_until(
                start + budget,
                || {
                    let index = calls.get();
                    calls.set(index + 1);
                    sequence[index.min(sequence.len() - 1)]
                },
                || start + elapsed.get(),
                |duration| elapsed.set(elapsed.get() + duration),
            );
            (outcome, calls.get())
        }
        let (eventual, calls) = run(
            &[Some(libc::EPERM), Some(libc::ESRCH)],
            Duration::from_millis(10),
        );
        assert_eq!(eventual, (true, Some(libc::ESRCH)));
        assert_eq!(calls, 2);
        assert_eq!(
            run(&[Some(libc::ESRCH)], Duration::from_millis(10)).0,
            (true, Some(libc::ESRCH))
        );
        assert_eq!(
            run(&[Some(libc::EPERM)], Duration::from_millis(10)).0,
            (false, Some(libc::EPERM))
        );
        assert_eq!(run(&[None], Duration::from_millis(10)).0, (false, None));
        assert_eq!(
            run(&[Some(libc::ESRCH)], Duration::ZERO),
            ((false, None), 0)
        );
        assert_eq!(
            run(&[Some(libc::EINVAL)], Duration::from_millis(10)),
            ((false, Some(libc::EINVAL)), 1)
        );
        assert_eq!(
            run(
                &[Some(libc::EPERM), Some(libc::ESRCH)],
                Duration::from_millis(5)
            )
            .0,
            (false, Some(libc::EPERM))
        );
    }

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
    fn private_hash_dir() -> std::path::PathBuf {
        let mut random = [0u8; 16];
        SystemRandom::new().fill(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
            .canonicalize()
            .unwrap();
        let path = home.join(format!("contour-hash-test-{name}"));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn executable_hash_rejects_world_writable_ancestor() {
        let p = private_hash_dir();
        let unsafe_ancestor = p.join("unsafe");
        std::fs::create_dir(&unsafe_ancestor).unwrap();
        let executable = unsafe_ancestor.join("executable");
        std::fs::write(&executable, b"fixture").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(hash_executable(&executable).is_ok());
        std::fs::set_permissions(&unsafe_ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            hash_executable(&executable),
            Err(ProcessError::Unsafe)
        ));
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn executable_hash_matches_sha256_across_read_boundaries() {
        let p = private_hash_dir();
        let executable = p.join("executable");
        for size in [1, 55, 56, 63, 64, 65, 65535, 65536, 65537, 131073] {
            let bytes: Vec<u8> = (0..size).map(|i| (i * 37 % 251) as u8).collect();
            std::fs::write(&executable, &bytes).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            let (actual, _) = hash_executable(&executable).unwrap();
            let expected: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(actual, expected, "size {size}");
        }
        let alias = p.join("alias");
        symlink(&executable, &alias).unwrap();
        assert!(matches!(hash_executable(&alias), Err(ProcessError::Unsafe)));
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o722)).unwrap();
        assert!(matches!(
            hash_executable(&executable),
            Err(ProcessError::Unsafe)
        ));
        std::fs::remove_dir_all(p).unwrap();
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
            "interactive" => {
                print!("READY-CLI");
                std::io::stdout().flush().unwrap();
                let mut bytes = [0; 4];
                std::io::stdin().read_exact(&mut bytes).unwrap();
                std::io::stdout().write_all(&bytes).unwrap();
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "noisy" => {
                eprint!("unexpected stderr");
                std::io::stderr().flush().unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "warning" => {
                eprint!("warning");
                std::io::stderr().flush().unwrap();
            }
            "descendant" => {
                // This subprocess has its own test mutex after exec.
                let _process_guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
                let mut child = fixture_command("stall", &_process_guard).spawn().unwrap();
                let _ = child.wait();
            }
            _ => std::process::exit(71),
        }
        std::process::exit(0);
    }
    // The guard parameter makes fixture launches require an acquired guard.
    fn fixture_command(mode: &str, _guard: &std::sync::MutexGuard<'_, ()>) -> Command {
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
    fn run_mode(
        mode: &str,
        duration: Duration,
        guard: &std::sync::MutexGuard<'_, ()>,
    ) -> (Result<Vec<u8>, ProcessError>, Option<bool>) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let process = launch(fixture_command(mode, guard), Instant::now() + duration).unwrap();
            let cleanup = process.cleanup();
            let result = tokio::time::timeout(Duration::from_secs(5), process.wait())
                .await
                .unwrap();
            (result, cleanup.result())
        })
    }
    #[test]
    fn owned_process_bounds_output_and_time() {
        let _process_guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
        let (ok, clean) = run_mode("ok", Duration::from_secs(2), &_process_guard);
        assert!(ok.unwrap().windows(17).any(|x| x == b"controlled-output"));
        assert_eq!(clean, Some(true));
        for mode in ["flood_out", "flood_err"] {
            let (r, c) = run_mode(mode, Duration::from_secs(2), &_process_guard);
            assert_eq!(r, Err(ProcessError::OutputLimit));
            assert_eq!(c, Some(true));
        }
        let (warning, clean) = run_mode("warning", Duration::from_secs(2), &_process_guard);
        assert_eq!(warning, Err(ProcessError::Exit));
        assert_eq!(clean, Some(true));
        let (failed, clean) = run_mode("fail", Duration::from_secs(2), &_process_guard);
        assert_eq!(failed, Err(ProcessError::Exit));
        assert_eq!(clean, Some(true));
        let (r, c) = run_mode("partial", Duration::from_millis(100), &_process_guard);
        assert_eq!(r, Err(ProcessError::Timeout));
        assert_eq!(c, Some(true));
    }
    #[test]
    fn dropping_handle_cancels_and_reaps_owned_group() {
        let _process_guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
        let process = launch(
            fixture_command("stall", &_process_guard),
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
        let _process_guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
        let process = launch(
            fixture_command("descendant", &_process_guard),
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
        let _process_guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let process = launch(
            fixture_command("stall", &_process_guard),
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
    #[test]
    fn interactive_owned_group_relays_and_cancels_locally() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _process_guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut process = launch_attached(
                fixture_command("interactive", &_process_guard),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            let cleanup = process.cleanup();
            let mut stream = process.take_stream().unwrap();
            let mut seen = Vec::new();
            let mut b = [0; 1];
            while !seen.ends_with(b"READY-CLI") {
                tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut b))
                    .await
                    .unwrap()
                    .unwrap();
                seen.push(b[0]);
                assert!(seen.len() < 256);
            }
            stream.write_all(b"PING").await.unwrap();
            let mut reply = [0; 4];
            tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply, b"PING");
            process.activate();
            drop(stream);
            drop(process);
            let until = Instant::now() + Duration::from_secs(4);
            while cleanup.result().is_none() && Instant::now() < until {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(cleanup.result(), Some(true));
        });
    }
    #[test]
    fn interactive_stderr_is_terminal() {
        let _process_guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let process = launch_attached(
                fixture_command("noisy", &_process_guard),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            let cleanup = process.cleanup();
            let until = Instant::now() + Duration::from_secs(4);
            while cleanup.result().is_none() && Instant::now() < until {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(cleanup.result(), Some(true));
            drop(process);
        });
    }
    #[test]
    fn start_marker_requires_exact_durable_cid_and_is_single_use() {
        let p = dir();
        let intent =
            OwnedCreateIntent::prepare_record(&p, [1; 32], [2; 32], [3; 32], [4; 32]).unwrap();
        assert!(intent.record_start([5; 32]).is_err());
        assert!(!p.join("create.start").exists());
        intent.record_cid([5; 32]).unwrap();
        assert!(intent.record_start([6; 32]).is_err());
        assert!(!p.join("create.start").exists());
        intent.record_start([5; 32]).unwrap();
        let record = std::fs::read(p.join("create.start")).unwrap();
        assert!(intent.record_start([5; 32]).is_err());
        assert_eq!(record, std::fs::read(p.join("create.start")).unwrap());
        drop(intent);
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn cid_receipt_is_exclusive_and_never_overwrites() {
        let p = dir();
        let intent =
            OwnedCreateIntent::prepare_record(&p, [1; 32], [2; 32], [3; 32], [4; 32]).unwrap();
        intent.record_cid([5; 32]).unwrap();
        let bytes = std::fs::read(p.join("create.cid")).unwrap();
        assert_eq!(&bytes[..9], b"CCI-CID1\n");
        assert_eq!(&bytes[9..], &[5; 32]);
        assert!(intent.record_cid([6; 32]).is_err());
        assert_eq!(std::fs::read(p.join("create.cid")).unwrap(), bytes);
        drop(intent);
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn fixed_create_recipe_has_no_shell_or_injected_mounts() {
        let identity = Identity {
            dev: 0,
            ino: 0,
            mode: 0,
            uid: 0,
            nlink: 0,
            len: 0,
            mtime: 0,
            mtime_ns: 0,
            ctime: 0,
            ctime_ns: 0,
        };
        let policy = DockerPolicy {
            binary: "/approved/docker".into(),
            socket: "/approved/socket".into(),
            config: "/approved/config".into(),
            binary_identity: identity,
            socket_identity: identity,
            config_identity: identity,
            executable_hash: [1; 32],
            digest: [2; 32],
        };
        let targets = [
            "/adapter/causal-codec.js",
            "/adapter/error-integration",
            "/adapter/live-integration",
            "/data/flows.json",
            "/run/apicontour/live/ca.pem",
            "/run/apicontour/live/export.key",
            "/run/apicontour/live/export.pem",
            "/run/apicontour/live/product.key",
            "/run/apicontour/live/product.pem",
            "/run/apicontour/live/server.key",
            "/run/apicontour/live/server.pem",
        ];
        let spec = FixedCreateSpec {
            network: "causal-net",
            owner: [3; 32],
            mounts: targets.iter().map(|d| ("/approved/source", *d)).collect(),
        };
        let cmd = policy.fixed_create_command(&spec).unwrap();
        assert_eq!(cmd.get_program(), "/approved/docker");
        let args: Vec<_> = cmd.get_args().map(|x| x.to_str().unwrap()).collect();
        assert_eq!(
            args.last(),
            Some(&"/adapter/live-integration/private-launch-proxy.js")
        );
        assert_eq!(args.iter().filter(|x| **x == "--mount").count(), 11);
        for required in [
            "--init",
            "--read-only",
            "--cap-drop",
            "--security-opt",
            "--log-driver",
            "none",
            "--entrypoint",
            "/usr/local/bin/node",
        ] {
            assert!(args.contains(&required));
        }
        assert!(!args.contains(&"/bin/sh"));
        assert!(!args.contains(&"--publish"));
        let mut bad = spec;
        bad.mounts[0].0 = "/approved/source,readonly=false";
        assert!(policy.fixed_create_command(&bad).is_err());
    }
}
