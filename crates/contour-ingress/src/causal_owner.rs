//! Dormant Unix external-owner journal for an exact original issue request.
//!
//! This records intent before invoking the checked issuer. It does not discover a
//! lost nonce, fence a producer, or authorize a replacement or restart. A session
//! can outlive this owner. Continuing a process after an unknown outcome requires
//! an operator to retain the same request and trusted configuration; no retry is
//! automatic. Directory and files must not be modified by another same-UID actor.
//! Forked processes must not use inherited owners; lock descriptors are close-on-exec.
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::{CausalError, CausalIssue, CausalIssuer, CausalSession};
use std::{
    ffi::{CStr, CString},
    fmt,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

const MAX_RECORD: usize = 4 + 64 + 4 + 4 + 10 * 36 + 32 + 36 + 8 + 8 + 2 * 1_048_576;
// Tests that spawn processes share this lock with lock-lifetime fixtures so
// fork/exec cannot transiently duplicate another test's journal descriptor.
#[cfg(test)]
pub(crate) static PROCESS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const LOCK: &CStr = c"lock";
const RECORD: &CStr = c"issue";
const GENERATION: &CStr = c"generation";
const LAUNCH: &CStr = c"launch";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalJournalError {
    Io,
    Unsafe,
    Busy,
    Mismatch,
    Corrupt,
}
impl fmt::Display for CausalJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CausalJournalError {}

fn checked(file: &File, directory: bool) -> Result<(), CausalJournalError> {
    let m = file.metadata().map_err(|_| CausalJournalError::Io)?;
    let kind = if directory {
        m.is_dir()
    } else {
        m.is_file() && m.nlink() == 1
    };
    // SAFETY: geteuid has no arguments and does not retain memory.
    if !kind
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
    {
        return Err(CausalJournalError::Unsafe);
    }
    Ok(())
}
fn open_at(dir: &File, name: &CStr, flags: i32) -> Result<File, std::io::Error> {
    // SAFETY: dir and name remain valid for the call; returned fd is uniquely owned.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_SYNC: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

fn sync_checked(file: &File) -> Result<(), CausalJournalError> {
    #[cfg(test)]
    if FAIL_SYNC.with(|counter| match counter.get() {
        Some(1) => {
            counter.set(None);
            true
        }
        Some(n) => {
            counter.set(Some(n - 1));
            false
        }
        None => false,
    }) {
        return Err(CausalJournalError::Io);
    }
    file.sync_all().map_err(|_| CausalJournalError::Io)
}

/// Opaque bound-launch journal input. No public constructor exists: a future
/// reviewed 503 checked-launch transition must mint it only after binding.
pub struct BoundLaunchRecord {
    slot: [u8; 32],
    launcher: [u8; 32],
    identity: [u8; 32],
    record: Vec<u8>,
}
impl fmt::Debug for BoundLaunchRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundLaunchRecord")
    }
}

/// Holds an exclusive advisory lock until dropped, including across issue futures.
/// This is not a producer fence; a returned session can outlive the owner.
pub struct CausalIssueOwner {
    _dir: File,
    _lock: File,
    request: CausalIssue,
}
impl fmt::Debug for CausalIssueOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalIssueOwner")
    }
}
impl CausalIssueOwner {
    /// Opens an existing private directory. Identities are trusted operator-supplied
    /// stable identifiers for source and key configuration, not values read from disk.
    /// A torn initial write is rejected and requires explicit operator remediation.
    pub fn prepare(
        directory: &Path,
        request: CausalIssue,
        source_identity: [u8; 32],
        key_config_identity: [u8; 32],
    ) -> Result<Self, CausalJournalError> {
        // Walk from the root with no-follow at every component. The held fd is
        // used for all later file operations; relative and dot paths are rejected.
        if directory
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|part| part == b"." || part == b"..")
        {
            return Err(CausalJournalError::Unsafe);
        }
        let mut components = directory.components();
        if components.next() != Some(Component::RootDir) {
            return Err(CausalJournalError::Unsafe);
        }
        // SAFETY: the static path is NUL-terminated; fd is uniquely owned.
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(CausalJournalError::Io);
        }
        let mut dir = unsafe { File::from_raw_fd(fd) };
        let mut count = 0;
        for component in components {
            let Component::Normal(name) = component else {
                return Err(CausalJournalError::Unsafe);
            };
            let name = CString::new(name.as_bytes()).map_err(|_| CausalJournalError::Unsafe)?;
            dir = open_at(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY)
                .map_err(|_| CausalJournalError::Unsafe)?;
            count += 1;
        }
        if count == 0 {
            return Err(CausalJournalError::Unsafe);
        }
        checked(&dir, true)?;
        let lock = open_at(&dir, LOCK, libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK)
            .map_err(|_| CausalJournalError::Io)?;
        checked(&lock, false)?;
        // SAFETY: fd is valid and held for owner lifetime.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let err = std::io::Error::last_os_error();
            return Err(if err.kind() == std::io::ErrorKind::WouldBlock {
                CausalJournalError::Busy
            } else {
                CausalJournalError::Io
            });
        }
        let original = request.original_bytes();
        let mut expected = Vec::with_capacity(72 + original.len());
        expected.extend_from_slice(b"COJ1");
        expected.extend_from_slice(&source_identity);
        expected.extend_from_slice(&key_config_identity);
        expected.extend_from_slice(&(original.len() as u32).to_be_bytes());
        expected.extend_from_slice(&original);
        match open_at(&dir, RECORD, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) {
            Ok(mut file) => {
                checked(&file, false)?;
                file.write_all(&expected)
                    .map_err(|_| CausalJournalError::Io)?;
                sync_checked(&file)?;
                sync_checked(&dir)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let file = open_at(&dir, RECORD, libc::O_RDONLY | libc::O_NONBLOCK)
                    .map_err(|_| CausalJournalError::Unsafe)?;
                checked(&file, false)?;
                if file.metadata().map_err(|_| CausalJournalError::Io)?.len() > MAX_RECORD as u64 {
                    return Err(CausalJournalError::Corrupt);
                }
                let mut saved = Vec::new();
                (&file)
                    .take((MAX_RECORD + 1) as u64)
                    .read_to_end(&mut saved)
                    .map_err(|_| CausalJournalError::Io)?;
                if saved.len() > MAX_RECORD || saved.len() < 72 || &saved[..4] != b"COJ1" {
                    return Err(CausalJournalError::Corrupt);
                }
                let n = u32::from_be_bytes(
                    saved[68..72]
                        .try_into()
                        .map_err(|_| CausalJournalError::Corrupt)?,
                ) as usize;
                if n != saved.len() - 72 || CausalIssue::from_original_bytes(&saved[72..]).is_err()
                {
                    return Err(CausalJournalError::Corrupt);
                }
                if saved != expected {
                    return Err(CausalJournalError::Mismatch);
                }
                // A previous process may have failed before syncing the file or directory.
                sync_checked(&file)?;
                sync_checked(&dir)?;
            }
            Err(_) => return Err(CausalJournalError::Io),
        }
        Ok(Self {
            _dir: dir,
            _lock: lock,
            request,
        })
    }
    // A generation is consumed even when the caller crashes before launch.
    pub(crate) fn claim_generation(&mut self) -> Result<[u8; 32], CausalJournalError> {
        use ring::rand::SecureRandom;
        let mut generation = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut generation)
            .map_err(|_| CausalJournalError::Io)?;
        if generation == [0; 32] {
            return Err(CausalJournalError::Io);
        }
        let mut file = open_at(
            &self._dir,
            GENERATION,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                CausalJournalError::Mismatch
            } else {
                CausalJournalError::Io
            }
        })?;
        checked(&file, false)?;
        file.write_all(b"COG1")
            .and_then(|_| file.write_all(&generation))
            .map_err(|_| CausalJournalError::Io)?;
        sync_checked(&file)?;
        sync_checked(&self._dir)?;
        Ok(generation)
    }
    pub(crate) fn consume_launch(&mut self) -> Result<(), CausalJournalError> {
        let mut file = open_at(
            &self._dir,
            LAUNCH,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                CausalJournalError::Mismatch
            } else {
                CausalJournalError::Io
            }
        })?;
        checked(&file, false)?;
        file.write_all(b"COL1")
            .map_err(|_| CausalJournalError::Io)?;
        sync_checked(&file)?;
        sync_checked(&self._dir)
    }
    // COL2 shares the exclusive launch name with COL1: either form consumes
    // the one-shot launch permanently, including after an uncertain fsync.
    pub fn consume_bound_launch(
        &mut self,
        input: &BoundLaunchRecord,
    ) -> Result<(), CausalJournalError> {
        let BoundLaunchRecord {
            slot,
            launcher,
            identity,
            record,
        } = input;
        use sha2::{Digest, Sha256};
        if *slot == [0; 32]
            || *launcher == [0; 32]
            || *identity == [0; 32]
            || record.is_empty()
            || record.len() > 8192
        {
            return Err(CausalJournalError::Unsafe);
        }
        let mut digest = Sha256::new();
        digest.update(b"apicontour/causal-launcher/1\n");
        digest.update(record);
        if digest.finalize().as_slice() != launcher {
            return Err(CausalJournalError::Mismatch);
        }
        let mut file = open_at(
            &self._dir,
            LAUNCH,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                CausalJournalError::Mismatch
            } else {
                CausalJournalError::Io
            }
        })?;
        checked(&file, false)?;
        file.write_all(b"COL2")
            .and_then(|_| file.write_all(slot))
            .and_then(|_| file.write_all(launcher))
            .and_then(|_| file.write_all(identity))
            .and_then(|_| file.write_all(&(record.len() as u32).to_be_bytes()))
            .and_then(|_| file.write_all(record))
            .map_err(|_| CausalJournalError::Io)?;
        sync_checked(&file)?;
        sync_checked(&self._dir)
    }
    /// One checked issue attempt. OutcomeUnknown is returned unchanged; caller decides
    /// whether to attempt the same original request again under current validation.
    pub async fn issue(
        &mut self,
        issuer: &mut CausalIssuer,
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
    ) -> Result<CausalSession, CausalError> {
        issuer
            .issue(&self.request, peer, grant_keys, policy_keys)
            .await
    }
    pub(crate) async fn issue_until(
        &mut self,
        issuer: &mut CausalIssuer,
        peer: &[u8; 32],
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
        deadline: tokio::time::Instant,
    ) -> Result<CausalSession, CausalError> {
        issuer
            .issue_until(&self.request, peer, grant_keys, policy_keys, deadline)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contour_postgres::CausalBinding;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::{
            MutexGuard,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    const ID: &str = "00000000-0000-4000-8000-000000000001";
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    // An exec test can briefly inherit other threads' CLOEXEC descriptors before
    // exec closes them. Isolate these process-global lock tests from that window;
    // production owners deliberately do not promise fork-safe handoff.
    struct Temp {
        path: std::path::PathBuf,
        _serial: MutexGuard<'static, ()>,
    }
    impl Temp {
        fn new() -> Self {
            let serial = PROCESS_TEST_LOCK.lock().unwrap();
            let path = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "contour-owner-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                path,
                _serial: serial,
            }
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    fn request(nonce: &str) -> CausalIssue {
        CausalIssue::new(
            CausalBinding::new([ID; 10], [3; 32]).unwrap(),
            nonce,
            Duration::from_secs(60),
            b"grant",
            b"policy",
        )
        .unwrap()
    }
    fn prepare(path: &Path) -> Result<CausalIssueOwner, CausalJournalError> {
        CausalIssueOwner::prepare(path, request(ID), [1; 32], [2; 32])
    }
    #[test]
    fn exact_reopen_and_in_process_lock() {
        let t = Temp::new();
        let owner = prepare(&t.path).unwrap();
        assert_eq!(prepare(&t.path).unwrap_err(), CausalJournalError::Busy);
        assert!(t.path.join("issue").exists());
        drop(owner);
        assert_eq!(
            CausalIssueOwner::prepare(&t.path, request(ID), [9; 32], [2; 32]).unwrap_err(),
            CausalJournalError::Mismatch
        );
        assert_eq!(
            CausalIssueOwner::prepare(&t.path, request(ID), [1; 32], [9; 32]).unwrap_err(),
            CausalJournalError::Mismatch
        );
        assert_eq!(
            CausalIssueOwner::prepare(
                &t.path,
                request("00000000-0000-4000-8000-000000000002"),
                [1; 32],
                [2; 32]
            )
            .unwrap_err(),
            CausalJournalError::Mismatch
        );
        prepare(&t.path).unwrap();
    }
    #[test]
    fn child_lock_probe() {
        if let Some(path) = std::env::var_os("CONTOUR_OWNER_TEST_DIR") {
            assert_eq!(
                prepare(Path::new(&path)).unwrap_err(),
                CausalJournalError::Busy
            );
        }
    }
    #[test]
    fn competing_exec_cannot_acquire_lock() {
        let t = Temp::new();
        let _owner = prepare(&t.path).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "causal_owner::tests::child_lock_probe",
                "--nocapture",
            ])
            .env("CONTOUR_OWNER_TEST_DIR", &t.path)
            .status()
            .unwrap();
        assert!(status.success());
    }
    #[test]
    fn generation_claim_is_single_use_across_owner_reopen() {
        let t = Temp::new();
        let mut owner = prepare(&t.path).unwrap();
        owner.claim_generation().unwrap();
        assert_eq!(owner.claim_generation(), Err(CausalJournalError::Mismatch));
        drop(owner);
        let mut reopened = prepare(&t.path).unwrap();
        assert_eq!(
            reopened.claim_generation(),
            Err(CausalJournalError::Mismatch)
        );
    }
    #[test]
    fn launch_consumption_is_single_use_even_on_sync_failure() {
        for step in 0..=2 {
            let t = Temp::new();
            let mut owner = prepare(&t.path).unwrap();
            let generation = owner.claim_generation().unwrap();
            assert_ne!(generation, [0; 32]);
            if step == 0 {
                owner.consume_launch().unwrap();
            } else {
                let _fail = SyncFailure::at(step);
                assert_eq!(owner.consume_launch(), Err(CausalJournalError::Io));
            }
            assert_eq!(owner.consume_launch(), Err(CausalJournalError::Mismatch));
            drop(owner);
            assert_eq!(
                prepare(&t.path).unwrap().claim_generation(),
                Err(CausalJournalError::Mismatch)
            );
        }
    }
    #[test]
    fn bound_launch_is_exact_exclusive_and_never_reusable_after_sync_failure() {
        use sha2::{Digest, Sha256};
        let record = b"{\"version\":1}";
        let mut h = Sha256::new();
        h.update(b"apicontour/causal-launcher/1\n");
        h.update(record);
        let hash: [u8; 32] = h.finalize().into();
        for step in 0..=2 {
            let t = Temp::new();
            let mut owner = prepare(&t.path).unwrap();
            owner.claim_generation().unwrap();
            assert_eq!(
                owner.consume_bound_launch(&BoundLaunchRecord {
                    slot: [1; 32],
                    launcher: [9; 32],
                    identity: [2; 32],
                    record: record.to_vec()
                }),
                Err(CausalJournalError::Mismatch)
            );
            assert!(!t.path.join("launch").exists());
            if step == 0 {
                owner
                    .consume_bound_launch(&BoundLaunchRecord {
                        slot: [1; 32],
                        launcher: hash,
                        identity: [2; 32],
                        record: record.to_vec(),
                    })
                    .unwrap();
            } else {
                let _fail = SyncFailure::at(step);
                assert_eq!(
                    owner.consume_bound_launch(&BoundLaunchRecord {
                        slot: [1; 32],
                        launcher: hash,
                        identity: [2; 32],
                        record: record.to_vec()
                    }),
                    Err(CausalJournalError::Io)
                );
            }
            let stored = std::fs::read(t.path.join("launch")).unwrap();
            assert_eq!(&stored[..4], b"COL2");
            assert_eq!(&stored[4..36], &[1; 32]);
            assert_eq!(&stored[36..68], &hash);
            assert_eq!(&stored[68..100], &[2; 32]);
            assert_eq!(
                u32::from_be_bytes(stored[100..104].try_into().unwrap()) as usize,
                record.len()
            );
            assert_eq!(&stored[104..], record);
            assert_eq!(
                owner.consume_bound_launch(&BoundLaunchRecord {
                    slot: [1; 32],
                    launcher: hash,
                    identity: [2; 32],
                    record: record.to_vec()
                }),
                Err(CausalJournalError::Mismatch)
            );
            assert_eq!(owner.consume_launch(), Err(CausalJournalError::Mismatch));
        }
    }
    #[test]
    fn old_launch_blocks_bound_launch_without_replacement() {
        use sha2::{Digest, Sha256};
        let t = Temp::new();
        let mut owner = prepare(&t.path).unwrap();
        owner.claim_generation().unwrap();
        owner.consume_launch().unwrap();
        let mut h = Sha256::new();
        h.update(b"apicontour/causal-launcher/1\n");
        h.update(b"x");
        let hash: [u8; 32] = h.finalize().into();
        assert_eq!(
            owner.consume_bound_launch(&BoundLaunchRecord {
                slot: [1; 32],
                launcher: hash,
                identity: [2; 32],
                record: b"x".to_vec()
            }),
            Err(CausalJournalError::Mismatch)
        );
        assert_eq!(std::fs::read(t.path.join("launch")).unwrap(), b"COL1");
    }

    #[test]
    fn uncertain_generation_sync_still_blocks_reuse() {
        for step in 1..=2 {
            let t = Temp::new();
            let mut owner = prepare(&t.path).unwrap();
            {
                let _fail = SyncFailure::at(step);
                assert_eq!(owner.claim_generation(), Err(CausalJournalError::Io));
            }
            drop(owner);
            assert_eq!(
                prepare(&t.path).unwrap().claim_generation(),
                Err(CausalJournalError::Mismatch)
            );
        }
    }
    #[test]
    fn torn_or_unsafe_files_fail_closed() {
        let t = Temp::new();
        drop(prepare(&t.path).unwrap());
        std::fs::write(t.path.join("issue"), b"COJ1").unwrap();
        assert_eq!(prepare(&t.path).unwrap_err(), CausalJournalError::Corrupt);
        std::fs::remove_file(t.path.join("issue")).unwrap();
        symlink("lock", t.path.join("issue")).unwrap();
        assert!(prepare(&t.path).is_err());
        std::fs::remove_file(t.path.join("issue")).unwrap();
        std::fs::hard_link(t.path.join("lock"), t.path.join("issue")).unwrap();
        assert!(prepare(&t.path).is_err());
        std::fs::remove_file(t.path.join("issue")).unwrap();
        std::fs::set_permissions(t.path.join("lock"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert_eq!(prepare(&t.path).unwrap_err(), CausalJournalError::Unsafe);
    }
    #[test]
    fn path_components_cannot_redirect_or_escape() {
        let t = Temp::new();
        assert_eq!(
            prepare(Path::new("relative")).unwrap_err(),
            CausalJournalError::Unsafe
        );
        assert_eq!(
            prepare(&t.path.join("../other")).unwrap_err(),
            CausalJournalError::Unsafe
        );
        assert_eq!(
            prepare(&t.path.join("./child")).unwrap_err(),
            CausalJournalError::Unsafe
        );
        let child = t.path.join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(prepare(&child).unwrap());
        let alias = t.path.join("alias");
        symlink(&t.path, &alias).unwrap();
        assert!(prepare(&alias.join("child")).is_err());
        let final_alias = t.path.join("final_alias");
        symlink(&child, &final_alias).unwrap();
        assert!(prepare(&final_alias).is_err());
        let mut trailing = final_alias.into_os_string();
        trailing.push("/");
        assert!(prepare(Path::new(&trailing)).is_err());
    }
    struct SyncFailure;
    impl SyncFailure {
        fn at(n: usize) -> Self {
            FAIL_SYNC.with(|counter| counter.set(Some(n)));
            Self
        }
    }
    impl Drop for SyncFailure {
        fn drop(&mut self) {
            FAIL_SYNC.with(|counter| counter.set(None));
        }
    }
    #[test]
    fn sync_failures_never_return_an_owner_and_reopen_requires_both_syncs() {
        // These inject syscall errors, not a hardware durability failure.
        for initial_failure in 1..=2 {
            let t = Temp::new();
            {
                let _reset = SyncFailure::at(initial_failure);
                assert_eq!(prepare(&t.path).unwrap_err(), CausalJournalError::Io);
            }
            for reopen_failure in 1..=2 {
                let _reset = SyncFailure::at(reopen_failure);
                assert_eq!(prepare(&t.path).unwrap_err(), CausalJournalError::Io);
            }
            // Also proves each failed attempt released the lifetime lock.
            drop(prepare(&t.path).unwrap());
        }
    }
    #[test]
    fn maximum_envelopes_reopen() {
        let t = Temp::new();
        let request = || {
            CausalIssue::new(
                CausalBinding::new([ID; 10], [3; 32]).unwrap(),
                ID,
                Duration::from_secs(60),
                &vec![1; 1_048_576],
                &vec![2; 1_048_576],
            )
            .unwrap()
        };
        drop(CausalIssueOwner::prepare(&t.path, request(), [1; 32], [2; 32]).unwrap());
        CausalIssueOwner::prepare(&t.path, request(), [1; 32], [2; 32]).unwrap();
    }
    #[test]
    fn directory_and_lock_symlink_rejected() {
        let t = Temp::new();
        std::fs::set_permissions(&t.path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(prepare(&t.path).unwrap_err(), CausalJournalError::Unsafe);
        std::fs::set_permissions(&t.path, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink("missing", t.path.join("lock")).unwrap();
        assert!(prepare(&t.path).is_err());
    }
}
