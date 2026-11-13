//! Local same-byte material evidence. The host, its dynamic libraries and clock
//! are trusted prerequisites; this is neither peer proof nor launch authority.
//! Protected source ancestors are required in addition to private snapshot files.
use crate::causal_launch_files::{FileSnapshot, snapshot_file};
use crate::causal_launch_process::{
    Identity, check_deadline, checked_path, hash_executable, launch,
};
use crate::causal_receiver_material::{
    LocalReceiverMaterialIdentity, ReceiverMaterialInputs, check_at,
};
use rustls::pki_types::UnixTime;
use std::{
    ffi::CString,
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverMaterialCheckError {
    Unsafe,
    Invalid,
    Process,
    Cleanup,
}

/// Absolute private source paths, in purpose order. All ten files must be 0600.
pub struct ReceiverMaterialPaths {
    pub marker_seed: PathBuf,
    pub product_cert: PathBuf,
    pub product_key: PathBuf,
    pub export_cert: PathBuf,
    pub export_key: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub evidence_cert: PathBuf,
    pub evidence_key: PathBuf,
    pub ca: PathBuf,
    pub server_name: String,
}
impl ReceiverMaterialPaths {
    fn paths(&self) -> [&Path; 10] {
        [
            &self.marker_seed,
            &self.product_cert,
            &self.product_key,
            &self.export_cert,
            &self.export_key,
            &self.server_cert,
            &self.server_key,
            &self.evidence_cert,
            &self.evidence_key,
            &self.ca,
        ]
    }
}
struct Captured {
    path: PathBuf,
    id: Identity,
    bytes: FileSnapshot,
}
fn capture(path: &Path) -> Result<Captured, ReceiverMaterialCheckError> {
    let before =
        Identity::from(&checked_path(path).map_err(|_| ReceiverMaterialCheckError::Unsafe)?);
    let bytes = snapshot_file(path, true).map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
    let after =
        Identity::from(&checked_path(path).map_err(|_| ReceiverMaterialCheckError::Unsafe)?);
    if before != after {
        return Err(ReceiverMaterialCheckError::Unsafe);
    }
    Ok(Captured {
        path: path.to_owned(),
        id: before,
        bytes,
    })
}
impl Captured {
    fn revalidate(&self) -> Result<(), ReceiverMaterialCheckError> {
        let current = capture(&self.path)?;
        if current.id != self.id || current.bytes.as_bytes() != self.bytes.as_bytes() {
            return Err(ReceiverMaterialCheckError::Unsafe);
        }
        Ok(())
    }
}
struct Tool {
    path: PathBuf,
    hash: [u8; 32],
    id: Identity,
}
impl Tool {
    fn revalidate(&self) -> Result<(), ReceiverMaterialCheckError> {
        let (hash, id) =
            hash_executable(&self.path).map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
        if hash != self.hash || id != self.id {
            return Err(ReceiverMaterialCheckError::Unsafe);
        }
        Ok(())
    }
}
/// Private retained snapshots and local identity. Best-effort clearing on drop is
/// not a memory-erasure guarantee. This object cannot authorize a launch.
pub struct CheckedReceiverMaterial {
    files: Vec<Captured>,
    tool: Tool,
    server_name: String,
    identity: LocalReceiverMaterialIdentity,
    ca_before: i64,
    ca_after: i64,
}
impl CheckedReceiverMaterial {
    pub(crate) fn deployment_commitment(&self) -> Result<[u8; 32], ReceiverMaterialCheckError> {
        use sha2::{Digest, Sha256};
        self.revalidate()?;
        let mut hash = Sha256::new();
        hash.update(b"apicontour/receiver504-material/1\n");
        for file in &self.files {
            hash.update((file.path.as_os_str().as_encoded_bytes().len() as u64).to_be_bytes());
            hash.update(file.path.as_os_str().as_encoded_bytes());
            hash.update(Sha256::digest(file.bytes.as_bytes()));
        }
        Ok(hash.finalize().into())
    }
    pub(crate) fn deployment_paths(
        &self,
    ) -> Result<Vec<(&Path, &'static str)>, ReceiverMaterialCheckError> {
        self.revalidate()?;
        let destinations = [
            "/run/apicontour/live/product.pem",
            "/run/apicontour/live/product.key",
            "/run/apicontour/live/export.pem",
            "/run/apicontour/live/export.key",
            "/run/apicontour/live/server.pem",
            "/run/apicontour/live/server.key",
            "/run/apicontour/live/evidence.pem",
            "/run/apicontour/live/evidence.key",
            "/run/apicontour/live/ca.pem",
        ];
        if self.files.len() != 10 {
            return Err(ReceiverMaterialCheckError::Invalid);
        }
        Ok(self
            .files
            .iter()
            .skip(1)
            .zip(destinations)
            .map(|(f, d)| (f.path.as_path(), d))
            .collect())
    }
    pub fn identity(&self) -> &LocalReceiverMaterialIdentity {
        &self.identity
    }
    /// Recheck retained source identity, bytes, tool, and current certificate time.
    pub fn revalidate(&self) -> Result<(), ReceiverMaterialCheckError> {
        self.tool.revalidate()?;
        for file in &self.files {
            file.revalidate()?;
        }
        let now = epoch()?;
        if now < self.ca_before || now >= self.ca_after {
            return Err(ReceiverMaterialCheckError::Invalid);
        }
        if evaluate(&self.files, &self.server_name, now)? != self.identity {
            return Err(ReceiverMaterialCheckError::Invalid);
        }
        Ok(())
    }
}
fn epoch() -> Result<i64, ReceiverMaterialCheckError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReceiverMaterialCheckError::Invalid)?
            .as_secs(),
    )
    .map_err(|_| ReceiverMaterialCheckError::Invalid)
}
fn evaluate(
    files: &[Captured],
    name: &str,
    now: i64,
) -> Result<LocalReceiverMaterialIdentity, ReceiverMaterialCheckError> {
    let b = |i: usize| files[i].bytes.as_bytes();
    let marker: &[u8; 32] = b(0)
        .try_into()
        .map_err(|_| ReceiverMaterialCheckError::Invalid)?;
    let input = ReceiverMaterialInputs {
        marker_seed: marker,
        product_cert: b(1),
        product_key: b(2),
        export_cert: b(3),
        export_key: b(4),
        server_cert: b(5),
        server_key: b(6),
        evidence_cert: b(7),
        evidence_key: b(8),
        ca: b(9),
        server_name: name,
    };
    check_at(
        &input,
        UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(now).map_err(|_| ReceiverMaterialCheckError::Invalid)?,
        )),
    )
    .map_err(|_| ReceiverMaterialCheckError::Invalid)
}
const COPIES: [(&str, usize); 5] = [
    ("product.pem", 1),
    ("export.pem", 3),
    ("server.pem", 5),
    ("evidence.pem", 7),
    ("ca.pem", 9),
];
struct Stage {
    path: PathBuf,
    files: Vec<Captured>,
    id: Option<Identity>,
    directory: Option<File>,
}
impl Stage {
    fn create(path: &Path, source: &[Captured]) -> Result<Self, ReceiverMaterialCheckError> {
        let parent = path.parent().ok_or(ReceiverMaterialCheckError::Unsafe)?;
        let parent_id =
            Identity::from(&checked_path(parent).map_err(|_| ReceiverMaterialCheckError::Unsafe)?);
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
        let mut stage = Self {
            path: path.to_owned(),
            files: Vec::new(),
            id: None,
            directory: None,
        };
        if !parent_id.same_object(&Identity::from(
            &checked_path(parent).map_err(|_| ReceiverMaterialCheckError::Unsafe)?,
        )) {
            return Err(ReceiverMaterialCheckError::Unsafe);
        }
        for (name, index) in COPIES {
            let input = &source[index];
            let p = path.join(name);
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&p)
                .map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
            f.write_all(input.bytes.as_bytes())
                .map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
            drop(f);
            let copy = capture(&p)?;
            if copy.bytes.as_bytes() != input.bytes.as_bytes() {
                return Err(ReceiverMaterialCheckError::Unsafe);
            }
            stage.files.push(copy);
        }
        stage.id = Some(Identity::from(
            &checked_path(path).map_err(|_| ReceiverMaterialCheckError::Unsafe)?,
        ));
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
        if Some(Identity::from(
            &directory
                .metadata()
                .map_err(|_| ReceiverMaterialCheckError::Unsafe)?,
        )) != stage.id
        {
            return Err(ReceiverMaterialCheckError::Unsafe);
        }
        stage.directory = Some(directory);
        stage.revalidate()?;
        Ok(stage)
    }
    fn revalidate(&self) -> Result<(), ReceiverMaterialCheckError> {
        let m = checked_path(&self.path).map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
        if !m.is_dir()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != 0o700
            || self.id != Some(Identity::from(&m))
        {
            return Err(ReceiverMaterialCheckError::Unsafe);
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or(ReceiverMaterialCheckError::Unsafe)?;
        if Some(Identity::from(
            &directory
                .metadata()
                .map_err(|_| ReceiverMaterialCheckError::Unsafe)?,
        )) != self.id
        {
            return Err(ReceiverMaterialCheckError::Unsafe);
        }
        for f in &self.files {
            f.revalidate()?;
        }
        if fs::read_dir(&self.path)
            .map_err(|_| ReceiverMaterialCheckError::Unsafe)?
            .count()
            != COPIES.len()
        {
            return Err(ReceiverMaterialCheckError::Unsafe);
        }
        Ok(())
    }
    fn cleanup(mut self) -> Result<(), ReceiverMaterialCheckError> {
        self.revalidate()
            .map_err(|_| ReceiverMaterialCheckError::Cleanup)?;
        let directory = self
            .directory
            .as_ref()
            .ok_or(ReceiverMaterialCheckError::Cleanup)?;
        for f in &self.files {
            let current_dir =
                checked_path(&self.path).map_err(|_| ReceiverMaterialCheckError::Cleanup)?;
            let held_dir = directory
                .metadata()
                .map_err(|_| ReceiverMaterialCheckError::Cleanup)?;
            let expected = self.id.ok_or(ReceiverMaterialCheckError::Cleanup)?;
            if !expected.same_object(&Identity::from(&current_dir))
                || !expected.same_object(&Identity::from(&held_dir))
            {
                return Err(ReceiverMaterialCheckError::Cleanup);
            }
            f.revalidate()
                .map_err(|_| ReceiverMaterialCheckError::Cleanup)?;
            let name = CString::new(
                f.path
                    .file_name()
                    .ok_or(ReceiverMaterialCheckError::Cleanup)?
                    .as_bytes(),
            )
            .map_err(|_| ReceiverMaterialCheckError::Cleanup)?;
            // The held directory descriptor and no-follow open bind this lookup
            // to our directory. Same-UID mutation between lookup and unlink is
            // outside the trusted-host prerequisite and cannot be made atomic
            // with portable unlinkat.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(ReceiverMaterialCheckError::Cleanup);
            }
            let opened = unsafe { File::from_raw_fd(fd) };
            if Identity::from(
                &opened
                    .metadata()
                    .map_err(|_| ReceiverMaterialCheckError::Cleanup)?,
            ) != f.id
            {
                return Err(ReceiverMaterialCheckError::Cleanup);
            }
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(ReceiverMaterialCheckError::Cleanup);
            }
        }
        let current = checked_path(&self.path).map_err(|_| ReceiverMaterialCheckError::Cleanup)?;
        if !self
            .id
            .ok_or(ReceiverMaterialCheckError::Cleanup)?
            .same_object(&Identity::from(&current))
        {
            return Err(ReceiverMaterialCheckError::Cleanup);
        }
        let parent_path = self
            .path
            .parent()
            .ok_or(ReceiverMaterialCheckError::Cleanup)?;
        let parent_meta =
            checked_path(parent_path).map_err(|_| ReceiverMaterialCheckError::Cleanup)?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent_path)
            .map_err(|_| ReceiverMaterialCheckError::Cleanup)?;
        if Identity::from(&parent_meta)
            != Identity::from(
                &parent
                    .metadata()
                    .map_err(|_| ReceiverMaterialCheckError::Cleanup)?,
            )
        {
            return Err(ReceiverMaterialCheckError::Cleanup);
        }
        let name = CString::new(
            self.path
                .file_name()
                .ok_or(ReceiverMaterialCheckError::Cleanup)?
                .as_bytes(),
        )
        .map_err(|_| ReceiverMaterialCheckError::Cleanup)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(ReceiverMaterialCheckError::Cleanup);
        }
        let opened = unsafe { File::from_raw_fd(fd) };
        if !self
            .id
            .ok_or(ReceiverMaterialCheckError::Cleanup)?
            .same_object(&Identity::from(
                &opened
                    .metadata()
                    .map_err(|_| ReceiverMaterialCheckError::Cleanup)?,
            ))
        {
            return Err(ReceiverMaterialCheckError::Cleanup);
        }
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(ReceiverMaterialCheckError::Cleanup);
        }
        self.files.clear();
        self.id = None;
        self.directory = None;
        Ok(())
    }
}
// Setup failure or cancellation can retain up to five public certificate
// copies in the private staging directory. No keys or seed are staged. Drop
// does not delete paths because ownership might no longer be provable.
impl Drop for Stage {
    fn drop(&mut self) { /* Never delete an unverified or replaced path. */
    }
}
fn check_all(
    tool: &Tool,
    source: &[Captured],
    stage: &Stage,
) -> Result<(), ReceiverMaterialCheckError> {
    tool.revalidate()?;
    for f in source {
        f.revalidate()?;
    }
    stage.revalidate()
}
async fn run(
    tool: &Tool,
    source: &[Captured],
    stage: &Stage,
    deadline: Instant,
    args: &[&str],
) -> Result<Vec<u8>, ReceiverMaterialCheckError> {
    check_deadline(deadline).map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
    check_all(tool, source, stage)?;
    check_deadline(deadline).map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
    let end = deadline.min(Instant::now() + Duration::from_secs(10));
    let mut command = Command::new(&tool.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("OPENSSL_CONF", "/dev/null")
        .env("OPENSSL_MODULES", "/dev/null")
        .args(args);
    let process = launch(command, end).map_err(|_| ReceiverMaterialCheckError::Process)?;
    let cleanup = process.cleanup();
    let result = process.wait().await;
    let after = check_all(tool, source, stage);
    if cleanup.result() != Some(true) {
        return Err(ReceiverMaterialCheckError::Cleanup);
    }
    after?;
    let out = result.map_err(|_| ReceiverMaterialCheckError::Process)?;
    if out.len() > 65536 {
        return Err(ReceiverMaterialCheckError::Invalid);
    }
    Ok(out)
}
fn extension<'a>(data: &'a [u8], title: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(data).ok()?;
    let (header, body) = text.split_once('\n')?;
    if header != format!("X509v3 {title}:") && header != format!("X509v3 {title}: critical") {
        return None;
    }
    body.strip_prefix("    ")?
        .strip_suffix('\n')
        .filter(|s| !s.contains('\n'))
}
fn ca_constraints(data: &[u8]) -> bool {
    match extension(data, "Basic Constraints") {
        Some("CA:TRUE") => true,
        Some(s) => s
            .strip_prefix("CA:TRUE, pathlen:")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())),
        None => false,
    }
}
fn ca_usage(data: &[u8]) -> bool {
    matches!(
        extension(data, "Key Usage"),
        Some("Certificate Sign") | Some("Certificate Sign, CRL Sign")
    )
}
fn leaf_usage(data: &[u8]) -> bool {
    let Some(s) = extension(data, "Key Usage") else {
        return false;
    };
    let values: Vec<_> = s.split(", ").collect();
    let allowed = [
        "Digital Signature",
        "Non Repudiation",
        "Key Encipherment",
        "Data Encipherment",
        "Key Agreement",
        "Certificate Sign",
        "CRL Sign",
        "Encipher Only",
        "Decipher Only",
    ];
    values.contains(&"Digital Signature")
        && values
            .iter()
            .enumerate()
            .all(|(i, v)| allowed.contains(v) && !values[..i].contains(v))
}
fn date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if !s.is_ascii()
        || b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b' '
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let n = |a: usize, z: usize| -> Option<u32> {
        let x = &s[a..z];
        if !x.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        x.parse().ok()
    };
    let d = time::Date::from_calendar_date(
        n(0, 4)? as i32,
        time::Month::try_from(n(5, 7)? as u8).ok()?,
        n(8, 10)? as u8,
    )
    .ok()?;
    let t = time::Time::from_hms(n(11, 13)? as u8, n(14, 16)? as u8, n(17, 19)? as u8).ok()?;
    Some(d.with_time(t).assume_utc().unix_timestamp())
}
fn dates(bytes: &[u8]) -> Option<(i64, i64)> {
    let s = std::str::from_utf8(bytes).ok()?;
    let (a, b) = s.split_once('\n')?;
    let a = date(a.strip_prefix("notBefore=")?)?;
    let b = date(b.strip_prefix("notAfter=")?.strip_suffix('\n')?)?;
    (a < b).then_some((a, b))
}
/// Check private captured material using an explicitly selected, hash-pinned
/// qualified OpenSSL. `stage_path` must not exist and its parent must be
/// protected. The caller must bound synchronous setup externally. The deadline
/// is absolute and must be at most 600 seconds away.
pub async fn check_receiver_material(
    paths: &ReceiverMaterialPaths,
    openssl: &Path,
    expected_sha256: [u8; 32],
    stage_path: &Path,
    deadline: Instant,
) -> Result<CheckedReceiverMaterial, ReceiverMaterialCheckError> {
    check_deadline(deadline).map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
    let (hash, id) = hash_executable(openssl).map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
    if hash != expected_sha256 {
        return Err(ReceiverMaterialCheckError::Unsafe);
    }
    let tool = Tool {
        path: openssl.to_owned(),
        hash,
        id,
    };
    let files: Vec<_> = paths
        .paths()
        .into_iter()
        .map(capture)
        .collect::<Result<_, _>>()?;
    let now = epoch()?;
    let identity = evaluate(&files, &paths.server_name, now)?;
    let stage = Stage::create(stage_path, &files)?;
    let outcome = async {
        let version = run(&tool, &files, &stage, deadline, &["version"]).await?;
        if version != b"OpenSSL 3.6.3 9 Jun 2026\n"
            && version != b"OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)\n"
        {
            return Err(ReceiverMaterialCheckError::Invalid);
        }
        let ca = stage.path.join("ca.pem");
        let ca = ca.to_str().ok_or(ReceiverMaterialCheckError::Unsafe)?;
        let output = run(
            &tool,
            &files,
            &stage,
            deadline,
            &[
                "x509", "-in", ca, "-noout", "-dates", "-dateopt", "iso_8601",
            ],
        )
        .await?;
        let (before, after) = dates(&output).ok_or(ReceiverMaterialCheckError::Invalid)?;
        if now < before || now >= after {
            return Err(ReceiverMaterialCheckError::Invalid);
        }
        if !ca_constraints(
            &run(
                &tool,
                &files,
                &stage,
                deadline,
                &["x509", "-in", ca, "-noout", "-ext", "basicConstraints"],
            )
            .await?,
        ) || !ca_usage(
            &run(
                &tool,
                &files,
                &stage,
                deadline,
                &["x509", "-in", ca, "-noout", "-ext", "keyUsage"],
            )
            .await?,
        ) {
            return Err(ReceiverMaterialCheckError::Invalid);
        }
        let epoch = now.to_string();
        let verified = run(
            &tool,
            &files,
            &stage,
            deadline,
            &[
                "verify",
                "-x509_strict",
                "-check_ss_sig",
                "-attime",
                &epoch,
                "-CAfile",
                ca,
                ca,
            ],
        )
        .await?;
        if verified != format!("{ca}: OK\n").as_bytes() {
            return Err(ReceiverMaterialCheckError::Invalid);
        }
        for name in ["product.pem", "export.pem", "server.pem", "evidence.pem"] {
            let p = stage.path.join(name);
            let p = p.to_str().ok_or(ReceiverMaterialCheckError::Unsafe)?;
            if !leaf_usage(
                &run(
                    &tool,
                    &files,
                    &stage,
                    deadline,
                    &["x509", "-in", p, "-noout", "-ext", "keyUsage"],
                )
                .await?,
            ) {
                return Err(ReceiverMaterialCheckError::Invalid);
            }
        }
        Ok((before, after))
    }
    .await;
    let cleanup = stage.cleanup();
    cleanup?;
    let (ca_before, ca_after) = outcome?;
    let result = CheckedReceiverMaterial {
        files,
        tool,
        server_name: paths.server_name.clone(),
        identity,
        ca_before,
        ca_after,
    };
    result.revalidate()?;
    check_deadline(deadline).map_err(|_| ReceiverMaterialCheckError::Unsafe)?;
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_parsers_reject_ambiguity() {
        assert!(ca_constraints(
            b"X509v3 Basic Constraints: critical\n    CA:TRUE, pathlen:0\n"
        ));
        assert!(!ca_constraints(
            b"X509v3 Basic Constraints:\n    CA:TRUE, pathlen:x\n"
        ));
        assert!(ca_usage(
            b"X509v3 Key Usage: critical\n    Certificate Sign, CRL Sign\n"
        ));
        assert!(!ca_usage(b"X509v3 Key Usage:\n    Digital Signature\n"));
        assert!(leaf_usage(
            b"X509v3 Key Usage: critical\n    Digital Signature, Key Encipherment\n"
        ));
        assert!(!leaf_usage(
            b"X509v3 Key Usage:\n    Digital Signature, Digital Signature\n"
        ));
        assert!(!leaf_usage(
            b"X509v3 Key Usage:\n    Digital Signature, Unknown\n"
        ));
        assert!(
            dates(b"notBefore=2026-01-01 00:00:00Z\nnotAfter=2027-01-01 00:00:00Z\n").is_some()
        );
        assert!(
            dates(b"notBefore=2026-02-30 00:00:00Z\nnotAfter=2027-01-01 00:00:00Z\n").is_none()
        );
    }
    #[test]
    fn staging_rejects_replacement_and_preserves_unknown_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap();
        let dir = root.join(format!("material-stage-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut sources = Vec::new();
        for i in 0..10 {
            let p = dir.join(format!("source-{i}"));
            fs::write(&p, format!("public fixture {i}")).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
            sources.push(capture(&p).unwrap());
        }
        let retained = Stage::create(&dir.join("retained"), &sources).unwrap();
        drop(retained);
        assert_eq!(fs::read_dir(dir.join("retained")).unwrap().count(), 5);
        assert!(!dir.join("retained/product.key").exists());
        let stage = Stage::create(&dir.join("stage"), &sources).unwrap();
        assert_eq!(stage.files.len(), 5);
        let replaced = dir.join("stage/product.pem");
        fs::rename(&replaced, dir.join("owned-original")).unwrap();
        fs::write(&replaced, b"unknown replacement").unwrap();
        fs::set_permissions(&replaced, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(stage.cleanup(), Err(ReceiverMaterialCheckError::Cleanup));
        assert_eq!(fs::read(&replaced).unwrap(), b"unknown replacement");
        assert!(dir.join("owned-original").exists());
        let bad = dir.join("unsafe");
        fs::write(&bad, b"fixture").unwrap();
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(capture(&bad).is_err());
        let alias = dir.join("alias");
        symlink(&bad, &alias).unwrap();
        assert!(capture(&alias).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn captured_tool_and_source_drift_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap();
        let dir = root.join(format!("material-drift-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let source = dir.join("source");
        fs::write(&source, b"one").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let captured = capture(&source).unwrap();
        fs::write(&source, b"two").unwrap();
        assert!(captured.revalidate().is_err());
        let executable = dir.join("executable");
        fs::write(&executable, b"one").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let (hash, id) = hash_executable(&executable).unwrap();
        let tool = Tool {
            path: executable.clone(),
            hash,
            id,
        };
        assert!(tool.revalidate().is_ok());
        fs::write(&executable, b"two").unwrap();
        assert!(tool.revalidate().is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    // Generator commands run only in this ignored synthetic test, under the
    // same pinned executable identity checks as the production recipes.
    #[test]
    #[ignore = "requires explicit qualified OpenSSL binary"]
    fn qualified_openssl_isolates_new_certificate_predicates() {
        use std::{ffi::OsStr, os::unix::fs::PermissionsExt, process::Stdio};
        let _guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
        let binary =
            PathBuf::from(std::env::var_os("CONTOUR_TEST_OPENSSL").expect("qualified path"));
        let (hash, id) = hash_executable(&binary).unwrap();
        assert_eq!(
            hash,
            [
                0x10, 0x3f, 0xc7, 0x70, 0x6c, 0xf6, 0x64, 0x6f, 0x22, 0x6d, 0x96, 0xf2, 0x92, 0x42,
                0xd8, 0x18, 0x90, 0x36, 0x34, 0x99, 0xaf, 0xc7, 0x30, 0xe7, 0xef, 0x1f, 0xad, 0xd6,
                0x4b, 0x3a, 0x12, 0x3c
            ]
        );
        let tool = Tool {
            path: binary,
            hash,
            id,
        };
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap();
        let dir = root.join(format!("material-variants-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let run_fixture = |args: &[&OsStr]| {
            tool.revalidate().unwrap();
            let status = Command::new(&tool.path)
                .args(args)
                .current_dir(&dir)
                .env_clear()
                .env("LC_ALL", "C")
                .env("OPENSSL_CONF", "/dev/null")
                .env("OPENSSL_MODULES", "/dev/null")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            tool.revalidate().unwrap();
            assert!(status.success(), "synthetic fixture command failed");
        };
        let cmd = |args: &[&str]| {
            let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
            run_fixture(&args);
        };
        cmd(&["genpkey", "-algorithm", "ED25519", "-out", "ca.key"]);
        let config = "[req]\ndistinguished_name=dn\n[dn]\nCN=fixture\n[ca_good]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n[ca_nonca]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n[ca_noku]\nbasicConstraints=critical,CA:TRUE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n[client]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n[client_nods]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n[server]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:receiver.example.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n";
        fs::write(dir.join("fixture.cnf"), config).unwrap();
        for (profile, name) in [
            ("ca_good", "good-ca.pem"),
            ("ca_nonca", "nonca.pem"),
            ("ca_noku", "noku-ca.pem"),
        ] {
            cmd(&[
                "req",
                "-new",
                "-x509",
                "-key",
                "ca.key",
                "-subj",
                "/CN=Fixture Root",
                "-days",
                "365",
                "-config",
                "fixture.cnf",
                "-extensions",
                profile,
                "-out",
                name,
            ]);
        }
        fs::create_dir(dir.join("issued")).unwrap();
        fs::write(dir.join("index"), b"").unwrap();
        fs::write(dir.join("index.attr"), b"unique_subject = no\n").unwrap();
        fs::write(dir.join("serial"), b"1000\n").unwrap();
        let mut config_file = OpenOptions::new()
            .append(true)
            .open(dir.join("fixture.cnf"))
            .unwrap();
        write!(config_file, "[ca]\ndefault_ca=fixture_ca\n[fixture_ca]\ndatabase=index\nnew_certs_dir=issued\nserial=serial\nprivate_key=ca.key\ncertificate=good-ca.pem\ndefault_md=default\npolicy=policy\n[policy]\ncommonName=supplied\n").unwrap();
        drop(config_file);
        cmd(&[
            "req",
            "-new",
            "-key",
            "ca.key",
            "-subj",
            "/CN=Fixture Root",
            "-out",
            "ca.csr",
        ]);
        cmd(&[
            "ca",
            "-selfsign",
            "-batch",
            "-notext",
            "-config",
            "fixture.cnf",
            "-extensions",
            "ca_good",
            "-startdate",
            "20200101000000Z",
            "-enddate",
            "20210101000000Z",
            "-in",
            "ca.csr",
            "-out",
            "expired-ca.pem",
        ]);
        cmd(&[
            "ca",
            "-selfsign",
            "-batch",
            "-notext",
            "-config",
            "fixture.cnf",
            "-extensions",
            "ca_good",
            "-startdate",
            "20400101000000Z",
            "-enddate",
            "20410101000000Z",
            "-in",
            "ca.csr",
            "-out",
            "future-ca.pem",
        ]);
        for (i, name) in ["product", "export", "server", "evidence"]
            .iter()
            .enumerate()
        {
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let pem = format!("{name}.pem");
            let serial = (i + 2).to_string();
            cmd(&["genpkey", "-algorithm", "ED25519", "-out", &key]);
            cmd(&[
                "req",
                "-new",
                "-key",
                &key,
                "-subj",
                "/CN=Fixture Leaf",
                "-out",
                &csr,
            ]);
            let ext = if *name == "server" {
                "server"
            } else {
                "client"
            };
            cmd(&[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "good-ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                &serial,
                "-days",
                "365",
                "-extfile",
                "fixture.cnf",
                "-extensions",
                ext,
                "-out",
                &pem,
            ]);
        }
        cmd(&[
            "x509",
            "-req",
            "-in",
            "product.csr",
            "-CA",
            "good-ca.pem",
            "-CAkey",
            "ca.key",
            "-set_serial",
            "11",
            "-days",
            "365",
            "-extfile",
            "fixture.cnf",
            "-extensions",
            "client_nods",
            "-out",
            "nods.pem",
        ]);
        cmd(&[
            "x509",
            "-in",
            "good-ca.pem",
            "-outform",
            "DER",
            "-out",
            "ca.der",
        ]);
        let mut der = fs::read(dir.join("ca.der")).unwrap();
        *der.last_mut().unwrap() ^= 1;
        fs::write(dir.join("bad-signature.der"), &der).unwrap();
        cmd(&[
            "x509",
            "-inform",
            "DER",
            "-in",
            "bad-signature.der",
            "-out",
            "bad-signature.pem",
        ]);
        fs::write(dir.join("marker"), [7u8; 32]).unwrap();
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let mode = if entry.file_type().unwrap().is_dir() {
                0o700
            } else {
                0o600
            };
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode)).unwrap();
        }
        let mut paths = ReceiverMaterialPaths {
            marker_seed: dir.join("marker"),
            product_cert: dir.join("product.pem"),
            product_key: dir.join("product.key"),
            export_cert: dir.join("export.pem"),
            export_key: dir.join("export.key"),
            server_cert: dir.join("server.pem"),
            server_key: dir.join("server.key"),
            evidence_cert: dir.join("evidence.pem"),
            evidence_key: dir.join("evidence.key"),
            ca: dir.join("good-ca.pem"),
            server_name: "receiver.example.test".into(),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (ca, product, valid) in [
            ("good-ca.pem", "product.pem", true),
            ("nonca.pem", "product.pem", false),
            ("noku-ca.pem", "product.pem", false),
            ("bad-signature.pem", "product.pem", false),
            ("expired-ca.pem", "product.pem", false),
            ("future-ca.pem", "product.pem", false),
            ("good-ca.pem", "nods.pem", false),
        ] {
            paths.ca = dir.join(ca);
            paths.product_cert = dir.join(product);
            let captures: Vec<_> = paths
                .paths()
                .into_iter()
                .map(|p| capture(p).unwrap())
                .collect();
            assert!(
                evaluate(&captures, &paths.server_name, epoch().unwrap()).is_ok(),
                "old checker control {ca} {product}"
            );
            let checked = rt.block_on(check_receiver_material(
                &paths,
                &tool.path,
                hash,
                &dir.join("stage"),
                Instant::now() + Duration::from_secs(60),
            ));
            if valid {
                assert!(checked.is_ok(), "new checker control");
            } else {
                let expected = if ca == "bad-signature.pem" || ca == "noku-ca.pem" {
                    ReceiverMaterialCheckError::Process
                } else {
                    ReceiverMaterialCheckError::Invalid
                };
                assert_eq!(checked.err(), Some(expected), "new checker {ca} {product}");
            }
            assert!(!dir.join("stage").exists());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires explicit qualified OpenSSL binary"]
    fn qualified_openssl_same_bytes_and_revalidation() {
        use std::os::unix::fs::PermissionsExt;
        let tool =
            std::env::var_os("CONTOUR_TEST_OPENSSL").expect("explicit qualified OpenSSL path");
        let _guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap();
        let dir = root.join(format!("material-fixture-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/causal-receiver-material");
        for name in [
            "product.pem",
            "product.key",
            "export.pem",
            "export.key",
            "server.pem",
            "server.key",
            "evidence.pem",
            "evidence.key",
            "ca.pem",
        ] {
            fs::copy(fixture.join(name), dir.join(name)).unwrap();
            fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(dir.join("marker"), [7u8; 32]).unwrap();
        fs::set_permissions(dir.join("marker"), fs::Permissions::from_mode(0o600)).unwrap();
        let paths = ReceiverMaterialPaths {
            marker_seed: dir.join("marker"),
            product_cert: dir.join("product.pem"),
            product_key: dir.join("product.key"),
            export_cert: dir.join("export.pem"),
            export_key: dir.join("export.key"),
            server_cert: dir.join("server.pem"),
            server_key: dir.join("server.key"),
            evidence_cert: dir.join("evidence.pem"),
            evidence_key: dir.join("evidence.key"),
            ca: dir.join("ca.pem"),
            server_name: "receiver.example.test".into(),
        };
        let hash = [
            0x10, 0x3f, 0xc7, 0x70, 0x6c, 0xf6, 0x64, 0x6f, 0x22, 0x6d, 0x96, 0xf2, 0x92, 0x42,
            0xd8, 0x18, 0x90, 0x36, 0x34, 0x99, 0xaf, 0xc7, 0x30, 0xe7, 0xef, 0x1f, 0xad, 0xd6,
            0x4b, 0x3a, 0x12, 0x3c,
        ];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let checked = runtime
            .block_on(check_receiver_material(
                &paths,
                Path::new(&tool),
                hash,
                &dir.join("stage"),
                Instant::now() + Duration::from_secs(60),
            ))
            .expect("qualified same-byte fixture");
        checked.revalidate().unwrap();
        assert!(!dir.join("stage").exists());
        let captures: Vec<_> = paths
            .paths()
            .into_iter()
            .map(|path| capture(path).unwrap())
            .collect();
        let stage = Stage::create(&dir.join("command-stage"), &captures).unwrap();
        let (observed_hash, id) = hash_executable(Path::new(&tool)).unwrap();
        let protected_tool = Tool {
            path: PathBuf::from(&tool),
            hash: observed_hash,
            id,
        };
        assert!(
            runtime
                .block_on(run(
                    &protected_tool,
                    &captures,
                    &stage,
                    Instant::now() + Duration::from_secs(10),
                    &["version"]
                ))
                .is_ok()
        );
        assert_eq!(
            runtime.block_on(run(
                &protected_tool,
                &captures,
                &stage,
                Instant::now() + Duration::from_secs(10),
                &["invalid-fixture-command"]
            )),
            Err(ReceiverMaterialCheckError::Process)
        );
        assert_eq!(
            runtime.block_on(run(
                &protected_tool,
                &captures,
                &stage,
                Instant::now(),
                &["version"]
            )),
            Err(ReceiverMaterialCheckError::Unsafe)
        );
        stage.cleanup().unwrap();
        fs::write(&paths.marker_seed, [8u8; 32]).unwrap();
        assert!(checked.revalidate().is_err());
        assert!(
            runtime
                .block_on(check_receiver_material(
                    &paths,
                    Path::new(&tool),
                    hash,
                    &dir.join("stage"),
                    Instant::now()
                ))
                .is_err()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
