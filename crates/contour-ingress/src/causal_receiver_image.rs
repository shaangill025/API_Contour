//! Local 504 image observation under a fixed process and archive policy.
//! Evidence does not authorize mounts or deployment. Host, dynamic libraries,
//! Python stdlib, clock and daemon are trusted prerequisites.
use crate::causal_launch_process::{Identity, checked_path};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageError {
    Unsafe,
    Io,
    Drift,
}
/// Exclusively created directory and durable intent. Unknown outcomes retain
/// the owned stage; no automatic deletion or adoption of existing paths occurs.
pub(crate) struct ImageStage {
    path: PathBuf,
    id: Identity,
    directory: File,
    parent_directory: File,
    parent_id: Identity,
    intent_id: Identity,
    image: [u8; 32],
    arm64: bool,
}
impl ImageStage {
    pub(crate) fn prepare(path: &Path, image: [u8; 32], arm64: bool) -> Result<Self, StageError> {
        if image == [0; 32] {
            return Err(StageError::Unsafe);
        }
        let parent = path.parent().ok_or(StageError::Unsafe)?;
        let before = checked_path(parent).map_err(|_| StageError::Unsafe)?;
        if !before.is_dir() {
            return Err(StageError::Unsafe);
        }
        let parent_id = Identity::from(&before);
        let parent_directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(parent)
            .map_err(|_| StageError::Unsafe)?;
        if !parent_id.same_object(&Identity::from(
            &parent_directory.metadata().map_err(|_| StageError::Io)?,
        )) {
            return Err(StageError::Drift);
        }
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| StageError::Unsafe)?;
        let after = checked_path(parent).map_err(|_| StageError::Unsafe)?;
        if !parent_id.same_object(&Identity::from(&after)) {
            return Err(StageError::Drift);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| StageError::Unsafe)?;
        let meta = directory.metadata().map_err(|_| StageError::Io)?;
        let id = Identity::from(&meta);
        if !meta.is_dir()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o7777 != 0o700
            || id != Identity::from(&checked_path(path).map_err(|_| StageError::Unsafe)?)
        {
            return Err(StageError::Unsafe);
        }
        let intent = path.join("save.intent");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&intent)
            .map_err(|_| StageError::Unsafe)?;
        let mut token = [0u8; 32];
        SystemRandom::new()
            .fill(&mut token)
            .map_err(|_| StageError::Io)?;
        file.write_all(b"apicontour/receiver504-save/1\n")
            .and_then(|_| file.write_all(&token))
            .and_then(|_| file.write_all(&image))
            .and_then(|_| file.write_all(&[u8::from(arm64)]))
            .and_then(|_| file.sync_all())
            .and_then(|_| directory.sync_all())
            .and_then(|_| parent_directory.sync_all())
            .map_err(|_| StageError::Io)?;
        token.fill(0);
        let intent_meta = file.metadata().map_err(|_| StageError::Io)?;
        if !intent_meta.is_file()
            || intent_meta.nlink() != 1
            || intent_meta.uid() != unsafe { libc::geteuid() }
            || intent_meta.mode() & 0o7777 != 0o600
        {
            return Err(StageError::Unsafe);
        }
        let intent_id = Identity::from(&intent_meta);
        let stage = Self {
            path: path.into(),
            id,
            directory,
            parent_directory,
            parent_id,
            intent_id,
            image,
            arm64,
        };
        stage.revalidate(false)?;
        Ok(stage)
    }
    pub(crate) fn image(&self) -> [u8; 32] {
        self.image
    }
    pub(crate) fn arm64(&self) -> bool {
        self.arm64
    }
    pub(crate) fn archive_path(&self) -> PathBuf {
        self.path.join("images.tar")
    }
    pub(crate) fn revalidate(&self, saved: bool) -> Result<(), StageError> {
        let parent = self.path.parent().ok_or(StageError::Unsafe)?;
        if !self.parent_id.same_object(&Identity::from(
            &checked_path(parent).map_err(|_| StageError::Drift)?,
        )) || !self.parent_id.same_object(&Identity::from(
            &self
                .parent_directory
                .metadata()
                .map_err(|_| StageError::Io)?,
        )) {
            return Err(StageError::Drift);
        }
        let path_meta = checked_path(&self.path).map_err(|_| StageError::Drift)?;
        let fd_meta = self.directory.metadata().map_err(|_| StageError::Io)?;
        if !self.id.same_object(&Identity::from(&path_meta))
            || !self.id.same_object(&Identity::from(&fd_meta))
            || path_meta.uid() != unsafe { libc::geteuid() }
            || path_meta.mode() & 0o7777 != 0o700
        {
            return Err(StageError::Drift);
        }
        let intent = checked_path(&self.path.join("save.intent")).map_err(|_| StageError::Drift)?;
        if Identity::from(&intent) != self.intent_id {
            return Err(StageError::Drift);
        }
        let mut names: Vec<_> = fs::read_dir(&self.path)
            .map_err(|_| StageError::Io)?
            .map(|e| e.map(|v| v.file_name()))
            .collect::<Result<_, _>>()
            .map_err(|_| StageError::Io)?;
        names.sort();
        let expected: Vec<std::ffi::OsString> = if saved {
            vec!["images.tar".into(), "save.intent".into()]
        } else {
            vec!["save.intent".into()]
        };
        if names != expected {
            return Err(StageError::Drift);
        }
        Ok(())
    }
    /// Called only after owned save completion and clean process-group reap.
    /// The returned observation is not image evidence or an archive verifier.
    pub(crate) fn completed_archive(&self) -> Result<Identity, StageError> {
        self.revalidate(true)?;
        let path = self.archive_path();
        let observed = checked_path(&path).map_err(|_| StageError::Drift)?;
        if !observed.is_file()
            || observed.nlink() != 1
            || observed.uid() != unsafe { libc::geteuid() }
            || observed.mode() & 0o7777 != 0o600
            || observed.len() == 0
            || observed.len() > 1024 * 1024 * 1024
        {
            return Err(StageError::Unsafe);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| StageError::Unsafe)?;
        let identity = Identity::from(&observed);
        if Identity::from(&file.metadata().map_err(|_| StageError::Io)?) != identity
            || Identity::from(&checked_path(&path).map_err(|_| StageError::Drift)?) != identity
        {
            return Err(StageError::Drift);
        }
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn stage_is_exclusive_and_unknown_contents_are_retained() {
        let checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = checkout
            .join("target")
            .join(format!("receiver-image-stage-{}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.join("stage");
        let stage = ImageStage::prepare(&path, [7; 32], true).unwrap();
        assert!(ImageStage::prepare(&path, [7; 32], true).is_err());
        stage.revalidate(false).unwrap();
        assert!(stage.completed_archive().is_err());
        let archive = stage.archive_path();
        fs::write(&archive, b"synthetic archive").unwrap();
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(stage.completed_archive().is_ok());
        fs::remove_file(archive).unwrap();
        fs::write(path.join("unexpected"), b"owned test fixture").unwrap();
        assert!(stage.revalidate(false).is_err());
        drop(stage);
        assert!(path.join("unexpected").exists());
        fs::remove_dir_all(parent).unwrap();
    }
}

/// Parsed output from a fixed owned Docker inspect. This is local observation
/// data only; it cannot be constructed by a public caller or mint evidence.
#[derive(PartialEq, Eq)]
struct SelectedImage {
    manifest: String,
    full: serde_json::Value,
}
impl SelectedImage {
    fn parse(raw: &[u8], arm64: bool) -> Result<Self, StageError> {
        if raw.is_empty() || raw.len() > 262_144 {
            return Err(StageError::Unsafe);
        }
        let records: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| StageError::Unsafe)?;
        let entries = records.as_array().ok_or(StageError::Unsafe)?;
        if entries.len() != 1 {
            return Err(StageError::Unsafe);
        }
        let value = entries[0].as_object().ok_or(StageError::Unsafe)?;
        let architecture = if arm64 { "arm64" } else { "amd64" };
        if value.get("Os").and_then(|v| v.as_str()) != Some("linux")
            || value.get("Architecture").and_then(|v| v.as_str()) != Some(architecture)
        {
            return Err(StageError::Unsafe);
        }
        let manifest = value
            .get("Id")
            .and_then(|v| v.as_str())
            .ok_or(StageError::Unsafe)?;
        let suffix = manifest.strip_prefix("sha256:").ok_or(StageError::Unsafe)?;
        if suffix.len() != 64
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(StageError::Unsafe);
        }
        let descriptor = value
            .get("Descriptor")
            .and_then(|v| v.as_object())
            .ok_or(StageError::Unsafe)?;
        let platform = descriptor
            .get("platform")
            .and_then(|v| v.as_object())
            .ok_or(StageError::Unsafe)?;
        if descriptor.get("digest").and_then(|v| v.as_str()) != Some(manifest)
            || descriptor.get("mediaType").and_then(|v| v.as_str())
                != Some("application/vnd.oci.image.manifest.v1+json")
            || platform.get("os").and_then(|v| v.as_str()) != Some("linux")
            || platform.get("architecture").and_then(|v| v.as_str()) != Some(architecture)
        {
            return Err(StageError::Unsafe);
        }
        if !value.get("Config").is_some_and(|v| v.is_object())
            || !value.get("RootFS").is_some_and(|v| v.is_object())
        {
            return Err(StageError::Unsafe);
        }
        Ok(Self {
            manifest: manifest.into(),
            full: entries[0].clone(),
        })
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    #[test]
    fn platform_manifest_selection_and_reinspection_drift() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let mut value = serde_json::json!([{ "Id": digest, "Os":"linux", "Architecture":"arm64", "Config":{"User":"1000"}, "RootFS":{"Layers":["one"]}, "Descriptor":{"digest":digest,"mediaType":"application/vnd.oci.image.manifest.v1+json", "platform":{"os":"linux","architecture":"arm64"}} }]);
        let before = SelectedImage::parse(&serde_json::to_vec(&value).unwrap(), true).unwrap();
        assert!(SelectedImage::parse(&serde_json::to_vec(&value).unwrap(), false).is_err());
        value[0]["Config"]["User"] = "0".into();
        assert!(
            before != SelectedImage::parse(&serde_json::to_vec(&value).unwrap(), true).unwrap()
        );
        value[0]["Descriptor"]["digest"] = "sha256:bad".into();
        assert!(SelectedImage::parse(&serde_json::to_vec(&value).unwrap(), true).is_err());
    }
}

use crate::causal_launch_files::snapshot_file;
use crate::causal_launch_process::{DockerPolicy, check_deadline, hash_executable, launch};
use std::{process::Command, time::Instant};

/// Local image observation only. It cannot authorize a mount, deployment or peer.
pub struct ReceiverImageEvidence {
    image: [u8; 32],
    arm64: bool,
    policy: [u8; 32],
    selected: SelectedImage,
    python: PathBuf,
    python_hash: [u8; 32],
    python_id: Identity,
    wrapper: PinnedFile,
    verifier: PinnedFile,
    deadline: Instant,
    candidate_config: String,
    base_history: String,
    candidate_history: String,
    _private: (),
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeOutput {
    version: u64,
    architecture: String,
    selected_manifest: String,
    candidate_config: String,
    candidate_history_sha256: String,
    base_history_sha256: String,
}
impl ProbeOutput {
    fn parse(raw: &[u8], arm64: bool, selected: &str) -> Result<Self, StageError> {
        let result: Self = serde_json::from_slice(raw).map_err(|_| StageError::Unsafe)?;
        fn hash(text: &str, prefix: &str) -> bool {
            text.strip_prefix(prefix).is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        }
        if result.version != 1
            || result.architecture != if arm64 { "arm64" } else { "amd64" }
            || result.selected_manifest != selected
            || !hash(&result.selected_manifest, "sha256:")
            || !hash(&result.candidate_config, "sha256:")
            || !hash(&result.candidate_history_sha256, "")
            || !hash(&result.base_history_sha256, "")
        {
            return Err(StageError::Unsafe);
        }
        Ok(result)
    }
}

struct PinnedFile {
    path: PathBuf,
    id: Identity,
    digest: [u8; 32],
}
impl PinnedFile {
    fn read(path: &Path, expected: [u8; 32]) -> Result<Self, StageError> {
        let meta = checked_path(path).map_err(|_| StageError::Unsafe)?;
        if !meta.is_file()
            || meta.mode() & 0o022 != 0
            || (meta.uid() != 0 && meta.uid() != unsafe { libc::geteuid() })
        {
            return Err(StageError::Unsafe);
        }
        let id = Identity::from(&meta);
        let data = snapshot_file(path, false).map_err(|_| StageError::Unsafe)?;
        let digest: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, data.as_bytes())
            .as_ref()
            .try_into()
            .map_err(|_| StageError::Unsafe)?;
        if digest != expected
            || Identity::from(&checked_path(path).map_err(|_| StageError::Drift)?) != id
        {
            return Err(StageError::Drift);
        }
        Ok(Self {
            path: path.into(),
            id,
            digest,
        })
    }
    fn revalidate(&self) -> Result<(), StageError> {
        let current = Self::read(&self.path, self.digest)?;
        if current.id != self.id {
            return Err(StageError::Drift);
        }
        Ok(())
    }
}
fn decode_hash(s: &str) -> [u8; 32] {
    let mut out = [0; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("compiled hash");
    }
    out
}
fn hex_image(image: &[u8; 32]) -> String {
    image.iter().map(|b| format!("{b:02x}")).collect()
}

/// Complete a fresh local archive observation under one deadline. The caller
/// selects the protected Python executable and the private, nonexistent stage.
/// A failure retains uncertain stage contents for explicit investigation.
pub struct ReceiverImageRequest<'a> {
    pub docker: &'a DockerPolicy,
    pub python: &'a Path,
    pub python_sha256: [u8; 32],
    pub scripts_dir: &'a Path,
    pub stage_path: &'a Path,
    pub image: [u8; 32],
    pub arm64: bool,
    pub owner: [u8; 32],
    pub deadline: Instant,
}
pub async fn observe_receiver_image(
    request: ReceiverImageRequest<'_>,
) -> Result<ReceiverImageEvidence, StageError> {
    let ReceiverImageRequest {
        docker,
        python,
        python_sha256,
        scripts_dir,
        stage_path,
        image,
        arm64,
        owner,
        deadline,
    } = request;
    check_deadline(deadline).map_err(|_| StageError::Unsafe)?;
    let (hash, python_id) = hash_executable(python).map_err(|_| StageError::Unsafe)?;
    if hash != python_sha256 || owner == [0; 32] {
        return Err(StageError::Unsafe);
    }
    let wrapper = PinnedFile::read(
        &scripts_dir.join("receiver504_image_probe.py"),
        decode_hash("58b08206eb052b6c817dfd3e3b10a6b3407487417d4d4b5cf037c4c327c4a093"),
    )?;
    let verifier = PinnedFile::read(
        &scripts_dir.join("node243_archive.py"),
        decode_hash("f0502fc2a5b3c0804818fc28a3e7e6909f6f1830144db0b6ecee5be8ffb743ca"),
    )?;
    let revalidate = || -> Result<(), StageError> {
        check_deadline(deadline).map_err(|_| StageError::Unsafe)?;
        docker
            .receiver_revalidate()
            .map_err(|_| StageError::Drift)?;
        if hash_executable(python).map_err(|_| StageError::Drift)? != (hash, python_id) {
            return Err(StageError::Drift);
        }
        wrapper.revalidate()?;
        verifier.revalidate()?;
        check_deadline(deadline).map_err(|_| StageError::Unsafe)
    };
    revalidate()?;
    let before_raw = docker
        .receiver_image_inspect(image, arm64, deadline)
        .map_err(|_| StageError::Io)?
        .wait()
        .await
        .map_err(|_| StageError::Io)?;
    revalidate()?;
    let selected = SelectedImage::parse(&before_raw, arm64)?;
    if selected.manifest != format!("sha256:{}", hex_image(&image)) {
        return Err(StageError::Unsafe);
    }
    let stage = ImageStage::prepare(stage_path, image, arm64)?;
    revalidate()?;
    docker
        .receiver_image_save(&stage, deadline)
        .map_err(|_| StageError::Io)?
        .wait()
        .await
        .map_err(|_| StageError::Io)?;
    revalidate()?;
    let archive_id = stage.completed_archive()?;
    let inspect_path = stage.path.join("inspect.json");
    let mut inspect = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&inspect_path)
        .map_err(|_| StageError::Io)?;
    let inspect_value: serde_json::Value =
        serde_json::from_slice(&before_raw).map_err(|_| StageError::Unsafe)?;
    let inspect_bytes = serde_json::to_vec(&inspect_value[0]).map_err(|_| StageError::Unsafe)?;
    inspect
        .write_all(&inspect_bytes)
        .and_then(|_| inspect.sync_all())
        .map_err(|_| StageError::Io)?;
    let inspect_id = Identity::from(&inspect.metadata().map_err(|_| StageError::Io)?);
    let mut cmd = Command::new(python);
    cmd.env_clear()
        .arg("-I")
        .arg("-B")
        .arg("-S")
        .arg(&wrapper.path)
        .arg(stage.archive_path())
        .arg(if arm64 { "arm64" } else { "amd64" })
        .arg(&selected.manifest)
        .arg(&inspect_path)
        .arg(hex_image(&owner));
    revalidate()?;
    let result = launch(cmd, deadline)
        .map_err(|_| StageError::Io)?
        .wait()
        .await
        .map_err(|_| StageError::Io)?;
    revalidate()?;
    if Identity::from(&checked_path(&inspect_path).map_err(|_| StageError::Drift)?) != inspect_id {
        return Err(StageError::Drift);
    }
    let output = ProbeOutput::parse(&result, arm64, &selected.manifest)?;
    let candidate_config = output.candidate_config;
    let base_history = output.base_history_sha256;
    let candidate_history = output.candidate_history_sha256;
    fs::remove_file(&inspect_path).map_err(|_| StageError::Io)?;
    if stage.completed_archive()? != archive_id {
        return Err(StageError::Drift);
    }
    stage.cleanup(archive_id)?;
    revalidate()?;
    let after_raw = docker
        .receiver_image_inspect(image, arm64, deadline)
        .map_err(|_| StageError::Io)?
        .wait()
        .await
        .map_err(|_| StageError::Io)?;
    revalidate()?;
    if SelectedImage::parse(&after_raw, arm64)?.full != selected.full {
        return Err(StageError::Drift);
    }
    Ok(ReceiverImageEvidence {
        image,
        arm64,
        policy: docker.policy_digest(),
        selected,
        python: python.into(),
        python_hash: hash,
        python_id,
        wrapper,
        verifier,
        deadline,
        candidate_config,
        base_history,
        candidate_history,
        _private: (),
    })
}

impl ImageStage {
    fn cleanup(&self, archive: Identity) -> Result<(), StageError> {
        if self.completed_archive()? != archive {
            return Err(StageError::Drift);
        }
        fs::remove_file(self.archive_path()).map_err(|_| StageError::Io)?;
        self.revalidate(false)?;
        fs::remove_file(self.path.join("save.intent")).map_err(|_| StageError::Io)?;
        self.directory.sync_all().map_err(|_| StageError::Io)?;
        if !self.id.same_object(&Identity::from(
            &checked_path(&self.path).map_err(|_| StageError::Drift)?,
        )) {
            return Err(StageError::Drift);
        }
        fs::remove_dir(&self.path).map_err(|_| StageError::Io)?;
        self.parent_directory
            .sync_all()
            .map_err(|_| StageError::Io)?;
        Ok(())
    }
}

impl ReceiverImageEvidence {
    pub(crate) fn deployment_image(&self) -> ([u8; 32], bool, [u8; 32], &serde_json::Value) {
        (self.image, self.arm64, self.policy, &self.selected.full)
    }
    /// Digest of the archive-verified candidate config.
    pub fn candidate_config(&self) -> &str {
        &self.candidate_config
    }
    /// Canonical history digests for the approved base and candidate.
    pub fn history_digests(&self) -> (&str, &str) {
        (&self.base_history, &self.candidate_history)
    }
    /// Reinspect the same image and protected request context immediately before
    /// a future create. This remains an observation, not create authority.
    pub async fn reinspect(&self, docker: &DockerPolicy) -> Result<(), StageError> {
        let validate = || -> Result<(), StageError> {
            check_deadline(self.deadline).map_err(|_| StageError::Unsafe)?;
            if docker.policy_digest() != self.policy {
                return Err(StageError::Drift);
            }
            docker
                .receiver_revalidate()
                .map_err(|_| StageError::Drift)?;
            if hash_executable(&self.python).map_err(|_| StageError::Drift)?
                != (self.python_hash, self.python_id)
            {
                return Err(StageError::Drift);
            }
            self.wrapper.revalidate()?;
            self.verifier.revalidate()?;
            check_deadline(self.deadline).map_err(|_| StageError::Unsafe)
        };
        validate()?;
        let raw = docker
            .receiver_image_inspect(self.image, self.arm64, self.deadline)
            .map_err(|_| StageError::Io)?
            .wait()
            .await
            .map_err(|_| StageError::Io)?;
        validate()?;
        if SelectedImage::parse(&raw, self.arm64)?.full != self.selected.full {
            return Err(StageError::Drift);
        }
        Ok(())
    }
}

#[cfg(test)]
mod probe_output_tests {
    use super::ProbeOutput;

    #[test]
    fn closed_output_rejects_untrusted_or_inconsistent_json() {
        let hash = "a".repeat(64);
        let selected = format!("sha256:{hash}");
        let valid = format!(
            r#"{{"version":1,"architecture":"arm64","selected_manifest":"{selected}","candidate_config":"sha256:{hash}","candidate_history_sha256":"{hash}","base_history_sha256":"{hash}"}}"#
        );
        assert!(ProbeOutput::parse(valid.as_bytes(), true, &selected).is_ok());
        assert!(ProbeOutput::parse(valid.as_bytes(), false, &selected).is_err());
        assert!(
            ProbeOutput::parse(
                valid.as_bytes(),
                true,
                &format!("sha256:{}", "b".repeat(64))
            )
            .is_err()
        );
        assert!(
            ProbeOutput::parse(
                valid
                    .replace("\"version\":1", "\"version\":1,\"version\":1")
                    .as_bytes(),
                true,
                &selected
            )
            .is_err()
        );
        assert!(
            ProbeOutput::parse(
                valid
                    .replace("\"version\":1", "\"version\":1,\"extra\":0")
                    .as_bytes(),
                true,
                &selected
            )
            .is_err()
        );
        assert!(ProbeOutput::parse(format!("{valid} {{}}").as_bytes(), true, &selected).is_err());
        let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
        value["candidate_config"] = "sha256:bad".into();
        assert!(ProbeOutput::parse(&serde_json::to_vec(&value).unwrap(), true, &selected).is_err());
        value["candidate_config"] = format!("sha256:{hash}").into();
        value["base_history_sha256"] = "bad".into();
        assert!(ProbeOutput::parse(&serde_json::to_vec(&value).unwrap(), true, &selected).is_err());
        value["base_history_sha256"] = hash.clone().into();
        value["candidate_history_sha256"] = "bad".into();
        assert!(ProbeOutput::parse(&serde_json::to_vec(&value).unwrap(), true, &selected).is_err());
    }
}
