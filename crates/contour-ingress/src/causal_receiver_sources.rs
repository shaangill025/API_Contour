//! Fixed 504 source data closure. This is not a deployment, image, mount,
//! process, peer, session, material, or permit attestation. Protected host and
//! absence of malicious concurrent same-UID mutation remain prerequisites.
use crate::causal_launch_process::{Identity, checked_path};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MANIFEST: &[u8] =
    include_bytes!("../../../collectors/nodered/receiver-integration/manifest-504.json");
const ARTIFACT: &[u8] =
    include_bytes!("../../../collectors/nodered/receiver-integration/artifact-504.json");
const MANIFEST_HASH: &str = "af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d";
const ARTIFACT_HASH: &str = "707e7b359fb757c668d8a22c999e067556b5f2a785f9c3333c12fca7debfa660";
const FLOW_HASH: &str = "d0644574d5e479bb3726f02c76adb9cbba548b51505705f95ba283e6a7b3896d";
const SOURCE_LIMIT: u64 = 4 * 1024 * 1024;
const TREE_LIMIT: u64 = 2 * 1024 * 1024;
const INVENTORY: [&str; 24] = [
    "causal-codec.js",
    "causal-evidence-codec.js",
    "error-integration/causal-marker.js",
    "error-integration/flow-source-transform.js",
    "error-integration/lexical-bridge.js",
    "error-integration/node-source-transform.js",
    "error-integration/private-causal-exporter.js",
    "error-integration/private-causal-receipt.js",
    "error-integration/private-handoff.js",
    "error-integration/private-wire-dispatch.js",
    "error-integration/private-wire-transform.js",
    "error-integration/wire-v2-loader.js",
    "live-integration/credential-check.js",
    "live-integration/lifecycle.js",
    "live-integration/live-profile.js",
    "receiver-integration/live-main-504.js",
    "receiver-integration/private-bootstrap-504.js",
    "receiver-integration/private-incoming.js",
    "receiver-integration/private-launch-proxy-504.js",
    "receiver-integration/private-owner-permit-504.js",
    "receiver-integration/private-producer-runtime.js",
    "receiver-integration/private-profile-504.js",
    "receiver-integration/private-receiver-exporter.js",
    "receiver-integration/private-root-handoff.js",
];
const TREES: [(&str, &str, &str); 2] = [
    (
        "/adapter/live-integration/tree-arm64.json",
        "error-integration/wire-v2-image-manifest.json",
        "63560c3dbe43d22c9391d0ac2e46dbad1d428f5b8ea8418b2a9038322da2ad0b",
    ),
    (
        "/adapter/live-integration/tree-x64.json",
        "error-integration/wire-v2-image-manifest-x64.json",
        "5f1c14c5e6a6cdbe9d841b5ee749058b05183fc9bee02e27f50ab0bd9a432e96",
    ),
];
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverSourcesError {
    Unsafe,
    Invalid,
    Drift,
    Io,
}
fn hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hash.iter().map(|v| format!("{v:02x}")).collect()
}
struct Source {
    destination: String,
    path: PathBuf,
    id: Identity,
    bytes: Vec<u8>,
    limit: u64,
}
impl Source {
    fn capture(destination: &str, path: &Path, limit: u64) -> Result<Self, ReceiverSourcesError> {
        let before = checked_path(path).map_err(|_| ReceiverSourcesError::Unsafe)?;
        if !before.is_file()
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > limit
            || before.mode() & 0o022 != 0
            || (before.uid() != 0 && before.uid() != unsafe { libc::geteuid() })
        {
            return Err(ReceiverSourcesError::Unsafe);
        }
        let id = Identity::from(&before);
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| ReceiverSourcesError::Io)?;
        if Identity::from(&file.metadata().map_err(|_| ReceiverSourcesError::Io)?) != id {
            return Err(ReceiverSourcesError::Drift);
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ReceiverSourcesError::Io)?;
        if bytes.len() as u64 != before.len()
            || Identity::from(&file.metadata().map_err(|_| ReceiverSourcesError::Io)?) != id
            || Identity::from(&checked_path(path).map_err(|_| ReceiverSourcesError::Drift)?) != id
        {
            return Err(ReceiverSourcesError::Drift);
        }
        Ok(Self {
            destination: destination.into(),
            path: path.into(),
            id,
            bytes,
            limit,
        })
    }
    fn revalidate(&self) -> Result<(), ReceiverSourcesError> {
        let fresh = Self::capture(&self.destination, &self.path, self.limit)?;
        if fresh.id != self.id || fresh.bytes != self.bytes {
            return Err(ReceiverSourcesError::Drift);
        }
        Ok(())
    }
}
/// Private retained source closure with no conversion to a launch capability.
pub struct ReceiverCandidateSources {
    root: PathBuf,
    root_id: Identity,
    sources: Vec<Source>,
}
impl std::fmt::Debug for ReceiverCandidateSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceiverCandidateSources")
    }
}
impl ReceiverCandidateSources {
    /// `root` is an absolute protected checkout root. All relative file names
    /// are compiled here; none are selected from caller-provided JSON. Larger
    /// public source/tree bounds do not change private material snapshot limits.
    pub fn seal(root: &Path) -> Result<Self, ReceiverSourcesError> {
        let meta = checked_path(root).map_err(|_| ReceiverSourcesError::Unsafe)?;
        if !meta.is_dir() {
            return Err(ReceiverSourcesError::Unsafe);
        }
        let root_id = Identity::from(&meta);
        if hex(MANIFEST) != MANIFEST_HASH || hex(ARTIFACT) != ARTIFACT_HASH {
            return Err(ReceiverSourcesError::Invalid);
        }
        let parsed: serde_json::Value =
            serde_json::from_slice(MANIFEST).map_err(|_| ReceiverSourcesError::Invalid)?;
        let files = parsed
            .get("files")
            .and_then(|v| v.as_object())
            .ok_or(ReceiverSourcesError::Invalid)?;
        if files.len() != INVENTORY.len()
            || parsed.get("artifact_sha256").and_then(|v| v.as_str()) != Some(ARTIFACT_HASH)
            || parsed.get("flow_sha256").and_then(|v| v.as_str()) != Some(FLOW_HASH)
            || parsed.get("profile_id").and_then(|v| v.as_str())
                != Some("00000000-0000-4000-8000-000000000504")
            || parsed.get("profile_name").and_then(|v| v.as_str())
                != Some("nodered_5_0_9_receiver_v1")
            || parsed.get("node").and_then(|v| v.as_str()) != Some("24.22.3")
        {
            return Err(ReceiverSourcesError::Invalid);
        }
        let base = root.join("collectors/nodered");
        let mut sources = Vec::with_capacity(29);
        let manifest = Source::capture(
            "/adapter/receiver-integration/manifest-504.json",
            &base.join("receiver-integration/manifest-504.json"),
            SOURCE_LIMIT,
        )?;
        if manifest.bytes != MANIFEST {
            return Err(ReceiverSourcesError::Invalid);
        }
        sources.push(manifest);
        let artifact = Source::capture(
            "/adapter/receiver-integration/artifact-504.json",
            &base.join("receiver-integration/artifact-504.json"),
            SOURCE_LIMIT,
        )?;
        if artifact.bytes != ARTIFACT {
            return Err(ReceiverSourcesError::Invalid);
        }
        sources.push(artifact);
        for relative in INVENTORY {
            let destination = format!("/adapter/{relative}");
            let expected = files
                .get(&destination)
                .and_then(|v| v.as_str())
                .ok_or(ReceiverSourcesError::Invalid)?;
            let item = Source::capture(&destination, &base.join(relative), SOURCE_LIMIT)?;
            if hex(&item.bytes) != expected {
                return Err(ReceiverSourcesError::Invalid);
            }
            sources.push(item);
        }
        for (index, (destination, relative, digest)) in TREES.iter().enumerate() {
            let arch = if index == 0 { "arm64" } else { "x64" };
            let tree = parsed
                .get("arch_trees")
                .and_then(|v| v.get(arch))
                .ok_or(ReceiverSourcesError::Invalid)?;
            if tree.get("path").and_then(|v| v.as_str()) != Some(*destination)
                || tree.get("sha256").and_then(|v| v.as_str()) != Some(*digest)
            {
                return Err(ReceiverSourcesError::Invalid);
            }
            let item = Source::capture(destination, &base.join(relative), TREE_LIMIT)?;
            if hex(&item.bytes) != *digest {
                return Err(ReceiverSourcesError::Invalid);
            }
            sources.push(item);
        }
        let flow = Source::capture(
            "/data/flows.json",
            &base.join("live-integration/flows.json"),
            SOURCE_LIMIT,
        )?;
        if hex(&flow.bytes) != FLOW_HASH {
            return Err(ReceiverSourcesError::Invalid);
        }
        sources.push(flow);
        let result = Self {
            root: root.into(),
            root_id,
            sources,
        };
        result.revalidate()?;
        Ok(result)
    }
    /// Fresh local identity and byte check. Filesystem work is synchronous and
    /// must be bounded by the caller's independent supervisor.
    pub fn revalidate(&self) -> Result<(), ReceiverSourcesError> {
        let root = checked_path(&self.root).map_err(|_| ReceiverSourcesError::Drift)?;
        if Identity::from(&root) != self.root_id {
            return Err(ReceiverSourcesError::Drift);
        }
        for source in &self.sources {
            source.revalidate()?;
        }
        if Identity::from(&checked_path(&self.root).map_err(|_| ReceiverSourcesError::Drift)?)
            != self.root_id
        {
            return Err(ReceiverSourcesError::Drift);
        }
        Ok(())
    }
    /// Retained destination, source path, and source bytes; these are data only.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &Path, &[u8])> {
        self.sources
            .iter()
            .map(|s| (s.destination.as_str(), s.path.as_path(), s.bytes.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> (PathBuf, PathBuf) {
        let checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let target = checkout.join("target");
        let root = target.join(format!("receiver-source-test-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let control = ReceiverCandidateSources::seal(&checkout).unwrap();
        assert_eq!(control.entries().count(), 29);
        for (_, original, _) in control.entries() {
            let relative = original.strip_prefix(&checkout).unwrap();
            let destination = root.join(relative);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::copy(original, &destination).unwrap();
        }
        (checkout, root)
    }
    #[test]
    fn fixed_closure_detects_each_changed_or_missing_source() {
        let (_, root) = fixture();
        let candidate = ReceiverCandidateSources::seal(&root).unwrap();
        let paths: Vec<_> = candidate
            .entries()
            .map(|(_, path, _)| path.to_path_buf())
            .collect();
        assert_eq!(paths.len(), 29);
        for path in &paths {
            let sealed = ReceiverCandidateSources::seal(&root).unwrap();
            let original = std::fs::read(path).unwrap();
            let mut changed = original.clone();
            changed.push(b'!');
            std::fs::write(path, &changed).unwrap();
            assert!(sealed.revalidate().is_err());
            assert!(ReceiverCandidateSources::seal(&root).is_err());
            std::fs::write(path, &original).unwrap();
            let moved = path.with_extension("owned-test-hold");
            std::fs::rename(path, &moved).unwrap();
            assert!(ReceiverCandidateSources::seal(&root).is_err());
            std::fs::rename(&moved, path).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn same_byte_replacement_and_redirect_are_rejected() {
        // This test is serialized with the other test's owned path by using a
        // different suffix even when Rust executes tests concurrently.
        let checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let root = checkout
            .join("target")
            .join(format!("receiver-replacement-test-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let control = ReceiverCandidateSources::seal(&checkout).unwrap();
        for (_, original, _) in control.entries() {
            let destination = root.join(original.strip_prefix(&checkout).unwrap());
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::copy(original, destination).unwrap();
        }
        let manifest = root.join("collectors/nodered/receiver-integration/manifest-504.json");
        let pinned = std::fs::read(&manifest).unwrap();
        let mut extra: serde_json::Value = serde_json::from_slice(&pinned).unwrap();
        extra["files"]
            .as_object_mut()
            .unwrap()
            .insert("/adapter/unexpected.js".into(), "00".repeat(32).into());
        std::fs::write(&manifest, serde_json::to_vec(&extra).unwrap()).unwrap();
        assert!(ReceiverCandidateSources::seal(&root).is_err());
        std::fs::copy(
            checkout.join("collectors/nodered/live-integration/manifest.json"),
            &manifest,
        )
        .unwrap();
        assert!(ReceiverCandidateSources::seal(&root).is_err());
        std::fs::write(&manifest, pinned).unwrap();
        let sealed = ReceiverCandidateSources::seal(&root).unwrap();
        let path = sealed.entries().nth(2).unwrap().1.to_owned();
        let bytes = std::fs::read(&path).unwrap();
        let old = path.with_extension("owned-test-hold");
        std::fs::rename(&path, &old).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(sealed.revalidate().is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(&old, &path).unwrap();
        assert!(ReceiverCandidateSources::seal(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
