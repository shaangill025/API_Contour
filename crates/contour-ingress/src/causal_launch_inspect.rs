//! Data-only Docker observation and retained mount revalidation. A sealed value
//! is not a 503 capability, a Docker attestation, or proof of TLS acceptance.
//! No public constructor accepts caller JSON; a future fixed Docker adapter must
//! perform the actual inspection and mint this value only after matching policy.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt},
        },
    },
    path::{Component, Path, PathBuf},
};
const IMAGE: &str = "docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963";
const MAX_JSON: usize = 262_144;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectError {
    Invalid,
    Drift,
    Io,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Mount {
    destination: String,
    kind: String,
    propagation: String,
    read_only: bool,
    source: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Network {
    aliases: Vec<String>,
    id: String,
    internal: bool,
    members: Vec<String>,
    name: String,
    owner: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Tmpfs {
    destination: String,
    options: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceFile {
    path: String,
    sha256: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Projection {
    attach_stderr: bool,
    attach_stdin: bool,
    attach_stdout: bool,
    auto_remove: bool,
    cap_add: Vec<String>,
    cap_drop: Vec<String>,
    cgroupns_mode: String,
    cmd: Vec<String>,
    container_id: String,
    context: String,
    cpu_nanos: u64,
    daemon_endpoint: String,
    device_cgroup_rules: Vec<String>,
    device_requests: Vec<String>,
    devices: Vec<String>,
    dns: Vec<String>,
    dns_options: Vec<String>,
    dns_search: Vec<String>,
    domainname: String,
    entrypoint: Vec<String>,
    env: Vec<String>,
    exposed_ports: Vec<String>,
    extra_hosts: Vec<String>,
    group_add: Vec<String>,
    hostname: String,
    image_id: String,
    image_ref: String,
    init: bool,
    ipc_mode: String,
    labels: Vec<String>,
    links: Vec<String>,
    log_driver: String,
    memory: u64,
    mounts: Vec<Mount>,
    name: String,
    network: Network,
    network_mode: String,
    no_new_privileges: bool,
    pid: u64,
    pid_mode: String,
    pids: u64,
    ports: Vec<String>,
    privileged: bool,
    publish_all_ports: bool,
    read_only_root: bool,
    restart_policy: String,
    running: bool,
    runtime: String,
    security_opt: Vec<String>,
    shm_size: u64,
    source_files: Vec<SourceFile>,
    started_at: String,
    sysctls: Vec<String>,
    tmpfs: Vec<Tmpfs>,
    tty: bool,
    user: String,
    userns_mode: String,
    uts_mode: String,
    version: u8,
    volumes_from: Vec<String>,
    working_dir: String,
}
fn lower_hex(x: &str, n: usize) -> bool {
    x.len() == n
        && x.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn safe_word(x: &str) -> bool {
    !x.is_empty()
        && x.len() <= 128
        && x.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn unique_sorted(x: &[String]) -> bool {
    x.windows(2).all(|w| w[0] < w[1])
}
fn abs_path(x: &str) -> bool {
    let p = Path::new(x);
    p.is_absolute()
        && x.len() <= 4096
        && !x.ends_with('/')
        && x.split('/')
            .skip(1)
            .all(|c| !c.is_empty() && c != "." && c != "..")
}
fn utc(x: &str) -> bool {
    let b = x.as_bytes();
    if !(b.len() == 20 || (22..=30).contains(&b.len()))
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last().unwrap_or(&0) != b'Z'
    {
        return false;
    }
    if b.len() > 20 && (b[19] != b'.' || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit)) {
        return false;
    }
    let number = |a: usize, z: usize| -> Option<u32> {
        let s = std::str::from_utf8(&b[a..z]).ok()?;
        if !s.bytes().all(|x| x.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let (Some(y), Some(m), Some(d), Some(h), Some(min), Some(sec)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    y >= 1
        && (1..=12).contains(&m)
        && d >= 1
        && d <= days[(m - 1) as usize]
        && h < 24
        && min < 60
        && sec < 60
}
fn expected_sources(mounts: &[Mount]) -> Result<Vec<String>, InspectError> {
    if mounts.len() != 11 {
        return Err(InspectError::Invalid);
    }
    let mut paths = vec![mounts[0].source.clone(), mounts[3].source.clone()];
    for name in [
        "causal-marker.js",
        "flow-source-transform.js",
        "lexical-bridge.js",
        "node-source-transform.js",
        "private-causal-exporter.js",
        "private-causal-receipt.js",
        "private-handoff.js",
        "private-owner-permit.js",
        "private-producer-runtime.js",
        "private-wire-dispatch.js",
        "private-wire-transform.js",
        "wire-v2-loader.js",
    ] {
        paths.push(format!("{}/{}", mounts[1].source, name));
    }
    for name in [
        "credential-check.js",
        "lifecycle.js",
        "live-main.js",
        "live-profile.js",
        "private-bootstrap.js",
        "private-launch-proxy.js",
        "manifest.json",
        "tree-arm64.json",
        "tree-x64.json",
    ] {
        paths.push(format!("{}/{}", mounts[2].source, name));
    }
    paths.sort();
    if paths.windows(2).any(|x| x[0] == x[1]) {
        return Err(InspectError::Invalid);
    }
    Ok(paths)
}
// Compare the retained source inventory to the exact reviewed 503 asset
// manifest. This is a source-integrity check, not Docker or producer proof.
fn candidate_source_digests_for(
    mounts: &[Mount],
    sources: &[SourceFile],
) -> Result<(), InspectError> {
    const MANIFEST: &[u8] =
        include_bytes!("../../../collectors/nodered/live-integration/manifest.json");
    const MANIFEST_HASH: &str = "a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e";
    if hex_digest(Sha256::digest(MANIFEST).into()) != MANIFEST_HASH || mounts.len() != 11 {
        return Err(InspectError::Invalid);
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(MANIFEST).map_err(|_| InspectError::Invalid)?;
    let files = manifest
        .get("files")
        .and_then(|v| v.as_object())
        .ok_or(InspectError::Invalid)?;
    let tree = manifest
        .get("arch_trees")
        .and_then(|v| v.as_object())
        .ok_or(InspectError::Invalid)?;
    if files.len() != 19 || sources.len() != 23 {
        return Err(InspectError::Invalid);
    }
    for entry in sources {
        let expected = if entry.path == mounts[0].source {
            files
                .get("/adapter/causal-codec.js")
                .and_then(|v| v.as_str())
        } else if entry.path == mounts[3].source {
            manifest.get("flow_sha256").and_then(|v| v.as_str())
        } else if let Some(name) = entry.path.strip_prefix(&(mounts[1].source.clone() + "/")) {
            files
                .get(&format!("/adapter/error-integration/{name}"))
                .and_then(|v| v.as_str())
        } else if let Some(name) = entry.path.strip_prefix(&(mounts[2].source.clone() + "/")) {
            match name {
                "manifest.json" => Some(MANIFEST_HASH),
                "tree-arm64.json" => tree
                    .get("arm64")
                    .and_then(|v| v.get("sha256"))
                    .and_then(|v| v.as_str()),
                "tree-x64.json" => tree
                    .get("x64")
                    .and_then(|v| v.get("sha256"))
                    .and_then(|v| v.as_str()),
                _ => files
                    .get(&format!("/adapter/live-integration/{name}"))
                    .and_then(|v| v.as_str()),
            }
        } else {
            None
        };
        if expected != Some(entry.sha256.as_str()) {
            return Err(InspectError::Drift);
        }
    }
    Ok(())
}
fn parse(input: &[u8]) -> Result<Projection, InspectError> {
    if input.is_empty() || input.len() > MAX_JSON {
        return Err(InspectError::Invalid);
    }
    let p: Projection = serde_json::from_slice(input).map_err(|_| InspectError::Invalid)?;
    if p.version != 1
        || !lower_hex(&p.container_id, 64)
        || !p
            .image_id
            .strip_prefix("sha256:")
            .is_some_and(|x| lower_hex(x, 64))
        || p.image_ref != IMAGE
        || !p.name.strip_prefix('/').is_some_and(safe_word)
        || !safe_word(&p.context)
        || !p
            .daemon_endpoint
            .strip_prefix("unix://")
            .is_some_and(abs_path)
        || !utc(&p.started_at)
        || p.pid == 0
        || !p.init
        || !p.running
        || p.tty
        || p.auto_remove
        || p.cmd != ["/adapter/live-integration/private-launch-proxy.js"]
        || !p.device_cgroup_rules.is_empty()
        || !p.device_requests.is_empty()
        || !p.devices.is_empty()
        || !p.dns.is_empty()
        || !p.dns_options.is_empty()
        || !p.dns_search.is_empty()
        || !p.domainname.is_empty()
        || p.exposed_ports != ["1880/tcp"]
        || !p.extra_hosts.is_empty()
        || !p.group_add.is_empty()
        || !p.links.is_empty()
        || !p.sysctls.is_empty()
        || !p.volumes_from.is_empty()
        || !matches!(p.ipc_mode.as_str(), "" | "private" | "shareable")
        || !p.pid_mode.is_empty()
        || !p.uts_mode.is_empty()
        || !matches!(p.userns_mode.as_str(), "" | "private")
        || !matches!(p.cgroupns_mode.as_str(), "" | "private")
        || p.restart_policy != "no"
        || p.security_opt != ["no-new-privileges:true"]
        || p.shm_size != 67_108_864
        || p.working_dir != "/data"
        || !p.attach_stdin
        || !p.attach_stdout
        || p.attach_stderr
        || p.privileged
        || p.publish_all_ports
        || p.runtime != "runc"
        || !p.read_only_root
        || !p.no_new_privileges
        || p.cap_drop != ["ALL"]
        || !p.cap_add.is_empty()
        || p.log_driver != "none"
        || !p.ports.is_empty()
        || p.memory == 0
        || p.memory > 536_870_912
        || p.cpu_nanos == 0
        || p.cpu_nanos > 1_000_000_000
        || p.pids == 0
        || p.pids > 128
        || p.entrypoint != ["/usr/local/bin/node"]
        || p.user.split_once(':').is_none_or(|(u, g)| {
            !u.parse::<u32>().is_ok_and(|v| v > 0) || !g.parse::<u32>().is_ok_and(|v| v > 0)
        })
        || p.user.len() > 32
    {
        return Err(InspectError::Invalid);
    }
    if p.env.len() != 10
        || !unique_sorted(&p.env)
        || p.labels.len() != 1
        || !p.labels[0]
            .strip_prefix("org.apicontour.causal.owner=")
            .is_some_and(|x| lower_hex(x, 64))
        || !lower_hex(&p.network.id, 64)
        || !safe_word(&p.network.name)
        || p.network_mode != p.network.name
        || !p.network.internal
        || p.hostname != "causal-live"
        || p.network.aliases.is_empty()
        || p.network.aliases.len() > 16
        || !unique_sorted(&p.network.aliases)
        || p.network.aliases.iter().any(|x| !safe_word(x))
        || !lower_hex(&p.network.owner, 64)
        || p.network.members.len() > 32
        || !unique_sorted(&p.network.members)
        || !p.network.members.contains(&p.container_id)
        || p.network.members.iter().any(|x| !lower_hex(x, 64))
    {
        return Err(InspectError::Invalid);
    }
    let keys: Vec<_> = p
        .env
        .iter()
        .filter_map(|x| x.split_once('=').map(|x| x.0))
        .collect();
    if p.env.iter().any(|x| x.len() > 4096)
        || keys
            != [
                "FLOWS",
                "HOME",
                "HOSTNAME",
                "LANG",
                "NODE_PATH",
                "NODE_RED_VERSION",
                "NODE_VERSION",
                "PATH",
                "TZ",
                "YARN_VERSION",
            ]
    {
        return Err(InspectError::Invalid);
    }
    let expected_mounts = [
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
    let exact_env=[
        "FLOWS=flows.json".to_string(), "HOME=/data".to_string(), format!("HOSTNAME={}",p.hostname),
        "LANG=C.UTF-8".to_string(), "NODE_PATH=/usr/src/node-red/node_modules".to_string(),
        "NODE_RED_VERSION=v5.0.9".to_string(), "NODE_VERSION=24.22.1".to_string(),
        "PATH=/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "TZ=UTC".to_string(), "YARN_VERSION=1.22.22".to_string(),
    ];
    if p.env != exact_env {
        return Err(InspectError::Invalid);
    }
    if p.mounts.len() != expected_mounts.len()
        || p.mounts
            .iter()
            .map(|m| m.destination.as_str())
            .ne(expected_mounts)
    {
        return Err(InspectError::Invalid);
    }
    let options = ["mode=1777", "nodev", "noexec", "nosuid", "rw", "size=16m"];
    if p.tmpfs.len() != 2
        || p.tmpfs
            .iter()
            .map(|x| x.destination.as_str())
            .ne(["/data", "/tmp"])
        || p.tmpfs
            .iter()
            .any(|x| x.options.iter().map(String::as_str).ne(options))
    {
        return Err(InspectError::Invalid);
    }
    if p.source_files.is_empty()
        || p.source_files.len() > 128
        || !p.source_files.windows(2).all(|w| w[0].path < w[1].path)
        || p.source_files
            .iter()
            .any(|x| !abs_path(&x.path) || !lower_hex(&x.sha256, 64))
    {
        return Err(InspectError::Invalid);
    }
    let mut dest = BTreeSet::new();
    for m in &p.mounts {
        if m.kind != "bind"
            || m.propagation != "rprivate"
            || !m.read_only
            || !abs_path(&m.source)
            || !abs_path(&m.destination)
            || !dest.insert(&m.destination)
        {
            return Err(InspectError::Invalid);
        }
    }
    if p.source_files
        .iter()
        .map(|x| x.path.as_str())
        .ne(expected_sources(&p.mounts)?.iter().map(String::as_str))
    {
        return Err(InspectError::Invalid);
    }
    Ok(p)
}
fn openat(parent: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    // SAFETY: the held fd and NUL-terminated name are valid and the returned fd
    // is uniquely owned by File.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn fingerprint(a: &std::fs::Metadata, b: &std::fs::Metadata, contents: bool) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && (a.is_dir() || a.nlink() == b.nlink())
        && (!contents
            || (a.len() == b.len()
                && a.mtime() == b.mtime()
                && a.mtime_nsec() == b.mtime_nsec()
                && a.ctime() == b.ctime()
                && a.ctime_nsec() == b.ctime_nsec()))
}
struct HeldMount {
    path: PathBuf,
    private: bool,
    directory: bool,
    components: Vec<(File, std::fs::Metadata)>,
    digest: Option<[u8; 32]>,
}
impl HeldMount {
    fn open(path: &Path, private: bool, directory: bool) -> Result<Self, InspectError> {
        let raw = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || raw.len() > 4096
            || raw.ends_with(b"/")
            || raw.split(|x| *x == b'/').any(|x| x == b"." || x == b"..")
        {
            return Err(InspectError::Invalid);
        }
        let names: Vec<_> = path
            .components()
            .skip(1)
            .map(|c| match c {
                Component::Normal(x) => Ok(x),
                _ => Err(InspectError::Invalid),
            })
            .collect::<Result<_, _>>()?;
        if names.is_empty() || names.len() > 128 {
            return Err(InspectError::Invalid);
        }
        // SAFETY: fixed root string; File owns the returned fd.
        let raw = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(InspectError::Io);
        }
        let root = unsafe { File::from_raw_fd(raw) };
        let root_meta = root.metadata().map_err(|_| InspectError::Io)?;
        let mut components = vec![(root, root_meta)];
        for (index, name) in names.iter().enumerate() {
            let name = CString::new(name.as_bytes()).map_err(|_| InspectError::Invalid)?;
            let is_dir = index + 1 < names.len() || directory;
            let flags =
                libc::O_RDONLY | libc::O_NONBLOCK | if is_dir { libc::O_DIRECTORY } else { 0 };
            let f = openat(
                &components.last().ok_or(InspectError::Invalid)?.0,
                &name,
                flags,
            )
            .map_err(|_| InspectError::Drift)?;
            let meta = f.metadata().map_err(|_| InspectError::Io)?;
            if is_dir && !meta.is_dir() {
                return Err(InspectError::Drift);
            }
            components.push((f, meta));
        }
        let (file, meta) = components.last().ok_or(InspectError::Invalid)?;
        let digest = if directory {
            None
        } else {
            // SAFETY: geteuid has no arguments or retained pointers.
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.len() == 0
                || meta.len() > 8_388_608
                || (private
                    && (meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o600))
            {
                return Err(InspectError::Drift);
            }
            struct Clear(Vec<u8>);
            impl Drop for Clear {
                fn drop(&mut self) {
                    self.0.fill(0);
                }
            }
            let mut buffer = Clear(vec![0u8; 65_536]);
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            loop {
                let remaining = meta.len().saturating_sub(offset);
                let limit = usize::try_from((remaining + 1).min(buffer.0.len() as u64))
                    .map_err(|_| InspectError::Invalid)?;
                let n = file
                    .read_at(&mut buffer.0[..limit], offset)
                    .map_err(|_| InspectError::Io)?;
                if n == 0 {
                    break;
                }
                offset = offset.checked_add(n as u64).ok_or(InspectError::Invalid)?;
                if offset > meta.len() {
                    return Err(InspectError::Drift);
                }
                hash.update(&buffer.0[..n]);
            }
            let after = file.metadata().map_err(|_| InspectError::Io)?;
            if offset != meta.len() || !fingerprint(meta, &after, true) {
                return Err(InspectError::Drift);
            }
            Some(hash.finalize().into())
        };
        Ok(Self {
            path: path.to_path_buf(),
            private,
            directory,
            components,
            digest,
        })
    }
    fn revalidate(&self) -> Result<(), InspectError> {
        let fresh = Self::open(&self.path, self.private, self.directory)?;
        if fresh.components.len() != self.components.len() || fresh.digest != self.digest {
            return Err(InspectError::Drift);
        }
        for (index, ((_, old), (_, new))) in
            self.components.iter().zip(&fresh.components).enumerate()
        {
            // Only the mounted leaf directory is sensitive to entries changing;
            // unrelated changes to ancestor directories must not fence a launch.
            let contents = index + 1 == self.components.len();
            if !fingerprint(old, new, contents) {
                return Err(InspectError::Drift);
            }
        }
        Ok(())
    }
}
// Both code directories are bind-mounted as directories. Checking just the
// named files would allow an additional Node module to shadow a checked file.
fn closed_code_directories(mounts: &[Mount], handles: &[HeldMount]) -> Result<(), InspectError> {
    let expected = expected_sources(mounts)?;
    for index in [1usize, 2] {
        let handle = handles.get(index).ok_or(InspectError::Invalid)?;
        let prefix = format!("{}/", mounts[index].source);
        let mut required: BTreeSet<&str> = expected
            .iter()
            .filter_map(|path| path.strip_prefix(&prefix))
            .collect();
        let before = handle
            .components
            .last()
            .ok_or(InspectError::Invalid)?
            .0
            .metadata()
            .map_err(|_| InspectError::Io)?;
        for entry in std::fs::read_dir(&handle.path).map_err(|_| InspectError::Drift)? {
            let entry = entry.map_err(|_| InspectError::Drift)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(InspectError::Drift)?;
            if !entry
                .file_type()
                .map_err(|_| InspectError::Drift)?
                .is_file()
            {
                return Err(InspectError::Drift);
            }
            if !(required.remove(name) || index == 2 && name == "README.md") {
                return Err(InspectError::Drift);
            }
        }
        let after = handle
            .components
            .last()
            .ok_or(InspectError::Invalid)?
            .0
            .metadata()
            .map_err(|_| InspectError::Io)?;
        if !required.is_empty() || !fingerprint(&before, &after, true) {
            return Err(InspectError::Drift);
        }
        handle.revalidate()?;
    }
    Ok(())
}
fn hex_digest(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}
#[derive(Serialize)]
struct FileIdentity<'a> {
    ctime_nsec: i64,
    ctime_sec: i64,
    dev: u64,
    ino: u64,
    mode: u32,
    mtime_nsec: i64,
    mtime_sec: i64,
    nlink: u64,
    path: &'a str,
    sha256: Option<String>,
    size: u64,
    uid: u32,
}
fn identity_list(sources: &[HeldMount]) -> Result<Vec<FileIdentity<'_>>, InspectError> {
    sources
        .iter()
        .map(|g| {
            let m = &g.components.last().ok_or(InspectError::Invalid)?.1;
            Ok(FileIdentity {
                ctime_nsec: m.ctime_nsec(),
                ctime_sec: m.ctime(),
                dev: m.dev(),
                ino: m.ino(),
                mode: m.mode(),
                mtime_nsec: m.mtime_nsec(),
                mtime_sec: m.mtime(),
                nlink: m.nlink(),
                path: g.path.to_str().ok_or(InspectError::Invalid)?,
                sha256: g.digest.map(hex_digest),
                size: m.len(),
                uid: m.uid(),
            })
        })
        .collect()
}
fn inventory_hash(domain: &[u8], sources: &[HeldMount]) -> Result<String, InspectError> {
    let bytes = serde_json::to_vec(&identity_list(sources)?).map_err(|_| InspectError::Invalid)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(&bytes);
    Ok(hex_digest(hash.finalize().into()))
}
// All inputs below originate in fixed CLI observations or in the already
// captured source set; no public raw-JSON constructor is exposed.
pub(crate) struct ActualExpected<'a> {
    pub(crate) cid: [u8; 32],
    pub(crate) image: [u8; 32],
    pub(crate) image_labels: &'a std::collections::BTreeMap<String, String>,
    pub(crate) owner: [u8; 32],
    pub(crate) network_id: [u8; 32],
    pub(crate) network_name: &'a str,
    pub(crate) network_owner: [u8; 32],
    pub(crate) network_label: &'a str,
    pub(crate) peers: Vec<[u8; 32]>,
    pub(crate) daemon: String,
    pub(crate) policy_digest: [u8; 32],
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActualState {
    Created,
    Running,
}
fn object_field<'a>(
    v: &'a serde_json::Value,
    k: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, InspectError> {
    v.get(k)
        .and_then(|x| x.as_object())
        .ok_or(InspectError::Invalid)
}
fn text_field<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a str, InspectError> {
    v.get(k)
        .and_then(|x| x.as_str())
        .ok_or(InspectError::Invalid)
}
fn bool_field(v: &serde_json::Value, k: &str) -> Result<bool, InspectError> {
    v.get(k)
        .and_then(|x| x.as_bool())
        .ok_or(InspectError::Invalid)
}
fn u64_field(v: &serde_json::Value, k: &str) -> Result<u64, InspectError> {
    v.get(k)
        .and_then(|x| x.as_u64())
        .ok_or(InspectError::Invalid)
}
fn strings_field(v: &serde_json::Value, k: &str) -> Result<Vec<String>, InspectError> {
    let x = v.get(k).ok_or(InspectError::Invalid)?;
    if x.is_null() {
        return Ok(Vec::new());
    }
    let mut result = x
        .as_array()
        .ok_or(InspectError::Invalid)?
        .iter()
        .map(|x| x.as_str().map(str::to_owned).ok_or(InspectError::Invalid))
        .collect::<Result<Vec<_>, _>>()?;
    result.sort();
    Ok(result)
}
fn nil_or_empty(value: &serde_json::Value) -> bool {
    value.is_null()
        || value.as_object().is_some_and(|v| v.is_empty())
        || value.as_array().is_some_and(|v| v.is_empty())
}
fn value_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) struct ValidatedActual {
    projection: Projection,
    state: ActualState,
}
impl ValidatedActual {
    pub(crate) fn identity(&self) -> (u64, &str) {
        (self.projection.pid, &self.projection.started_at)
    }
    pub(crate) fn normalized(&self) -> Result<Vec<u8>, InspectError> {
        if self.state != ActualState::Running {
            return Err(InspectError::Invalid);
        }
        serde_json::to_vec(&self.projection).map_err(|_| InspectError::Invalid)
    }
}

pub(crate) fn validate_actual_container(
    container: &crate::causal_launch_process::ActualDockerObservation,
    network: &crate::causal_launch_process::ActualDockerObservation,
    sources: &CandidateSources,
    expected: &ActualExpected<'_>,
    state_kind: ActualState,
) -> Result<ValidatedActual, InspectError> {
    sources.revalidate()?;
    project_actual_container(
        container,
        network,
        &sources.mounts,
        &sources.source_entries,
        expected,
        state_kind,
    )
}
fn project_actual_container(
    container: &crate::causal_launch_process::ActualDockerObservation,
    network: &crate::causal_launch_process::ActualDockerObservation,
    source_mounts: &[Mount],
    source_entries: &[SourceFile],
    expected: &ActualExpected<'_>,
    state_kind: ActualState,
) -> Result<ValidatedActual, InspectError> {
    use crate::causal_launch_process::DockerInspect;
    if container.observed_at() > std::time::Instant::now()
        || network.observed_at() > std::time::Instant::now()
    {
        return Err(InspectError::Invalid);
    }
    if container.recipe() != DockerInspect::Container(expected.cid)
        || network.recipe() != DockerInspect::Network(expected.network_id)
        || container.policy_digest() != expected.policy_digest
        || network.policy_digest() != expected.policy_digest
    {
        return Err(InspectError::Invalid);
    }
    let container = serde_json::Value::Object(
        crate::causal_launch_docker::one_object(container.bytes())
            .map_err(|_| InspectError::Invalid)?,
    );
    let network = serde_json::Value::Object(
        crate::causal_launch_docker::one_object(network.bytes())
            .map_err(|_| InspectError::Invalid)?,
    );
    let cid = value_hex(&expected.cid);
    let image = format!("sha256:{}", value_hex(&expected.image));
    if text_field(&container, "Id")? != cid || text_field(&container, "Image")? != image {
        return Err(InspectError::Drift);
    }
    let config = container.get("Config").ok_or(InspectError::Invalid)?;
    let host = container.get("HostConfig").ok_or(InspectError::Invalid)?;
    let state = container.get("State").ok_or(InspectError::Invalid)?;
    let settings = container
        .get("NetworkSettings")
        .ok_or(InspectError::Invalid)?;
    if text_field(config, "Image")? != IMAGE
        || text_field(config, "User")? != "1000:1000"
        || !bool_field(config, "AttachStdin")?
        || !bool_field(config, "AttachStdout")?
        || bool_field(config, "AttachStderr")?
        || !bool_field(config, "OpenStdin")?
    {
        return Err(InspectError::Drift);
    }
    if !nil_or_empty(host.get("PortBindings").ok_or(InspectError::Invalid)?)
        || !nil_or_empty(host.get("Devices").ok_or(InspectError::Invalid)?)
        || !nil_or_empty(host.get("DeviceRequests").ok_or(InspectError::Invalid)?)
        || !nil_or_empty(host.get("DeviceCgroupRules").ok_or(InspectError::Invalid)?)
        // Docker 29 omits this field when unset; only null or an empty object
        // is accepted when it is present.
        || host.get("Sysctls").is_some_and(|value| {
            !value.is_null() && !value.as_object().is_some_and(|map| map.is_empty())
        })
    {
        return Err(InspectError::Drift);
    }
    // Reject inherited privilege and resource overrides outside the fixed CLI
    // recipe. Extra mask/readonly paths only make the container more restrictive.
    for key in [
        "Binds",
        "Ulimits",
        "BlkioWeightDevice",
        "BlkioDeviceReadBps",
        "BlkioDeviceWriteBps",
        "BlkioDeviceReadIOps",
        "BlkioDeviceWriteIOps",
    ] {
        if !nil_or_empty(host.get(key).ok_or(InspectError::Invalid)?) {
            return Err(InspectError::Drift);
        }
    }
    for key in [
        "CpuShares",
        "CpuPeriod",
        "CpuQuota",
        "CpuRealtimePeriod",
        "CpuRealtimeRuntime",
        "MemoryReservation",
        "OomScoreAdj",
        "BlkioWeight",
        "CpuCount",
        "CpuPercent",
        "IOMaximumIOps",
        "IOMaximumBandwidth",
    ] {
        if host.get(key).and_then(|v| v.as_i64()) != Some(0) {
            return Err(InspectError::Drift);
        }
    }
    for key in [
        "Cgroup",
        "CgroupParent",
        "CpusetCpus",
        "CpusetMems",
        "VolumeDriver",
        "Isolation",
    ] {
        if !text_field(host, key)?.is_empty() {
            return Err(InspectError::Drift);
        }
    }
    if !matches!(
        host.get("OomKillDisable"),
        Some(serde_json::Value::Null) | Some(serde_json::Value::Bool(false))
    ) {
        return Err(InspectError::Drift);
    }
    let swap = host
        .get("MemorySwap")
        .and_then(|v| v.as_i64())
        .ok_or(InspectError::Invalid)?;
    if swap <= 0 || swap > 1_073_741_824 {
        return Err(InspectError::Drift);
    }
    let masked = strings_field(host, "MaskedPaths")?;
    let readonly = strings_field(host, "ReadonlyPaths")?;
    if ["/proc/kcore", "/proc/keys", "/sys/firmware"]
        .iter()
        .any(|x| !masked.iter().any(|y| y == x))
        || [
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger",
        ]
        .iter()
        .any(|x| !readonly.iter().any(|y| y == x))
    {
        return Err(InspectError::Drift);
    }
    let log = host.get("LogConfig").ok_or(InspectError::Invalid)?;
    if !nil_or_empty(log.get("Config").ok_or(InspectError::Invalid)?) {
        return Err(InspectError::Drift);
    }
    let started = text_field(state, "StartedAt")?.to_owned();
    let pid = u64_field(state, "Pid")?;
    let running = bool_field(state, "Running")?;
    match state_kind {
        ActualState::Created
            if text_field(state, "Status")? == "created"
                && !running
                && pid == 0
                && started == "0001-01-01T00:00:00Z" => {}
        ActualState::Running
            if text_field(state, "Status")? == "running" && running && pid > 0 && utc(&started) => {
        }
        _ => return Err(InspectError::Drift),
    }
    let actual_mounts = container
        .get("Mounts")
        .and_then(|v| v.as_array())
        .ok_or(InspectError::Invalid)?;
    if actual_mounts.len() != source_mounts.len() {
        return Err(InspectError::Drift);
    }
    let mut mounts = Vec::with_capacity(actual_mounts.len());
    for m in actual_mounts {
        mounts.push(Mount {
            destination: text_field(m, "Destination")?.into(),
            kind: text_field(m, "Type")?.into(),
            propagation: text_field(m, "Propagation")?.into(),
            read_only: !bool_field(m, "RW")?,
            source: text_field(m, "Source")?.into(),
        });
    }
    mounts.sort_by(|a, b| a.destination.cmp(&b.destination));
    if mounts != source_mounts {
        return Err(InspectError::Drift);
    }
    let exposed = object_field(config, "ExposedPorts")?;
    let mut exposed_ports: Vec<_> = exposed.keys().cloned().collect();
    exposed_ports.sort();
    let ports = settings.get("Ports").ok_or(InspectError::Invalid)?;
    if !(state_kind == ActualState::Created && ports.is_null()) {
        let ports = ports.as_object().ok_or(InspectError::Invalid)?;
        if ports.keys().any(|k| k != "1880/tcp") || ports.values().any(|v| !v.is_null()) {
            return Err(InspectError::Drift);
        }
    }
    let endpoints = object_field(settings, "Networks")?;
    if endpoints.len() != 1 {
        return Err(InspectError::Drift);
    }
    let endpoint = endpoints
        .get(expected.network_name)
        .ok_or(InspectError::Drift)?;
    let actual_network_id = text_field(endpoint, "NetworkID")?;
    if (state_kind == ActualState::Running && actual_network_id != value_hex(&expected.network_id))
        || (state_kind == ActualState::Created && !actual_network_id.is_empty())
    {
        return Err(InspectError::Drift);
    }
    let mut aliases = strings_field(endpoint, "Aliases")?;
    if state_kind == ActualState::Created && aliases.is_empty() {
        aliases.push("causal-node".into());
    }
    if !aliases.iter().any(|x| x == "causal-node") {
        return Err(InspectError::Drift);
    }
    if text_field(&network, "Id")? != value_hex(&expected.network_id)
        || text_field(&network, "Name")? != expected.network_name
        || !bool_field(&network, "Internal")?
    {
        return Err(InspectError::Drift);
    }
    let net_labels = object_field(&network, "Labels")?;
    if net_labels
        .get(expected.network_label)
        .and_then(|v| v.as_str())
        != Some(value_hex(&expected.network_owner).as_str())
    {
        return Err(InspectError::Drift);
    }
    let containers = object_field(&network, "Containers")?;
    let mut expected_members: Vec<_> = expected.peers.iter().map(|x| value_hex(x)).collect();
    if state_kind == ActualState::Running {
        expected_members.push(cid.clone());
    }
    expected_members.sort();
    if expected_members.windows(2).any(|w| w[0] == w[1])
        || containers.keys().ne(expected_members.iter())
    {
        return Err(InspectError::Drift);
    }
    let tmpfs = object_field(host, "Tmpfs")?;
    let mut tmpfs_entries = Vec::new();
    for (dest, options) in tmpfs {
        let mut options: Vec<String> = options
            .as_str()
            .ok_or(InspectError::Invalid)?
            .split(',')
            .map(str::to_owned)
            .collect();
        options.sort();
        tmpfs_entries.push(Tmpfs {
            destination: dest.clone(),
            options,
        });
    }
    let labels = object_field(config, "Labels")?;
    let owner_label = "org.apicontour.causal.owner";
    if labels.len() != expected.image_labels.len() + 1
        || labels.get(owner_label).and_then(|v| v.as_str())
            != Some(value_hex(&expected.owner).as_str())
        || expected
            .image_labels
            .iter()
            .any(|(key, value)| labels.get(key).and_then(|v| v.as_str()) != Some(value.as_str()))
    {
        return Err(InspectError::Drift);
    }
    // The immutable image ID commits to its verified defaults. Keep the
    // established canonical projection's owner-only label representation.
    let labels = vec![format!("{owner_label}={}", value_hex(&expected.owner))];
    let security_opt = strings_field(host, "SecurityOpt")?;
    let restart = host.get("RestartPolicy").ok_or(InspectError::Invalid)?;
    let mut p = Projection {
        attach_stderr: bool_field(config, "AttachStderr")?,
        attach_stdin: bool_field(config, "AttachStdin")?,
        attach_stdout: bool_field(config, "AttachStdout")?,
        auto_remove: bool_field(host, "AutoRemove")?,
        cap_add: strings_field(host, "CapAdd")?,
        cap_drop: strings_field(host, "CapDrop")?,
        cgroupns_mode: text_field(host, "CgroupnsMode")?.into(),
        cmd: strings_field(config, "Cmd")?,
        container_id: cid,
        context: "explicit-unix".into(),
        cpu_nanos: u64_field(host, "NanoCpus")?,
        daemon_endpoint: expected.daemon.clone(),
        device_cgroup_rules: Vec::new(),
        device_requests: Vec::new(),
        devices: Vec::new(),
        dns: strings_field(host, "Dns")?,
        dns_options: strings_field(host, "DnsOptions")?,
        dns_search: strings_field(host, "DnsSearch")?,
        domainname: text_field(config, "Domainname")?.into(),
        entrypoint: strings_field(config, "Entrypoint")?,
        env: strings_field(config, "Env")?,
        exposed_ports,
        extra_hosts: strings_field(host, "ExtraHosts")?,
        group_add: strings_field(host, "GroupAdd")?,
        hostname: text_field(config, "Hostname")?.into(),
        image_id: image,
        image_ref: text_field(config, "Image")?.into(),
        init: bool_field(host, "Init")?,
        ipc_mode: text_field(host, "IpcMode")?.into(),
        labels,
        links: strings_field(host, "Links")?,
        log_driver: text_field(host.get("LogConfig").ok_or(InspectError::Invalid)?, "Type")?.into(),
        memory: u64_field(host, "Memory")?,
        mounts,
        name: text_field(&container, "Name")?.into(),
        network: Network {
            aliases,
            id: value_hex(&expected.network_id),
            internal: true,
            members: expected_members.clone(),
            name: expected.network_name.into(),
            owner: value_hex(&expected.network_owner),
        },
        network_mode: text_field(host, "NetworkMode")?.into(),
        no_new_privileges: security_opt == ["no-new-privileges:true"],
        pid,
        pid_mode: text_field(host, "PidMode")?.into(),
        pids: u64_field(host, "PidsLimit")?,
        ports: Vec::new(),
        privileged: bool_field(host, "Privileged")?,
        publish_all_ports: bool_field(host, "PublishAllPorts")?,
        read_only_root: bool_field(host, "ReadonlyRootfs")?,
        restart_policy: text_field(restart, "Name")?.into(),
        running,
        runtime: text_field(host, "Runtime")?.into(),
        security_opt,
        shm_size: u64_field(host, "ShmSize")?,
        source_files: source_entries.to_vec(),
        started_at: started,
        sysctls: Vec::new(),
        tmpfs: tmpfs_entries,
        tty: bool_field(config, "Tty")?,
        user: text_field(config, "User")?.into(),
        userns_mode: text_field(host, "UsernsMode")?.into(),
        uts_mode: text_field(host, "UTSMode")?.into(),
        version: 1,
        volumes_from: strings_field(host, "VolumesFrom")?,
        working_dir: text_field(config, "WorkingDir")?.into(),
    };
    // Running-only validator is reused with explicitly synthetic state fields
    // solely for pre-start validation; these bytes cannot mint running state.
    if state_kind == ActualState::Created {
        p.running = true;
        p.pid = 1;
        p.started_at = "2000-01-01T00:00:00Z".into();
        p.network.members.push(value_hex(&expected.cid));
        p.network.members.sort();
    }
    let bytes = serde_json::to_vec(&p).map_err(|_| InspectError::Invalid)?;
    parse(&bytes)?;
    candidate_source_digests_for(&p.mounts, &p.source_files)?;
    Ok(ValidatedActual {
        projection: p,
        state: state_kind,
    })
}

/// Retained candidate source and mount identities captured without following
/// path components. This is data only; it does not establish container use.
pub struct CandidateSources {
    mounts: Vec<Mount>,
    mount_handles: Vec<HeldMount>,
    source_handles: Vec<HeldMount>,
    source_entries: Vec<SourceFile>,
    snapshots: Vec<crate::FileSnapshot>,
}
impl CandidateSources {
    /// Capture the fixed eleven mount sources in destination order. Keys must be
    /// owned 0600 files; source inventory must match the compiled 503 manifest.
    pub fn capture(paths: &[PathBuf; 11]) -> Result<Self, InspectError> {
        let destinations = [
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
        let mut mounts = Vec::with_capacity(11);
        let mut mount_handles = Vec::with_capacity(11);
        for (index, path) in paths.iter().enumerate() {
            let value = path.to_str().ok_or(InspectError::Invalid)?;
            if !abs_path(value)
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
            {
                return Err(InspectError::Invalid);
            }
            let private = destinations[index].ends_with(".key");
            mount_handles.push(HeldMount::open(path, private, index == 1 || index == 2)?);
            mounts.push(Mount {
                destination: destinations[index].into(),
                kind: "bind".into(),
                propagation: "rprivate".into(),
                read_only: true,
                source: value.into(),
            });
        }
        let mut source_handles = Vec::new();
        let mut source_entries = Vec::new();
        for path in expected_sources(&mounts)? {
            let handle = HeldMount::open(Path::new(&path), false, false)?;
            let digest = handle.digest.ok_or(InspectError::Invalid)?;
            source_entries.push(SourceFile {
                path,
                sha256: hex_digest(digest),
            });
            source_handles.push(handle);
        }
        candidate_source_digests_for(&mounts, &source_entries)?;
        closed_code_directories(&mounts, &mount_handles)?;
        let mut snapshots = Vec::new();
        for (index, path) in paths.iter().enumerate().skip(4) {
            let snapshot = crate::snapshot_file(path, destinations[index].ends_with(".key"))
                .map_err(|_| InspectError::Drift)?;
            let digest: [u8; 32] = Sha256::digest(snapshot.as_bytes()).into();
            if mount_handles[index].digest != Some(digest) {
                return Err(InspectError::Drift);
            }
            snapshots.push(snapshot);
        }
        let captured = Self {
            mounts,
            mount_handles,
            source_handles,
            source_entries,
            snapshots,
        };
        captured.revalidate()?;
        Ok(captured)
    }
    pub(crate) fn seal(
        self,
        actual: ValidatedActual,
    ) -> Result<(InspectedDeployment, [crate::FileSnapshot; 7]), InspectError> {
        if actual.state != ActualState::Running
            || actual.projection.mounts != self.mounts
            || actual.projection.source_files != self.source_entries
        {
            return Err(InspectError::Drift);
        }
        self.revalidate()?;
        let snapshots: [crate::FileSnapshot; 7] = self
            .snapshots
            .try_into()
            .map_err(|_| InspectError::Invalid)?;
        Ok((
            InspectedDeployment {
                projection: actual.projection,
                sources: self.mount_handles,
                source_files: self.source_handles,
            },
            snapshots,
        ))
    }
    pub(crate) fn paths(&self) -> Result<[PathBuf; 11], InspectError> {
        self.mounts
            .iter()
            .map(|m| PathBuf::from(&m.source))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| InspectError::Invalid)
    }
    pub(crate) fn mount_pairs(&self) -> Vec<(&str, &str)> {
        self.mounts
            .iter()
            .map(|m| (m.source.as_str(), m.destination.as_str()))
            .collect()
    }
    pub(crate) fn commitment(&self) -> Result<[u8; 32], InspectError> {
        self.revalidate()?;
        let mount = serde_json::to_vec(&identity_list(&self.mount_handles)?)
            .map_err(|_| InspectError::Invalid)?;
        let source = serde_json::to_vec(&identity_list(&self.source_handles)?)
            .map_err(|_| InspectError::Invalid)?;
        let mut hash = Sha256::new();
        hash.update(b"apicontour/candidate-sources/1\n");
        hash.update((mount.len() as u64).to_be_bytes());
        hash.update(mount);
        hash.update((source.len() as u64).to_be_bytes());
        hash.update(source);
        Ok(hash.finalize().into())
    }
    /// Reopen every absolute path and compare every retained ancestor and leaf.
    pub fn revalidate(&self) -> Result<(), InspectError> {
        candidate_source_digests_for(&self.mounts, &self.source_entries)?;
        closed_code_directories(&self.mounts, &self.mount_handles)?;
        for handle in self.mount_handles.iter().chain(&self.source_handles) {
            handle.revalidate()?;
        }
        if self.snapshots.len() != 7 {
            return Err(InspectError::Invalid);
        }
        for (index, snapshot) in self.snapshots.iter().enumerate() {
            let digest: [u8; 32] = Sha256::digest(snapshot.as_bytes()).into();
            if self.mount_handles[index + 4].digest != Some(digest) {
                return Err(InspectError::Drift);
            }
        }
        Ok(())
    }
}

/// Sealed inspected state. It cannot be constructed from caller-supplied JSON;
/// the future fixed Docker adapter must create it only after actual inspection.
/// It conveys no 503 authorization and is not an attestation.
pub struct InspectedDeployment {
    projection: Projection,
    sources: Vec<HeldMount>,
    source_files: Vec<HeldMount>,
}
impl std::fmt::Debug for InspectedDeployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InspectedDeployment")
    }
}
impl InspectedDeployment {
    /// Revalidate the same normalized Docker observation, then reopen every
    /// retained absolute mount source and compare all ancestors and leaf contents.
    /// Call only with a fresh result from the same fixed daemon inspection; a raw
    /// caller-supplied value does not make it trustworthy.
    pub fn revalidate(
        &self,
        observation: &[u8],
        materials: &[(&str, &crate::FileSnapshot)],
    ) -> Result<(), InspectError> {
        let current = parse(observation)?;
        if current != self.projection
            || self.sources.len() != current.mounts.len()
            || self.source_files.len() != current.source_files.len()
        {
            return Err(InspectError::Drift);
        }
        for (mount, source) in current.mounts.iter().zip(&self.sources) {
            let expected_dir = matches!(
                mount.destination.as_str(),
                "/adapter/error-integration" | "/adapter/live-integration"
            );
            if source.path != Path::new(&mount.source)
                || source.directory != expected_dir
                || source.private != mount.destination.ends_with(".key")
            {
                return Err(InspectError::Drift);
            }
            source.revalidate()?;
        }
        for (expected, source) in current.source_files.iter().zip(&self.source_files) {
            if source.path != Path::new(&expected.path)
                || source.directory
                || source.private
                || source.digest.map(hex_digest).as_deref() != Some(expected.sha256.as_str())
            {
                return Err(InspectError::Drift);
            }
            source.revalidate()?;
        }
        let required = [
            "/run/apicontour/live/ca.pem",
            "/run/apicontour/live/export.key",
            "/run/apicontour/live/export.pem",
            "/run/apicontour/live/product.key",
            "/run/apicontour/live/product.pem",
            "/run/apicontour/live/server.key",
            "/run/apicontour/live/server.pem",
        ];
        if materials.len() != required.len() || materials.iter().map(|x| x.0).ne(required) {
            return Err(InspectError::Invalid);
        }
        for (destination, snapshot) in materials {
            let index = current
                .mounts
                .iter()
                .position(|m| m.destination == *destination)
                .ok_or(InspectError::Drift)?;
            let digest: [u8; 32] = Sha256::digest(snapshot.as_bytes()).into();
            if self.sources[index].digest != Some(digest) {
                return Err(InspectError::Drift);
            }
        }
        Ok(())
    }
    /// Validate all source digests against the fixed candidate 503 manifest.
    /// Call `revalidate` separately to reopen the retained paths and material.
    pub fn validate_candidate_sources(&self) -> Result<(), InspectError> {
        candidate_source_digests_for(&self.projection.mounts, &self.projection.source_files)
    }
    pub(crate) fn matches_actual(&self, actual: &ValidatedActual) -> bool {
        actual.state == ActualState::Running && self.projection == actual.projection
    }
    /// Canonical public data record for correlation only; never a bearer token.
    pub fn canonical_record(&self) -> Result<Vec<u8>, InspectError> {
        if self.sources.len() != self.projection.mounts.len()
            || self.source_files.len() != self.projection.source_files.len()
        {
            return Err(InspectError::Invalid);
        }
        let source_digest = inventory_hash(
            b"apicontour/causal-source-inventory/1\n",
            &self.source_files,
        )?;
        let mount_digest = inventory_hash(b"apicontour/causal-mount-inventory/1\n", &self.sources)?;
        let value = serde_json::to_value(&self.projection).map_err(|_| InspectError::Invalid)?;
        let object = value.as_object().ok_or(InspectError::Invalid)?;
        let mut record: std::collections::BTreeMap<&str, serde_json::Value> = object
            .iter()
            .filter(|(k, _)| k.as_str() != "source_files")
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        record.insert(
            "source_inventory_sha256",
            serde_json::Value::String(source_digest),
        );
        record.insert(
            "mount_inventory_sha256",
            serde_json::Value::String(mount_digest),
        );
        let result = serde_json::to_vec(&record).map_err(|_| InspectError::Invalid)?;
        if result.len() > 8192 {
            return Err(InspectError::Invalid);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    const TARGETS: [&str; 11] = [
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
    #[test]
    fn code_directories_reject_shadow_modules_and_transient_changes() {
        let f = Fixture::new();
        let mounts = &f.inspected.projection.mounts;
        let held = &f.inspected.sources;
        assert_eq!(expected_sources(mounts).unwrap().len(), 23);
        assert_eq!(closed_code_directories(mounts, held), Ok(()));
        let shadow = f.root.join("item02/private-bootstrap");
        std::fs::write(&shadow, b"shadow").unwrap();
        assert_eq!(
            closed_code_directories(mounts, held),
            Err(InspectError::Drift)
        );
        std::fs::remove_file(shadow).unwrap();
        // Even when the injected entry is removed, the retained directory's
        // change timestamps fence the previous capture.
        assert_eq!(
            closed_code_directories(mounts, held),
            Err(InspectError::Drift)
        );

        let f = Fixture::new();
        std::fs::create_dir(f.root.join("item01/node_modules")).unwrap();
        assert_eq!(
            closed_code_directories(&f.inspected.projection.mounts, &f.inspected.sources),
            Err(InspectError::Drift)
        );

        let f = Fixture::new();
        let file = f.root.join("item02/private-bootstrap.js");
        let original = std::fs::read(&file).unwrap();
        std::fs::write(&file, b"temporary-change").unwrap();
        std::fs::write(&file, original).unwrap();
        let source = f
            .inspected
            .source_files
            .iter()
            .find(|s| s.path == file)
            .unwrap();
        assert_eq!(source.revalidate(), Err(InspectError::Drift));
    }
    struct Fixture {
        root: PathBuf,
        inspected: InspectedDeployment,
        snapshots: Vec<crate::FileSnapshot>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "contour-inspector-{}-{}-{sequence}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            let mut mounts = Vec::new();
            let mut sources = Vec::new();
            let mut snapshots = Vec::new();
            for (i, target) in TARGETS.iter().enumerate() {
                let path = root.join(format!("item{i:02}"));
                let dir = i == 1 || i == 2;
                if dir {
                    std::fs::create_dir(&path).unwrap();
                } else {
                    std::fs::write(&path, format!("synthetic-{i}")).unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                mounts.push(Mount {
                    destination: (*target).into(),
                    kind: "bind".into(),
                    propagation: "rprivate".into(),
                    read_only: true,
                    source: path.to_str().unwrap().into(),
                });
            }
            let source_paths = expected_sources(&mounts).unwrap();
            for path in &source_paths {
                if !Path::new(path).exists() {
                    std::fs::write(path, b"synthetic-source").unwrap();
                }
            }
            for (i, mount) in mounts.iter().enumerate() {
                let private = mount.destination.ends_with(".key");
                let directory = i == 1 || i == 2;
                sources
                    .push(HeldMount::open(Path::new(&mount.source), private, directory).unwrap());
                if i >= 4 {
                    snapshots
                        .push(crate::snapshot_file(Path::new(&mount.source), private).unwrap());
                }
            }
            let source_guards: Vec<_> = source_paths
                .iter()
                .map(|p| HeldMount::open(Path::new(p), false, false).unwrap())
                .collect();
            let source_entries: Vec<_> = source_guards
                .iter()
                .map(|g| SourceFile {
                    path: g.path.to_str().unwrap().into(),
                    sha256: hex_digest(g.digest.unwrap()),
                })
                .collect();
            let cid = "11".repeat(32);
            let options = ["mode=1777", "nodev", "noexec", "nosuid", "rw", "size=16m"]
                .map(str::to_string)
                .to_vec();
            let p=Projection{attach_stderr:false,attach_stdin:true,attach_stdout:true,auto_remove:false,cap_add:vec![],cap_drop:vec!["ALL".into()],cgroupns_mode:"private".into(),cmd:vec!["/adapter/live-integration/private-launch-proxy.js".into()],container_id:cid.clone(),context:"local".into(),cpu_nanos:1_000_000_000,daemon_endpoint:"unix:///tmp/docker.sock".into(),device_cgroup_rules:vec![],device_requests:vec![],devices:vec![],dns:vec![],dns_options:vec![],dns_search:vec![],domainname:"".into(),entrypoint:vec!["/usr/local/bin/node".into()],env:["FLOWS=flows.json","HOME=/data","HOSTNAME=causal-live","LANG=C.UTF-8","NODE_PATH=/usr/src/node-red/node_modules","NODE_RED_VERSION=v5.0.9","NODE_VERSION=24.22.1","PATH=/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","TZ=UTC","YARN_VERSION=1.22.22"].map(str::to_string).to_vec(),exposed_ports:vec!["1880/tcp".into()],extra_hosts:vec![],group_add:vec![],hostname:"causal-live".into(),image_id:format!("sha256:{}","22".repeat(32)),image_ref:IMAGE.into(),init:true,ipc_mode:"private".into(),labels:vec![format!("org.apicontour.causal.owner={}","33".repeat(32))],links:vec![],log_driver:"none".into(),memory:536_870_912,mounts,name:"/contour-causal-proxy".into(),network:Network{aliases:vec!["causal-node".into()],id:"44".repeat(32),internal:true,members:vec![cid],name:"causal-net".into(),owner:"55".repeat(32)},network_mode:"causal-net".into(),no_new_privileges:true,pid:123,pid_mode:"".into(),pids:128,ports:vec![],privileged:false,publish_all_ports:false,read_only_root:true,restart_policy:"no".into(),running:true,runtime:"runc".into(),security_opt:vec!["no-new-privileges:true".into()],shm_size:67_108_864,source_files:source_entries,started_at:"2026-11-07T00:00:00Z".into(),sysctls:vec![],tmpfs:vec![Tmpfs{destination:"/data".into(),options:options.clone()},Tmpfs{destination:"/tmp".into(),options}],tty:false,user:"1000:1000".into(),userns_mode:"".into(),uts_mode:"".into(),version:1,volumes_from:vec![],working_dir:"/data".into()};
            Self {
                root,
                inspected: InspectedDeployment {
                    projection: p,
                    sources,
                    source_files: source_guards,
                },
                snapshots,
            }
        }
        fn material(&self) -> Vec<(&str, &crate::FileSnapshot)> {
            TARGETS[4..].iter().copied().zip(&self.snapshots).collect()
        }
        fn bytes(&self) -> Vec<u8> {
            serde_json::to_vec(&self.inspected.projection).unwrap()
        }
    }
    #[test]
    fn sealed_revalidation_detects_projection_and_material_changes() {
        let f = Fixture::new();
        assert_eq!(f.inspected.revalidate(&f.bytes(), &f.material()), Ok(()));
        assert!(
            f.inspected.canonical_record().is_ok(),
            "record length {}",
            f.bytes().len()
        );
        let mut p = f.inspected.projection.clone();
        p.network.members.push("aa".repeat(32));
        assert_eq!(
            f.inspected
                .revalidate(&serde_json::to_vec(&p).unwrap(), &f.material()),
            Err(InspectError::Drift)
        );
        let mut material = f.material();
        material.swap(0, 1);
        assert_eq!(
            f.inspected.revalidate(&f.bytes(), &material),
            Err(InspectError::Invalid)
        );
        let mut material = f.material();
        material[0].1 = &f.snapshots[1];
        assert_eq!(
            f.inspected.revalidate(&f.bytes(), &material),
            Err(InspectError::Drift)
        );
        let path = Path::new(&f.inspected.projection.mounts[4].source);
        std::fs::write(path, b"different").unwrap();
        assert_eq!(
            f.inspected.revalidate(&f.bytes(), &f.material()),
            Err(InspectError::Drift)
        );
    }
    #[test]
    fn source_inventory_and_content_are_bound() {
        let f = Fixture::new();
        let record = f.inspected.canonical_record().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&record).unwrap();
        assert!(value.get("source_files").is_none());
        assert!(
            value["source_inventory_sha256"]
                .as_str()
                .is_some_and(|x| lower_hex(x, 64))
        );
        let mut p = f.inspected.projection.clone();
        p.source_files.pop();
        assert!(parse(&serde_json::to_vec(&p).unwrap()).is_err());
        let p = &f.inspected.projection.source_files[0].path;
        std::fs::write(p, b"modified source").unwrap();
        assert_eq!(
            f.inspected.revalidate(&f.bytes(), &f.material()),
            Err(InspectError::Drift)
        );
    }
    #[test]
    fn ancestor_replacement_and_symlinks_fail_without_adoption() {
        let f = Fixture::new();
        let child = f.root.join("item02");
        let old = f.root.join("old");
        std::fs::rename(&child, &old).unwrap();
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("live-main.js"), b"synthetic-source").unwrap();
        assert_eq!(
            f.inspected.revalidate(&f.bytes(), &f.material()),
            Err(InspectError::Drift)
        );
        std::fs::remove_dir_all(&child).unwrap();
        symlink(&old, &child).unwrap();
        assert!(f.inspected.revalidate(&f.bytes(), &f.material()).is_err());
    }
    #[test]
    fn same_bytes_at_a_replaced_mount_inode_and_changed_source_mode_are_refused() {
        let f = Fixture::new();
        let path = Path::new(&f.inspected.projection.mounts[4].source);
        let old = path.with_extension("old");
        let bytes = std::fs::read(path).unwrap();
        std::fs::rename(path, &old).unwrap();
        std::fs::write(path, bytes).unwrap();
        assert_eq!(
            f.inspected.revalidate(&f.bytes(), &f.material()),
            Err(InspectError::Drift)
        );
        let f = Fixture::new();
        let path = Path::new(&f.inspected.projection.source_files[0].path);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            f.inspected.revalidate(&f.bytes(), &f.material()),
            Err(InspectError::Drift)
        );
    }
    #[test]
    fn init_and_exact_manifest_hostname_are_required() {
        let f = Fixture::new();
        let mut p = f.inspected.projection.clone();
        p.init = false;
        assert_eq!(
            parse(&serde_json::to_vec(&p).unwrap()).err(),
            Some(InspectError::Invalid)
        );
        let mut p = f.inspected.projection.clone();
        p.hostname = "foreign".into();
        p.env
            .iter_mut()
            .find(|x| x.starts_with("HOSTNAME="))
            .unwrap()
            .replace_range(.., "HOSTNAME=foreign");
        assert_eq!(
            parse(&serde_json::to_vec(&p).unwrap()).err(),
            Some(InspectError::Invalid)
        );
    }
    #[test]
    fn strict_projection_refuses_unknown_duplicate_security_and_topology() {
        let f = Fixture::new();
        let b = f.bytes();
        assert!(parse(&b).is_ok());
        let text = String::from_utf8(b.clone()).unwrap();
        let dup = text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
        assert!(parse(dup.as_bytes()).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        v["unknown"] = serde_json::json!(true);
        assert!(parse(&serde_json::to_vec(&v).unwrap()).is_err());
        for (field, value) in [
            ("privileged", serde_json::json!(true)),
            ("publish_all_ports", serde_json::json!(true)),
            ("attach_stderr", serde_json::json!(true)),
            ("attach_stdin", serde_json::json!(false)),
            ("read_only_root", serde_json::json!(false)),
            ("no_new_privileges", serde_json::json!(false)),
            ("cap_add", serde_json::json!(["SYS_ADMIN"])),
            ("cap_drop", serde_json::json!([])),
            ("runtime", serde_json::json!("untrusted")),
            ("security_opt", serde_json::json!([])),
            ("user", serde_json::json!("00:00")),
            ("daemon_endpoint", serde_json::json!("tcp://elsewhere")),
            ("restart_policy", serde_json::json!("always")),
            ("ipc_mode", serde_json::json!("container:other")),
            ("device_cgroup_rules", serde_json::json!(["a *:* rwm"])),
            ("links", serde_json::json!(["other"])),
            ("pid_mode", serde_json::json!("host")),
            ("tty", serde_json::json!(true)),
            ("log_driver", serde_json::json!("json-file")),
            ("devices", serde_json::json!(["/dev/kvm"])),
            ("ports", serde_json::json!(["0.0.0.0:1880"])),
            ("image_ref", serde_json::json!("untrusted")),
        ] {
            let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
            v[field] = value;
            assert!(parse(&serde_json::to_vec(&v).unwrap()).is_err(), "{field}");
        }
        let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        v["mounts"][0]["read_only"] = serde_json::json!(false);
        assert!(parse(&serde_json::to_vec(&v).unwrap()).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        v["network"]["members"] = serde_json::json!(["11".repeat(32), "11".repeat(32)]);
        assert!(parse(&serde_json::to_vec(&v).unwrap()).is_err());
        assert!(parse(&vec![b'x'; MAX_JSON + 1]).is_err());
    }
    #[test]
    fn candidate_inventory_rejects_each_source_digest_mutation() {
        let fixture = Fixture::new();
        let mut p = fixture.inspected.projection.clone();
        let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../collectors/nodered/live-integration/manifest.json"
        ))
        .unwrap();
        let entries = p
            .source_files
            .iter()
            .map(|entry| {
                let source = &entry.path;
                let expected = if *source == p.mounts[0].source {
                    manifest["files"]["/adapter/causal-codec.js"]
                        .as_str()
                        .unwrap()
                } else if *source == p.mounts[3].source {
                    manifest["flow_sha256"].as_str().unwrap()
                } else if let Some(name) = source.strip_prefix(&(p.mounts[1].source.clone() + "/"))
                {
                    manifest["files"][format!("/adapter/error-integration/{name}")]
                        .as_str()
                        .unwrap()
                } else {
                    let name = source
                        .strip_prefix(&(p.mounts[2].source.clone() + "/"))
                        .unwrap();
                    match name {
                        "manifest.json" => {
                            "a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e"
                        }
                        "tree-arm64.json" => {
                            manifest["arch_trees"]["arm64"]["sha256"].as_str().unwrap()
                        }
                        "tree-x64.json" => {
                            manifest["arch_trees"]["x64"]["sha256"].as_str().unwrap()
                        }
                        _ => manifest["files"][format!("/adapter/live-integration/{name}")]
                            .as_str()
                            .unwrap(),
                    }
                };
                SourceFile {
                    path: source.clone(),
                    sha256: expected.into(),
                }
            })
            .collect();
        p.source_files = entries;
        assert_eq!(
            candidate_source_digests_for(&p.mounts, &p.source_files),
            Ok(())
        );
        for index in 0..23 {
            let mut bad = p.clone();
            bad.source_files[index].sha256 = "00".repeat(32);
            assert_eq!(
                candidate_source_digests_for(&bad.mounts, &bad.source_files),
                Err(InspectError::Drift)
            );
        }
    }
    #[test]
    fn exact_node_entrypoint_and_proxy_command_only() {
        let fixture = Fixture::new();
        let mut p = fixture.inspected.projection.clone();
        assert!(parse(&serde_json::to_vec(&p).unwrap()).is_ok());
        p.entrypoint
            .push("/adapter/live-integration/private-launch-proxy.js".into());
        p.cmd.clear();
        assert!(parse(&serde_json::to_vec(&p).unwrap()).is_err());
        p.entrypoint = vec!["/bin/sh".into()];
        p.cmd = vec!["-c".into(), "node proxy.js".into()];
        assert!(parse(&serde_json::to_vec(&p).unwrap()).is_err());
        p.entrypoint = vec!["/usr/local/bin/node".into()];
        p.cmd = vec![
            "/adapter/live-integration/private-launch-proxy.js".into(),
            "extra".into(),
        ];
        assert!(parse(&serde_json::to_vec(&p).unwrap()).is_err());
    }
    #[test]
    fn fixed_actual_projection_rejects_container_and_network_drift() {
        use crate::causal_launch_process::{ActualDockerObservation, DockerInspect};
        let fixture = Fixture::new();
        let mut p = fixture.inspected.projection.clone();
        let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../collectors/nodered/live-integration/manifest.json"
        ))
        .unwrap();
        for entry in &mut p.source_files {
            let source = &entry.path;
            let expected = if *source == p.mounts[0].source {
                manifest["files"]["/adapter/causal-codec.js"]
                    .as_str()
                    .unwrap()
            } else if *source == p.mounts[3].source {
                manifest["flow_sha256"].as_str().unwrap()
            } else if let Some(name) = source.strip_prefix(&(p.mounts[1].source.clone() + "/")) {
                manifest["files"][format!("/adapter/error-integration/{name}")]
                    .as_str()
                    .unwrap()
            } else {
                let name = source
                    .strip_prefix(&(p.mounts[2].source.clone() + "/"))
                    .unwrap();
                match name {
                    "manifest.json" => {
                        "a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e"
                    }
                    "tree-arm64.json" => {
                        manifest["arch_trees"]["arm64"]["sha256"].as_str().unwrap()
                    }
                    "tree-x64.json" => manifest["arch_trees"]["x64"]["sha256"].as_str().unwrap(),
                    _ => manifest["files"][format!("/adapter/live-integration/{name}")]
                        .as_str()
                        .unwrap(),
                }
            };
            entry.sha256 = expected.into();
        }
        let raw_mounts:Vec<_>=p.mounts.iter().map(|m|serde_json::json!({"Destination":m.destination,"Type":"bind","Propagation":"rprivate","RW":false,"Source":m.source})).collect();
        let cid = "11".repeat(32);
        let netid = "44".repeat(32);
        let owner = "33".repeat(32);
        let netowner = "55".repeat(32);
        let mut host = serde_json::json!({"PortBindings":null,"Devices":null,"DeviceRequests":null,"DeviceCgroupRules":null,"Sysctls":{},"AutoRemove":false,"CapAdd":null,"CapDrop":["ALL"],"CgroupnsMode":"private","NanoCpus":1000000000,"Dns":[],"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"Init":true,"IpcMode":"private","Links":null,"LogConfig":{"Type":"none"}});
        let remaining = serde_json::json!({"Memory":536870912,"NetworkMode":"causal-net","PidMode":"","PidsLimit":128,"Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":true,"RestartPolicy":{"Name":"no"},"Runtime":"runc","SecurityOpt":["no-new-privileges:true"],"ShmSize":67108864,"Tmpfs":{"/data":"rw,nosuid,nodev,noexec,size=16m,mode=1777","/tmp":"rw,nosuid,nodev,noexec,size=16m,mode=1777"},"UsernsMode":"","UTSMode":"","VolumesFrom":null});
        host.as_object_mut()
            .unwrap()
            .extend(remaining.as_object().unwrap().clone());
        let safety = serde_json::json!({"Binds":null,"Ulimits":null,"BlkioWeightDevice":null,"BlkioDeviceReadBps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteIOps":null,"CpuShares":0,"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"MemoryReservation":0,"OomScoreAdj":0,"BlkioWeight":0,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"Cgroup":"","CgroupParent":"","CpusetCpus":"","CpusetMems":"","VolumeDriver":"","Isolation":"","OomKillDisable":false,"MemorySwap":1073741824,"MaskedPaths":["/proc/kcore","/proc/keys","/sys/firmware"],"ReadonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]});
        host.as_object_mut()
            .unwrap()
            .extend(safety.as_object().unwrap().clone());
        host["LogConfig"]["Config"] = serde_json::json!({});
        // Stock labels from the fixed image's created-container inspection.
        let image_labels: std::collections::BTreeMap<String, String> = [
            (
                "authors",
                "Dave Conway-Jones, Nick O'Leary, James Thomas, Raymond Mouthaan",
            ),
            ("org.label-schema.arch", ""),
            ("org.label-schema.build-date", "2026-10-21T15:52:22Z"),
            (
                "org.label-schema.description",
                "Low-code programming for event-driven applications.",
            ),
            (
                "org.label-schema.docker.dockerfile",
                ".docker/Dockerfile.alpine",
            ),
            ("org.label-schema.license", "Apache-2.0"),
            ("org.label-schema.name", "Node-RED"),
            ("org.label-schema.url", "https://nodered.org"),
            ("org.label-schema.vcs-ref", ""),
            ("org.label-schema.vcs-type", "Git"),
            (
                "org.label-schema.vcs-url",
                "https://github.com/node-red/node-red-docker",
            ),
            ("org.label-schema.version", "5.0.9"),
            (
                "org.opencontainers.image.source",
                "https://github.com/node-red/node-red-docker",
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let mut container_labels = image_labels.clone();
        container_labels.insert("org.apicontour.causal.owner".into(), owner.clone());
        let config = serde_json::json!({"Image":IMAGE,"User":"1000:1000","AttachStdin":true,"AttachStdout":true,"AttachStderr":false,"OpenStdin":true,"Tty":false,"Cmd":["/adapter/live-integration/private-launch-proxy.js"],"Entrypoint":["/usr/local/bin/node"],"Env":p.env,"ExposedPorts":{"1880/tcp":{}},"Domainname":"","Hostname":"causal-live","Labels":container_labels,"WorkingDir":"/data"});
        let mut container = serde_json::json!([{ "Id":cid,"Image":format!("sha256:{}","22".repeat(32)),"Name":"/contour-causal-proxy","State":{"Status":"running","Running":true,"Pid":123,"StartedAt":"2026-11-07T00:00:00Z"},"Config":config,"HostConfig":host,"Mounts":raw_mounts,"NetworkSettings":{"Ports":{"1880/tcp":null},"Networks":{"causal-net":{"NetworkID":netid,"Aliases":["causal-node"]}}}}]);
        let mut network = serde_json::json!([{"Id":netid,"Name":"causal-net","Internal":true,"Labels":{"org.apicontour.causal.owner":netowner},"Containers":{cid.clone():{}}}]);
        let expected = ActualExpected {
            cid: [0x11; 32],
            image: [0x22; 32],
            image_labels: &image_labels,
            owner: [0x33; 32],
            network_id: [0x44; 32],
            network_name: "causal-net",
            network_owner: [0x55; 32],
            network_label: "org.apicontour.causal.owner",
            peers: vec![],
            daemon: "unix:///tmp/docker.sock".into(),
            policy_digest: [0x66; 32],
        };
        let check = |c: &serde_json::Value, n: &serde_json::Value| {
            let co = ActualDockerObservation::fake(
                DockerInspect::Container([0x11; 32]),
                [0x66; 32],
                serde_json::to_vec(c).unwrap(),
            );
            let no = ActualDockerObservation::fake(
                DockerInspect::Network([0x44; 32]),
                [0x66; 32],
                serde_json::to_vec(n).unwrap(),
            );
            project_actual_container(
                &co,
                &no,
                &p.mounts,
                &p.source_files,
                &expected,
                ActualState::Running,
            )
            .is_ok()
        };
        // Docker 29 created inspect, with only identities and host paths
        // normalized. Keep the actual security/configuration field shapes.
        let mut captured: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/docker29_created_normalized.json"
        ))
        .unwrap();
        for mount in captured[0]["Mounts"].as_array_mut().unwrap() {
            let destination = mount["Destination"].as_str().unwrap();
            let expected_mount = p
                .mounts
                .iter()
                .find(|m| m.destination == destination)
                .unwrap();
            mount["Source"] = serde_json::json!(expected_mount.source);
        }
        let captured_observation = ActualDockerObservation::fake(
            DockerInspect::Container([0x11; 32]),
            [0x66; 32],
            serde_json::to_vec(&captured).unwrap(),
        );
        let captured_network = ActualDockerObservation::fake(
            DockerInspect::Network([0x44; 32]),
            [0x66; 32],
            serde_json::to_vec(
                &serde_json::json!([{"Id":netid,"Name":"causal-net","Internal":true,
                "Labels":{"org.apicontour.causal.owner":netowner},"Containers":{}}]),
            )
            .unwrap(),
        );
        assert!(
            project_actual_container(
                &captured_observation,
                &captured_network,
                &p.mounts,
                &p.source_files,
                &expected,
                ActualState::Created
            )
            .is_ok(),
            "Docker 29 created replay"
        );
        for valid in [serde_json::Value::Null, serde_json::json!({})] {
            let mut same = captured.clone();
            same[0]["HostConfig"]["Sysctls"] = valid;
            let observed = ActualDockerObservation::fake(
                DockerInspect::Container([0x11; 32]),
                [0x66; 32],
                serde_json::to_vec(&same).unwrap(),
            );
            assert!(
                project_actual_container(
                    &observed,
                    &captured_network,
                    &p.mounts,
                    &p.source_files,
                    &expected,
                    ActualState::Created
                )
                .is_ok()
            );
        }
        for invalid in [
            serde_json::json!({"net.ipv4.ip_forward":"1"}),
            serde_json::json!("invalid"),
            serde_json::json!([]),
        ] {
            let mut bad = captured.clone();
            bad[0]["HostConfig"]["Sysctls"] = invalid;
            let observed = ActualDockerObservation::fake(
                DockerInspect::Container([0x11; 32]),
                [0x66; 32],
                serde_json::to_vec(&bad).unwrap(),
            );
            assert!(
                project_actual_container(
                    &observed,
                    &captured_network,
                    &p.mounts,
                    &p.source_files,
                    &expected,
                    ActualState::Created
                )
                .is_err()
            );
        }
        assert!(check(&container, &network));
        for mutation in 0..4 {
            let mut bad = container.clone();
            let labels = bad[0]["Config"]["Labels"].as_object_mut().unwrap();
            match mutation {
                0 => {
                    labels.insert("unexpected".into(), serde_json::json!("extra"));
                }
                1 => {
                    labels.insert(
                        "org.label-schema.version".into(),
                        serde_json::json!("changed"),
                    );
                }
                2 => {
                    labels.remove("org.label-schema.version");
                }
                _ => {
                    labels.insert(
                        "org.apicontour.causal.owner".into(),
                        serde_json::json!("ff".repeat(32)),
                    );
                }
            }
            assert!(!check(&bad, &network));
        }
        for (field, value) in [
            ("Init", serde_json::json!(false)),
            ("CapAdd", serde_json::json!(["SYS_ADMIN"])),
            ("ReadonlyRootfs", serde_json::json!(false)),
            ("PublishAllPorts", serde_json::json!(true)),
            ("Memory", serde_json::json!(536870913)),
        ] {
            let mut bad = container.clone();
            bad[0]["HostConfig"][field] = value;
            assert!(!check(&bad, &network));
        }
        let mut bad = container.clone();
        bad[0]["Mounts"][0]["RW"] = serde_json::json!(true);
        assert!(!check(&bad, &network));
        let mut bad = container.clone();
        bad[0]["Id"] = serde_json::json!("ff".repeat(32));
        assert!(!check(&bad, &network));
        let mut created = container.clone();
        created[0]["State"] = serde_json::json!({"Status":"created","Running":false,"Pid":0,"StartedAt":"0001-01-01T00:00:00Z"});
        created[0]["NetworkSettings"]["Ports"] = serde_json::Value::Null;
        created[0]["NetworkSettings"]["Networks"]["causal-net"]["NetworkID"] =
            serde_json::json!("");
        let mut empty = network.clone();
        empty[0]["Containers"] = serde_json::json!({});
        let co = ActualDockerObservation::fake(
            DockerInspect::Container([0x11; 32]),
            [0x66; 32],
            serde_json::to_vec(&created).unwrap(),
        );
        let no = ActualDockerObservation::fake(
            DockerInspect::Network([0x44; 32]),
            [0x66; 32],
            serde_json::to_vec(&empty).unwrap(),
        );
        assert!(
            project_actual_container(
                &co,
                &no,
                &p.mounts,
                &p.source_files,
                &expected,
                ActualState::Created
            )
            .is_ok()
        );
        assert!(
            project_actual_container(
                &co,
                &no,
                &p.mounts,
                &p.source_files,
                &expected,
                ActualState::Running
            )
            .is_err()
        );
        container[0]["HostConfig"]["Privileged"] = serde_json::json!(true);
        assert!(!check(&container, &network));
        container[0]["HostConfig"]["Privileged"] = serde_json::json!(false);
        container[0]["Config"]["Cmd"] =
            serde_json::json!(["/adapter/live-integration/private-launch-proxy.js", "extra"]);
        assert!(!check(&container, &network));
        container[0]["Config"]["Cmd"] =
            serde_json::json!(["/adapter/live-integration/private-launch-proxy.js"]);
        network[0]["Containers"]["foreign"] = serde_json::json!({});
        assert!(!check(&container, &network));
    }
}
