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
        || !p.cmd.is_empty()
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
        || p.entrypoint
            != [
                "/usr/local/bin/node",
                "/adapter/live-integration/private-launch-proxy.js",
            ]
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
            let contents = !self.directory && index + 1 == self.components.len();
            if !fingerprint(old, new, contents) {
                return Err(InspectError::Drift);
            }
        }
        Ok(())
    }
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
            let p=Projection{attach_stderr:false,attach_stdin:true,attach_stdout:true,auto_remove:false,cap_add:vec![],cap_drop:vec!["ALL".into()],cgroupns_mode:"private".into(),cmd:vec![],container_id:cid.clone(),context:"local".into(),cpu_nanos:1_000_000_000,daemon_endpoint:"unix:///tmp/docker.sock".into(),device_cgroup_rules:vec![],device_requests:vec![],devices:vec![],dns:vec![],dns_options:vec![],dns_search:vec![],domainname:"".into(),entrypoint:vec!["/usr/local/bin/node".into(),"/adapter/live-integration/private-launch-proxy.js".into()],env:["FLOWS=flows.json","HOME=/data","HOSTNAME=causal-live","LANG=C.UTF-8","NODE_PATH=/usr/src/node-red/node_modules","NODE_RED_VERSION=v5.0.9","NODE_VERSION=24.22.1","PATH=/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","TZ=UTC","YARN_VERSION=1.22.22"].map(str::to_string).to_vec(),exposed_ports:vec!["1880/tcp".into()],extra_hosts:vec![],group_add:vec![],hostname:"causal-live".into(),image_id:format!("sha256:{}","22".repeat(32)),image_ref:IMAGE.into(),init:true,ipc_mode:"private".into(),labels:vec![format!("org.apicontour.causal.owner={}","33".repeat(32))],links:vec![],log_driver:"none".into(),memory:536_870_912,mounts,name:"/contour-causal-proxy".into(),network:Network{aliases:vec!["causal-node".into()],id:"44".repeat(32),internal:true,members:vec![cid],name:"causal-net".into(),owner:"55".repeat(32)},network_mode:"causal-net".into(),no_new_privileges:true,pid:123,pid_mode:"".into(),pids:128,ports:vec![],privileged:false,publish_all_ports:false,read_only_root:true,restart_policy:"no".into(),running:true,runtime:"runc".into(),security_opt:vec!["no-new-privileges:true".into()],shm_size:67_108_864,source_files:source_entries,started_at:"2026-11-07T00:00:00Z".into(),sysctls:vec![],tmpfs:vec![Tmpfs{destination:"/data".into(),options:options.clone()},Tmpfs{destination:"/tmp".into(),options}],tty:false,user:"1000:1000".into(),userns_mode:"".into(),uts_mode:"".into(),version:1,volumes_from:vec![],working_dir:"/data".into()};
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
}
