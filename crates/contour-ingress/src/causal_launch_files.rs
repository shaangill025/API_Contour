//! Bounded, component-safe local file snapshots. File inspection alone does not
//! prove a container uses these bytes or authorize any producer launch.
use std::{
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
    path::{Component, Path},
};
const MAX: u64 = 65536;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    Unsafe,
    Io,
    Changed,
}
/// Owned private snapshot. Its Debug output never includes its bytes. The
/// best-effort clear on drop is not a key-memory erasure guarantee.
pub struct FileSnapshot {
    bytes: Vec<u8>,
}
impl FileSnapshot {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::fmt::Debug for FileSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileSnapshot")
    }
}
impl Drop for FileSnapshot {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}
fn openat(parent: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    // SAFETY: the parent fd and NUL-terminated name remain valid during openat;
    // on success the returned descriptor is uniquely owned by File.
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
fn same(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.nlink() == b.nlink()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
/// Read one absolute non-dot path without following any path component. A
/// private file must be owned by the effective UID and have mode exactly 0600.
/// The calling launcher must separately prove the selected mount and its use.
pub fn snapshot_file(path: &Path, private: bool) -> Result<FileSnapshot, SnapshotError> {
    let raw_path = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || raw_path.ends_with(b"/")
        || raw_path
            .split(|b| *b == b'/')
            .any(|part| part == b"." || part == b"..")
    {
        return Err(SnapshotError::Unsafe);
    }
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(SnapshotError::Unsafe);
    }
    let names: Vec<_> = parts
        .map(|c| match c {
            Component::Normal(x) => Ok(x),
            _ => Err(SnapshotError::Unsafe),
        })
        .collect::<Result<_, _>>()?;
    if names.is_empty() {
        return Err(SnapshotError::Unsafe);
    }
    // SAFETY: the fixed root C string is valid; File owns the returned fd.
    let raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(SnapshotError::Io);
    }
    let mut dir = unsafe { File::from_raw_fd(raw) };
    for name in &names[..names.len() - 1] {
        let name = CString::new(name.as_bytes()).map_err(|_| SnapshotError::Unsafe)?;
        dir = openat(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|_| SnapshotError::Unsafe)?;
    }
    let name = CString::new(names.last().ok_or(SnapshotError::Unsafe)?.as_bytes())
        .map_err(|_| SnapshotError::Unsafe)?;
    let file = openat(&dir, &name, libc::O_RDONLY | libc::O_NONBLOCK)
        .map_err(|_| SnapshotError::Unsafe)?;
    let before = file.metadata().map_err(|_| SnapshotError::Io)?;
    // SAFETY: geteuid has no arguments or retained pointers.
    if !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX
        || (private
            && (before.uid() != unsafe { libc::geteuid() } || before.mode() & 0o7777 != 0o600))
    {
        return Err(SnapshotError::Unsafe);
    }
    let mut snapshot = FileSnapshot {
        bytes: vec![0u8; before.len() as usize + 1],
    };
    let mut n = 0;
    while n < snapshot.bytes.len() {
        let read = file
            .read_at(&mut snapshot.bytes[n..], n as u64)
            .map_err(|_| SnapshotError::Io)?;
        if read == 0 {
            break;
        }
        n += read;
    }
    let after = file.metadata().map_err(|_| SnapshotError::Io)?;
    let reopened = openat(&dir, &name, libc::O_RDONLY | libc::O_NONBLOCK)
        .map_err(|_| SnapshotError::Changed)?;
    let current = reopened.metadata().map_err(|_| SnapshotError::Io)?;
    if n != before.len() as usize || !same(&before, &after) || !same(&after, &current) {
        return Err(SnapshotError::Changed);
    }
    snapshot.bytes.truncate(n);
    Ok(snapshot)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn snapshot_rejects_redirects_links_modes_and_unbounded_input() {
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "contour-snapshot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("key");
        std::fs::write(&file, b"synthetic").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(snapshot_file(&file, true).unwrap().as_bytes(), b"synthetic");
        assert!(snapshot_file(Path::new("relative"), true).is_err());
        assert!(snapshot_file(&dir.join("../escape"), true).is_err());
        assert!(snapshot_file(&dir.join("./key"), true).is_err());
        let child = dir.join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("key"), b"synthetic").unwrap();
        std::fs::set_permissions(child.join("key"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let alias = dir.join("alias");
        symlink(&child, &alias).unwrap();
        assert!(snapshot_file(&alias.join("key"), true).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_file(child.join("key")).unwrap();
        std::fs::remove_dir(child).unwrap();
        let link = dir.join("link");
        symlink(&file, &link).unwrap();
        assert!(snapshot_file(&link, true).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::hard_link(&file, &link).unwrap();
        assert!(snapshot_file(&file, true).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(snapshot_file(&file, true).is_err());
        std::fs::write(&file, vec![b'x'; MAX as usize + 1]).unwrap();
        assert!(snapshot_file(&file, false).is_err());
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
    use std::time::UNIX_EPOCH;
}
