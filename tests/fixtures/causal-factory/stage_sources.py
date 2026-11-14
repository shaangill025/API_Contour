"""Prepare the closed candidate source mounts for an owned factory fixture.

This does not start Docker, connect to PostgreSQL, or qualify the factory.
The caller owns the private destination and must keep source paths and ancestors
under operator control through use.
"""
import hashlib
import json
import os
from pathlib import Path

MANIFEST = "a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e"


def checked_file(path):
    path = Path(path)
    if not path.is_absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("source path must be absolute and contain no symlinks")
    if not path.is_file():
        raise ValueError("source file unavailable")
    return path


def copy_checked(source, destination, expected):
    data = checked_file(source).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("source digest mismatch")
    with destination.open("xb") as output:
        output.write(data)
    # The private parent remains 0700; mounted public code must be readable by
    # the fixed container UID 1000, which may differ from the host operator.
    destination.chmod(0o644)
    if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
        raise ValueError("staged digest mismatch")


def stage(root, destination):
    root, destination = Path(root), Path(destination)
    if not destination.is_absolute() or any(p.is_symlink() for p in (destination, *destination.parents)):
        raise ValueError("destination must be absolute and contain no symlinks")
    if not destination.is_dir() or any(destination.iterdir()):
        raise ValueError("destination must be a fresh empty directory")
    if destination.stat().st_mode & 0o777 != 0o700 or destination.stat().st_uid != os.geteuid():
        raise ValueError("destination must be owner-only")
    live = root / "collectors/nodered/live-integration"
    error = root / "collectors/nodered/error-integration"
    manifest_path = checked_file(live / "manifest.json")
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST:
        raise ValueError("manifest digest mismatch")
    manifest = json.loads(raw)
    if len(manifest["files"]) != 19:
        raise ValueError("manifest inventory mismatch")
    error_out, live_out = destination / "error", destination / "live"
    error_out.mkdir(mode=0o700)
    live_out.mkdir(mode=0o700)
    error_out.chmod(0o755)
    live_out.chmod(0o755)
    for target, digest in manifest["files"].items():
        path = Path(target)
        if path == Path("/adapter/causal-codec.js"):
            source, out = root / "collectors/nodered/causal-codec.js", destination / "causal-codec.js"
        elif path.parent == Path("/adapter/error-integration"):
            source, out = error / path.name, error_out / path.name
        elif path.parent == Path("/adapter/live-integration"):
            source, out = live / path.name, live_out / path.name
        else:
            raise ValueError("unexpected manifest path")
        copy_checked(source, out, digest)
    copy_checked(manifest_path, live_out / "manifest.json", MANIFEST)
    for arch, name in (("arm64", "wire-v2-image-manifest.json"), ("x64", "wire-v2-image-manifest-x64.json")):
        copy_checked(error / name, live_out / ("tree-" + arch + ".json"), manifest["arch_trees"][arch]["sha256"])
    copy_checked(live / "flows.json", destination / "flows.json", manifest["flow_sha256"])
    if sum(1 for p in destination.rglob("*") if p.is_file()) != 23:
        raise ValueError("staged inventory mismatch")
    return [destination / "causal-codec.js", error_out, live_out, destination / "flows.json"]
