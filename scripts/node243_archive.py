#!/usr/bin/env python3
"""Bounded OCI save-archive metadata inspection; this does not verify layer contents.

The candidate manifest digest is supplied by the caller and is not authority for
its association with any engine image ID. The result describes the opened file
descriptor, not a receipt for a pathname. No files are extracted or executed.
"""
import hashlib
import json
import os
import re
import stat
import tarfile
import time

MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_MEMBERS = 256
MAX_METADATA = 1024 * 1024
MAX_BLOB = 512 * 1024 * 1024
MAX_LAYERS = 128
MAX_SECONDS = 120
HEX = re.compile(r'^[0-9a-f]{64}$')
BLOB = re.compile(r'^blobs/sha256/([0-9a-f]{64})$')
MANIFEST_TYPE = 'application/vnd.oci.image.manifest.v1+json'
CONFIG_TYPE = 'application/vnd.oci.image.config.v1+json'
LAYER_TYPES = {'application/vnd.oci.image.layer.v1.tar+gzip',
               'application/vnd.oci.image.layer.v1.tar'}
KNOWN = {
 'arm64': {'node': ('f44b069ce4b5d00cb4f7dff81821a4a6953e3790420040abf300139b1d317c6c', '9ca3f7b76099c042f1e655ca8936e0a1ccda68b3c74a8a36375428ef76476d4e'),
           'base': ('fa98d2867f299a67275ae74b7f78f01d34cc7d86f6cb63ea086beb45bac3b9a8', 'a2130198be80a76bc657795801e4e4c880f4f6aa2bd7d964766d4b953445248a')},
 'amd64': {'node': ('d8d97e479cdc64f052f81f129362168717c59783ade8dcc1abd22e1cca8dbd7c', 'b791832e17c3a8a5897bdb5087381ffbc07b77bc634d204bf603b5f63c1ffe57'),
           'base': ('051b217b585013c692006e238faa1067adc52f7ded972cbca3d944f5f9563d80', '1c532f9dd00d6f77750bb2a9fedcdbb3f178ca6e539cbefb66084494d9e568d6')},
}


def fail(message):
    raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        if key in result: fail('duplicate JSON key')
        result[key] = value
    return result


def parse(data):
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: fail('invalid JSON number'))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        fail('invalid JSON')


def digest(value):
    if not isinstance(value, str) or not value.startswith('sha256:') or not HEX.fullmatch(value[7:]):
        fail('invalid digest')
    return value[7:]


def descriptor(value, media, max_size=MAX_BLOB):
    if not isinstance(value, dict) or value.get('mediaType') not in media:
        fail('descriptor media type')
    h = digest(value.get('digest'))
    n = value.get('size')
    if type(n) is not int or n < 0 or n > max_size: fail('descriptor size')
    return h, n


class Archive:
    """Index ordinary ustar entries without allowing tar extension records."""
    def __init__(self, path):
        self.deadline = time.monotonic() + MAX_SECONDS
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        self.fd = os.open(path, flags)
        try:
            self.before = os.fstat(self.fd)
            if not stat.S_ISREG(self.before.st_mode) or not 0 < self.before.st_size <= MAX_ARCHIVE:
                fail('archive size or type')
            self.f = os.fdopen(self.fd, 'rb')
        except BaseException:
            os.close(self.fd)
            raise
        try:
            self.entries = {}
            pos = 0
            while True:
                self.check_time()
                if pos + 512 > self.before.st_size: fail('truncated tar')
                self.f.seek(pos)
                block = self.f.read(512)
                if block == bytes(512):
                    # The rest of an archive is padding, and must not hide entries.
                    self.f.seek(pos)
                    remaining = self.before.st_size - pos
                    if remaining < 1024 or remaining % 512: fail('tar terminator')
                    while remaining:
                        self.check_time()
                        b = self.f.read(min(remaining, 1024 * 1024))
                        if not b or any(b): fail('tar trailing data')
                        remaining -= len(b)
                    break
                try:
                    member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
                except (tarfile.TarError, UnicodeError, ValueError, OverflowError):
                    fail('invalid tar header')
                name = member.name.rstrip('/') if member.isdir() else member.name
                if name in self.entries or not name or len(name.encode('utf-8')) > 256:
                    fail('duplicate or invalid tar path')
                if member.isdir():
                    if name not in ('blobs', 'blobs/sha256') or member.size != 0: fail('unexpected directory')
                elif member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    if not (BLOB.fullmatch(name) or name in ('index.json', 'manifest.json', 'oci-layout')):
                        fail('unexpected archive member')
                    cap = MAX_BLOB if BLOB.fullmatch(name) else MAX_METADATA
                    if member.size < 0 or member.size > cap: fail('member size')
                else:
                    fail('unsupported tar member')
                end = pos + 512 + ((member.size + 511) // 512) * 512
                if end > self.before.st_size: fail('truncated member')
                self.entries[name] = (pos + 512, member.size)
                if len(self.entries) > MAX_MEMBERS: fail('member count')
                pos = end
        except BaseException:
            self.f.close()
            raise

    def check_time(self):
        if time.monotonic() > self.deadline: raise TimeoutError('archive deadline')

    def close(self):
        self.f.close()

    def stable(self):
        after = os.fstat(self.fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(self.before, k) != getattr(after, k) for k in fields): fail('archive changed')

    def blob(self, h, size=None, read=False):
        name = 'blobs/sha256/' + h
        if name not in self.entries: fail('missing blob')
        off, actual = self.entries[name]
        if size is not None and actual != size: fail('descriptor size mismatch')
        if not read: return
        if actual > MAX_METADATA: fail('metadata size')
        self.check_time()
        self.f.seek(off)
        data = self.f.read(actual)
        if len(data) != actual or hashlib.sha256(data).hexdigest() != h: fail('blob digest mismatch')
        return data

    def metadata(self, h, size=None):
        return parse(self.blob(h, size, True))

    def named_metadata(self, name):
        if name not in self.entries: fail('missing metadata')
        off, size = self.entries[name]
        if size > MAX_METADATA: fail('metadata size')
        self.f.seek(off)
        data = self.f.read(size)
        if len(data) != size: fail('truncated metadata')
        return parse(data)


def image(archive, manifest_hash, config_hash, arch, version):
    manifest = archive.metadata(manifest_hash)
    if not isinstance(manifest, dict) or (type(manifest.get('schemaVersion')) is not int or manifest.get('schemaVersion') != 2) or manifest.get('mediaType') != MANIFEST_TYPE:
        fail('manifest format')
    conf_h, conf_n = descriptor(manifest.get('config'), {CONFIG_TYPE}, MAX_METADATA)
    if config_hash is not None and conf_h != config_hash: fail('config identity')
    config = archive.metadata(conf_h, conf_n)
    if not isinstance(config, dict) or config.get('os') != 'linux' or config.get('architecture') != arch:
        fail('platform')
    cfg = config.get('config')
    env = cfg.get('Env') if isinstance(cfg, dict) else None
    if not isinstance(env, list) or any(not isinstance(e, str) for e in env): fail('environment')
    if [e for e in env if e.startswith('NODE_VERSION=')] != ['NODE_VERSION=' + version]: fail('node version')
    layers = manifest.get('layers')
    if not isinstance(layers, list) or not 0 < len(layers) <= MAX_LAYERS: fail('layers')
    parsed = [(x['mediaType'], *descriptor(x, LAYER_TYPES)) if isinstance(x, dict) and 'mediaType' in x
              else fail('layer descriptor') for x in layers]
    for _, h, n in parsed: archive.blob(h, n)
    root = config.get('rootfs')
    diffs = root.get('diff_ids') if isinstance(root, dict) and root.get('type') == 'layers' else None
    if not isinstance(diffs, list) or len(diffs) != len(layers): fail('diff IDs')
    for item in diffs: digest(item)
    return parsed, diffs, conf_h


def verify_metadata(path, arch, candidate_manifest_digest):
    """Inspect metadata only. Caller must separately bind candidate to its image ID."""
    if arch not in KNOWN: fail('architecture')
    candidate = digest(candidate_manifest_digest)
    archive = Archive(path)
    try:
        node_manifest, node_config = KNOWN[arch]['node']
        base_manifest, base_config = KNOWN[arch]['base']
        index = archive.named_metadata('index.json')
        descriptors = index.get('manifests') if isinstance(index, dict) and type(index.get('schemaVersion')) is int and index.get('schemaVersion') == 2 else None
        if not isinstance(descriptors, list) or len(descriptors) > MAX_MEMBERS: fail('index')
        for wanted in (node_manifest, base_manifest, candidate):
            selected = [d for d in descriptors if isinstance(d, dict) and d.get('digest') == 'sha256:' + wanted]
            if len(selected) != 1: fail('index selection')
            h, n = descriptor(selected[0], {MANIFEST_TYPE}, MAX_METADATA)
            platform = selected[0].get('platform')
            if not isinstance(platform, dict) or platform.get('os') != 'linux' or platform.get('architecture') != arch: fail('index platform')
            archive.blob(h, n)
        image(archive, node_manifest, node_config, arch, '24.22.3')
        base_layers, base_diffs, _ = image(archive, base_manifest, base_config, arch, '24.22.1')
        layers, diffs, candidate_config = image(archive, candidate, None, arch, '24.22.3')
        if len(layers) != len(base_layers) + 1 or layers[:-1] != base_layers or diffs[:-1] != base_diffs:
            fail('base layer prefix')
        archive.stable()
        return {'scope': 'oci-metadata-only', 'architecture': arch,
                'candidate_manifest': 'sha256:' + candidate,
                'candidate_config': 'sha256:' + candidate_config,
                'remaining_unverified': ['layer_blob_digests_and_diff_ids', 'added_layer_contents',
                    'donor_overlay_and_binary', 'engine_rootindex_association', 'publisher_provenance',
                    'actual_TLS', 'profile504']}
    finally:
        archive.close()
