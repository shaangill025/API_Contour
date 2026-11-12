#!/usr/bin/env python3
"""Bounded OCI save-archive metadata and optional streaming layer inspection.

The candidate manifest digest is supplied by the caller and is not authority for
its association with any engine image ID. The result describes the opened file
descriptor, not a receipt for a pathname. No files are extracted or executed.
"""
import gzip
import hashlib
import json
import os
import re
import stat
import tarfile
import time
import zlib

MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_MEMBERS = 256
MAX_METADATA = 1024 * 1024
MAX_BLOB = 512 * 1024 * 1024
MAX_LAYERS = 128
MAX_SECONDS = 120
MAX_CONTENT_SECONDS = 600
MAX_LAYER_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 6 * 1024 * 1024 * 1024
MAX_TOTAL_COMPRESSED = 2 * 1024 * 1024 * 1024
MAX_LAYER_MEMBERS = 250000
MAX_TOTAL_MEMBERS = 500000
MAX_LAYER_PATH_BYTES = 32 * 1024 * 1024
MAX_TOTAL_PATH_BYTES = 64 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
CHUNK = 1024 * 1024
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
    def __init__(self, path, seconds=MAX_SECONDS):
        self.deadline = time.monotonic() + seconds
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


def selected_images(archive, arch, candidate):
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
    node_layers, node_diffs, _ = image(archive, node_manifest, node_config, arch, '24.22.3')
    base_layers, base_diffs, _ = image(archive, base_manifest, base_config, arch, '24.22.1')
    layers, diffs, candidate_config = image(archive, candidate, None, arch, '24.22.3')
    if len(layers) != len(base_layers) + 1 or layers[:-1] != base_layers or diffs[:-1] != base_diffs:
        fail('base layer prefix')
    return node_layers, node_diffs, base_layers, base_diffs, layers[-1], diffs[-1], candidate_config


def verify_metadata(path, arch, candidate_manifest_digest):
    """Inspect metadata only. Caller must separately bind candidate to its image ID."""
    if arch not in KNOWN: fail('architecture')
    candidate = digest(candidate_manifest_digest)
    archive = Archive(path)
    try:
        *_, candidate_config = selected_images(archive, arch, candidate)
        archive.stable()
        return {'scope': 'oci-metadata-only', 'architecture': arch,
                'candidate_manifest': 'sha256:' + candidate,
                'candidate_config': 'sha256:' + candidate_config,
                'remaining_unverified': ['layer_blob_digests_and_diff_ids', 'added_layer_contents',
                    'donor_overlay_and_binary', 'engine_rootindex_association', 'publisher_provenance',
                    'actual_TLS', 'profile504']}
    finally:
        archive.close()


class Budget:
    def __init__(self):
        self.compressed = self.uncompressed = self.members = self.path_bytes = 0


class LayerInput:
    """Read only the descriptor's archive extent while hashing compressed bytes."""
    def __init__(self, archive, layer, budget):
        self.archive, self.budget = archive, budget
        _, self.expected, self.remaining = layer
        self.initial = self.remaining
        self.hash = hashlib.sha256()
        off, size = archive.entries['blobs/sha256/' + self.expected]
        if size != self.remaining: fail('layer size')
        archive.f.seek(off)

    def read(self, n=-1):
        self.archive.check_time()
        if n is None or n < 0: n = self.remaining
        n = min(n, self.remaining, CHUNK)
        if not n: return b''
        b = self.archive.f.read(n)
        if len(b) != n: fail('truncated layer blob')
        self.remaining -= len(b)
        self.budget.compressed += len(b)
        if self.budget.compressed > MAX_TOTAL_COMPRESSED: fail('compressed byte budget')
        self.hash.update(b)
        return b


class LayerOutput:
    def __init__(self, archive, layer, expected_diff, budget):
        self.archive, self.budget = archive, budget
        self.raw = LayerInput(archive, layer, budget)
        media = layer[0]
        if media == 'application/vnd.oci.image.layer.v1.tar+gzip':
            self.stream = gzip.GzipFile(fileobj=self.raw, mode='rb')
        elif media == 'application/vnd.oci.image.layer.v1.tar':
            self.stream = self.raw
        else: fail('layer compression')
        self.expected_diff = digest(expected_diff)
        self.hash = hashlib.sha256()
        self.total = 0

    def read(self, n):
        self.archive.check_time()
        if n < 0 or n > CHUNK: fail('read bound')
        try:
            b = self.stream.read(n)
        except (EOFError, OSError, zlib.error) as exc:
            raise ValueError('invalid compressed layer') from exc
        self.total += len(b)
        self.budget.uncompressed += len(b)
        if self.total > MAX_LAYER_UNCOMPRESSED or self.budget.uncompressed > MAX_TOTAL_UNCOMPRESSED:
            fail('uncompressed byte budget')
        self.hash.update(b)
        return b

    def exact(self, n):
        b = self.read(n)
        if len(b) != n: fail('truncated layer tar')
        return b

    def finish(self):
        while self.read(CHUNK): pass
        if self.raw.remaining or self.raw.hash.hexdigest() != self.raw.expected: fail('compressed layer digest')
        if self.hash.hexdigest() != self.expected_diff: fail('uncompressed layer digest')


def layer_path(name):
    if not isinstance(name, str) or len(name.encode('utf-8')) > 4096 or '\\' in name or name.startswith('/'):
        fail('layer path')
    while name.startswith('./'): name = name[2:]
    name = name.rstrip('/')
    if name in ('', '.'): return ''
    parts = name.split('/')
    if any(p in ('', '.', '..') for p in parts): fail('layer path')
    return name


NODE_PATH = 'usr/local/bin/node'
PARENTS = {'usr', 'usr/local', 'usr/local/bin'}


def inspect_layer(archive, layer, expected_diff, budget, kind, donor):
    stream = LayerOutput(archive, layer, expected_diff, budget)
    if kind == 'base':
        stream.finish()
        return donor
    names = set()
    binary = None
    count = 0
    path_bytes = 0
    while True:
        block = stream.exact(512)
        if block == bytes(512):
            if stream.exact(512) != bytes(512): fail('layer tar terminator')
            while True:
                rest = stream.read(CHUNK)
                if not rest: break
                if any(rest): fail('layer tar trailing data')
            if stream.total % 512: fail('layer tar alignment')
            break
        try:
            member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
        except (tarfile.TarError, UnicodeError, ValueError, OverflowError):
            fail('invalid layer header')
        count += 1
        budget.members += 1
        if count > MAX_LAYER_MEMBERS or budget.members > MAX_TOTAL_MEMBERS: fail('layer member budget')
        if not member.isdir() and member.name.endswith('/'):
            fail('non-directory trailing slash')
        name = layer_path(member.name)
        path_bytes += len(name.encode('utf-8'))
        budget.path_bytes += len(name.encode('utf-8'))
        if path_bytes > MAX_LAYER_PATH_BYTES or budget.path_bytes > MAX_TOTAL_PATH_BYTES: fail('layer path budget')
        if name.startswith(NODE_PATH + '/'): fail('node descendant ambiguity')
        if name in names: fail('duplicate layer path')
        names.add(name)
        if any(part.startswith('.wh.') for part in name.split('/')): fail('whiteout')
        regular = member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
        directory = member.type == tarfile.DIRTYPE
        symlink = member.type == tarfile.SYMTYPE
        if not (regular or directory or (kind == 'donor' and symlink)):
            fail('unsupported layer member')
        if member.size < 0 or member.size > MAX_FILE or (not regular and member.size != 0): fail('layer member size')
        if any(type(x) is not int or x < 0 or x > 0xffffffff for x in (member.uid, member.gid, member.mode)):
            fail('layer ownership or mode')
        if member.mode > 0o7777: fail('layer mode')
        if kind == 'added':
            if not ((name in PARENTS and directory) or (name == NODE_PATH and regular)):
                fail('unexpected added layer member')
            if name in PARENTS and (member.uid, member.gid, member.mode) != (0, 0, 0o755):
                fail('added parent attributes')
        else:
            if name in PARENTS and not directory: fail('donor ancestor ambiguity')
            if name == NODE_PATH and not regular: fail('donor node ambiguity')
            if not name and not directory: fail('donor root ambiguity')
        filehash = hashlib.sha256() if name == NODE_PATH else None
        left = member.size
        while left:
            b = stream.exact(min(left, CHUNK))
            if filehash is not None: filehash.update(b)
            left -= len(b)
        pad = (-member.size) % 512
        if pad: stream.exact(pad)
        if filehash is not None:
            binary = {'sha256': filehash.hexdigest(), 'size': member.size, 'mode': member.mode,
                      'uid': member.uid, 'gid': member.gid}
            if not member.size: fail('empty node binary')
    stream.finish()
    if kind == 'added':
        if names != PARENTS | {NODE_PATH} or binary is None: fail('added layer members')
        return binary
    return binary if binary is not None else donor


def verify_content(path, arch, candidate_manifest_digest, probe):
    """Verify local bytes; caller supplies untrusted candidate and execution observation.

    Base layers are hashed, not parsed as filesystems; their framing and paths
    are not inspected. The result describes the opened descriptor, not a path.
    """
    if arch not in KNOWN: fail('architecture')
    candidate = digest(candidate_manifest_digest)
    if not isinstance(probe, dict) or not HEX.fullmatch(probe.get('sha256', '') if isinstance(probe.get('sha256'), str) else ''):
        fail('probe sha256')
    if any(type(probe.get(k)) is not int or not 0 <= probe[k] <= 0xffffffff for k in ('mode', 'uid', 'gid')):
        fail('probe attributes')
    if type(probe.get('size')) is not int or not 0 < probe['size'] <= MAX_FILE:
        fail('probe size')
    archive = Archive(path, MAX_CONTENT_SECONDS)
    try:
        node_layers, node_diffs, base_layers, base_diffs, added, added_diff, config = selected_images(archive, arch, candidate)
        budget = Budget()
        donor = None
        for layer, diff in zip(node_layers, node_diffs):
            donor = inspect_layer(archive, layer, diff, budget, 'donor', donor)
        if donor is None: fail('donor node missing')
        for layer, diff in zip(base_layers, base_diffs):
            inspect_layer(archive, layer, diff, budget, 'base', None)
        derived = inspect_layer(archive, added, added_diff, budget, 'added', None)
        if donor != derived or any(derived[k] != probe[k] for k in ('sha256', 'size', 'mode', 'uid', 'gid')):
            fail('node binary mismatch')
        archive.stable()
        return {'scope': 'oci-local-layer-content', 'architecture': arch,
                'candidate_manifest': 'sha256:' + candidate, 'candidate_config': 'sha256:' + config,
                'node': derived, 'remaining_unverified': ['engine_rootindex_association',
                    'caller_probe_association', 'base_filesystem_semantics', 'publisher_provenance', 'actual_TLS', 'profile504']}
    finally:
        archive.close()
