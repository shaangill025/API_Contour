#!/usr/bin/env python3
"""Fixed 504 archive check; standalone output is data, never daemon evidence.

The internal caller must bind its own same-request Docker observations, protect
all paths and executables, bound the process and save, and revalidate them. This
script cannot establish an image/daemon association or authorize a launch.
"""
import datetime
import hashlib
import json
import os
import re
import stat
import sys

_SOURCE_HASH = 'f0502fc2a5b3c0804818fc28a3e7e6909f6f1830144db0b6ecee5be8ffb743ca'
_FACTS = {
    'arm64': {'sha256': 'f6a453bcbfd0d866cabbc7b02fa5b173931ca08ddbfdca866fe71253b8b583d5', 'size': 128247648, 'mode': 493, 'uid': 0, 'gid': 0},
    'amd64': {'sha256': '7e027679034844bb06f53bead732673553cf5bb0de424bbbd257b35c989d34b0', 'size': 132502712, 'mode': 493, 'uid': 0, 'gid': 0},
}
_OWNER = 'org.apicontour.fixture-owner'
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_CREATED = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z')


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit:
            raise ValueError('input')
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != before.st_size or _identity(os.fstat(fd)) != _identity(before):
            raise ValueError('input changed')
        return bytes(data), _identity(before)
    finally:
        os.close(fd)


def _canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


def _compare_config(base, candidate, observed, owner):
    if not isinstance(base, dict) or not isinstance(candidate, dict) or candidate != observed:
        raise ValueError('observed config mismatch')
    expected = dict(base)
    env = base.get('Env')
    if not isinstance(env, list) or any(not isinstance(e, str) for e in env):
        raise ValueError('base environment')
    if [x for x in env if x.startswith('NODE_VERSION=')] != ['NODE_VERSION=24.22.1']:
        raise ValueError('base node version')
    expected['Env'] = ['NODE_VERSION=24.22.3' if x.startswith('NODE_VERSION=') else x for x in env]
    labels = base.get('Labels')
    if labels is None:
        labels = {}
    if not isinstance(labels, dict) or _OWNER in labels or not _HEX.fullmatch(owner):
        raise ValueError('base labels')
    expected['Labels'] = {**labels, _OWNER: owner}
    if candidate != expected:
        raise ValueError('candidate config mismatch')


def _compare_rootfs(candidate, observed):
    rootfs = candidate.get('rootfs')
    if (not isinstance(rootfs, dict) or set(rootfs) != {'type', 'diff_ids'}
            or not isinstance(observed, dict) or set(observed) != {'Type', 'Layers'}):
        raise ValueError('rootfs')
    if (rootfs.get('type') != 'layers' or not isinstance(rootfs.get('diff_ids'), list)
            or rootfs.get('type') != observed.get('Type') or rootfs.get('diff_ids') != observed.get('Layers')):
        raise ValueError('observed rootfs mismatch')


def _check_history(base, candidate):
    if not isinstance(base.get('history'), list) or not isinstance(candidate.get('history'), list):
        raise ValueError('history')
    if candidate['history'][:len(base['history'])] != base['history']:
        raise ValueError('history prefix')
    added = candidate['history'][len(base['history']):]
    if len(added) != 2 or any(not isinstance(x, dict) for x in added):
        raise ValueError('history append')
    created = added[0].get('created')
    if not isinstance(created, str) or not _CREATED.fullmatch(created):
        raise ValueError('history timestamp')
    # Validate the calendar and clock without truncating the accepted nanosecond
    # representation when comparing the two exact metadata records.
    datetime.datetime.strptime(created[:19], '%Y-%m-%dT%H:%M:%S')
    expected = [
        {'created': created, 'comment': 'buildkit.dockerfile.v0',
         'created_by': 'COPY /usr/local/bin/node /usr/local/bin/node # buildkit'},
        {'created': created, 'comment': 'buildkit.dockerfile.v0',
         'created_by': 'ENV NODE_VERSION=24.22.3', 'empty_layer': True},
    ]
    if added != expected:
        raise ValueError('history metadata')
    for config in (base, candidate):
        rootfs = config.get('rootfs')
        diff_ids = rootfs.get('diff_ids') if isinstance(rootfs, dict) else None
        if not isinstance(diff_ids, list) or any(not isinstance(x, dict) for x in config['history']):
            raise ValueError('history format')
        if sum(1 for x in config['history'] if x.get('empty_layer') is not True) != len(diff_ids):
            raise ValueError('history layer count')
    return _canonical_hash(base['history']), _canonical_hash(candidate['history'])


def _compare_image_metadata(base, candidate, arch):
    keys = {'architecture', 'config', 'created', 'history', 'os', 'rootfs'}
    if (not isinstance(base, dict) or not isinstance(candidate, dict)
            or set(base) != keys or set(candidate) != keys
            or arch not in _FACTS or base['architecture'] != arch
            or candidate['architecture'] != arch
            or base['os'] != 'linux' or candidate['os'] != 'linux'):
        raise ValueError('image config schema')
    histories = _check_history(base, candidate)
    if candidate['created'] != candidate['history'][-1]['created']:
        raise ValueError('image config timestamp')
    return histories


def verify(archive_path, arch, selected, inspect_path, owner):
    if arch not in _FACTS or not selected.startswith('sha256:') or not _HEX.fullmatch(selected[7:]):
        raise ValueError('selection')
    source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'node243_archive.py')
    source, source_id = _read(source_path, 65536)
    if hashlib.sha256(source).hexdigest() != _SOURCE_HASH:
        raise ValueError('verifier source')
    namespace = {'__name__': '_receiver504_pinned_archive'}
    exec(compile(source, '<pinned-node243-archive>', 'exec'), namespace)
    inspect_bytes, inspect_id = _read(inspect_path, 262144)
    inspected = namespace['parse'](inspect_bytes)
    if not isinstance(inspected, dict):
        raise ValueError('inspect')
    before = os.stat(archive_path, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('archive')
    result = namespace['verify_content'](archive_path, arch, selected, _FACTS[arch])
    archive = namespace['Archive'](archive_path)
    try:
        manifest = archive.metadata(selected[7:])
        candidate_hash, candidate_size = namespace['descriptor'](manifest.get('config'), {namespace['CONFIG_TYPE']}, namespace['MAX_METADATA'])
        candidate = archive.metadata(candidate_hash, candidate_size)
        base_hash = namespace['KNOWN'][arch]['base'][1]
        base = archive.metadata(base_hash)
        if result['candidate_config'] != 'sha256:' + candidate_hash:
            raise ValueError('candidate config digest')
        _compare_config(base.get('config'), candidate.get('config'), inspected.get('Config'), owner)
        _compare_rootfs(candidate, inspected.get('RootFS'))
        base_history, history = _compare_image_metadata(base, candidate, arch)
        archive.stable()
    finally:
        archive.close()
    after = os.stat(archive_path, follow_symlinks=False)
    if _identity(before) != _identity(after):
        raise ValueError('archive changed')
    source_after, source_id_after = _read(source_path, 65536)
    inspect_after, inspect_id_after = _read(inspect_path, 262144)
    if source_after != source or source_id_after != source_id or inspect_after != inspect_bytes or inspect_id_after != inspect_id:
        raise ValueError('source changed')
    return {'version': 1, 'architecture': arch, 'selected_manifest': selected,
            'candidate_config': result['candidate_config'], 'candidate_history_sha256': history,
            'base_history_sha256': base_history}


def main():
    if len(sys.argv) != 6:
        return 1
    try:
        value = verify(*sys.argv[1:])
        print(json.dumps(value, sort_keys=True, separators=(',', ':')))
        return 0
    except Exception:
        return 1


if __name__ == '__main__':
    sys.exit(main())
