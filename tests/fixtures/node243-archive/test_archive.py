import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('node243_archive', ROOT / 'scripts/node243_archive.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def data(obj):
    return json.dumps(obj, separators=(',', ':')).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def desc(b, kind):
    return {'mediaType': kind, 'digest': 'sha256:' + sha(b), 'size': len(b)}


def fixture(mutator=None, manifest_mutator=None):
    blobs = {}
    layer_type = 'application/vnd.oci.image.layer.v1.tar+gzip'
    layers = [b'base compressed layer', b'added compressed layer']
    for b in layers: blobs[sha(b)] = b
    layer_desc = [desc(b, layer_type) for b in layers]
    diff = ['sha256:' + '1' * 64, 'sha256:' + '2' * 64]
    imgs = {}
    for name, version, count in [('node', '24.22.3', 1), ('base', '24.22.1', 1), ('candidate', '24.22.3', 2)]:
        config = {'architecture': 'arm64', 'os': 'linux', 'config': {'Env': ['NODE_VERSION=' + version]},
                  'rootfs': {'type': 'layers', 'diff_ids': diff[:count]}}
        if mutator: mutator(name, config, layer_desc)
        c = data(config); blobs[sha(c)] = c
        manifest_obj = {'schemaVersion': 2, 'mediaType': m.MANIFEST_TYPE,
                        'config': desc(c, m.CONFIG_TYPE), 'layers': layer_desc[:count]}
        if manifest_mutator: manifest_mutator(name, manifest_obj)
        manifest = data(manifest_obj)
        blobs[sha(manifest)] = manifest
        imgs[name] = (manifest, c)
    index = {'schemaVersion': 2, 'manifests': [dict(desc(imgs[name][0], m.MANIFEST_TYPE),
              platform={'os': 'linux', 'architecture': 'arm64'}) for name in imgs]}
    # Node and base otherwise have the same manifest in a tiny synthetic fixture.
    if sha(imgs['node'][0]) == sha(imgs['base'][0]): raise AssertionError()
    return blobs, index, imgs


def archive(path, blobs, index, extra=(), index_raw=None):
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as t:
        entries = [('index.json', index_raw if index_raw is not None else data(index))]
        entries += [('blobs/sha256/' + h, b) for h, b in blobs.items()]
        entries += list(extra)
        for name, b in entries:
            info = tarfile.TarInfo(name); info.size = len(b)
            t.addfile(info, io.BytesIO(b))


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'image.tar'

    def run_fixture(self, mutate=None, alter=None, extra=(), index_raw=None, manifest_mutator=None):
        blobs, index, imgs = fixture(mutate, manifest_mutator)
        known = {'arm64': {k: (sha(imgs[k][0]), sha(imgs[k][1])) for k in ('node', 'base')}}
        if alter: alter(blobs, index, imgs)
        archive(self.path, blobs, index, extra, index_raw)
        with patch.object(m, 'KNOWN', known):
            return m.verify_metadata(self.path, 'arm64', 'sha256:' + sha(imgs['candidate'][0]))

    def test_accepts_metadata_and_reports_scope(self):
        result = self.run_fixture()
        self.assertEqual(result['scope'], 'oci-metadata-only')
        self.assertIn('added_layer_contents', result['remaining_unverified'])
        self.assertIn('engine_rootindex_association', result['remaining_unverified'])

    def test_wrong_platform_and_environment(self):
        for key, val in [('architecture', 'amd64'), ('os', 'windows')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.run_fixture(lambda name, c, _: c.update({key: val}) if name == 'node' else None)
        with self.assertRaises(ValueError):
            self.run_fixture(lambda name, c, _: c['config'].update(Env=['NODE_VERSION=24.22.2']) if name == 'base' else None)

    def test_schema_version_requires_integer_two(self):
        for value in (2.0, True, None):
            with self.subTest(location='index', value=value), self.assertRaises(ValueError):
                def change_index(blobs, index, imgs):
                    if value is None: del index['schemaVersion']
                    else: index['schemaVersion'] = value
                self.run_fixture(alter=change_index)
            with self.subTest(location='manifest', value=value), self.assertRaises(ValueError):
                def change_manifest(name, manifest):
                    if name == 'node':
                        if value is None: del manifest['schemaVersion']
                        else: manifest['schemaVersion'] = value
                self.run_fixture(manifest_mutator=change_manifest)

    def test_nonregular_archive_paths(self):
        fifo = Path(self.tmp.name) / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError): m.Archive(fifo)
        with self.assertRaises(ValueError): m.Archive(self.tmp.name)
        target = Path(self.tmp.name) / 'target'
        target.write_bytes(b'archive')
        link = Path(self.tmp.name) / 'link'
        link.symlink_to(target)
        with self.assertRaises(OSError): m.Archive(link)

    def test_index_platform_and_missing_layer(self):
        def platform(blobs, index, imgs): index['manifests'][0]['platform']['architecture'] = 'amd64'
        with self.assertRaises(ValueError): self.run_fixture(alter=platform)
        def missing(blobs, index, imgs): del blobs[sha(b'added compressed layer')]
        with self.assertRaises(ValueError): self.run_fixture(alter=missing)

    def test_prefix_drift(self):
        with self.assertRaises(ValueError):
            self.run_fixture(lambda name, c, _: c['rootfs'].update(diff_ids=['sha256:' + '3'*64, 'sha256:' + '2'*64]) if name == 'candidate' else None)

    def test_digest_and_size_drift(self):
        def drift(blobs, index, imgs): blobs[sha(imgs['node'][1])] += b' '
        with self.assertRaises(ValueError): self.run_fixture(alter=drift)
        def wrong_size(blobs, index, imgs): index['manifests'][0]['size'] += 1
        with self.assertRaises(ValueError): self.run_fixture(alter=wrong_size)

    def test_duplicate_json_and_outer_paths(self):
        with self.assertRaises(ValueError): self.run_fixture(index_raw=b'{"schemaVersion":2,"schemaVersion":2,"manifests":[]}')
        with self.assertRaises(ValueError): self.run_fixture(extra=[('index.json', b'{}')])

    def test_oversize_truncation_and_link(self):
        self.run_fixture()
        raw = self.path.read_bytes()
        self.path.write_bytes(raw[:700])
        with self.assertRaises(ValueError): m.Archive(self.path)
        with tarfile.open(self.path, 'w') as t:
            x = tarfile.TarInfo('index.json'); x.type = tarfile.SYMTYPE; x.linkname = 'elsewhere'; t.addfile(x)
        with self.assertRaises(ValueError): m.Archive(self.path)
        with patch.object(m, 'MAX_METADATA', 10):
            with self.assertRaises(ValueError): self.run_fixture()

    def test_rejects_wrong_known_manifest_and_config(self):
        blobs, index, imgs = fixture()
        archive(self.path, blobs, index)
        known = {'arm64': {'node': ('0'*64, sha(imgs['node'][1])), 'base': (sha(imgs['base'][0]), sha(imgs['base'][1]))}}
        with patch.object(m, 'KNOWN', known), self.assertRaises(ValueError):
            m.verify_metadata(self.path, 'arm64', 'sha256:' + sha(imgs['candidate'][0]))
        known['arm64']['node'] = (sha(imgs['node'][0]), '0'*64)
        with patch.object(m, 'KNOWN', known), self.assertRaises(ValueError):
            m.verify_metadata(self.path, 'arm64', 'sha256:' + sha(imgs['candidate'][0]))




def make_layer(entries):
    import gzip
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as t:
        for entry in entries:
            name, kind, contents = entry[:3]
            item = tarfile.TarInfo(name)
            item.mode, item.uid, item.gid = entry[3] if len(entry) == 4 else (0o755, 0, 0)
            item.type = kind
            item.size = len(contents) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): item.linkname = 'elsewhere'
            t.addfile(item, io.BytesIO(contents) if item.size else None)
    uncompressed = raw.getvalue()
    return gzip.compress(uncompressed, mtime=0), 'sha256:' + sha(uncompressed)


def content_fixture(donor_entries=None, added_entries=None, base_diff=None):
    node = b'tiny node binary'
    dirs = [(p, tarfile.DIRTYPE, b'') for p in ('usr', 'usr/local', 'usr/local/bin')]
    normal = dirs + [('usr/local/bin/node', tarfile.REGTYPE, node)]
    donor_entries = normal if donor_entries is None else donor_entries
    added_entries = normal if added_entries is None else added_entries
    donor_sets = donor_entries if donor_entries and isinstance(donor_entries[0], list) else [donor_entries]
    donor = [make_layer(entries) for entries in donor_sets]
    base = make_layer([('base', tarfile.REGTYPE, b'base')])
    added = make_layer(added_entries)
    blobs, imgs = {}, {}
    layer_type = 'application/vnd.oci.image.layer.v1.tar+gzip'
    for name, version, selected in [('node', '24.22.3', donor), ('base', '24.22.1', [base]),
                                    ('candidate', '24.22.3', [base, added])]:
        for layer, _ in selected: blobs[sha(layer)] = layer
        diffs = [d for _, d in selected]
        if base_diff is not None and name in ('base', 'candidate'): diffs[0] = base_diff
        c = data({'architecture': 'arm64', 'os': 'linux', 'config': {'Env': ['NODE_VERSION=' + version]},
                  'rootfs': {'type': 'layers', 'diff_ids': diffs}})
        blobs[sha(c)] = c
        manifest = data({'schemaVersion': 2, 'mediaType': m.MANIFEST_TYPE,
                         'config': desc(c, m.CONFIG_TYPE), 'layers': [desc(x, layer_type) for x, _ in selected]})
        blobs[sha(manifest)] = manifest
        imgs[name] = (manifest, c)
    index = {'schemaVersion': 2, 'manifests': [dict(desc(imgs[name][0], m.MANIFEST_TYPE),
             platform={'os': 'linux', 'architecture': 'arm64'}) for name in imgs]}
    probe = {'sha256': sha(node), 'size': len(node), 'mode': 0o755, 'uid': 0, 'gid': 0}
    return blobs, index, imgs, probe


class ContentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'image.tar'

    def run_content(self, donor=None, added=None, probe_change=None, blob_change=None, base_diff=None):
        blobs, index, imgs, probe = content_fixture(donor, added, base_diff)
        if probe_change: probe.update(probe_change)
        if blob_change: blob_change(blobs, imgs)
        archive(self.path, blobs, index)
        known = {'arm64': {k: (sha(imgs[k][0]), sha(imgs[k][1])) for k in ('node', 'base')}}
        with patch.object(m, 'KNOWN', known):
            return m.verify_content(self.path, 'arm64', 'sha256:' + sha(imgs['candidate'][0]), probe)

    def test_accepts_matching_layers_and_probe(self):
        result = self.run_content()
        self.assertEqual(result['scope'], 'oci-local-layer-content')
        self.assertEqual(result['node']['sha256'], sha(b'tiny node binary'))
        self.assertIn('caller_probe_association', result['remaining_unverified'])
        self.assertIn('base_filesystem_semantics', result['remaining_unverified'])

    def test_rejects_added_extra_link_whiteout_traversal_duplicate_and_sparse(self):
        normal = [(p, tarfile.DIRTYPE, b'') for p in ('usr', 'usr/local', 'usr/local/bin')]
        normal += [('usr/local/bin/node', tarfile.REGTYPE, b'tiny node binary')]
        cases = [('etc/other', tarfile.REGTYPE, b'x'), ('usr/local/bin/link', tarfile.SYMTYPE, b''),
                 ('usr/.wh.foo', tarfile.REGTYPE, b''), ('../escape', tarfile.REGTYPE, b''),
                 ('usr', tarfile.DIRTYPE, b''), ('usr/local/bin/node/', tarfile.REGTYPE, b'x'),
                 ('sparse', tarfile.GNUTYPE_SPARSE, b''), ('pax', tarfile.XHDTYPE, b''),
                 ('gnu', tarfile.GNUTYPE_LONGNAME, b''), ('hard', tarfile.LNKTYPE, b'')]
        for entry in cases:
            with self.subTest(entry=entry), self.assertRaises(ValueError): self.run_content(added=normal + [entry])

    def test_added_parent_attributes_are_root_owned_0755(self):
        for parent in ('usr', 'usr/local', 'usr/local/bin'):
            for attributes in ((0o755, 1, 0), (0o755, 0, 1), (0o777, 0, 0),
                               (0o4755, 0, 0), (0o2755, 0, 0), (0o700, 0, 0)):
                entries = [(p, tarfile.DIRTYPE, b'', attributes if p == parent else (0o755, 0, 0))
                           for p in ('usr', 'usr/local', 'usr/local/bin')]
                entries.append(('usr/local/bin/node', tarfile.REGTYPE, b'tiny node binary'))
                with self.subTest(parent=parent, attributes=attributes):
                    with self.assertRaisesRegex(ValueError, 'added parent attributes'):
                        self.run_content(added=entries)

    def test_donor_ancestor_and_whiteout_rejected(self):
        for entry in [('usr/local', tarfile.SYMTYPE, b''), ('usr/.wh.local', tarfile.REGTYPE, b'')]:
            with self.subTest(entry=entry), self.assertRaises(ValueError): self.run_content(donor=[entry])

    def test_donor_last_layer_and_later_ambiguity(self):
        initial = [('usr/local/bin/node', tarfile.REGTYPE, b'old node')]
        final = [('usr/local/bin/node', tarfile.REGTYPE, b'tiny node binary')]
        self.run_content(donor=[initial, final])
        with self.assertRaises(ValueError): self.run_content(donor=[final, initial])
        with self.assertRaises(ValueError):
            self.run_content(donor=[final, [('usr/local/bin', tarfile.SYMTYPE, b'')]])

    def test_rejects_valid_gzip_with_wrong_compressed_hash(self):
        def drift(blobs, imgs):
            manifest = json.loads(imgs['candidate'][0]); h = manifest['layers'][-1]['digest'][7:]
            payload = bytearray(blobs[h]); payload[4] ^= 1; blobs[h] = bytes(payload)
        with self.assertRaisesRegex(ValueError, 'compressed layer digest'): self.run_content(blob_change=drift)

    def test_binary_probe_and_digest_mismatch(self):
        with self.assertRaises(ValueError): self.run_content(probe_change={'sha256': '0' * 64})
        with self.assertRaises(ValueError): self.run_content(probe_change={'mode': 0o700})
        with self.assertRaises(ValueError): self.run_content(base_diff='sha256:' + '0' * 64)
        def corrupt(blobs, imgs):
            manifest = json.loads(imgs['candidate'][0]); h = manifest['layers'][-1]['digest'][7:]
            b = bytearray(blobs[h]); b[-1] ^= 1; blobs[h] = bytes(b)
        with self.assertRaises((ValueError, OSError)): self.run_content(blob_change=corrupt)

    def test_probe_size_required_and_exact(self):
        for value in (None, True, 0, 1, m.MAX_FILE + 1):
            with self.subTest(size=value), self.assertRaises(ValueError):
                self.run_content(probe_change={'size': value})
        blobs, index, imgs, probe = content_fixture()
        del probe['size']
        archive(self.path, blobs, index)
        known = {'arm64': {k: (sha(imgs[k][0]), sha(imgs[k][1])) for k in ('node', 'base')}}
        with patch.object(m, 'KNOWN', known), self.assertRaises(ValueError):
            m.verify_content(self.path, 'arm64', 'sha256:' + sha(imgs['candidate'][0]), probe)

    def test_regular_node_trailing_slash_is_rejected(self):
        entries = [(p, tarfile.DIRTYPE, b'') for p in ('usr', 'usr/local', 'usr/local/bin')]
        entries.append(('usr/local/bin/node/', tarfile.REGTYPE, b'tiny node binary'))
        with self.assertRaisesRegex(ValueError, 'non-directory trailing slash'):
            self.run_content(added=entries)

    def test_unaligned_tar_tail_is_rejected(self):
        import gzip
        packed, _ = make_layer([('usr', tarfile.DIRTYPE, b'')])
        raw = gzip.decompress(packed) + b'\0'
        packed = gzip.compress(raw, mtime=0)
        blobs = {sha(packed): packed}
        archive(self.path, blobs, {'schemaVersion': 2, 'manifests': []})
        a = m.Archive(self.path)
        self.addCleanup(a.close)
        with self.assertRaisesRegex(ValueError, 'layer tar alignment'):
            m.inspect_layer(a, ('application/vnd.oci.image.layer.v1.tar+gzip', sha(packed), len(packed)),
                            'sha256:' + sha(raw), m.Budget(), 'donor', None)

    def test_limits_and_truncation(self):
        with patch.object(m, 'MAX_LAYER_UNCOMPRESSED', 1000), self.assertRaises(ValueError): self.run_content()
        with patch.object(m, 'MAX_TOTAL_COMPRESSED', 10), self.assertRaises(ValueError): self.run_content()
        with patch.object(m, 'MAX_LAYER_MEMBERS', 1), self.assertRaises(ValueError): self.run_content()
        def truncate(blobs, imgs):
            manifest = json.loads(imgs['candidate'][0]); h = manifest['layers'][-1]['digest'][7:]
            blobs[h] = blobs[h][:-1]
        with self.assertRaises(ValueError): self.run_content(blob_change=truncate)


if __name__ == '__main__': unittest.main()
