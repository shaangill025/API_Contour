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


if __name__ == '__main__': unittest.main()
