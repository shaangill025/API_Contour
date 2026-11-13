"""Offline behavioral tests for the fixed archive helper, not daemon evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[3] / 'scripts/receiver504_image_probe.py'
spec = importlib.util.spec_from_file_location('receiver504_image_probe', PATH)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class ProbeTests(unittest.TestCase):
    def test_config_allows_only_fixed_patch_and_owner(self):
        base = {'Env': ['PATH=/bin', 'NODE_VERSION=24.22.1'], 'Labels': {'base':'value'},
                'Entrypoint':['node'], 'Cmd':['main'], 'User':'1000'}
        expected = copy.deepcopy(base)
        expected['Env'][1] = 'NODE_VERSION=24.22.3'
        expected['Labels'][probe._OWNER] = 'a' * 64
        probe._compare_config(base, expected, copy.deepcopy(expected), 'a' * 64)
        for field, bad in [('User','0'), ('Cmd',['other']), ('Entrypoint',['sh'])]:
            changed = copy.deepcopy(expected); changed[field] = bad
            with self.assertRaises(ValueError): probe._compare_config(base, changed, changed, 'a' * 64)
        changed = copy.deepcopy(expected); changed['Env'].append('EXTRA=1')
        with self.assertRaises(ValueError): probe._compare_config(base, changed, changed, 'a' * 64)
        with self.assertRaises(ValueError): probe._compare_config(base, expected, base, 'a' * 64)

    def test_daemon_rootfs_matches_archive(self):
        archive = {"rootfs": {"type": "layers", "diff_ids": ["sha256:abc"]}}
        probe._compare_rootfs(archive, {"Type": "layers", "Layers": ["sha256:abc"]})
        with self.assertRaises(ValueError):
            probe._compare_rootfs(archive, {"Type": "layers", "Layers": ["sha256:other"]})
        archive['rootfs']['extra'] = True
        with self.assertRaises(ValueError):
            probe._compare_rootfs(archive, {"Type": "layers", "Layers": ["sha256:abc"]})

    def test_history_prefix_and_layer_count(self):
        base = {'history':[{'created_by':'base'}], 'rootfs':{'diff_ids':['one']}}
        timestamp = '2026-11-12T19:51:49.800391919Z'
        candidate = {'history':[{'created_by':'base'},
                     {'created_by':'COPY /usr/local/bin/node /usr/local/bin/node # buildkit',
                      'created':timestamp, 'comment':'buildkit.dockerfile.v0'},
                     {'created_by':'ENV NODE_VERSION=24.22.3', 'created':timestamp,
                      'comment':'buildkit.dockerfile.v0', 'empty_layer':True}],
                     'rootfs':{'diff_ids':['one','two']}}
        self.assertEqual(len(probe._check_history(base,candidate)[1]), 64)
        changed = copy.deepcopy(candidate); changed['history'][0]['created_by'] = 'other'
        with self.assertRaises(ValueError): probe._check_history(base,changed)
        changed = copy.deepcopy(candidate); changed['rootfs']['diff_ids'].pop()
        with self.assertRaises(ValueError): probe._check_history(base,changed)
        variants = []
        changed = copy.deepcopy(candidate); changed['history'].append({'empty_layer':True})
        variants.append(changed)
        for field, value in [('created_by','arbitrary command'), ('comment','other'), ('author','other')]:
            changed = copy.deepcopy(candidate); changed['history'][1][field] = value
            variants.append(changed)
        changed = copy.deepcopy(candidate); changed['history'].pop()
        variants.append(changed)
        for timestamp in ['2026-02-30T19:51:49Z', '2026-11-12T25:51:49Z',
                          '2026-11-12T19:51:49+00:00', '2026-11-12T19:51:49.1234567890Z']:
            changed = copy.deepcopy(candidate)
            for entry in changed['history'][1:]: entry['created'] = timestamp
            variants.append(changed)
        changed = copy.deepcopy(candidate); changed['history'][2]['created'] = '2026-11-12T19:51:50Z'
        variants.append(changed)
        for changed in variants:
            with self.subTest(history=changed['history'][1:]):
                with self.assertRaises(ValueError): probe._check_history(base,changed)
        base.update(architecture='arm64', os='linux', created='2026-10-21T15:54:44.297622251Z', config={})
        candidate.update(architecture='arm64', os='linux', created=candidate['history'][-1]['created'], config={})
        probe._compare_image_metadata(base, candidate, 'arm64')
        for key, value in [('author','other'), ('unknown',True), ('architecture','amd64'),
                           ('os','other'), ('created','2026-11-12T19:51:50Z')]:
            changed = copy.deepcopy(candidate); changed[key] = value
            with self.subTest(field=key):
                with self.assertRaises(ValueError): probe._compare_image_metadata(base,changed,'arm64')

if __name__ == '__main__':
    unittest.main()
