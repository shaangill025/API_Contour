import copy
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[3] / 'scripts/qualify-node243-layer.py'
spec = importlib.util.spec_from_file_location('node243_qualification', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
OWNER = 'a' * 64


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.base = {'Os': 'linux', 'Architecture': 'arm64', 'Config': {'Env': ['PATH=/bin', 'NODE_VERSION=24.22.1'], 'Labels': {'upstream': 'yes'}, 'User': 'node-red'}, 'RootFS': {'Layers': ['sha256:'+'1'*64]}}
        self.final = copy.deepcopy(self.base)
        self.final['Config']['Env'][1] = 'NODE_VERSION=24.22.3'
        self.final['Config']['Labels'][module.OWNER] = OWNER
        self.final['RootFS']['Layers'].append('sha256:'+'2'*64)

    def test_expected_change(self):
        self.assertTrue(module.compare_images(self.base, self.final, OWNER))

    def test_rejects_owner_config_and_layer_drift(self):
        for mutate in (lambda x: x['Config']['Labels'].__setitem__(module.OWNER, 'b'*64), lambda x: x['Config'].__setitem__('User', 'root'), lambda x: x['RootFS']['Layers'].append('sha256:'+'3'*64), lambda x: x['Config']['Env'].append('UNEXPECTED=1')):
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(self.final); mutate(value)
                with self.assertRaises(ValueError): module.compare_images(self.base, value, OWNER)

    def test_main_never_claims_qualification(self):
        self.assertEqual(module.main(), 1)


if __name__ == '__main__': unittest.main()
