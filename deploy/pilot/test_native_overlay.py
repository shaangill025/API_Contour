"""Validate the resolved native Compose startup graph with the existing CLI."""
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NativeOverlay(unittest.TestCase):
    def test_startup_dependency_graph(self):
        result = subprocess.run([
            'docker', 'compose', '-f', 'deploy/pilot/compose.yaml',
            '-f', 'deploy/pilot/native-overlay.yaml', '--profile', 'native-capture',
            'config', '--format', 'json',
        ], cwd=ROOT, env=dict(os.environ, LOCAL_UID=str(os.getuid()), LOCAL_GID=str(os.getgid())),
            capture_output=True, check=True, timeout=15)
        services = json.loads(result.stdout)['services']
        def dependencies(name):
            return {key: value['condition'] for key, value in services[name].get('depends_on', {}).items()}
        self.assertEqual(dependencies('native-gateway'), {
            'destination': 'service_started',
            'pilot-capture-ingress': 'service_started',
        })
        self.assertEqual(dependencies('native-envoy'), {'native-gateway': 'service_started'})
        for replica in ('replica1', 'replica2'):
            self.assertEqual(dependencies(replica), {'native-envoy': 'service_started'})
        self.assertFalse(services['pilot-capture-ingress'].get('ports'))


if __name__ == '__main__':
    unittest.main()
