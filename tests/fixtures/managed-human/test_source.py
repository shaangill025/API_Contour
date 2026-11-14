import unittest
from deploy.local import origin21_profile as profiles, origin21_state as state


class SourceClosureTest(unittest.TestCase):
    def test_human_closure_is_explicit_and_distinct(self):
        files = state.HUMAN_SOURCE_FILES
        self.assertTrue(set(state.MANAGED_SOURCE_FILES).issubset(files))
        for name in ('deploy/local/origin21-managed-human-compose.yaml',
                     'deploy/local/origin21_managed_human_preflight.py',
                     'deploy/local/origin21_managed_human_secret.py',
                     'tests/fixtures/managed-human/test_source.py'):
            self.assertIn(name, files)
            self.assertNotIn(name, state.MANAGED_SOURCE_FILES)
        self.assertEqual(len(files), len(set(files)))
        snapshot = state._source_snapshot(context=profiles.HUMAN)
        self.assertEqual(set(snapshot), set(files))
        self.assertEqual(len(state._source_identity(snapshot, context=profiles.HUMAN)), 64)
        with self.assertRaises(ValueError):
            state._source_identity({}, context=profiles.HUMAN)
