"""Offline closed-bundle shape, permissions, and journal checks."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from deploy.local import capture_profiles
from deploy.pilot import origin_credentials as credentials, origin_setup_state as journal


class Bundle(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'origin-pilot'; self.root.mkdir(mode=0o700)
        self.profile=capture_profiles.ORIGIN_PILOT._replace(state=self.root)
        patch=mock.patch.object(capture_profiles,'ORIGIN_PILOT',self.profile); patch.start(); self.addCleanup(patch.stop)
        self.op=credentials.Credentials(self.profile, self.root/'ca-cert',self.root/'ca-key')

    def create_shape(self):
        for path in sorted(credentials.DIRS,key=lambda x:(x.count('/'),x)): (self.root/path).mkdir(mode=0o700)
        for path in credentials.FILES:
            p=self.root/path; p.write_bytes(b'fixture'); p.chmod(0o600)

    def test_empty_partial_unexpected_and_closed_inventory(self):
        self.assertEqual(self.op.inspect(),journal.ABSENT)
        (self.root/'unexpected').write_bytes(b'fixture'); (self.root/'unexpected').chmod(0o600)
        self.assertEqual(self.op.inspect(),journal.DRIFT)
        (self.root/'unexpected').unlink()
        (self.root/'capture').mkdir(mode=0o700)
        self.assertEqual(self.op.inspect(),journal.DRIFT)

    def test_closed_shape_mode_links_and_commitment(self):
        self.create_shape()
        with mock.patch.object(self.op,'_verify'):
            self.assertEqual(self.op.inspect(),journal.EXACT)
            before=self.op.commitment()
            target=self.root/'replica1/client.crt'; target.write_bytes(b'changed')
            self.assertNotEqual(self.op.commitment(),before)
            target.chmod(0o644); self.assertEqual(self.op.inspect(),journal.DRIFT); target.chmod(0o600)
            target.unlink(); target.symlink_to(self.root/'replica2/client.crt'); self.assertEqual(self.op.inspect(),journal.DRIFT)
            target.unlink(); os.link(self.root/'replica2/client.crt',target); self.assertEqual(self.op.inspect(),journal.DRIFT)

    def test_phase_is_closed_and_defers_policy_and_roles(self):
        self.assertNotIn('capture/private/policy.json',credentials.FILES)
        self.assertIn('capture/private/policy.key',credentials.FILES)
        self.assertIn('capture/runtime/ingress.password',credentials.FILES)
        self.assertIn('capture/runtime/worker.password',credentials.FILES)
        self.assertTrue(set(credentials.FILES).isdisjoint({'ca.key','capture/runtime/policy.key'}))
        with self.assertRaises(ValueError): credentials.Credentials(capture_profiles.DEFAULT,'x','y')

    def test_ca_mismatch_prevents_any_bundle_creation(self):
        # Construction/order test only; the owned OpenSSL fixture verifies crypto.
        with mock.patch.object(credentials,'_file',side_effect=[b'fixture-ca',b'fixture-key']), \
             mock.patch.object(credentials,'_run',side_effect=[b'cert-public',b'other-public']):
            with self.assertRaisesRegex(ValueError,'CA key mismatch'): self.op.apply()
        self.assertFalse(any((self.root/name).exists() for name in ('capture','replica1','replica2','destination','native')))

    def test_completed_journal_detects_changed_bundle_commitment(self):
        class Fake:
            def __init__(self): self.value=journal.ABSENT; self.digest='a'*64
            def inspect(self): return self.value
            def apply(self): self.value=journal.EXACT
            def commitment(self): return self.digest
        ops={name:Fake() for name in journal.CREDENTIAL_PHASES}
        journal.run(self.profile,ops,through_credentials=True)
        ops['credentials'].digest='b'*64
        with self.assertRaisesRegex(ValueError,'credential commitment drift'):
            journal.run(self.profile,ops,through_credentials=True)


if __name__ == '__main__': unittest.main()
