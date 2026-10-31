"""Synthetic preparation controls; no existing credential or network access."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from deploy.pilot import native_prepare as prepare


class NativePrepare(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name); self.pilot = self.state/'pilot'; self.pilot.mkdir(mode=0o700)
        self.capture = self.pilot/'capture'; self.capture.mkdir(mode=0o700)
        self.private = self.capture/'private'; self.private.mkdir(mode=0o700)
        self.runtime = self.capture/'runtime'; self.runtime.mkdir(mode=0o700)
        for path in [self.state/'ca.key', self.state/'ca.crt', self.private/'collector.key.der', self.runtime/'collector.crt.der', self.runtime/'ca.der', self.runtime/'policy.raw']:
            path.write_bytes(('synthetic-'+path.name).encode()); path.chmod(0o600)
        self.profile = prepare.PROFILE._replace(capture=self.capture)
        for name, config in prepare.capture_renew.p.runtime_configs(self.profile.collector).items():
            path=self.runtime/name; path.write_text(json.dumps(config)); path.chmod(0o600)
        self.stack = [mock.patch.object(prepare,'STATE',self.state), mock.patch.object(prepare,'PILOT',self.pilot),
                      mock.patch.object(prepare,'NATIVE',self.pilot/'native'), mock.patch.object(prepare,'PROFILE',self.profile)]
        for patch in self.stack: patch.start(); self.addCleanup(patch.stop)

    def fake_openssl(self, *args):
        args = list(map(str,args))
        if args[0] == 'x509' and '-outform' in args and '-out' not in args:
            return b'synthetic-ca.der' if Path(args[args.index('-in')+1]).name == 'ca.crt' else b'synthetic-forwarder.der'
        for flag in ['-keyout','-out']:
            if flag in args:
                path=Path(args[args.index(flag)+1]); path.write_bytes(('synthetic-'+path.name).encode()); path.chmod(0o600)
        return b''

    def test_role_separation_and_existing_state_refusal(self):
        with mock.patch.object(prepare,'live_policy'), mock.patch.object(prepare,'openssl',side_effect=self.fake_openssl), mock.patch('builtins.print'):
            prepare.prepare()
            native=self.pilot/'native'; gateway=native/'gateway'; forwarder=native/'forwarder'
            settings=json.loads((gateway/'gateway.json').read_text())
            self.assertEqual((settings['method'],settings['path'],settings['route']),('POST','/pilot','/pilot'))
            self.assertEqual(settings['collector'], self.profile.collector)
            self.assertEqual(settings['delivery_address'],'pilot-capture-ingress:9445')
            self.assertEqual(settings['delivery_name'],'ingress')
            self.assertTrue((gateway/'collector-key.der').is_file())
            self.assertTrue((gateway/'upstream-client-key.der').is_file())
            self.assertFalse((forwarder/'collector-key.der').exists())
            self.assertFalse((gateway/'forwarder.key').exists())
            self.assertFalse((gateway/'ca.key').exists()); self.assertFalse((forwarder/'ca.key').exists())
            self.assertTrue((forwarder/'edge.key').is_file()); self.assertTrue((forwarder/'forwarder.key').is_file())
            prepare.check()
            for name in ['pilot-ca.pem','observer-ca.pem']:
                path=forwarder/name; before_ca=path.read_bytes(); path.write_bytes(before_ca+b'\nextra bundle')
                with self.assertRaisesRegex(RuntimeError, 'approved CA drift'): prepare.check()
                path.write_bytes(before_ca)
            ca=self.runtime/'ca.der'; before_ca=ca.read_bytes(); ca.write_bytes(b'wrong CA')
            with self.assertRaisesRegex(RuntimeError, 'approved CA drift'): prepare.check()
            ca.write_bytes(before_ca)
            (gateway/'collector.der').write_bytes(b'drift')
            with self.assertRaisesRegex(RuntimeError, 'credential drift'): prepare.check()
            (gateway/'collector.der').write_bytes((self.runtime/'collector.crt.der').read_bytes())
            (gateway/'forwarder.der').write_bytes(b'drift')
            with self.assertRaisesRegex(RuntimeError, 'forwarder identity drift'): prepare.check()
            (gateway/'forwarder.der').write_bytes(b'synthetic-forwarder.der')
            before=(gateway/'gateway.json').read_bytes()
            with self.assertRaises(FileExistsError): prepare.prepare()
            self.assertEqual((gateway/'gateway.json').read_bytes(), before)
            settings['source'] = 'drift'
            (gateway/'gateway.json').write_text(json.dumps(settings))
            with self.assertRaisesRegex(RuntimeError, 'configuration drift'): prepare.check()

    def test_pending_journal_stops_before_creating_native_state(self):
        (self.private/'renew.pending').write_text('fixture')
        with self.assertRaisesRegex(RuntimeError,'requires reconciliation'): prepare.prepare()
        self.assertFalse((self.pilot/'native').exists())


if __name__ == '__main__': unittest.main()
