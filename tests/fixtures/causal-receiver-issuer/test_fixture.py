"""Offline issuer scenario wiring; no services or cryptographic proof."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('issuer_fixture',ROOT/'scripts/receiver_issuer_fixture.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class FixtureTests(unittest.TestCase):
    def test_fixed_cases_role_and_durable_scope(self):
        calls=[]; payloads=[]; files={}; latest={}
        def execute(sql):
            calls.append(sql)
            if sql.startswith('SELECT count(*)::text FROM contour.causal_sessions'):
                self.assertIn(latest['nonce'],sql)
                return '1' if latest['mode']=='positive' else '0'
            if sql.startswith('SELECT coalesce((SELECT used_bytes'): return str(13+(len(latest['batch'].encode()) if latest.get('mode')=='positive' else 0))
            if sql.startswith('SELECT count(*)::text FROM contour.causal_inbox_events'): return '1'
            if sql.startswith('SELECT (count(*)=1'): return 'true'
            return ''
        def openssl(args):
            if args[:2]==['genpkey','-algorithm']: return b'-----BEGIN PRIVATE KEY-----\nsynthetic\n'
            if args[0]=='pkey': return bytes.fromhex('302a300506032b6570032100')+bytes([3])*32
            if args[0]=='pkeyutl': return bytes([4])*64
            raise AssertionError('unexpected command')
        def write(name,body):
            self.assertNotIn(name,files);files[name]=body
        def probe(raw):
            value=json.loads(raw);payloads.append(value);latest.clear();latest.update(value)
        data=(ROOT/'crates/contour-postgres/tests/fixtures/causal_bridge.json').read_bytes()
        result=m.run(execute=execute,openssl=openssl,write_private=write,private_dir='/private',probe_call=probe,ca_pem=b'CA',port='5432',passwords={'issuer':'a'*64,'wrong':'b'*64},fixture_bytes=data)
        self.assertEqual(result,m.CHECKS)
        self.assertEqual([v['mode'] for v in payloads],['generic','wrong-profile','wrong-profile','wrong-peer','wrong-scope','expired','wrong-role','deadline','wrong-signature','positive'])
        self.assertEqual(len({v['nonce'] for v in payloads}),len(payloads))
        self.assertEqual(payloads[-1]['epoch'],'1');self.assertEqual(payloads[-1]['ids'],list(m.IDS))
        self.assertTrue(any('INSERT INTO contour.policy_revisions' in s and 'active_revision=2' in s for s in calls))
        self.assertTrue(any('contour.enroll_causal_runtime' in s and m.MANIFEST in s for s in calls))
        self.assertTrue(any('bool_and(epoch=1' in s and m.MANIFEST in s for s in calls))
        self.assertFalse(any('UPDATE contour.policy_revisions' in s or 'DISABLE TRIGGER' in s for s in calls))
        self.assertEqual(payloads[6]['user'],'causal_provisioner_login')
        self.assertTrue(any('GRANT contour_causal_inbox_writer TO causal_event_writer_login' in sql for sql in calls))
        batch=json.loads(payloads[-1]['batch']); self.assertEqual(batch['events'][0]['kind'],'root')
        self.assertNotEqual(json.loads(payloads[-1]['wrong_batch'])['tenant_id'],batch['tenant_id'])
        self.assertTrue(any('causal_receipt_digest' in sql and payloads[-1]['batch'].encode().hex() in sql for sql in calls))
        self.assertEqual(sum('SELECT coalesce((SELECT used_bytes' in sql for sql in calls),2)
    def test_refuses_unverified_result(self):
        with self.assertRaises(ValueError):
            m.run(execute=None,openssl=None,write_private=None,private_dir='/private',probe_call=None,ca_pem=b'CA',port='1',passwords={'issuer':'secret','wrong':'b'*64},fixture_bytes=b'{}')

if __name__=='__main__': unittest.main()
