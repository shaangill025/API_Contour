"""Offline orchestration checks; these do not execute or validate SQL."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('observer_driver',ROOT/'scripts/test-causal-observer-inbox.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
U='00000000-0000-4000-8000-000000000001'

class DriverTests(unittest.TestCase):
    def _run(self, fail_fixture=False):
        policy={'issued_at':'2026-11-12T12:00:00Z','expires_at':'2026-11-12T12:10:00Z'}
        payload=base64.urlsafe_b64encode(json.dumps(policy).encode()).rstrip(b'=').decode()
        envelope=json.dumps({'payload_base64url':payload}).encode().hex()
        proof={k:U for k in ('origin_project_id','origin_service_id','origin_environment_id','origin_deployment_id','instance_id','lifecycle_id','credential_id')};proof['leaf']='22'*32
        ledger25='{'+','.join(map(str,range(1,26)))+'}';ledger27='{'+','.join(map(str,range(1,28)))+'}'
        calls=[]; submissions=[]
        def execute(sql,timeout=30):
            calls.append(sql)
            if 'row_to_json(x)' in sql and 'policy_revisions' in sql:return json.dumps({'revision':'2','envelope':envelope})
            if 'row_to_json(x)' in sql and 'origin_proofs' in sql:return json.dumps(proof)
            if sql.startswith('SELECT array_agg'):return ledger25 if sum(x.startswith('SELECT array_agg') for x in calls)==1 else ledger27
            if 'CREATE TEMP TABLE observer_seed' in sql and fail_fixture:raise RuntimeError('fixture failed')
            return ''
        def submit(body,status):submissions.append((body,status))
        item={'record_id':U,'project_id':U,'service_id':U,'environment_id':U,'deployment_id':U,'source_id':U,'policy_revision':1,'direction':'request'}
        body={'tenant_id':U,'collector_id':U,'batch_id':U,'records':[{'record':dict(item)},{'record':dict(item),'origin_witness':{'kind':'downstream_mtls_leaf_sha256_v1','leaf_sha256':'22'*32}}]}
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)
            with mock.patch.object(module,'_sign',return_value=b'signed'), mock.patch.object(module.subprocess,'run',return_value=mock.Mock(stdout='Processed\n',stderr='')):
                if fail_fixture:
                    with self.assertRaisesRegex(RuntimeError,'fixture failed'):module.run_cases(execute,submit,body,'5432',directory,{},'/unused')
                    self.assertFalse((directory/'causal-observer.done').exists())
                else:
                    module.run_cases(execute,submit,body,'5432',directory,{},'/unused')
                    self.assertEqual((directory/'causal-observer.done').read_bytes(),b'causal-observer-complete\n')
        return calls,submissions,body
    def test_owned_new_request_and_same_psql_seed(self):
        calls,submissions,body=self._run()
        candidate,status=submissions[0];self.assertEqual(status,'accepted')
        self.assertEqual(candidate['records'][0]['record']['source_id'],module.GATE_SOURCE)
        self.assertEqual(candidate['records'][0]['record']['policy_revision'],3)
        self.assertEqual(body['batch_id'],U)
        self.assertNotEqual(module.GATE_SOURCE,module.RUNTIME_SOURCE)
        combined=[sql for sql in calls if 'CREATE TEMP TABLE observer_seed' in sql]
        self.assertEqual(len(combined),1)
        self.assertIn('trusted synthetic observer seed required',combined[0])
        self.assertIn('nodered_5_0_9_wire_v1',combined[0])
    def test_diagnostics_preserve_fixture_exactly(self):
        fixture=(ROOT/'db/tests/causal_observer_inbox.sql').read_text()
        sql=module._diagnostic_sql(module.SEED_SQL,fixture)
        self.assertTrue(sql.startswith('\\set VERBOSITY verbose\n\\echo observer-step=runtime-source\n'))
        marked=sql.split('\\echo observer-step=cases\n',1)[1]
        for label in ('parser','first-accept','replay','negativeclaims','quota','graph','chains'):
            marker='\\echo observer-step='+label+'\n'
            self.assertEqual(marked.count(marker),1);marked=marked.replace(marker,'',1)
        self.assertEqual(marked,fixture)
        with self.assertRaises(ValueError):module._diagnostic_sql(module.SEED_SQL,fixture+'\n-- Disposable PostgreSQL only.')
        for label in ('profile','runtime-enroll','session','generation','marker','gateway','proof','canonical'):
            self.assertEqual(sql.count('observer-step='+label+'\n'),1)
        with self.assertRaises(ValueError):module._diagnostic_sql('bad',fixture)
    def test_failure_never_writes_receipt(self):self._run(True)

if __name__=='__main__':unittest.main()
