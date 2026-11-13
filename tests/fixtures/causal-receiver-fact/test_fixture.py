"""Offline checks for bounded synthetic fact construction; no TLS or database."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('receiver_fact_fixture', ROOT / 'scripts/receiver_fact_fixture.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

class FactConstruction(unittest.TestCase):
    def setUp(self):
        self.args = dict(tenant='f0000000-0000-4000-8000-000000000001',
                         gateway='fe000000-0000-4000-8000-000000000020',
                         gateway_generation='a' * 32,
                         runtime='fc000000-0000-4000-8000-000000000010',
                         epoch='1', delivery_handle='b' * 32,
                         local_root='c' * 32, binding_digest='d' * 64)

    def test_closed_canonical_scope(self):
        value = fixture.canonical_fact(**self.args)
        self.assertEqual(value, (b'{"binding_digest":"' + b'd' * 64 +
            b'","delivery_handle":"' + b'b' * 32 +
            b'","gateway_generation":"' + b'a' * 32 +
            b'","gateway_id":"fe000000-0000-4000-8000-000000000020",'
            b'"local_root":"' + b'c' * 32 +
            b'","receiver_runtime_id":"fc000000-0000-4000-8000-000000000010",'
            b'"receiver_session_epoch":"1","tenant_id":"f0000000-0000-4000-8000-000000000001",'
            b'"wire_version":1}'))

    def test_rejects_noncanonical_or_unbounded_values(self):
        for key, value in [('tenant', self.args['tenant'].upper()), ('runtime', 'x'),
                           ('gateway_generation', 'a' * 31), ('delivery_handle', 'A' * 32),
                           ('local_root', 'x' * 100000), ('binding_digest', 'f' * 63),
                           ('epoch', '01'), ('epoch', 1), ('epoch', '1' * 21), ('epoch', '18446744073709551616')]:
            with self.subTest(key=key, value=str(value)[:32]), self.assertRaises(ValueError):
                fixture.canonical_fact(**dict(self.args, **{key: value}))

class QualifierWiring(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('reader', ROOT / 'scripts/test-postgres-causal-receiver-reader.py')
        self.reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.reader)

    def test_opt_in_arguments_are_explicit_and_closed(self):
        q=self.reader
        self.assertEqual(q.qualifier_arguments(['/private/out','/private/tls']), (False,['/private/out','/private/tls']))
        self.assertEqual(q.qualifier_arguments(['--receiver-facts','/private/out','/private/tls']), (True,['/private/out','/private/tls']))
        for args in (['--receiver-facts','/private/out'], ['--other','/private/out','/private/tls']):
            with self.subTest(args=args), self.assertRaises(ValueError): q.qualifier_arguments(args)

    def test_fourth_artifact_must_match_source_and_be_unique(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();target=root/'target';target.mkdir()
            binary=target/'fact';binary.write_bytes(b'fixture');binary.chmod(0o700)
            source=root/'fact.rs'
            def row(src=source, name='causal_receiver_fact_probe'):
                return json.dumps({'reason':'compiler-artifact','target':{'name':name,'kind':['example'],'src_path':str(src)},'profile':{'test':False},'executable':str(binary)})
            self.assertEqual(self.reader.select_probe([row()],target,source,fact=True)[0],binary)
            for rows in ([],[row(),row()],[row(src=root/'wrong.rs')],[row(name='causal_receiver_issuer_probe')]):
                with self.subTest(rows=rows),self.assertRaises(ValueError): self.reader.select_probe(rows,target,source,fact=True)
            with self.assertRaises(ValueError): self.reader.select_probe([row()],target,source,fact=True,issuer=True)

class ReceiptProof(unittest.TestCase):
    def test_private_probe_output_is_closed_for_each_mode(self):
        spec = importlib.util.spec_from_file_location('reader_receipt', ROOT / 'scripts/test-postgres-causal-receiver-reader.py')
        reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
        digest='ab'*32
        positive=b'PASS receiver-fact-probe '+digest.encode()+b'\n'
        self.assertEqual(reader.parse_fact_probe_output('positive',positive),digest)
        self.assertIsNone(reader.parse_fact_probe_output('retry-denied',b'PASS receiver-fact-probe\n'))
        for mode, output in [('positive',positive.upper()),('positive',b'PASS receiver-fact-probe '+digest.upper().encode()+b'\n'),('positive',positive+b'extra'),
                             ('positive',positive[:-1]),('positive',b'PASS receiver-fact-probe\n'),
                             ('retry-denied',positive),('other',b'PASS receiver-fact-probe\n'),
                             ('positive',positive.decode()),(None,positive)]:
            with self.subTest(mode=mode,output=output),self.assertRaises(ValueError):
                reader.parse_fact_probe_output(mode,output)

    def test_owner_stored_digest_must_equal_returned_digest(self):
        digest='ab'*32
        fixture.require_matching_receipt_digest(digest,digest)
        for returned,stored in [(digest,'cd'*32),(digest,digest.upper()),(digest,digest+'\n'),
                                (digest,None),(None,digest),(digest.encode(),digest),('a'*63,digest)]:
            with self.subTest(returned=returned,stored=stored),self.assertRaises(ValueError):
                fixture.require_matching_receipt_digest(returned,stored)


class HttpResultProof(unittest.TestCase):
    def test_closed_pool_recovery_result(self):
        spec=importlib.util.spec_from_file_location('receiver_http',ROOT/'scripts/receiver_http_fixture.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        digest='ab'*32
        self.assertEqual(module.parse_result(0,b'PASS receiver-http-probe '+digest.encode()+b' '+digest.encode()+b'\n',b''),('passed',digest,digest))
        self.assertEqual(module.parse_result(1,b'',b'RED receiver-http-pool-recovery '+digest.encode()+b'\nFAIL receiver-http-probe\n'),('pool-recovery-red',None,digest))
        for code,out,err in [(0,b'',b''),(0,b'PASS receiver-http-probe '+digest.upper().encode()+b'\n',b''),(1,b'',b'FAIL receiver-http-probe\n'),(1,b'x',b'RED receiver-http-pool-recovery\nFAIL receiver-http-probe\n')]:
            with self.assertRaises(RuntimeError): module.parse_result(code,out,err)

    def test_event_receipt_requires_owner_confirmation_and_substitution_rejection(self):
        import json
        spec=importlib.util.spec_from_file_location('receiver_http_event',ROOT/'scripts/receiver_http_fixture.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        tenant='f0000000-0000-4000-8000-000000000001'; runtime='fc000000-0000-4000-8000-000000000010'
        batch={'batch_id':'00000000-0000-4000-8000-000000000001','tenant_id':tenant,'runtime_id':runtime,'session_epoch':1}
        payload={'ids':[tenant,runtime],'batch':json.dumps(batch,sort_keys=True,separators=(',',':'))}
        statements=[]
        module.verify_event_receipt(lambda query: (statements.append(query) or 'true'),payload,'ab'*32)
        self.assertIn("receipt_id::text",statements[0])
        self.assertIn("CASE WHEN receipt_id=",statements[0])
        with self.assertRaises(RuntimeError): module.verify_event_receipt(lambda _: 'false',payload,'ab'*32)
        with self.assertRaises(ValueError): module.verify_event_receipt(lambda _: 'true',payload,'AB'*32)

if __name__ == '__main__':
    unittest.main()
