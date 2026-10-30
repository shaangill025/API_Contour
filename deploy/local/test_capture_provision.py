"""Capture role drift tests; no database, network or secrets are used."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PATH=Path(__file__).with_name('capture_provision.py')
spec=importlib.util.spec_from_file_location('capture_provision',PATH)
provision=importlib.util.module_from_spec(spec); spec.loader.exec_module(provision)

class GroupAttributes(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.capture=Path(self.directory.name); runtime=self.capture/'runtime'; runtime.mkdir()
        private=self.capture/'private'; private.mkdir(); (private/'policy.json').write_text('{}')
        for name in ['server.crt.der','server.key.der','collector.crt.der','ca.der','policy.raw','ingress.password','worker.password']:
            (runtime/name).write_text('fixture')

    def execute(self, group_count, exact='true'):
        statements=[]
        def sql(statement):
            statements.append(statement)
            if statement.startswith('SELECT count(*) FROM pg_roles WHERE rolname IN'): return group_count
            if statement.startswith('SELECT count(*) FROM pg_roles WHERE rolname='): return '1'
            if statement.startswith('SELECT r.rolname FROM pg_roles'):
                return 'contour_ingestion\ncontour_runtime' if "'contour_local_ingress'" in statement else 'contour_catalog_worker'
            if statement.startswith('SELECT (rolcanlogin'): return 'true'
            if statement.startswith('SELECT count(*) FROM contour.collectors'): return '1'
            if statement.startswith('SELECT EXISTS'): return 'true'
            if statement.startswith('SELECT ((SELECT count(*) FROM contour.sources'): return exact
            raise AssertionError('unexpected statement')
        with mock.patch.object(provision,'CAPTURE',self.capture), mock.patch.object(provision.base,'psql',side_effect=sql), \
             mock.patch.object(provision.base,'private_file',return_value='fixture'), mock.patch('builtins.print'):
            if group_count!='3':
                with self.assertRaisesRegex(RuntimeError,'group attributes drift'): provision.main()
            elif exact!='true':
                with self.assertRaisesRegex(RuntimeError,'capture enrollment drift'): provision.main()
            else: provision.main()
        return statements

    def test_unsafe_inherited_groups_rejected_before_enrollment(self):
        for count in ['0','1','2']:
            statements=self.execute(count)
            self.assertEqual(len(statements),1)
            query=statements[0]
            for flag in ['NOT rolcanlogin','NOT rolsuper','NOT rolbypassrls','NOT rolcreaterole',
                         'NOT rolcreatedb','NOT rolreplication','rolinherit','rolconfig IS NULL']:
                self.assertIn(flag,query)
            for group in ['contour_ingestion','contour_runtime','contour_catalog_worker']:
                self.assertIn("'"+group+"'",query)

    def test_extra_collector_source_binding_or_assignment_is_rejected(self):
        statements=self.execute('3',exact='false')
        query=next(s for s in statements if s.startswith('SELECT ((SELECT count(*) FROM contour.sources'))
        for table in ['contour.sources','contour.source_authorization','contour.source_instance_bindings','contour.workload_assignments']:
            self.assertIn('FROM '+table,query)
        self.assertEqual(query.count("collector_id='"+provision.COLLECTOR+"'"),6)
        self.assertEqual(query.count("tenant_id='"+provision.TENANT+"'"),6)
        self.assertIn("binding_mode='instance'",query)
        self.assertIn("source_nonce='"+provision.NONCE+"'",query)
        self.assertFalse((self.capture/'runtime'/'ingress.json').exists())

    def test_valid_groups_allow_enrollment_validation(self):
        statements=self.execute('3')
        self.assertTrue(any('FROM contour.collectors' in s for s in statements))
        self.assertTrue(any('FROM contour.collector_authorization' in s for s in statements))

if __name__=='__main__': unittest.main()
