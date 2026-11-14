"""Offline schema observation and phase-decision regression tests."""
import copy
import json
import unittest
from unittest import mock
from deploy.local import origin21_schema as schema, origin21_setup as setup, origin21_state as state


def envelope(stage,phase='pre'):
    return {'database':'contour_local','ledger':list(range(1,stage+1)),
            'inventory':copy.deepcopy(schema.require_reference(stage,phase))}


def raw(value):return json.dumps(value,separators=(',',':'))

class SnapshotTests(unittest.TestCase):
    def test_every_pinned_reference_and_fresh_statement(self):
        for stage,phase in schema.REFERENCE_SHA256:
            with self.subTest(stage=stage,phase=phase):
                query=mock.Mock(return_value=raw(envelope(stage,phase)))
                schema.require_snapshot(query,stage,phase)
                self.assertEqual(query.call_count,1)
                sql=query.call_args.args[0]
                self.assertIn('pg_catalog.current_database()',sql)
                self.assertIn('contour.schema_migrations',sql)
                self.assertIn(schema.inventory_sql().rstrip().removesuffix(';'),sql)

    def test_closed_typed_envelope_rejects_malformed_and_drift(self):
        good=envelope(21,'enrolled')
        cases=[]
        for key,value in [('database','other'),('ledger',list(range(1,21))),('ledger',list(range(1,23))),('ledger',[True]+list(range(2,22))),('inventory',None)]:
            item=copy.deepcopy(good);item[key]=value;cases.append(raw(item))
        cases += [raw({'database':'contour_local','ledger':good['ledger']}), raw(dict(good,extra=1)),
                  '{"database":"contour_local","database":"contour_local","ledger":[],"inventory":{}}',
                  raw(good)[:-1], ' '* (8*1024*1024+1)]
        for value in cases:
            with self.subTest(prefix=value[:80]),self.assertRaises((ValueError,RuntimeError)):
                schema.require_snapshot(lambda _:value,21,'enrolled')
        acl=copy.deepcopy(good)
        acl['inventory']['items'].append({'kind':'database_acl','value':{'grantable':True}})
        with self.assertRaises(RuntimeError):schema.require_snapshot(lambda _:raw(acl),21,'enrolled')
        wrongtype=copy.deepcopy(good);wrongtype['inventory']['version']=True
        with self.assertRaises(ValueError):schema.require_snapshot(lambda _:raw(wrongtype),21,'enrolled')

    def test_stage14_classification_and_migration(self):
        for phase,expected in [('pre',state.ABSENT),('groups',state.EXACT)]:
            with self.subTest(phase=phase):
                query=mock.Mock(return_value=raw(envelope(14,phase)))
                self.assertEqual(setup.Groups(query,{'login':False}).inspect(),expected)
                self.assertEqual(setup.Migration(query,15,b'',{'login':False}).inspect(),state.ABSENT if phase=='groups' else state.DRIFT)
        for stage in range(15,22):
            context={'login':stage==21};phase='enrolled' if context['login'] else 'pre'
            query=mock.Mock(return_value=raw(envelope(stage,phase)))
            for version in range(15,stage+1):
                self.assertEqual(setup.Migration(query,version,b'',context).inspect(),state.EXACT)

    def test_mutation_between_phase_calls_is_detected(self):
        good=envelope(21,'enrolled'); drift=copy.deepcopy(good)
        drift['inventory']['items'].append({'kind':'database_acl','value':{'grantable':True}})
        query=mock.Mock(side_effect=[raw(good),raw(drift)])
        self.assertEqual(setup.Groups(query,{'login':True}).inspect(),state.EXACT)
        self.assertEqual(setup.Migration(query,15,b'',{'login':True}).inspect(),state.DRIFT)
        self.assertEqual(query.call_count,2)

    def test_nested_boolean_cannot_equal_integer(self):
        original={'version':1,'server_major':16,'items':[{'kind':'role','value':{'ordinal':1}}]}
        changed=copy.deepcopy(original);changed['items'][0]['value']['ordinal']=True
        snap={'ledger':list(range(1,22)),'inventory':changed}
        with mock.patch.object(schema,'require_reference',return_value=original):
            self.assertFalse(schema.snapshot_matches(snap,21,'enrolled'))

if __name__=='__main__':unittest.main()
