"""Offline exact-profile schema comparator checks."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from deploy.local import origin21_schema, origin25_schema

ROOT=Path(__file__).resolve().parents[3]

class Origin25SchemaTests(unittest.TestCase):
    def test_fixed_references_and_exact_internal_stages(self):
        for stage in (22,23,24,25):
            path=ROOT/'deploy/local'/('origin25_reference_%d_enrolled.json'%stage)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),origin25_schema.REFERENCE_SHA256[stage])
            self.assertEqual(origin25_schema._reference(stage)['server_major'],16)
        for invalid in (True,21,26,'25',None):
            with self.assertRaises(ValueError): origin25_schema._reference(invalid)

    def test_public_ready_accepts_only_exact25_and_full_inventory(self):
        inventory=origin25_schema._reference(25)
        envelope={'database':'contour_local','ledger':list(range(1,26)),'inventory':inventory}
        execute=mock.Mock(return_value=json.dumps(envelope))
        self.assertIsNone(origin25_schema.require_ready(execute))
        execute.assert_called_once_with(origin25_schema._SNAPSHOT_SQL)
        self.assertIn(origin21_schema.inventory_sql().rstrip().removesuffix(';'),origin25_schema._SNAPSHOT_SQL)
        for ledger in (list(range(1,25)),list(range(1,27)),[2,3,25],[1,25,25],[],list(range(1,25))+[True]):
            with self.subTest(ledger=ledger):
                called=mock.Mock(return_value=json.dumps(dict(envelope,ledger=ledger)))
                with self.assertRaises(ValueError): origin25_schema.require_ready(called)
                called.assert_called_once_with(origin25_schema._SNAPSHOT_SQL)
        drift=copy.deepcopy(inventory);drift['items'][0]['value']={'acl':'changed'}
        for bad in (dict(envelope,inventory=drift),dict(envelope,database='other'),dict(envelope,inventory={**inventory,'version':True})):
            called=mock.Mock(return_value=json.dumps(bad))
            with self.assertRaises(RuntimeError): origin25_schema.require_ready(called)
            called.assert_called_once_with(origin25_schema._SNAPSHOT_SQL)
        for bad in (dict(envelope,extra='unexpected'),dict(envelope,ledger=None)):
            called=mock.Mock(return_value=json.dumps(bad))
            with self.assertRaises(ValueError): origin25_schema.require_ready(called)
            called.assert_called_once_with(origin25_schema._SNAPSHOT_SQL)
        with self.assertRaises(RuntimeError): origin25_schema.require_ready(lambda _: 'x'*(8*1024*1024+1))
        duplicate='{\"database\":\"contour_local\",'+json.dumps(envelope)[1:]
        with self.assertRaises(ValueError): origin25_schema.require_ready(lambda _: duplicate)
        with self.assertRaises(ValueError): origin21_schema.require_ledger(list(range(1,26)))

    def test_reference_mutation_missing_symlink_and_noncanonical_are_rejected(self):
        original=(ROOT/'deploy/local/origin25_reference_25_enrolled.json').read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp).resolve(); path=folder/'origin25_reference_25_enrolled.json'
            with mock.patch.object(origin25_schema,'_REFERENCE_DIR',folder):
                with self.assertRaises((ValueError,OSError)): origin25_schema._reference(25)
                path.write_bytes(original); self.assertEqual(origin25_schema._reference(25)['server_major'],16)
                path.write_bytes(original+b' ')
                with self.assertRaises(ValueError): origin25_schema._reference(25)
                path.unlink(); other=folder/'other';other.write_bytes(original);path.symlink_to(other)
                with self.assertRaises((ValueError,OSError)): origin25_schema._reference(25)
                path.unlink(); value=json.loads(original);raw=json.dumps(value,indent=1).encode();path.write_bytes(raw)
                with mock.patch.object(origin25_schema,'REFERENCE_SHA256',{**origin25_schema.REFERENCE_SHA256,25:hashlib.sha256(raw).hexdigest()}):
                    with self.assertRaises(ValueError): origin25_schema._reference(25)

    def test_reference_identity_and_pg_version_fail_even_with_matching_digest(self):
        original=(ROOT/'deploy/local/origin25_reference_25_enrolled.json').read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp).resolve();path=folder/'origin25_reference_25_enrolled.json'
            for change in ('stage','phase','version','postgres','extra'):
                value=json.loads(original)
                if change=='stage': value['stage']=24
                elif change=='phase': value['phase']='pre'
                elif change=='version': value['inventory']['version']=True
                elif change=='postgres': value['inventory']['server_major']=15
                else: value['unexpected']='extra'
                raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();path.write_bytes(raw)
                with self.subTest(change=change),mock.patch.object(origin25_schema,'_REFERENCE_DIR',folder),mock.patch.object(origin25_schema,'REFERENCE_SHA256',{**origin25_schema.REFERENCE_SHA256,25:hashlib.sha256(raw).hexdigest()}):
                    with self.assertRaises(ValueError): origin25_schema._reference(25)

    def test_migration_stage_is_internal_and_never_public_ready(self):
        for stage in (22,23,24):
            inventory=origin25_schema._reference(stage)
            psql=lambda sql:json.dumps({'database':'contour_local','ledger':list(range(1,stage+1)),'inventory':inventory})
            self.assertIsNone(origin25_schema._require_migration_stage(psql,stage))
            with self.assertRaises(ValueError): origin25_schema.require_ready(psql)
        for stage in (21,25,26,True):
            with self.assertRaises(ValueError): origin25_schema._require_migration_stage(mock.Mock(),stage)

if __name__=='__main__': unittest.main()
