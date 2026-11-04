import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock
import subprocess

MODULE=runpy.run_path(str(Path(__file__).resolve().parents[3]/'scripts/test-postgres-causal-registry.py'))


class DriverTests(unittest.TestCase):
    def test_foreign_container_never_removed(self):
        calls=[]
        def run(args):
            calls.append(args)
            return json.dumps([{'Id':'b'*64,'Name':'/foreign','Config':{'Labels':{}}}])
        with self.assertRaises(RuntimeError): MODULE['cleanup_owned'](run,'a'*64,'expected','run')
        self.assertEqual(len(calls),1)

    def test_create_timeout_recovers_and_removes_exact_owned_id(self):
        main=MODULE['main']; g=main.__globals__; calls=[]; cid='a'*64
        def fake(args, **kwargs):
            calls.append(args)
            if args[1:3]==['image','inspect']: return subprocess.CompletedProcess(args,0,'','')
            if args[1]=='create': raise subprocess.TimeoutExpired(args,30)
            if args[1]=='inspect':
                name=args[2]
                if name==cid: name=next(x[x.index('--name')+1] for x in calls if 'create' in x)
                create=next(x for x in calls if 'create' in x)
                label=create[create.index('--label')+1].split('=',1)[1]
                return subprocess.CompletedProcess(args,0,json.dumps([{'Id':cid,'Name':'/'+name,'Config':{'Labels':{'org.apicontour.registry-run':label}}}]),'')
            return subprocess.CompletedProcess(args,0,'','')
        with mock.patch.dict(g, {'source_snapshot':lambda: {}, 'verify_qualified_profile':lambda: None}), \
             mock.patch.object(g['subprocess'],'run',side_effect=fake), mock.patch.object(g['sys'] if 'sys' in g else __import__('sys'),'argv',['driver']):
            with self.assertRaises(subprocess.TimeoutExpired): main()
        self.assertIn(['docker','rm','-f',cid],calls)

    def test_malformed_create_output_recovers_owned_container(self):
        main=MODULE['main']; g=main.__globals__; calls=[]; cid='b'*64
        def fake(args, **kwargs):
            calls.append(args)
            if args[1]=='create': return subprocess.CompletedProcess(args,0,'truncated-id','')
            if args[1]=='inspect':
                create=next(x for x in calls if 'create' in x)
                name=create[create.index('--name')+1]
                label=create[create.index('--label')+1].split('=',1)[1]
                return subprocess.CompletedProcess(args,0,json.dumps([{'Id':cid,'Name':'/'+name,'Config':{'Labels':{'org.apicontour.registry-run':label}}}]),'')
            return subprocess.CompletedProcess(args,0,'','')
        with mock.patch.dict(g, {'source_snapshot':lambda: {}, 'verify_qualified_profile':lambda: None}), \
             mock.patch.object(g['subprocess'],'run',side_effect=fake), mock.patch.object(__import__('sys'),'argv',['driver']):
            with self.assertRaisesRegex(RuntimeError,'invalid container identity'): main()
        self.assertIn(['docker','rm','-f',cid],calls)

    def test_recovery_rejects_foreign_and_inspection_errors(self):
        recover=MODULE['recover_owned_container']; cid='a'*64
        with self.assertRaises(RuntimeError): recover(lambda name:[{'Id':cid,'Name':'/'+name,'Config':{'Labels':{'org.apicontour.registry-run':'foreign'}}}],'owned','expected')
        with self.assertRaises(RuntimeError): recover(lambda name: (_ for _ in ()).throw(RuntimeError('daemon unavailable')),'owned','expected')
        self.assertIsNone(recover(lambda name:None,'owned','expected'))

    def test_cleanup_failure_propagates(self):
        cid='a'*64
        def run(args):
            if args[1]=='inspect': return json.dumps([{'Id':cid,'Name':'/owned','Config':{'Labels':{'org.apicontour.registry-run':'id'}}}])
            raise RuntimeError('remove failed')
        with self.assertRaises(RuntimeError): MODULE['cleanup_owned'](run,cid,'owned','id')

    def test_manifest_and_source_fail_closed(self):
        f=MODULE['verify_qualified_profile']; old=f.__globals__['ROOT']; digest=f.__globals__['MANIFEST_SHA256']
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); f.__globals__['ROOT']=root
            try:
                with self.assertRaises(ValueError): f()
                source=root/'collectors/nodered/error-integration/profile.js'; source.parent.mkdir(parents=True); source.write_text('fixture')
                manifest=root/'collectors/nodered/qualified-runtime-profile.json'
                data={'profile_id':'00000000-0000-4000-8000-000000000501','profile_source':'collectors/nodered/error-integration/profile.js','profile_source_sha256':hashlib.sha256(b'fixture').hexdigest()}
                canonical=json.dumps(data,sort_keys=True,separators=(',',':')).encode(); manifest.write_bytes(canonical+b'\n')
                f.__globals__['MANIFEST_SHA256']=hashlib.sha256(canonical).hexdigest(); f()
                source.write_text('changed')
                with self.assertRaises(ValueError): f()
                source.write_text('fixture'); manifest.write_bytes(canonical+b' \n')
                with self.assertRaises(ValueError): f()
                manifest.unlink(); manifest.symlink_to(source)
                with self.assertRaises(ValueError): f()
            finally: f.__globals__['ROOT']=old; f.__globals__['MANIFEST_SHA256']=digest

    def test_unrelated_database_failure_is_not_expected_failure(self):
        f=MODULE['verify_migration_failures']; original=f.__globals__['verify_qualified_profile']; f.__globals__['verify_qualified_profile']=lambda:None
        try:
            def execute(sql):
                if sql.startswith('SELECT'): return 'true'
                raise MODULE['PostgresDiagnosticError']('42830','unrelated foreign key')
            with self.assertRaises(AssertionError): f(execute,'unused')
        finally: f.__globals__['verify_qualified_profile']=original


if __name__=='__main__': unittest.main()
