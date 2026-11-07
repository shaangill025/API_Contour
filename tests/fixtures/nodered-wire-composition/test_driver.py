"""Offline controls for portable qualification. No Docker or listeners."""
import importlib.util
from pathlib import Path
import tempfile
import os
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('node_qualification',ROOT/'scripts/test-nodered-wire-composition.py')
q=importlib.util.module_from_spec(spec); spec.loader.exec_module(q)


class DriverTests(unittest.TestCase):
    def test_seven_exact_stage_lists_and_exit_status(self):
        self.assertEqual(len(q.MODES),7)
        for mode,stages in q.MODES.items():
            output=(b'' if mode=='exporter' else q.WIRE_WARNING)+('\n'.join('PASS: '+stage for stage in stages)+'\n').encode()
            q.validate_mode(mode,output,'0')
            for bad,status in ((output,'1'),(output+b'PASS: extra\n','0'),(output+b'FAIL: bad\n','0'),(output+b'partial','0'),(b'unexpected\n'+output,'0'),(output[:-1], '0'),(output+b'\xff','0'),(b'', '0')):
                with self.assertRaises(RuntimeError): q.validate_mode(mode,bad,status)
        with self.assertRaises(RuntimeError): q.validate_mode('other',b'', '0')

    def test_ownership_requires_exact_identity_image_and_namespace(self):
        cid='a'*64; token='b'*32; image='sha256:'+'c'*64; name='owned'
        obj={'Id':cid,'Name':'/'+name,'Image':image,'Config':{'Image':q.IMAGE,'Labels':{q.LABEL:token}},'HostConfig':{'NetworkMode':'none'}}
        q.validate_owned(obj,name,token,cid,image)
        for changes in ({'Id':'d'*64},{'Name':'/other'},{'Image':'sha256:'+'e'*64},{'HostConfig':{'NetworkMode':'bridge'}},{'Config':{'Image':q.IMAGE,'Labels':{q.LABEL:'wrong'}}},{'Config':{'Image':q.IMAGE,'Labels':{q.LABEL:token,'com.docker.compose.project':'foreign'}}}):
            with self.assertRaises(RuntimeError): q.validate_owned(dict(obj,**changes),name,token,cid,image)
        with self.assertRaises(RuntimeError): q.validate_owned(obj,name,token,'invalid',image)

    def test_profile_detects_wrong_source(self):
        snap=q.snapshot(); q.verify_profile(snap)
        altered=dict(snap); altered['collectors/nodered/error-integration/private-handoff.js']='0'*64
        with self.assertRaises(RuntimeError): q.verify_profile(altered)
        altered=dict(snap); altered['collectors/nodered/error-integration/wire-v2-profile.js']='0'*64
        with self.assertRaises(RuntimeError): q.verify_profile(altered)

    def test_platform_and_both_manifest_pins_are_closed(self):
        snap=q.snapshot(); q.verify_profile(snap)
        for arch in ('amd64','arm64'):
            q.validate_image_platform({'Architecture':arch,'Os':'linux'},snap)
        for obj in ({'Architecture':'x64','Os':'linux'}, {'Architecture':'s390x','Os':'linux'},
                    {'Architecture':'amd64','Os':'windows'}, {'Os':'linux'}):
            with self.assertRaises(RuntimeError): q.validate_image_platform(obj,snap)
        for name in ('wire-v2-image-manifest.json','wire-v2-image-manifest-x64.json'):
            rel='collectors/nodered/error-integration/'+name
            for replacement in (None,'0'*64):
                bad=dict(snap)
                if replacement is None: del bad[rel]
                else: bad[rel]=replacement
                with self.assertRaises(RuntimeError): q.verify_profile(bad)
                arch='arm64' if name.endswith('manifest.json') else 'amd64'
                with self.assertRaises(RuntimeError): q.validate_image_platform({'Architecture':arch,'Os':'linux'},bad)
        swapped=dict(snap)
        a='collectors/nodered/error-integration/wire-v2-image-manifest.json'
        b='collectors/nodered/error-integration/wire-v2-image-manifest-x64.json'
        swapped[a],swapped[b]=swapped[b],swapped[a]
        with self.assertRaises(RuntimeError): q.verify_profile(swapped)
        for arch in ('amd64','arm64'):
            with self.assertRaises(RuntimeError): q.validate_image_platform({'Architecture':arch,'Os':'linux'},swapped)

    def test_durable_intent_is_private_and_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp); q.durable_intent(folder,{'mode':'wire-positive'})
            self.assertEqual((folder/'owner-intent.json').stat().st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError): q.durable_intent(folder,{})

    def test_success_needs_expected_stages_and_verified_cleanup(self):
        calls=[]; cid='a'*64
        def checked(args,*_):
            calls.append(args)
            if args[1]=='create': return (cid+'\n').encode()
            if args[1]=='wait': return b'0\n'
            if args[1]=='logs': return q.WIRE_WARNING+b'PASS: synthetic pinned Node-RED mTLS causal wire fixture\n'
            return b''
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(q,'checked',side_effect=checked), mock.patch.object(q,'owned') as owned:
            folder=Path(tmp); q.run_mode('wire-positive',folder,folder,'sha256:'+'b'*64)
        self.assertEqual(owned.call_count,2)
        self.assertEqual(sum(args[1]=='rm' for args in calls),1)

    def test_ambiguous_create_is_failure_even_if_owned_object_cleaned(self):
        cid='a'*64; removed=[]
        def checked(args,*_):
            if args[1]=='create': raise TimeoutError('uncertain')
            if args[1]=='rm': removed.append(args[-1]); return b''
            return b''
        def inspect(name):
            token=name.removeprefix('contour-node-component-')
            return {'Id':cid,'Name':'/'+name,'Image':'sha256:'+'b'*64,'Config':{'Image':q.IMAGE,'Labels':{q.LABEL:token}},'HostConfig':{'NetworkMode':'none'}}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(q,'checked',side_effect=checked), mock.patch.object(q,'inspect',side_effect=inspect), mock.patch.object(q,'owned'):
            with self.assertRaises(RuntimeError): q.run_mode('wire-positive',Path(tmp),Path(tmp),'sha256:'+'b'*64)
        self.assertEqual(removed,[cid])

    def test_foreign_ambiguous_object_is_never_removed(self):
        removed=[]
        def checked(args,*_):
            if args[1]=='create': raise TimeoutError('uncertain')
            if args[1]=='rm': removed.append(args)
            return b''
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(q,'checked',side_effect=checked), mock.patch.object(q,'inspect',return_value={'Id':'a'*64}):
            with self.assertRaises(RuntimeError): q.run_mode('wire-positive',Path(tmp),Path(tmp),'sha256:'+'b'*64)
        self.assertEqual(removed,[])

    def test_failed_stage_still_requires_cleanup_and_fails(self):
        cid='a'*64; removed=[]
        def checked(args,*_):
            if args[1]=='create': return cid.encode()
            if args[1]=='wait': return b'0'
            if args[1]=='logs': return b'PASS: wrong stage\n'
            if args[1]=='rm': removed.append(args[-1])
            return b''
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(q,'checked',side_effect=checked), mock.patch.object(q,'owned'):
            with self.assertRaises(RuntimeError): q.run_mode('wire-positive',Path(tmp),Path(tmp),'sha256:'+'b'*64)
        self.assertEqual(removed,[cid])

    def test_command_timeout_and_output_bound(self):
        with self.assertRaises(TimeoutError):
            q.command([sys.executable,'-c','import time; time.sleep(10)'],timeout=.1,limit=1024)
        # Parent exits while its descendant retains the output pipe. The group
        # is still signalled at the deadline and the wait remains bounded.
        with self.assertRaises(TimeoutError):
            q.command([sys.executable,'-c','import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"])'],timeout=.2,limit=1024)
        with self.assertRaisesRegex(RuntimeError,'output bound'):
            q.command([sys.executable,'-c','import sys; sys.stdout.write("x"*100000); sys.stdout.flush()'],timeout=5,limit=1024)

    def test_denied_group_signal_never_passes(self):
        real_kill=os.killpg
        def denied_after_cleanup(pid, sig):
            real_kill(pid,sig)
            raise PermissionError('simulated denial')
        with mock.patch.object(q.os,'killpg',side_effect=denied_after_cleanup):
            with self.assertRaisesRegex(RuntimeError,'signal denied'):
                q.command([sys.executable,'-c','import time; time.sleep(10)'],timeout=.1,limit=1024)

    def test_directory_sync_before_create(self):
        # Each mode's intent file and its directory are synced before create.
        order=[]; cid='a'*64
        real_intent=q.durable_intent
        def intent(folder,value):
            real_intent(folder,value); order.append('intent')
        def checked(args,*_):
            if args[1]=='create': order.append('create'); return cid.encode()
            if args[1]=='wait': return b'0'
            if args[1]=='logs': return q.WIRE_WARNING+b'PASS: synthetic pinned Node-RED mTLS causal wire fixture\n'
            return b''
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(q,'durable_intent',side_effect=intent), mock.patch.object(q,'checked',side_effect=checked), mock.patch.object(q,'owned'):
            q.run_mode('wire-positive',Path(tmp),Path(tmp),'sha256:'+'b'*64)
        self.assertEqual(order,['intent','create'])

    def test_main_syncs_temp_parent_and_each_mode_directory(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(q.sys,'argv',['driver']), \
             mock.patch.object(q.os,'getuid',return_value=1000), mock.patch.object(q.os,'umask'), \
             mock.patch.object(q.tempfile,'gettempdir',return_value=tmp), \
             mock.patch.object(q,'head_and_clean',return_value='a'*40), mock.patch.object(q,'snapshot',return_value={}), \
             mock.patch.object(q,'verify_profile'), mock.patch.object(q,'validate_image_platform'), mock.patch.object(q,'make_certificates'), \
             mock.patch.object(q,'run_mode'), mock.patch.object(q,'sync_directory') as sync, \
             mock.patch.object(q,'checked',return_value=b'[{"Id":"sha256:' + b'b'*64 + b'","Architecture":"amd64","Os":"linux"}]'), \
             mock.patch('builtins.print'):
            q.main()
        self.assertEqual(sync.call_count,8)
        self.assertEqual(sync.call_args_list[0].args[0],Path(tmp).resolve())
        self.assertTrue(all(call.args[0].parent==Path(tmp).resolve() for call in sync.call_args_list[1:]))

    def test_cli_rejects_arguments_before_external_commands(self):
        with mock.patch.object(q.sys,'argv',['driver','--unknown']), mock.patch.object(q,'head_and_clean') as head:
            with self.assertRaises(ValueError): q.main()
            head.assert_not_called()

    def test_cleanup_failure_prevents_pass(self):
        cid='a'*64
        def checked(args,*_):
            if args[1]=='create': return cid.encode()
            if args[1]=='wait': return b'0'
            if args[1]=='logs': return q.WIRE_WARNING+b'PASS: synthetic pinned Node-RED mTLS causal wire fixture\n'
            if args[1]=='rm': raise RuntimeError('failed')
            return b''
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(q,'checked',side_effect=checked), mock.patch.object(q,'owned'):
            with self.assertRaises(RuntimeError): q.run_mode('wire-positive',Path(tmp),Path(tmp),'sha256:'+'b'*64)


if __name__=='__main__': unittest.main()
