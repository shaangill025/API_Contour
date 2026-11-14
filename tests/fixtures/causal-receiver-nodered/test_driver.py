import copy
import importlib.util
import json
import os
import tempfile
import stat
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('qualify_receiver', ROOT/'scripts/qualify-receiver-nodered.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
CID = 'a'*64
TOKEN = 'b'*64
IMAGE = 'sha256:'+'c'*64
SOURCE = Path('/owned/source')
SCRIPT = m.SCRIPTS['identity'][0]


def container():
    return {'Id':CID,'Image':IMAGE,'Created':'2026-11-12T00:00:00Z','RestartCount':0,
        'Config':{'User':'node-red','Entrypoint':['/usr/local/bin/node'],'Cmd':[SCRIPT],'Labels':{m.OWNER:TOKEN}},
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
            'Memory':536870912,'PidsLimit':32,'Privileged':False,'CapAdd':None,'Devices':None,'PidMode':'',
            'IpcMode':'private','UTSMode':'','UsernsMode':'','PortBindings':None,'PublishAllPorts':False,
            'AutoRemove':False,'RestartPolicy':{'Name':'no'},'OomKillDisable':False,
            'Tmpfs':{'/data':'rw,noexec,nosuid,size=16m,uid=1000,gid=1000,mode=0700','/tmp':'rw,noexec,nosuid,size=16m'}},
        'Mounts':[{'Type':'bind','Source':str(SOURCE),'Destination':'/work','RW':False},
                  {'Type':'tmpfs','Destination':'/data'},{'Type':'tmpfs','Destination':'/tmp'}],
        'State':{'Status':'created','Running':False,'ExitCode':0,'StartedAt':'0001-01-01T00:00:00Z'}}


class Fences(unittest.TestCase):
    def test_created_and_exit_generation(self):
        c = container(); frozen = m.created(c,CID,TOKEN,IMAGE,SCRIPT,SOURCE)
        c['State'] = {'Status':'exited','Running':False,'ExitCode':0,'StartedAt':'2026-11-12T01:02:03.123456789Z'}
        c['HostConfig']['OomKillDisable'] = None
        self.assertEqual(m.generation(c,CID,TOKEN,IMAGE,SCRIPT,SOURCE,frozen),c['State']['StartedAt'])
        for state in ({'Status':'exited','Running':False,'ExitCode':1,'StartedAt':'2026-11-12T01:02:03Z'},
                      {'Status':'running','Running':True,'ExitCode':0,'StartedAt':'2026-11-12T01:02:03Z'},
                      {'Status':'exited','Running':False,'ExitCode':0,'StartedAt':'2026-02-30T01:02:03Z'}):
            c['State'] = state
            with self.assertRaises(ValueError): m.generation(c,CID,TOKEN,IMAGE,SCRIPT,SOURCE,frozen)

    def test_isolation_and_config_drift(self):
        base = container(); frozen = m.created(base,CID,TOKEN,IMAGE,SCRIPT,SOURCE)
        for section,key,value in [('HostConfig','NetworkMode','host'),('HostConfig','Privileged',True),
                                  ('HostConfig','ReadonlyRootfs',False),('HostConfig','PidsLimit',0),
                                  ('HostConfig','CapAdd',['SYS_ADMIN']),('HostConfig','OomKillDisable',True),
                                  ('Config','Cmd',['/other']),('Config','User','root')]:
            with self.subTest(section=section,key=key):
                c = copy.deepcopy(base); c[section][key] = value
                with self.assertRaises(ValueError): m.created(c,CID,TOKEN,IMAGE,SCRIPT,SOURCE)
        c = copy.deepcopy(base); c['HostConfig']['UnexpectedSetting'] = 'changed'
        c['State'] = {'Status':'exited','Running':False,'ExitCode':0,'StartedAt':'2026-11-12T01:02:03Z'}
        with self.assertRaises(ValueError): m.generation(c,CID,TOKEN,IMAGE,SCRIPT,SOURCE,frozen)

    def test_data_tmpfs_permission_model_and_exact_options(self):
        # Prior default root:root 0755 denies the observed uid 1000; the new
        # dedicated uid 1000 0700 directory permits only its owner to write.
        def writable(uid, owner, group_member, mode):
            bits = (mode >> 6) if uid == owner else ((mode >> 3) if group_member else mode)
            return bool(bits & 0o2)
        self.assertFalse(writable(1000,0,False,0o755))
        self.assertTrue(writable(1000,1000,True,0o700))
        self.assertFalse(writable(1001,1000,True,0o700))
        self.assertFalse(writable(1001,1000,False,0o700))
        valid = container(); m.created(valid,CID,TOKEN,IMAGE,SCRIPT,SOURCE)
        for bad in ('rw,noexec,nosuid,size=16m',
                    'rw,noexec,nosuid,size=16m,uid=0,gid=1000,mode=0700',
                    'rw,noexec,nosuid,size=16m,uid=1000,gid=0,mode=0700',
                    'rw,noexec,nosuid,size=16m,uid=1000,gid=1000,mode=0777'):
            c = copy.deepcopy(valid); c['HostConfig']['Tmpfs']['/data'] = bad
            with self.subTest(options=bad), self.assertRaises(ValueError):
                m.created(c,CID,TOKEN,IMAGE,SCRIPT,SOURCE)

    def test_tmpfs_inspect_models_and_partial_rejection(self):
        both = container()
        m.created(both,CID,TOKEN,IMAGE,SCRIPT,SOURCE)
        bind_only = copy.deepcopy(both); bind_only['Mounts'] = bind_only['Mounts'][:1]
        m.created(bind_only,CID,TOKEN,IMAGE,SCRIPT,SOURCE)
        partial = copy.deepcopy(both); partial['Mounts'] = partial['Mounts'][:2]
        with self.assertRaises(ValueError): m.created(partial,CID,TOKEN,IMAGE,SCRIPT,SOURCE)
        other = copy.deepcopy(both); other['Mounts'][2]['Destination'] = '/elsewhere'
        with self.assertRaises(ValueError): m.created(other,CID,TOKEN,IMAGE,SCRIPT,SOURCE)
        other = copy.deepcopy(bind_only); del other['HostConfig']['Tmpfs']['/tmp']
        with self.assertRaises(ValueError): m.created(other,CID,TOKEN,IMAGE,SCRIPT,SOURCE)

    def test_mounts_identity_and_owner(self):
        for change in ('rw','source','extra','owner','image'):
            with self.subTest(change=change):
                c = container()
                if change == 'rw': c['Mounts'][0]['RW'] = True
                if change == 'source': c['Mounts'][0]['Source'] = '/other'
                if change == 'extra': c['Mounts'].append({'Type':'bind','Destination':'/extra'})
                if change == 'owner': c['Config']['Labels'][m.OWNER] = 'other'
                if change == 'image': c['Image'] = 'sha256:'+'d'*64
                with self.assertRaises(ValueError): m.created(c,CID,TOKEN,IMAGE,SCRIPT,SOURCE)

    def test_image_identity_platform_environment(self):
        image = {'Id':IMAGE,'Os':'linux','Architecture':'arm64', 'Config':{'Labels':{m.OWNER:TOKEN},'Env':['NODE_VERSION=24.22.3']}}
        m.check_image(image,IMAGE,'arm64',TOKEN)
        for key,value in [('Architecture','amd64'),('Id','sha256:'+'d'*64)]:
            other = copy.deepcopy(image); other[key] = value
            with self.assertRaises(ValueError): m.check_image(other,IMAGE,'arm64',TOKEN)
        other = copy.deepcopy(image); other['Config']['Env'].append('NODE_VERSION=24.22.3')
        with self.assertRaises(ValueError): m.check_image(other,IMAGE,'arm64',TOKEN)

    def test_retention_and_durable_cleanup_order(self):
        for failure in ('create', 'start', 'exit', 'second_inspect', None):
            events = []
            inspect_count = 0
            def record(_owner, name, _value): events.append(('record', name.split('-')[0]))
            def docker(*args, **kwargs):
                nonlocal inspect_count
                events.append(('docker', args[0]))
                if args[0] == 'create':
                    self.assertIn('/data:rw,noexec,nosuid,size=16m,uid=1000,gid=1000,mode=0700',args)
                    self.assertIn('/tmp:rw,noexec,nosuid,size=16m',args)
                    if failure == 'create': raise RuntimeError('unknown create')
                    return (CID+'\n').encode()
                if args[0] == 'start':
                    if failure == 'start': raise RuntimeError('unknown execution')
                    return m.SCRIPTS['identity'][1]
                if args[0] == 'inspect':
                    inspect_count += 1
                    c = container()
                    if inspect_count > 1:
                        c['State'] = {'Status':'exited','Running':False,'ExitCode':1 if failure == 'exit' else 0,
                                      'StartedAt':'2026-11-12T01:02:03Z'}
                    if inspect_count == 3 and failure == 'second_inspect': c['RestartCount'] = 1
                    return json.dumps([c]).encode()
                return b''
            with self.subTest(failure=failure), patch.object(m,'record',record):
                if failure:
                    with self.assertRaises((ValueError,RuntimeError)):
                        m.run_case(docker,None,'arm64','identity',IMAGE,TOKEN,SOURCE)
                    self.assertNotIn(('docker','rm'),events)
                else:
                    m.run_case(docker,None,'arm64','identity',IMAGE,TOKEN,SOURCE)
                    self.assertLess(events.index(('record','intent')),events.index(('docker','create')))
                    self.assertLess(events.index(('record','cid')),events.index(('docker','start')))
                    self.assertLess(events.index(('record','generation')),events.index(('docker','rm')))
                    self.assertGreater(events.index(('docker','ps')),events.index(('docker','rm')))

    def test_arbitrary_tool_hash_rejected_before_spawn(self):
        for value in ('0'*64, 'not-a-hash', ''):
            run = Mock(); shared = Mock()
            args = SimpleNamespace(docker_sha256=value, docker='/arbitrary/tool', receipt='/arbitrary/receipt')
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'unqualified docker hash'):
                m.qualify(args,shared,run,None)
            run.assert_not_called()
            shared.checked_path.assert_not_called()

    def test_docker_tool_private_executable_and_parent_guards(self):
        with tempfile.TemporaryDirectory(prefix='contour-tool-test-',dir=Path.home()) as directory:
            root = Path(directory); root.chmod(0o700)
            tool = root/'docker'; tool.write_bytes(b'executable'); tool.chmod(0o500)
            identity, digest = m.tool_snapshot(tool,True)
            self.assertEqual(len(digest),64); self.assertEqual(m.tool_snapshot(tool)[0],identity)
            tool.chmod(0o700)
            with self.assertRaises(ValueError): m.tool_snapshot(tool)
            tool.chmod(0o500)
            hard = root/'hard'; os.link(tool,hard)
            with self.assertRaises(ValueError): m.tool_snapshot(tool)
            hard.unlink()
            link = root/'link'; link.symlink_to(tool)
            with self.assertRaises((ValueError,OSError)): m.tool_snapshot(link)
            actual_fstat = os.fstat
            def wrong_owner(fd):
                result = actual_fstat(fd)
                if stat.S_ISREG(result.st_mode):
                    return SimpleNamespace(st_mode=result.st_mode,st_uid=os.geteuid()+1)
                return result
            with patch.object(m.os,'fstat',side_effect=wrong_owner):
                with self.assertRaises(ValueError): m.tool_snapshot(tool)
            parent = root/'unsafe'; parent.mkdir(mode=0o700)
            child = parent/'private'; child.mkdir(mode=0o700)
            nested = child/'docker'; nested.write_bytes(b'executable'); nested.chmod(0o500)
            parent.chmod(0o777)
            try:
                with self.assertRaises(ValueError): m.tool_snapshot(nested)
            finally: parent.chmod(0o700)
            alias = root/'alias'; alias.symlink_to(child,target_is_directory=True)
            with self.assertRaises((ValueError,OSError)): m.tool_snapshot(alias/'docker')

    def test_receipt_private_file_and_parent_guards(self):
        with tempfile.TemporaryDirectory(prefix='contour-receipt-test-',dir=Path.home()) as directory:
            root = Path(directory); root.chmod(0o700)
            f = root/'receipt.json'; f.write_bytes(b'{}'); f.chmod(0o600)
            raw, _ = m.receipt_file(f); self.assertEqual(raw,b'{}')
            f.chmod(0o644)
            with self.assertRaises(ValueError): m.receipt_file(f)
            f.chmod(0o600)
            hard = root/'hard'; os.link(f,hard)
            with self.assertRaises(ValueError): m.receipt_file(f)
            hard.unlink()
            link = root/'link'; link.symlink_to(f)
            with self.assertRaises((ValueError,OSError)): m.receipt_file(link)
            root.chmod(0o755)
            try:
                with self.assertRaises(ValueError): m.receipt_file(f)
            finally: root.chmod(0o700)
            intermediate = root/'unsafe'; intermediate.mkdir(mode=0o700)
            nested = intermediate/'private'; nested.mkdir(mode=0o700)
            child = nested/'receipt'; child.write_bytes(b'{}'); child.chmod(0o600)
            intermediate.chmod(0o777)
            try:
                with self.assertRaises(ValueError): m.receipt_file(child)
            finally: intermediate.chmod(0o700)
            alias = root/'alias'; alias.symlink_to(nested, target_is_directory=True)
            with self.assertRaises((ValueError,OSError)): m.receipt_file(alias/'receipt')

    def test_receipt_invalid_and_duplicate_json(self):
        with self.assertRaises(ValueError): m.receipt(b'{"token":"a","token":"b"}')
        probe = {'sha256':'d'*64,'size':123,'mode':493,'uid':0,'gid':0,'user':1000}
        r = {'token':TOKEN,'scope':'version-native-bcrypt-config-and-layer-prefix','images':{x:{'image':IMAGE,'probe':probe} for x in ('arm64','amd64')}}
        self.assertEqual(m.receipt(json.dumps(r).encode())['token'],TOKEN)
        r['images']['arm64']['probe']['user'] = 1001
        with self.assertRaises(ValueError): m.receipt(json.dumps(r).encode())
        r['images']['arm64']['probe']['user'] = 1000
        r['images']['arm64']['probe']['size'] = True
        with self.assertRaises(ValueError): m.receipt(json.dumps(r).encode())


if __name__ == '__main__': unittest.main()
