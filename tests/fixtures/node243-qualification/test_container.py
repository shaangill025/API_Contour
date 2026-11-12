import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile
import os

spec = importlib.util.spec_from_file_location('node243', Path(__file__).resolve().parents[3]/'scripts/qualify-node243-layer.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.cid = 'a'*64
        self.token = 'b'*64
        self.image = 'sha256:'+'c'*64
        self.container = {'Id':self.cid, 'Image':self.image,
            'Config':{'Labels':{m.OWNER:self.token},'User':'node-red','Entrypoint':['/usr/local/bin/node'],'Cmd':['-e',m.PROBE]},
            'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
                'SecurityOpt':['no-new-privileges'],'Memory':536870912,'PidsLimit':32,
                'Tmpfs':{'/data':'rw,noexec,nosuid,size=16m','/tmp':'rw,noexec,nosuid,size=16m'},
                'Privileged':False,'CapAdd':None,'Devices':None,'PidMode':'','IpcMode':'private',
                'UTSMode':'','UsernsMode':'','PortBindings':None,'PublishAllPorts':False,'OomKillDisable':False},
                'Mounts':[],'Created':'created','RestartCount':0,
                'State':{'Running':False,'Status':'created','StartedAt':'0001-01-01T00:00:00Z','ExitCode':0}}

    def test_valid_identity_and_confinement(self):
        m.validate_container(self.container,self.cid,self.token,self.image)

    def test_rejects_identity_or_confinement_drift(self):
        for section, key, value in [('root','Id','d'*64),('root','Image','sha256:'+'e'*64),
            ('Config','Labels',{}),('Config','User','root'),('Config','Cmd',[]),
            ('HostConfig','NetworkMode','bridge'),('HostConfig','ReadonlyRootfs',False),
            ('HostConfig','CapDrop',[]),('HostConfig','SecurityOpt',[]),
            ('HostConfig','Memory',0),('HostConfig','PidsLimit',0),('HostConfig','Tmpfs',{}),
            ('root','Mounts',[{}]),('root','RestartCount',1),('HostConfig','Privileged',True),
            ('HostConfig','CapAdd',['SYS_ADMIN']),('HostConfig','Devices',[{}]),
            ('HostConfig','PidMode','host'),('HostConfig','IpcMode','host'),
            ('HostConfig','PortBindings',{'80/tcp':[{}]}),('HostConfig','OomKillDisable',True),('HostConfig','OomKillDisable',0),('HostConfig','OomKillDisable','false')]:
            with self.subTest(key=key):
                obj=copy.deepcopy(self.container)
                (obj if section=='root' else obj[section])[key]=value
                with self.assertRaises((ValueError, KeyError)):
                    m.validate_container(obj,self.cid,self.token,self.image)


class GenerationTests(ContainerTests):
    def test_generation_fences_config_and_restart(self):
        frozen=m.created_signature(self.container,self.cid,self.token,self.image)
        stopped=copy.deepcopy(self.container)
        stopped['State'].update(Status='exited',StartedAt='2026-11-12T01:02:03Z',ExitCode=0)
        self.assertEqual(m.generation(stopped,self.cid,self.token,self.image,frozen),'2026-11-12T01:02:03Z')
        for change in ('config','restart','exit','start'):
            value=copy.deepcopy(stopped)
            if change=='config': value['Config']['Hostname']='changed'
            if change=='restart': value['RestartCount']=1
            if change=='exit': value['State']['ExitCode']=1
            if change=='start': value['State']['StartedAt']='0001-01-01T00:00:00Z'
            with self.subTest(change=change), self.assertRaises(ValueError):
                m.generation(value,self.cid,self.token,self.image,frozen)

    def test_enabled_oom_default_null_false_transition_only(self):
        frozen=m.created_signature(self.container,self.cid,self.token,self.image)
        stopped=copy.deepcopy(self.container)
        stopped['State'].update(Status='exited',StartedAt='2026-11-12T01:02:03Z',ExitCode=0)
        stopped['HostConfig']['OomKillDisable']=None
        self.assertEqual(m.generation(stopped,self.cid,self.token,self.image,frozen),'2026-11-12T01:02:03Z')
        for bad in (True,0,'false'):
            stopped['HostConfig']['OomKillDisable']=bad
            with self.assertRaises(ValueError):m.generation(stopped,self.cid,self.token,self.image,frozen)
        stopped['HostConfig'].pop('OomKillDisable')
        with self.assertRaises((ValueError,KeyError)):m.generation(stopped,self.cid,self.token,self.image,frozen)

    def test_iid_regular_private_file_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'iid'; path.write_text('sha256:'+'a'*64+'\n'); path.chmod(0o600)
            self.assertEqual(m.image_id_file(path),'sha256:'+'a'*64)
            path.chmod(0o644)
            with self.assertRaises(ValueError): m.image_id_file(path)
            path.unlink(); path.symlink_to('/dev/null')
            with self.assertRaises((ValueError,OSError)): m.image_id_file(path)


class ProbeFenceTests(ContainerTests):
    def test_generation_record_failures_retain_container(self):
        from unittest import mock
        import json
        frozen = m.created_signature(self.container,self.cid,self.token,self.image)
        stopped = copy.deepcopy(self.container)
        stopped['State'].update(Status='exited', StartedAt='2026-11-12T01:02:03.123456789Z', ExitCode=0)
        for failure in ('write', 'fsync', 'verify_before', 'verify_after'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                class Owner:
                    fd = os.open(directory,os.O_RDONLY)
                    count = 0
                    def verify(self):
                        self.count += 1
                        if failure == 'verify_before' or (failure == 'verify_after' and self.count == 2): raise OSError('injected')
                owner=Owner(); calls=[]
                def docker(*args, **kwargs):
                    calls.append(args[0])
                    if args[0]=='start': return b'{}'
                    if args[0]=='inspect': return json.dumps([stopped]).encode()
                    raise AssertionError('unexpected destructive command')
                real_fdopen=os.fdopen
                class FailingWrite:
                    def __init__(self, fd, mode): self.file=real_fdopen(fd,mode)
                    def __enter__(self): return self
                    def __exit__(self,*args): self.file.close()
                    def write(self,data): raise OSError('injected')
                try:
                    with mock.patch.object(m.os,'fdopen',side_effect=FailingWrite) if failure=='write' else mock.patch.object(m.os,'fsync',side_effect=OSError('injected')) if failure=='fsync' else mock.patch.object(m.os,'fsync',wraps=os.fsync):
                        with self.assertRaises(OSError): m.run_probe(docker,owner,'arm64',self.cid,self.token,self.image,frozen)
                    self.assertEqual(calls,['start','inspect'])
                    self.assertNotIn('rm',calls); self.assertNotIn('stop',calls)
                finally: os.close(owner.fd)

    def test_started_at_strict_calendar_and_nanosecond_bounds(self):
        frozen=m.created_signature(self.container,self.cid,self.token,self.image)
        stopped=copy.deepcopy(self.container)
        stopped['State'].update(Status='exited', ExitCode=0)
        for value in ('', '0001-01-01T00:00:00Z', '2026-02-30T00:00:00Z',
                      '2026-11-12T25:00:00Z', '2026-11-12T01:02:03.1234567890Z',
                      '2026-11-12T01:02:03+00:00', 'garbage', None):
            stopped['State']['StartedAt']=value
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.generation(stopped,self.cid,self.token,self.image,frozen)
        for value in ('2026-11-12T01:02:03Z','2026-11-12T01:02:03.123456789Z'):
            stopped['State']['StartedAt']=value
            self.assertEqual(m.generation(stopped,self.cid,self.token,self.image,frozen),value)
