"""Offline ownership/fence tests; no Docker or private credential access."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('receiver504_runner',ROOT/'scripts/qualify-receiver504.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
CID='a'*64;TOKEN='b'*64;IMAGE='sha256:'+'c'*64;SOURCE=Path('/owned/source');MATERIAL=Path('/owned/material');SCRIPT=m.SCRIPTS['component'][0]
def container():
 mounts=[{'Type':'bind','Source':src,'Destination':dst,'RW':False} for dst,src in m.mount_map(SOURCE,MATERIAL).items()]+[{'Type':'tmpfs','Destination':'/data'},{'Type':'tmpfs','Destination':'/tmp'}]
 return {'Id':CID,'Image':IMAGE,'Created':'2026-11-12T00:00:00Z','RestartCount':0,'Config':{'User':str(os.getuid())+':'+str(os.getgid()),'Hostname':'causal-live','OpenStdin':True,'Tty':False,'StdinOnce':True,'Entrypoint':['/bin/sh'],'Cmd':['-c',m.PARENT_COMMAND],'Labels':{m.OWNER:TOKEN}},'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':536870912,'PidsLimit':32,'Privileged':False,'CapAdd':None,'Devices':None,'PidMode':'','IpcMode':'private','UTSMode':'','UsernsMode':'','PortBindings':None,'PublishAllPorts':False,'AutoRemove':False,'RestartPolicy':{'Name':'no'},'OomKillDisable':False,'Tmpfs':{'/data':m.DATA_TMPFS,'/tmp':m.TMP_TMPFS},'ExtraHosts':['causal-receiver:127.0.0.1','causal-ingress:127.0.0.1','pilot-gateway:127.0.0.1']},'Mounts':mounts,'State':{'Status':'created','Running':False,'ExitCode':0,'StartedAt':'0001-01-01T00:00:00Z'}}
class Fences(unittest.TestCase):
 def test_mounts_and_stdin_isolation(self):
  obj=container();frozen=m.created(obj,CID,TOKEN,IMAGE,SCRIPT,SOURCE,MATERIAL)
  self.assertNotIn('/fixture',m.mount_map(SOURCE,MATERIAL));self.assertEqual(len(m.MATERIAL_NAMES),9)
  for change in ('write','source','missing','extra','alias','network','uid','stdin','tty','once','shell'):
   item=copy.deepcopy(obj)
   if change=='write':item['Mounts'][0]['RW']=True
   if change=='source':item['Mounts'][0]['Source']='/foreign'
   if change=='missing':item['Mounts'].pop(0)
   if change=='extra':item['Mounts'].append({'Type':'bind','Source':'/x','Destination':'/fixture','RW':False})
   if change=='alias':item['HostConfig']['ExtraHosts'].append('foreign:127.0.0.1')
   if change=='network':item['HostConfig']['NetworkMode']='host'
   if change=='uid':item['Config']['User']='root'
   if change=='stdin':item['Config']['OpenStdin']=False
   if change=='tty':item['Config']['Tty']=True
   if change=='once':item['Config']['StdinOnce']=False
   if change=='shell':item['Config']['Cmd']=['-c',m.PARENT_COMMAND+'; echo injected']
   with self.subTest(change=change),self.assertRaises(ValueError):m.created(item,CID,TOKEN,IMAGE,SCRIPT,SOURCE,MATERIAL)
  obj['State']={'Status':'exited','Running':False,'ExitCode':0,'StartedAt':'2026-11-12T01:02:03Z'}
  self.assertEqual(m.generation(obj,CID,TOKEN,IMAGE,SCRIPT,SOURCE,MATERIAL,frozen),obj['State']['StartedAt'])
  obj['Config']['Cmd']=['/foreign']
  with self.assertRaises(ValueError):m.generation(obj,CID,TOKEN,IMAGE,SCRIPT,SOURCE,MATERIAL,frozen)
 def test_adapter_mounts_match_manifest_closure_without_nested_readonly_ancestor(self):
  import json
  manifest=json.loads((ROOT/'collectors/nodered/receiver-integration/manifest-504.json').read_text())
  mounts=m.mount_map(SOURCE,MATERIAL)
  expected=set(manifest['files'])|{'/adapter/receiver-integration/artifact-504.json','/adapter/receiver-integration/manifest-504.json','/adapter/live-integration/tree-arm64.json','/adapter/live-integration/tree-x64.json'}
  self.assertEqual({p for p in mounts if p.startswith('/adapter/')},expected)
  for target in manifest['files']:
   self.assertEqual(mounts[target],str(SOURCE/'collectors/nodered'/target.removeprefix('/adapter/')))
  m.no_nested_bind_targets(mounts)
  with self.assertRaises(ValueError):m.no_nested_bind_targets([*mounts,'/adapter'])
  item=container();item['Mounts'].append({'Type':'bind','Source':'/foreign','Destination':'/adapter','RW':False})
  with self.assertRaises(ValueError):m.created(item,CID,TOKEN,IMAGE,SCRIPT,SOURCE,MATERIAL)
 def test_material_inventory_and_privacy(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
   path=Path(tmp);path.chmod(0o700)
   for name in m.MATERIAL_NAMES:(path/name).write_bytes(b'synthetic');(path/name).chmod(0o600)
   self.assertEqual(len(m.material_snapshot(path)[1]),9)
   (path/'extra').write_bytes(b'x')
   with self.assertRaises(ValueError):m.material_snapshot(path)
   (path/'extra').unlink();(path/'server.key').chmod(0o644)
   with self.assertRaises(ValueError):m.material_snapshot(path)
 def test_unverified_create_is_retained(self):
  calls=[]
  def docker(*args,**kw):
   calls.append(args[0]);return CID.encode() if args[0]=='create' else b'[]'
  with patch.object(m,'record') as record:
   with self.assertRaises(ValueError):m.run_case(docker,Mock(),'arm64','component',IMAGE,TOKEN,SOURCE,MATERIAL,Path('/owned/input'),'d'*64)
  self.assertEqual(calls,['create','inspect']);self.assertEqual(record.call_count,2)
 def test_failed_start_retains_exact_created_container(self):
  calls=[]
  def docker(*args,**kw):
   calls.append(args[0])
   if args[0]=='create':return CID.encode()
   if args[0]=='inspect':return b'ignored'
   if args[0]=='start-private':raise RuntimeError('uncertain')
   raise AssertionError('unexpected cleanup')
  with patch.object(m,'record') as record,patch.object(m,'one',return_value=container()):
   with self.assertRaises(RuntimeError):m.run_case(docker,Mock(),'arm64','component',IMAGE,TOKEN,SOURCE,MATERIAL,Path('/owned/input'),'d'*64)
  self.assertEqual(calls,['create','inspect','start-private']);self.assertEqual(record.call_count,3)
 def test_failure_location_is_closed_and_excludes_exception_data(self):
  try:m.fail('private-path-secret-and-sql')
  except ValueError as error:
   locations=m.failure_locations(error)
   self.assertTrue(locations);self.assertTrue(all(__import__('re').fullmatch(r'qualify-receiver504\.py:[1-9][0-9]{0,6}',x) for x in locations))
   self.assertNotIn('private',repr(locations));self.assertNotIn('secret',repr(locations))
   group=ExceptionGroup('private',[error,ValueError('private')]);self.assertEqual(m.failure_locations(group),locations)
  try:raise ValueError('foreign-private')
  except ValueError as foreign:self.assertEqual(m.failure_locations(foreign),[])
 def test_shared_runner_location_is_allowlisted_without_error_payload(self):
  shared=str(ROOT/'scripts/qualify-origin21-onboarding.py')
  try:exec(compile("raise RuntimeError('synthetic-secret/private-path')",shared,'exec'),{})
  except RuntimeError as error:
   locations=m.failure_locations(error)
   self.assertEqual(locations,['qualify-origin21-onboarding.py:1'])
   self.assertNotIn('secret',repr(locations));self.assertNotIn('private',repr(locations))
  try:exec(compile("raise RuntimeError('private')",'/foreign/qualify-origin21-onboarding.py','exec'),{})
  except RuntimeError as error:self.assertEqual(m.failure_locations(error),[])
 def test_preflight_failure_has_closed_stage(self):
  from types import SimpleNamespace
  progress={'phase':'setup'}
  with self.assertRaises(ValueError):m.qualify(SimpleNamespace(docker_sha256='wrong'),Mock(),Mock(),Mock(),progress)
  self.assertEqual(progress['phase'],'tool');self.assertIn(progress['phase'],m.PHASES)
 def test_endpoint_drift_stops_before_start_or_removal(self):
  for failure in ('after-create','before-start','before-rm'):
   calls=[];state={'endpoint':'old','inspects':0}
   def observe():return state['endpoint']
   def underlying(*args,**kw):
    calls.append(args[0])
    if args[0]=='create':
     if failure=='after-create':state['endpoint']='new'
     return CID.encode()
    if args[0]=='inspect':
     state['inspects']+=1;obj=container()
     if state['inspects']>1:obj['State']={'Status':'exited','Running':False,'ExitCode':0,'StartedAt':'2026-11-12T01:02:03Z'}
     if failure=='before-rm' and state['inspects']==3:state['endpoint']='new'
     import json
     return json.dumps([obj]).encode()
    if args[0]=='start-private':return b''
    raise AssertionError('unexpected removal')
   def guarded(*args,**kw):return m.endpoint_call('old',observe,lambda:underlying(*args,**kw))
   def record(_owner,name,_value):
    if failure=='before-start' and name.startswith('created-'):state['endpoint']='new'
   with self.subTest(failure=failure),patch.object(m,'record',side_effect=record),self.assertRaises(ValueError):
    m.run_case(guarded,Mock(),'arm64','component',IMAGE,TOKEN,SOURCE,MATERIAL,Path('/owned/input'),'d'*64)
   self.assertNotIn('rm',calls)
   if failure in ('after-create','before-start'):self.assertNotIn('start-private',calls)
if __name__=='__main__':unittest.main()
