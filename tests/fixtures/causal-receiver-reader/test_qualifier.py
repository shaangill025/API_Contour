"""Offline closed topology and seed controls; no Docker or database."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('reader_qualifier',ROOT/'scripts/test-postgres-causal-receiver-reader.py')
q=importlib.util.module_from_spec(spec); spec.loader.exec_module(q)
T='a'*32; C='b'*64; N='c'*64; I='sha256:'+'d'*64; START='2026-11-12T01:02:03.123456Z'; NAME='contour-origin21-qual-'+T

def sample():
    return {'Id':C,'Name':'/'+NAME+'-postgres','Image':I,'Mounts':[],
      'Config':{'Nested':{'flag':True,'number':1},'Image':q.IMAGE,'Labels':{q.LABEL:T},'Cmd':['postgres'],'Env':['ONE=1']},
      'HostConfig':{'OomKillDisable':False,'Init':True,'Privileged':False,'PublishAllPorts':False,'NetworkMode':N,'PortBindings':{'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]},'Binds':None,'CapAdd':None,'Memory':536870912,'NanoCpus':1000000000,'PidsLimit':128,'Tmpfs':{'/var/lib/postgresql/data':'rw,nosuid,noexec,size=256m'}},
      'State':{'Status':'running','Running':True,'Pid':123,'StartedAt':START},
      'NetworkSettings':{'Networks':{NAME:{'NetworkID':N,'Aliases':['postgres']}},'Ports':{'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':'32768'}]}}}

class Boundaries(unittest.TestCase):
    def test_exact_loopback_and_identity(self):
        source=sample(); self.assertEqual(q.validate_container(source,T,C,I,N,['postgres'],['ONE=1'],START),32768)
        for change in ('port','wildcard','owner','cmd','env','mount','started','network','privileged'):
            x=copy.deepcopy(source)
            if change=='port': x['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']='0'
            if change=='wildcard': x['NetworkSettings']['Ports']['5432/tcp'][0]['HostIp']='0.0.0.0'
            if change=='owner': x['Config']['Labels'][q.LABEL]='e'*32
            if change=='cmd': x['Config']['Cmd'].append('other')
            if change=='env': x['Config']['Env'].append('OTHER=1')
            if change=='mount': x['Mounts'].append({'Type':'bind'})
            if change=='started': x['State']['StartedAt']='2026-11-12T01:02:04Z'
            if change=='network': x['NetworkSettings']['Networks'][NAME]['NetworkID']='f'*64
            if change=='privileged': x['HostConfig']['Privileged']=True
            with self.subTest(change=change),self.assertRaises(ValueError): q.validate_container(x,T,C,I,N,['postgres'],['ONE=1'],START)
    def test_network_requires_exact_no_masquerade_bridge(self):
        network={'Id':N,'Name':NAME,'Internal':False,'Driver':'bridge','Options':dict(q.NETWORK_OPTIONS),'Labels':{q.LABEL:T},'Containers':{}}
        q.validate_network(network,T,N,[])
        for field,value in [('Internal',True),('Driver','host'),('Options',{}),('Options',{**q.NETWORK_OPTIONS,'com.docker.network.bridge.enable_ip_masquerade':'true'}),('Options',{**q.NETWORK_OPTIONS,'com.docker.network.enable_ipv4':'false'}),('Options',{**q.NETWORK_OPTIONS,'com.docker.network.enable_ipv6':'true'}),('Options',{**q.NETWORK_OPTIONS,'unknown':'false'}),('Options',{k:v for k,v in q.NETWORK_OPTIONS.items() if k!='com.docker.network.enable_ipv4'})]:
            bad=copy.deepcopy(network);bad[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):q.validate_network(bad,T,N,[])
        wildcard=sample();wildcard['HostConfig']['PortBindings']['5432/tcp'][0]['HostIp']='0.0.0.0'
        with self.assertRaises(ValueError):q.validate_container(wildcard,T,C,I,N,['postgres'],['ONE=1'],START)
    def test_start_transition_only_env_reordering_and_known_oom_form(self):
        before=q.configuration_snapshot(sample());before['Config']['Env']=['ONE=1','TWO=2']
        running=copy.deepcopy(before);running['Config']['Env'].reverse();running['HostConfig']['OomKillDisable']=None
        q.validate_start_transition(before,running)
        same=copy.deepcopy(before);q.validate_start_transition(before,same)
        missing=sample();del missing['Mounts']
        with self.assertRaises(ValueError):q.configuration_snapshot(missing)
        self.assertFalse(q.exact_json_equal({'v':float('nan')},{'v':float('nan')}))
        for kind in ('true-oom','changed','missing','duplicate','security','mount','cid','bool-int','int-float','missing-null','nan'):
            bad=copy.deepcopy(running)
            if kind=='true-oom':bad['HostConfig']['OomKillDisable']=True
            if kind=='changed':bad['Config']['Env'][0]='TWO=other'
            if kind=='missing':bad['Config']['Env'].pop()
            if kind=='duplicate':bad['Config']['Env'].append('ONE=1')
            if kind=='security':bad['HostConfig']['Privileged']=True
            if kind=='mount':bad['Mounts'].append({'Type':'bind'})
            if kind=='cid':bad['Id']='e'*64
            if kind=='bool-int':bad['Config']['Nested']['flag']=1
            if kind=='int-float':bad['Config']['Nested']['number']=1.0
            if kind=='missing-null':bad['Config']['Nested']['absent']=None
            if kind=='nan':bad['Config']['Nested']['number']=float('nan')
            with self.subTest(kind=kind),self.assertRaises(ValueError):q.validate_start_transition(before,bad)
    def test_ownership_requires_matching_source_generation_and_network(self):
        import json
        class Output:
            def verify(self): pass
        class Tool:
            changed=False;config_drift=False;env_drift=False;oom_drift=False;type_drift=False
            def call(self,args):
                if args[:2]==['docker','inspect']:
                    x=sample()
                    if self.changed: x['State']['StartedAt']='2026-11-12T01:02:04Z'
                    if self.config_drift: x['HostConfig']['Unexpected']='drift'
                    if self.env_drift: x['Config']['Env'].reverse()
                    if self.oom_drift: x['HostConfig']['OomKillDisable']=None
                    if self.type_drift: x['Config']['Nested']['flag']=1
                    return json.dumps([x]).encode()
                return json.dumps([{'Id':N,'Name':NAME,'Internal':False,'Driver':'bridge','Options':dict(q.NETWORK_OPTIONS),'Labels':{q.LABEL:T},'Containers':{C:{}}}]).encode()
            def check(self): pass
        source=object();tool=Tool();fixture={'clean_head':lambda _: 'head','tracked_snapshot':lambda _: {'source':'hash'}}
        fence=q.OwnershipFence(tool,fixture,source,Output(),'head',{'source':'hash'},T,C,I,N,['postgres'],['ONE=1'],START,{k:sample().get(k) for k in ('Id','Name','Image','Config','HostConfig','Mounts')})
        fence();tool.changed=True
        with self.assertRaises(ValueError): fence()
        tool.changed=False;tool.config_drift=True
        with self.assertRaises(RuntimeError): fence()
        tool.config_drift=False;tool.oom_drift=True
        with self.assertRaises(RuntimeError): fence()
        tool.oom_drift=False;tool.type_drift=True
        with self.assertRaises(RuntimeError): fence()
        tool.type_drift=False;fence.head='other'
        with self.assertRaises(RuntimeError): fence()
    def test_tool_fence_checks_before_and_after_each_command(self):
        from types import SimpleNamespace
        class Metadata:
            DOCKER='/fixed/docker'; SOCKET='/fixed/socket'
            changed=False
            def _tool(self,*args): return ('changed' if self.changed else 'tool',)
            def _socket(self,*args): return ('socket',)
            def _config(self,*args): return ('config',)
        m=Metadata(); calls=[]
        def process(args,**kwargs):
            calls.append(args); return SimpleNamespace(returncode=0,stderr=b'',stdout=b'ok\n')
        fence=q.ToolFence(m,'/private/config',process,{})
        self.assertEqual(fence.call(['docker','inspect','x']),b'ok'); self.assertEqual(len(calls),1)
        m.changed=True
        with self.assertRaises(RuntimeError): fence.call(['docker','inspect','x'])
        self.assertEqual(len(calls),1)
        m.changed=False
        def drift(args,**kwargs): m.changed=True; return SimpleNamespace(returncode=0,stderr=b'',stdout=b'ok')
        fence.process=drift
        with self.assertRaises(RuntimeError): fence.call(['docker','inspect','x'])
    def test_transport_only_accepts_exact_owned_container_commands(self):
        from types import SimpleNamespace
        from unittest import mock
        events=[]; held={}
        class Tool:
            metadata=SimpleNamespace(DOCKER='/fixed/docker',SOCKET='/fixed/socket');config='/private/config'
            def check(self): events.append('tool')
        def fresh(sql,env,token,**kwargs): held.update(kwargs);events.append('fresh');return sql
        q.qualified_transport(fresh,'fixed shell',C,T,{},Tool(),lambda **_:events.append('owner'),lambda:events.append('intent'))
        self.assertEqual(events[0],'intent');self.assertEqual(events[1],'fresh')
        with mock.patch('subprocess.run',return_value=SimpleNamespace(returncode=0)) as run:
            held['run'](['docker','kill',C]); self.assertEqual(run.call_args.args[0][-2:],['kill',C])
            with self.assertRaises(ValueError): held['run'](['docker','kill','e'*64])
            self.assertEqual(run.call_count,1)
    def test_artifact_selection_requires_one_new_target_executable(self):
        import json, tempfile
        with tempfile.TemporaryDirectory(dir=Path.home()) as d:
            target=Path(d)/'target';target.mkdir();probe=target/'probe';probe.write_bytes(b'probe');probe.chmod(0o700)
            source=Path(d)/'source.rs'
            def line(p): return json.dumps({'reason':'compiler-artifact','target':{'name':'causal_receiver_reader_probe','kind':['example'],'src_path':str(source)},'profile':{'test':False},'executable':str(p)})
            found,digest=q.select_probe([line(probe)],target,source);self.assertEqual(found,probe);self.assertEqual(len(digest),64)
            issuer_line=line(probe).replace('causal_receiver_reader_probe','causal_receiver_issuer_probe')
            self.assertEqual(q.select_probe([line(probe),issuer_line],target,source,issuer=True)[0],probe)
            with self.assertRaises(ValueError): q.select_probe([line(probe)],target,source,issuer=True)
            with self.assertRaises(ValueError): q.select_probe([issuer_line],target,source,issuer=False)
            with self.assertRaises(ValueError): q.select_probe([issuer_line],target,source,issuer='true')
            with self.assertRaises(ValueError): q.select_probe([line(probe),line(probe)],target,source)
            outside=Path(d)/'outside';outside.write_bytes(b'x');outside.chmod(0o700)
            with self.assertRaises(ValueError): q.select_probe([line(outside)],target,source)
            link=target/'link';link.symlink_to(probe)
            with self.assertRaises(ValueError): q.select_probe([line(link)],target,source)
    def test_two_cargo_examples_select_exact_distinct_issuer_and_reader(self):
        import json,tempfile
        with tempfile.TemporaryDirectory(dir=Path.home()) as folder:
            root=Path(folder);target=root/'target';target.mkdir()
            reader=target/'reader';issuer=target/'issuer'
            for path in (reader,issuer): path.write_bytes(path.name.encode());path.chmod(0o700)
            rsrc=root/'reader.rs';isrc=root/'issuer.rs'
            def line(name,src,exe,kind=['example']):
                return json.dumps({'reason':'compiler-artifact','target':{'name':name,'kind':kind,'src_path':str(src)},'profile':{'test':False},'executable':str(exe)})
            r=line('causal_receiver_reader_probe',rsrc,reader);i=line('causal_receiver_issuer_probe',isrc,issuer)
            self.assertEqual(q.select_probe([r,i],target,rsrc)[0],reader)
            self.assertEqual(q.select_probe([r,i],target,isrc,issuer=True)[0],issuer)
            for lines,source in (([r,i,i],isrc),([r,i],rsrc),([r,line('wrong_target',isrc,issuer)],isrc),([r,line('causal_receiver_issuer_probe',isrc,issuer,kind=['bin'])],isrc)):
                with self.assertRaises(ValueError): q.select_probe(lines,target,source,issuer=True)
            with self.assertRaises(ValueError): q.select_probe([i],target,isrc,issuer=1)

    def test_gateway_is_selected_only_from_the_exact_third_artifact(self):
        import json,tempfile
        with tempfile.TemporaryDirectory(dir=Path.home()) as folder:
            root=Path(folder);target=root/'target';target.mkdir()
            def artifact(name):
                path=target/name;path.write_bytes(name.encode());path.chmod(0o700);return path
            paths=[artifact(name) for name in ('reader','issuer','gateway')]
            sources=[root/(name+'.rs') for name in ('reader','issuer','gateway')]
            names=['causal_receiver_reader_probe','causal_receiver_issuer_probe','causal_gateway_reader_probe']
            def line(name,src,exe,kind=['example']):
                return json.dumps({'reason':'compiler-artifact','target':{'name':name,'kind':kind,'src_path':str(src)},'profile':{'test':False},'executable':str(exe)})
            rows=[line(n,s,p) for n,s,p in zip(names,sources,paths)]
            self.assertEqual(q.select_probe(rows,target,sources[2],gateway=True)[0],paths[2])
            for bad in (rows+[rows[2]], rows[:2], rows[:2]+[line(names[2],sources[0],paths[2])], rows[:2]+[line(names[2],sources[2],paths[2],kind=['bin'])]):
                with self.assertRaises(ValueError): q.select_probe(bad,target,sources[2],gateway=True)
            outside=root/'outside';outside.write_bytes(b'x');outside.chmod(0o700)
            with self.assertRaises(ValueError): q.select_probe([line(names[2],sources[2],outside)],target,sources[2],gateway=True)
            for kwargs in ({'gateway':1},{'gateway':True,'issuer':True}):
                with self.assertRaises(ValueError): q.select_probe(rows,target,sources[2],**kwargs)

    def test_issuer_failure_location_is_closed(self):
        try: exec(compile('raise ValueError("private-canary")','/private/receiver_issuer_fixture.py','exec'))
        except ValueError as error: line=q.failure_diagnostic(error,'issuer')
        self.assertIn('receiver_issuer_fixture.py:1',line)
        self.assertNotIn('private-canary',line);self.assertNotIn('/private/',line)

    def test_probe_snapshot_detects_replaced_and_modified_binary(self):
        import tempfile
        from deploy.local import docker_metadata as metadata
        with tempfile.TemporaryDirectory(dir=Path.home()) as d:
            root=Path(d);root.chmod(0o700);target=root/'target';target.mkdir(mode=0o700)
            probe=target/'probe';probe.write_bytes(b'one');probe.chmod(0o700)
            original=q.probe_snapshot(probe,target,metadata)
            probe.write_bytes(b'two');self.assertNotEqual(q.probe_snapshot(probe,target,metadata),original)
            probe.unlink();probe.symlink_to(target/'missing')
            with self.assertRaises((ValueError,OSError)): q.probe_snapshot(probe,target,metadata)
    def test_diagnostic_is_closed_and_redacts_exception_text(self):
        try: raise ValueError('SENTINEL-PRIVATE-KEY /secret/path SQL')
        except ValueError as error: line=q.failure_diagnostic(error,'schema')
        self.assertEqual(line,'FAIL receiver_reader_fixture phase=schema type=ValueError location=unavailable')
        self.assertNotIn('SENTINEL',line);self.assertNotIn('/secret',line);self.assertNotIn('SQL',line)
        class Unexpected(Exception): pass
        line=q.failure_diagnostic(Unexpected('SENTINEL'),'untrusted-phase')
        self.assertEqual(line,'FAIL receiver_reader_fixture phase=other type=OtherError location=unavailable')
    def test_primary_and_cleanup_failure_are_both_retained(self):
        primary=ValueError('first');cleanup=RuntimeError('second')
        with self.assertRaises(BaseExceptionGroup) as seen:q.raise_failures(primary,[cleanup])
        self.assertEqual(seen.exception.exceptions,(primary,cleanup))
    def test_revocation_seed_is_distinct_and_follows_close(self):
        seed=(ROOT/'tests/fixtures/causal-receiver-reader/seed.sql').read_text();later=q.revocation_seed(seed)
        for value in ("<>3","repeat('e2',32)","repeat('e3',32)","repeat('e4',32)","000000000019'::uuid"):
            self.assertIn(value,later)
        source=(ROOT/'scripts/test-postgres-causal-receiver-reader.py').read_text()
        self.assertLess(source.index("closed=dict(base"),source.index('later=json.loads'))
        self.assertLess(source.index("mode='positive',user='receiver_reader_login'",source.index('later=json.loads')),source.index("credential_revoked','fa000000-0000-4000-8000-000000000003"))
        self.assertLess(source.index("credential_revoked','fa000000-0000-4000-8000-000000000003"),source.index("latest['mode']='unavailable'"))
    def test_build_uses_qualified_absolute_rustc_without_env_injection(self):
        env=q.build_environment({'PATH':'/usr/bin:/bin','HOME':'/private/home'},'/private/target','/qualified/rustc',{'RUSTUP_TOOLCHAIN':'fixed','RUSTC':'/attacker','RUSTFLAGS':'private','PATH':'/attacker'})
        self.assertEqual(env['RUSTC'],'/qualified/rustc');self.assertEqual(env['CARGO_TARGET_DIR'],'/private/target');self.assertEqual(env['PATH'],'/usr/bin:/bin');self.assertEqual(env['RUSTUP_TOOLCHAIN'],'fixed');self.assertNotIn('RUSTFLAGS',env)
        with self.assertRaises(ValueError):q.build_environment({},'/private/target','rustc',{})
    def test_only_closed_distinct_synthetic_login_roles(self):
        p={'reader':'1'*64,'wrong':'2'*64,'mixed':'3'*64};sql=q.reader_login_sql(p)
        self.assertIn('GRANT contour_causal_receiver_reader TO receiver_reader_login;',sql)
        self.assertIn('GRANT contour_causal_issuer TO receiver_wrong_login;',sql)
        self.assertIn('GRANT contour_causal_receiver_reader,contour_causal_issuer TO receiver_mixed_login;',sql)
        for changed in ({**p,'wrong':p['reader']},{**p,'reader':'x'*64},{**p,'extra':'4'*64}):
            with self.assertRaises(ValueError): q.reader_login_sql(changed)
    def test_sensitive_executor_is_distinct_and_uses_one_fresh_request_per_call(self):
        from deploy.local import origin21_logins,origin21_profile
        requests=[]
        def execute(text): requests.append(text);return 'done'
        sensitive=q.dedicated_sensitive_executor(execute)
        self.assertIsNot(sensitive,execute)
        login=origin21_logins.Logins(origin21_profile.PROFILE,execute,sensitive,lambda *_:False)
        self.assertEqual(login.sensitive_execute('one'),'done');self.assertEqual(login.sensitive_execute('two'),'done')
        self.assertEqual(requests,['one','two'])
        with self.assertRaises(ValueError):origin21_logins.Logins(origin21_profile.PROFILE,execute,execute,lambda *_:False)
        transport=(ROOT/'scripts/fixture_psql_transport.py').read_text()
        self.assertIn('timeout -k 1 "$seconds" psql -XAtq',transport)
    def test_reader_hooks_apply_fixture_without_independent_races(self):
        from types import SimpleNamespace
        calls=[]
        base=SimpleNamespace(after_forward=lambda stage,execute:calls.append(('base',stage)))
        delegate=SimpleNamespace(base=base,files={k:k.encode() for k in ('m26','m27','m28','fixture')})
        hooks=q.ReaderHooks(delegate)
        def execute(sql):
            calls.append(sql)
            if sql.startswith('SELECT array_agg'): return '{'+','.join(map(str,range(1,29)))+'}'
        hooks.after_forward(24,execute);hooks.after_forward(25,execute)
        self.assertTrue(hooks.complete);self.assertEqual(calls[2:6],['m26','m27','m28','fixture'])
        with self.assertRaises(RuntimeError): hooks.after_forward(25,execute)
    def test_seed_selects_separate_live_product_and_new_purposes(self):
        seed=(ROOT/'tests/fixtures/causal-receiver-reader/seed.sql').read_text()
        for literal in ("'fc000000-0000-4000-8000-000000000008'::uuid,(SELECT epoch FROM receiver_reader_epoch)", "'fa000000-0000-4000-8000-000000000003'", "repeat('03',32)", "repeat('b8',32)", "repeat('d1',32)", "repeat('d2',32)", "repeat('d3',32)"):
            self.assertIn(literal,seed)
        self.assertNotIn('DELETE FROM',seed);self.assertNotIn('DISABLE TRIGGER',seed)

if __name__=='__main__': unittest.main()
