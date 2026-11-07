#!/usr/bin/env python3
"""Owned synthetic native-edge rotation; no primary DB or persisted capture.

Requires a clean committed checkout, cached pinned images and Docker. Creates
only uniquely labelled resources; an uncertain create is never accepted.
"""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from deploy.gateway.managed_edge import ManagedEdge,NativeReplicaPeer
from deploy.pilot import native_envoy,native_gateway_config
from deploy.pilot.managed_edge_controller import ManagedEdgeController,LABEL

NODE='docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'
ENVOY='envoyproxy/envoy:v1.37.11@sha256:7765ad61185fca9c9a770c9e2cad640d085d708ae9c22f3741345e88331472a4'
ID='00000000-0000-4000-8000-000000000001'
FIXTURE=ROOT/'tests/fixtures/managed-native-edge'


def source_snapshot(run):
    head=run(['git','rev-parse','HEAD'],timeout=15).decode().strip()
    if not re.fullmatch('[0-9a-f]{40}',head): raise ValueError('source head invalid')
    if run(['git','status','--porcelain','--untracked-files=all'],timeout=15): raise ValueError('clean frozen source required')
    paths=run(['git','ls-files','-z'],timeout=15).split(b'\0'); result={}
    for value in paths:
        if not value: continue
        path=ROOT/os.fsdecode(value)
        if any(p.is_symlink() for p in (path,*path.parents)) or not path.is_file(): raise ValueError('unsafe source')
        result[str(path.relative_to(ROOT))]=hashlib.sha256(path.read_bytes()).hexdigest()
    return head,result


def run_process_helper():
    path=ROOT/'scripts/test-postgres-causal-bridge.py'
    if any(p.is_symlink() for p in (path,*path.parents)) or not path.is_file(): raise ValueError('unsafe helper')
    digest=hashlib.sha256(path.read_bytes()).digest(); module=runpy.run_path(str(path))
    if hashlib.sha256(path.read_bytes()).digest()!=digest: raise ValueError('helper changed')
    return module['run_process']


def command(runner,args,*,data=None,timeout=30,limit=1048576,allow_absent=False):
    result=runner(args,data=data,cwd=ROOT,env=os.environ.copy(),timeout=timeout,limit=limit)
    if result.returncode:
        if allow_absent and re.fullmatch(rb'Error: No such object: '+re.escape(args[-1].encode())+rb'\s*',result.stderr): return None
        raise RuntimeError('owned command failed')
    return result.stdout


class Monitor:
    """Bounded private output; all child groups are owned and explicitly reaped."""
    def __init__(self,args,service_id=None):
        self.service_id=service_id
        self.proc=subprocess.Popen(args,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        self.lock=threading.Lock(); self.out=bytearray(); self.err=bytearray(); self.overflow=False; self.read_error=False; self.threads=[]
        for target,stream in ((self.out,self.proc.stdout),(self.err,self.proc.stderr)):
            t=threading.Thread(target=self._read,args=(stream,target),daemon=True); t.start(); self.threads.append(t)
    def _read(self,stream,target):
        try:
            while True:
                data=os.read(stream.fileno(),4096)
                if not data: return
                with self.lock:
                    if len(target)+len(data)>65536: self.overflow=True
                    elif not self.overflow: target.extend(data)
        except Exception:
            with self.lock: self.read_error=True
    def lines(self):
        with self.lock:
            if self.overflow or self.err or self.read_error: raise RuntimeError('fixture output invalid')
            raw=bytes(self.out)
        if len(raw)>65536 or any(len(x)>128 for x in raw.splitlines()): raise RuntimeError('fixture output bound')
        return raw.splitlines()
    def wait(self,value,count=1,timeout=30):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if self.lines().count(value)>=count: return
            if self.proc.poll() is not None: raise RuntimeError('fixture process exited')
            time.sleep(.02)
        raise TimeoutError('fixture barrier deadline')
    def send(self,line):
        if line not in ('RELEASE_REQUEST','RELEASE_RESPONSE'): raise ValueError('invalid fixture control')
        self.proc.stdin.write((line+'\n').encode()); self.proc.stdin.flush()
    def finish(self,expected):
        try: self.proc.wait(timeout=10)
        finally: self.reap()
        if self.proc.returncode!=0 or self.lines()!=expected: raise RuntimeError('fixture process result invalid')
    def reap(self):
        if self.proc.poll() is None:
            try: os.killpg(self.proc.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            self.proc.wait(timeout=5)
        for t in self.threads: t.join(timeout=5)
        if any(t.is_alive() for t in self.threads): raise RuntimeError('fixture reader remains')
        for f in (self.proc.stdin,self.proc.stdout,self.proc.stderr):
            if f and not f.closed: f.close()
        self.lines()


def cleanup_monitors(monitors,removed):
    errors=[]
    for monitor in reversed(monitors):
        try:
            if monitor.service_id is not None:
                if monitor.service_id not in removed: raise RuntimeError('service removal not verified')
                try: monitor.proc.wait(timeout=10)
                except subprocess.TimeoutExpired: raise RuntimeError('service attach did not terminate')
            monitor.reap()
            if monitor.service_id is not None and monitor.proc.returncode not in (0,137):
                raise RuntimeError('service attach termination invalid')
        except Exception as exc:
            errors.append(exc)
            try: monitor.reap()
            except Exception as reap_exc: errors.append(reap_exc)
    return errors


def inspect_container(run,ref):
    fmt='{{json .Id}}\n{{json .Name}}\n{{json .Config.Labels}}\n{{json .Image}}\n{{json .State.Running}}'
    out=run(['docker','inspect','--format',fmt,ref],timeout=15,allow_absent=True)
    if out is None: return None
    values=out.splitlines()
    if len(values)!=5: raise RuntimeError('container inspection invalid')
    return tuple(json.loads(x) for x in values)


def owned_container(run,ref,name,token,known=None):
    info=inspect_container(run,ref)
    if info is None: raise RuntimeError('container identity unavailable')
    cid,actual,labels,image,running=info
    if not re.fullmatch('[0-9a-f]{64}',cid) or actual!='/'+name or (labels or {}).get(LABEL)!=token or (known and cid!=known): raise RuntimeError('container ownership mismatch')
    return info


def remote_absent(run,cid,pid):
    if not re.fullmatch(rb'[1-9][0-9]{0,9}',pid): raise ValueError('invalid remote pid')
    out=run(['docker','exec',cid,'/bin/sh','-c','if test -d "/proc/$1"; then printf PRESENT; else printf ABSENT; fi','fixture',pid.decode()],timeout=10)
    if out!=b'ABSENT': raise RuntimeError('remote process remains')


def artifact_identity(run,tag,token,head):
    out=run(['docker','image','inspect','--format','{{json .Id}}\n{{json .Config.Labels}}',tag],timeout=15).splitlines()
    if len(out)!=2: raise RuntimeError('image receipt invalid')
    ident,labels=map(json.loads,out)
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',ident) or (labels or {}).get(LABEL)!=token or (labels or {}).get('org.apicontour.managed-edge.source')!=head: raise RuntimeError('image receipt mismatch')
    return ident


def signed_policy(run,folder):
    key=folder/'policy.key'; pub=folder/'policy.pub'; raw=folder/'policy.raw'; msg=folder/'policy.message'; sig=folder/'policy.sig'
    run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],timeout=15)
    der=run(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'],timeout=15)
    if len(der)!=44 or not der.startswith(bytes.fromhex('302a300506032b6570032100')): raise ValueError('policy public key invalid')
    pub.write_bytes(der); raw.write_bytes(der[-32:]); now=datetime.datetime.now(datetime.timezone.utc)
    stamp=lambda x:x.isoformat(timespec='microseconds').replace('+00:00','Z')
    payload={'tenant_id':ID,'collector_id':ID,'revision':1,'issued_at':stamp(now-datetime.timedelta(minutes=1)),'expires_at':stamp(now+datetime.timedelta(minutes=14)),'enabled':True,'service_ids':[ID],'techniques':['gateway'],'approved_names':['POST','probe','result'],'denied_templates':[],'inspection_bytes':65536,'depth_limit':32,'queue_bytes':1048576,'queue_ttl_seconds':3600,'durable_queue_enabled':False,'approved_route_segments':['pilot'],'parser_profiles':['http_json_v1']}
    data=json.dumps(payload,separators=(',',':')).encode(); msg.write_bytes(b'apicontour/policy/1\n'+data)
    run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(key),'-in',str(msg),'-out',str(sig)],timeout=15)
    run(['openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',str(pub),'-keyform','DER','-in',str(msg),'-sigfile',str(sig)],timeout=15)
    signature=sig.read_bytes()
    if len(signature)!=64: raise ValueError('policy signature invalid')
    enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
    return {'key_id':'fixture','signature_profile':'ed25519-v1','payload_base64url':enc(data),'signature_base64url':enc(signature)}


def generate_certificates(run,folder):
    """Only synthetic keys created in this unique private directory are used."""
    ca=folder/'ca.crt'; cakey=folder/'ca.key'; conf=folder/'request.cnf'
    conf.write_text('[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256','-config',str(conf),'-extensions','ca','-subj','/CN=synthetic fixture CA','-keyout',str(cakey),'-out',str(ca)],timeout=30)
    specs=[('replica-client','clientAuth','DNS:fixture-replica'),('replica-server','serverAuth','DNS:localhost'),('destination','serverAuth','DNS:pilot-destination'),('gateway','serverAuth','DNS:native-gateway.test'),('forwarder','clientAuth','DNS:envoy-forwarder'),('upstream','clientAuth','DNS:native-observer-upstream'),('collector','clientAuth','DNS:fixture-collector'),('authority','serverAuth','DNS:fixture-authority'),('wrong','serverAuth','DNS:wrong.invalid')]
    for name,purpose,san in specs:
        ext=folder/(name+'.ext'); ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+purpose+'\nsubjectAltName='+san+'\n')
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN=fixture','-keyout',str(folder/(name+'.key')),'-out',str(folder/(name+'.csr'))],timeout=30)
        run(['openssl','x509','-req','-in',str(folder/(name+'.csr')),'-CA',str(ca),'-CAkey',str(cakey),'-set_serial',str(secrets.randbits(127)+1),'-days','1','-sha256','-extfile',str(ext),'-out',str(folder/(name+'.crt'))],timeout=30)
        run(['openssl','x509','-in',str(folder/(name+'.crt')),'-outform','DER','-out',str(folder/(name+'.der'))],timeout=15)
        run(['openssl','pkcs8','-topk8','-nocrypt','-in',str(folder/(name+'.key')),'-outform','DER','-out',str(folder/(name+'-key.der'))],timeout=15)
    run(['openssl','x509','-in',str(ca),'-outform','DER','-out',str(folder/'ca.der')],timeout=15)
    for p in folder.iterdir():
        if p.is_file(): p.chmod(0o600)
    return ca,cakey


def network_info(run,name,token,known=None):
    out=run(['docker','network','inspect','--format','{{json .Id}}\n{{json .Name}}\n{{json .Labels}}\n{{json .Internal}}\n{{json .Containers}}',name],timeout=15).splitlines()
    if len(out)!=5: raise RuntimeError('network inspection invalid')
    ident,actual,labels,internal,members=map(json.loads,out)
    if not re.fullmatch('[0-9a-f]{64}',ident) or actual!=name or (labels or {}).get(LABEL)!=token or internal is not True or (known and known!=ident) or type(members) is not dict: raise RuntimeError('network ownership mismatch')
    return ident,members


def check_product_probe(run,cid):
    out=run(['docker','exec',cid,'/usr/local/bin/node','/pilot/probe.js','normal'],timeout=15,limit=2048)
    data=json.loads(out)
    if type(data) is not dict or set(data)!={'status','expected_body','exception','admin_status','admin_exception'} or data['status']!=200 or data['expected_body'] is not True or data['exception']!='none' or data['admin_status']==200: raise AssertionError('stock replica request failed')


def durable_record(folder,name,value):
    path=folder/name
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(value,f,sort_keys=True,separators=(',',':')); f.flush(); os.fsync(f.fileno())
    directory=os.open(folder,os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def replica_definition(name,network,token,mounts):
    return {'services':{'replica':{'image':NODE,'container_name':name,
        'user':f'{os.getuid()}:{os.getgid()}',
        'entrypoint':['node','/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/pilot/settings.js'],
        'environment':{'PILOT_TARGET':'https://pilot-gateway:9443/pilot'},
        'volumes':[{'type':'bind','source':src,'target':dst,'read_only':True} for dst,src in mounts.items()],
        'read_only':True,'tmpfs':['/data:rw,nosuid,nodev,noexec,size=16m,mode=1777','/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777'],
        'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'pids_limit':128,'mem_limit':'256m',
        'labels':{LABEL:token},'networks':['default']}},
        'networks':{'default':{'external':True,'name':network}}}


def main():
    if len(sys.argv)!=1: raise ValueError('no arguments accepted')
    if os.getuid()==0: raise RuntimeError('nonroot required')
    os.umask(0o077); runner=run_process_helper(); run=lambda args,**kw:command(runner,args,**kw)
    head,before=source_snapshot(run); token=uuid.uuid4().hex; prefix='contour-managed-edge-'+token
    folder=Path(tempfile.mkdtemp(prefix=prefix+'-')).resolve(); folder.chmod(0o700)
    resources=[]; monitors=[]; remote=[]; network=None; image=None; paused=None; clean=False; failure=None
    netname=prefix+'-net'; tag=prefix+':fixture'; image_attempted=False; network_attempted=False
    durable_record(folder,'intent.json',{'version':1,'head':head,'token':token,'network':netname,'tag':tag,'containers':[prefix+'-'+n for n in ('destination','authority','gateway','envoy','replica')]})
    def mount(path,target): return ['--mount','type=bind,src='+str(path)+',dst='+target+',readonly']
    def create(name,image_ref,extra,args):
        fullname=prefix+'-'+name; intent={'name':fullname,'id':None}; resources.append(intent)
        output=run(['docker','create','--pull=never','--name',fullname,'--label',LABEL+'='+token,'--network',network,'--user',f'{os.getuid()}:{os.getgid()}','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','256m',*extra,image_ref,*args],timeout=30).decode().strip()
        if not re.fullmatch('[0-9a-f]{64}',output): raise RuntimeError('container create uncertain')
        owned_container(run,output,fullname,token,output); intent['id']=output
        durable_record(folder,name+'.receipt.json',{'id':output}); return output
    try:
        for image_ref in (NODE,ENVOY): run(['docker','image','inspect',image_ref],timeout=20)
        image_attempted=True
        run(['docker','build','--pull=false','--label',LABEL+'='+token,'--label','org.apicontour.managed-edge.source='+head,'--tag',tag,'-f','deploy/local/Dockerfile','.'],timeout=1800,limit=16777216)
        image=artifact_identity(run,tag,token,head)
        durable_record(folder,'image.receipt.json',{'id':image})
        if source_snapshot(run)!=(head,before): raise RuntimeError('source changed after build')
        ca,cakey=generate_certificates(run,folder); policy=signed_policy(run,folder)
        (folder/'authority.json').write_text(json.dumps({'id':ID,'source':ID,'peer':hashlib.sha256((folder/'collector.der').read_bytes()).hexdigest(),'policy':policy},separators=(',',':')))
        for name in ('authority.json','policy.raw'): (folder/name).chmod(0o600)
        for name in ('state','published','watched','gateway','forwarder'): (folder/name).mkdir(mode=0o700)
        g=folder/'gateway'; f=folder/'forwarder'
        for dest,source in {'server.der':'gateway.der','server-key.der':'gateway-key.der','forwarder-ca.der':'ca.der','forwarder.der':'forwarder.der','upstream-ca.der':'ca.der','upstream-client.der':'upstream.der','upstream-client-key.der':'upstream-key.der','delivery-ca.der':'ca.der','collector.der':'collector.der','collector-key.der':'collector-key.der','policy-public-key.bin':'policy.raw'}.items(): shutil.copyfile(folder/source,g/dest); (g/dest).chmod(0o600)
        gc=native_gateway_config.config(upstream_ip='pilot-destination',delivery_ip='fixture-authority',delivery_name='fixture-authority',tenant=ID,collector=ID,source=ID,workload=[ID]*4,policy_key_id='fixture')
        (g/'gateway.json').write_text(json.dumps(gc)); (g/'gateway.json').chmod(0o600)
        for dest,source in {'pilot-ca.pem':'ca.crt','observer-ca.pem':'ca.crt','forwarder.pem':'forwarder.crt','forwarder.key':'forwarder.key'}.items(): shutil.copyfile(folder/source,f/dest); (f/dest).chmod(0o600)
        (f/'envoy.json').write_text(json.dumps(native_envoy.config(managed_edge=True))); (f/'envoy.json').chmod(0o600)
        network_attempted=True
        out=run(['docker','network','create','--internal','--label',LABEL+'='+token,netname],timeout=30).decode().strip()
        network,members=network_info(run,netname,token)
        if out!=network or members: raise RuntimeError('network create mismatch')
        durable_record(folder,'network.receipt.json',{'id':network})
        dest=create('destination',NODE,['--network-alias','pilot-destination','-i','--entrypoint','node',*mount(folder/'destination.crt','/pilot/tls/server.crt'),*mount(folder/'destination.key','/pilot/tls/server.key'),*mount(ca,'/pilot/ca.crt'),*mount(FIXTURE/'held_destination.js','/pilot/destination.js')],['/pilot/destination.js'])
        auth=create('authority',NODE,['--network-alias','fixture-authority','-i','--entrypoint','node',*mount(folder/'authority.crt','/fixture/server.crt'),*mount(folder/'authority.key','/fixture/server.key'),*mount(ca,'/fixture/ca.crt'),*mount(folder/'authority.json','/fixture/authority.json'),*mount(FIXTURE/'authority.js','/fixture/authority.js')],['/fixture/authority.js'])
        for cid in (dest,auth):
            m=Monitor(['docker','start','-a','-i',cid],service_id=cid); monitors.append(m); m.wait(b'READY',timeout=30)
        gateway=create('gateway',image,['--network-alias','native-gateway','--entrypoint','/usr/local/bin/local_gateway',*mount(g,'/run/native')],['/run/native/gateway.json'])
        if run(['docker','start',gateway],timeout=30).strip()!=gateway.encode(): raise RuntimeError('gateway start mismatch')
        replica_mounts={str('/pilot/'+n):str(ROOT/'deploy/pilot'/n) for n in ('settings.js','flows.json','flows-wrong-name.json','flows-wrong-ca.json','check_tls.js','probe.js')}
        replica_mounts.update({'/pilot/ca.crt':str(ca),'/pilot/tls/client.crt':str(folder/'replica-client.crt'),'/pilot/tls/client.key':str(folder/'replica-client.key'),'/pilot/tls/server.crt':str(folder/'replica-server.crt'),'/pilot/tls/server.key':str(folder/'replica-server.key'),'/pilot/native_edge_probe.js':str(ROOT/'deploy/pilot/native_edge_probe.js')})
        envoy_mounts={'/certs':str(folder/'published'),'/run/watch':str(folder/'watched'),'/run/forwarder':str(f)}
        envoy_extra=['--network-alias','pilot-gateway']+sum((mount(src,dst) for dst,src in envoy_mounts.items()),[])
        envoy=create('envoy',ENVOY,envoy_extra,['-c','/run/forwarder/envoy.json','--log-level','error'])
        replica_name=prefix+'-replica'; intent={'name':replica_name,'id':None}; resources.append(intent)
        durable_record(folder,'replica.compose.json',replica_definition(replica_name,netname,token,replica_mounts))
        run(['docker','compose','--project-name',prefix,'-f',str(folder/'replica.compose.json'),'create','--no-build','--pull','never','replica'],timeout=30)
        replica=owned_container(run,replica_name,replica_name,token)[0]; intent['id']=replica
        durable_record(folder,'replica.receipt.json',{'id':replica})
        node_id=json.loads(run(['docker','image','inspect','--format','{{json .Id}}',NODE],timeout=15)); envoy_id=json.loads(run(['docker','image','inspect','--format','{{json .Id}}',ENVOY],timeout=15))
        peer=NativeReplicaPeer(replica,node_id,network,replica_mounts,envoy,envoy_id,envoy_mounts)
        with ManagedEdgeController(folder/'state',folder/'published',folder/'watched',ca,cakey,peer,token) as controller:
            controller.bootstrap(); owner=controller.edge
            # Prove the stock Node-RED flow plus fresh signed authority and an
            # actual rejected capture delivery attempt before rotation controls.
            deadline=time.monotonic()+30
            while True:
                try: check_product_probe(run,replica); break
                except Exception:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.2)
            monitors[1].wait(b'AUTHORITY_SENT',timeout=30); monitors[1].wait(b'BATCH_ATTEMPT',timeout=30)
            src=(FIXTURE/'held_client.js').read_text()
            shell='/usr/local/bin/node -e "$1" "$2" <&0 & p=$!; printf "PID %s\\n" "$p"; wait "$p"'
            def held(mode,operation):
                d=monitors[0]; req_before=d.lines().count(b'REQUEST_PREFIX'); resp_before=d.lines().count(b'RESPONSE_WRITTEN')
                args=['docker','exec','-i','--env','LD_PRELOAD=','--env','LD_LIBRARY_PATH=','--env','LD_AUDIT=','--env','NODE_OPTIONS=','--env','NODE_PATH=',replica,'/usr/bin/env','-i','/bin/sh','-c',shell,'fixture',src,mode]
                m=Monitor(args); monitors.append(m); deadline=time.monotonic()+15; pid=None
                while time.monotonic()<deadline:
                    lines=m.lines()
                    if lines:
                        found=re.fullmatch(rb'PID ([1-9][0-9]{0,9})',lines[0])
                        if not found: raise RuntimeError('remote pid unavailable')
                        pid=found.group(1); remote.append((replica,pid)); break
                    if m.proc.poll() is not None: raise RuntimeError('remote client exited')
                    time.sleep(.02)
                if pid is None: raise TimeoutError('remote pid deadline')
                if mode=='request': m.wait(b'CLIENT_WRITTEN'); d.wait(b'REQUEST_PREFIX',req_before+1)
                else: d.wait(b'RESPONSE_WRITTEN',resp_before+1); m.wait(b'RESPONSE_PREFIX')
                old=owner._load()['current_commitment']['cert_sha256']; operation(); new=owner._load()['current_commitment']['cert_sha256']
                if old==new: raise AssertionError('served edge fingerprint unchanged')
                if mode=='request': m.send('RELEASE_REQUEST')
                else: d.send('RELEASE_RESPONSE')
                m.wait(b'PASS'); expected=[b'PID '+pid,b'CLIENT_WRITTEN' if mode=='request' else b'RESPONSE_PREFIX',b'PASS']; m.finish(expected)
                remote_absent(run,replica,pid); remote.remove((replica,pid))
            held('request',owner.renew); held('response',owner.rollback); held('response',owner.renew); held('request',owner.rollback)
            # Candidate validation must reject a real CA-signed wrong-name pair.
            wrong='v-'+uuid.uuid4().hex; wrongdir=folder/'published'/wrong; wrongdir.mkdir(mode=0o700)
            for n in ('cert','key'): shutil.copyfile(folder/('wrong.'+n),wrongdir/(n+'.pem')); (wrongdir/(n+'.pem')).chmod(0o600)
            before_state=owner._load()
            try: owner.certs.validate_native_edge(wrong)
            except ValueError: pass
            else: raise AssertionError('wrong certificate accepted')
            if owner._load()!=before_state: raise AssertionError('wrong certificate changed journal')
            shutil.rmtree(wrongdir)
            # Real unavailable Envoy leaves a pending publication; always unpause.
            paused=envoy; run(['docker','pause',envoy],timeout=15)
            try:
                try: owner.renew()
                except (ValueError,RuntimeError,OSError,TimeoutError): pass
                else: raise AssertionError('unconfirmed publication accepted')
                if owner._load()['pending'] is None: raise AssertionError('publication ambiguity lost')
                for transition in (owner.renew,owner.rollback):
                    try: transition()
                    except RuntimeError: pass
                    else: raise AssertionError('pending publication did not block')
            finally:
                run(['docker','unpause',envoy],timeout=15); paused=None
            owner.reconcile()
        if source_snapshot(run)!=(head,before): raise RuntimeError('source changed')
        clean=True
    except BaseException as error: failure=error
    finally:
        errors=[]; removed=set()
        for monitor in monitors:
            if monitor.service_id is not None and monitor.proc.poll() is not None:
                errors.append(RuntimeError('service exited before removal'))
        if paused:
            try: owned_container(run,paused,prefix+'-envoy',token,paused); run(['docker','unpause',paused],timeout=15)
            except Exception as exc: errors.append(exc)
        # A create without an acknowledged exact ID is a hard failure. Only a
        # matching uniquely labeled name may be removed during reconciliation.
        for item in reversed(resources):
            try:
                info=inspect_container(run,item['name'])
                if info is None:
                    if item['id'] is None: raise RuntimeError('container creation uncertain')
                    if run(['docker','ps','-aq','--no-trunc','--filter','id='+item['id']],timeout=15): raise RuntimeError('container remains')
                    removed.add(item['id']); continue
                current=owned_container(run,item['name'],item['name'],token,item['id'])
                run(['docker','rm','-f',current[0]],timeout=30)
                if run(['docker','ps','-aq','--no-trunc','--filter','id='+current[0]],timeout=15): raise RuntimeError('container remains')
                removed.add(current[0])
            except Exception as exc: errors.append(exc)
        errors.extend(cleanup_monitors(monitors,removed))
        if remote: errors.append(RuntimeError('remote process completion unverified'))
        if network_attempted:
            try:
                ident,members=network_info(run,netname,token,network)
                if members: raise RuntimeError('owned network not empty')
                run(['docker','network','rm',ident],timeout=30)
                if run(['docker','network','ls','-q','--no-trunc','--filter','id='+ident],timeout=15): raise RuntimeError('network remains')
            except Exception as exc: errors.append(exc)
        if image_attempted:
            try:
                ident=artifact_identity(run,tag,token,head)
                if image and image!=ident: raise RuntimeError('image identity changed')
                run(['docker','image','rm',tag],timeout=30)
                if run(['docker','image','ls','-q','--no-trunc','--filter','reference='+tag],timeout=15): raise RuntimeError('image tag remains')
            except Exception as exc: errors.append(exc)
        try:
            if source_snapshot(run)!=(head,before): raise RuntimeError('source changed')
        except Exception as exc: errors.append(exc)
        if not errors: shutil.rmtree(folder)
        if errors: clean=False; failure=RuntimeError('owned cleanup or source verification failed')
    if failure is not None: raise failure
    if not clean: raise RuntimeError('qualification incomplete')
    print('PASS: owned native-edge mTLS rotation, rollback and held streams; capture delivery rejected')

if __name__=='__main__':
    try: main()
    except BaseException as exc: print('FAIL:',type(exc).__name__,file=sys.stderr); raise SystemExit(1) from None
