"""Owned local native-edge SDS publication; not a production CA or scheduler.

One operator owns the private journal, CA and loopback mTLS confirmation inputs.
No pending outcome is interpreted as an Envoy acknowledgement.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import ssl
import stat
import subprocess
import time
import uuid

from deploy.gateway.certificates import Certificates

_VERSION = re.compile(r'v-[0-9a-f]{32}\Z')
_MAX_VERSIONS = 32


def _sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _private_dir(path):
    path=Path(path)
    if not path.is_absolute() or any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('unsafe managed directory')
    st=path.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:
        raise ValueError('unsafe managed directory')
    return path


def _regular(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>limit:
            raise ValueError('unsafe managed file')
        with os.fdopen(fd,'rb',closefd=False) as stream: data=stream.read(limit+1)
        if len(data)>limit: raise ValueError('unsafe managed file')
        return data
    finally: os.close(fd)


def _public_bytes(path):
    path=Path(path)
    if not path.is_absolute() or any(p.is_symlink() for p in (path,*path.parents)): raise ValueError('unsafe public certificate')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size>65536: raise ValueError('unsafe public certificate')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(65537)
        if len(raw)>65536: raise ValueError('unsafe public certificate')
        return raw
    finally: os.close(fd)


def _replace(directory,name,data):
    temp=directory/('.pending-'+uuid.uuid4().hex)
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.replace(temp,directory/name); _sync_dir(directory)
    finally:
        if temp.exists(): temp.unlink()


_PROBE_SHA='109ec7b2ee7022e60c92ef3e413f68a6a7b22b2521648491f032dd5b53140b81'
_NODE_IMAGE='docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'
_ENVOY_IMAGE='envoyproxy/envoy:v1.37.11@sha256:7765ad61185fca9c9a770c9e2cad640d085d708ae9c22f3741345e88331472a4'
_PROFILE_MOUNTS={'/pilot/settings.js','/pilot/flows.json','/pilot/flows-wrong-name.json','/pilot/flows-wrong-ca.json','/pilot/check_tls.js','/pilot/probe.js','/pilot/tls/server.crt','/pilot/tls/server.key'}
_PROBE=Path(__file__).resolve().parents[2]/'deploy/pilot/native_edge_probe.js'

def _command(args, timeout=10):
    proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector(); out=bytearray(); err=bytearray(); deadline=time.monotonic()+timeout
    try:
        selector.register(proc.stdout,selectors.EVENT_READ,out); selector.register(proc.stderr,selectors.EVENT_READ,err)
        while selector.get_map():
            left=deadline-time.monotonic()
            if left<=0: raise TimeoutError('native peer deadline')
            events=selector.select(left)
            if not events: raise TimeoutError('native peer deadline')
            for event,_ in events:
                data=os.read(event.fd,4096)
                if not data: selector.unregister(event.fileobj); continue
                event.data.extend(data)
                if len(out)+len(err)>65536: raise ValueError('native peer output bound')
        left=deadline-time.monotonic()
        if left<=0: raise TimeoutError('native peer deadline')
        if proc.wait(timeout=left)!=0 or err: raise RuntimeError('native peer command failed')
        return bytes(out)
    finally:
        selector.close()
        if proc.poll() is None: proc.kill(); proc.wait(timeout=5)
        proc.stdout.close(); proc.stderr.close()


def _probe_hash():
    if any(p.is_symlink() for p in (_PROBE,*_PROBE.parents)): raise ValueError('unsafe native probe')
    fd=os.open(_PROBE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size>32768: raise ValueError('unsafe native probe')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(32769)
    finally: os.close(fd)
    if len(raw)>32768 or hashlib.sha256(raw).hexdigest()!=_PROBE_SHA: raise ValueError('native probe source mismatch')
    return _PROBE_SHA


class NativeReplicaPeer:
    """Fixed handshake inside one operator-selected, rechecked owned replica."""
    def __init__(self, cid, image_id, network_id, mounts, envoy_cid, envoy_image_id, envoy_mounts):
        if not re.fullmatch(r'[0-9a-f]{64}',cid) or not re.fullmatch(r'sha256:[0-9a-f]{64}',image_id) or not re.fullmatch(r'[0-9a-f]{64}',network_id): raise ValueError('invalid replica identity')
        if not re.fullmatch(r'[0-9a-f]{64}',envoy_cid) or not re.fullmatch(r'sha256:[0-9a-f]{64}',envoy_image_id) or cid==envoy_cid: raise ValueError('invalid envoy identity')
        destinations={'/pilot/ca.crt','/pilot/tls/client.crt','/pilot/tls/client.key','/pilot/native_edge_probe.js'}|_PROFILE_MOUNTS
        if type(mounts) is not dict or set(mounts)!=destinations or any(type(p) is not str or not Path(p).is_absolute() for p in mounts.values()): raise ValueError('invalid replica mounts')
        if mounts['/pilot/native_edge_probe.js']!=str(_PROBE): raise ValueError('invalid replica probe mount')
        if type(envoy_mounts) is not dict or set(envoy_mounts)!={'/certs','/run/watch','/run/forwarder'} or any(type(p) is not str or not Path(p).is_absolute() for p in envoy_mounts.values()): raise ValueError('invalid envoy mounts')
        self.cid=cid; self.image_id=image_id; self.network_id=network_id; self.mounts=dict(mounts)
        self.envoy_cid=envoy_cid; self.envoy_image_id=envoy_image_id; self.envoy_mounts=dict(envoy_mounts)
        _probe_hash()

    def identity(self):
        return {'kind':'native-replica','cid':self.cid,'image_id':self.image_id,'network_id':self.network_id,'mounts':dict(self.mounts),'envoy_cid':self.envoy_cid,'envoy_image_id':self.envoy_image_id,'envoy_mounts':dict(self.envoy_mounts),'probe_sha':_probe_hash()}

    @staticmethod
    def _invoke(args,deadline):
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('native confirmation deadline')
        return _command(args,timeout=min(10,remaining))

    def _inspect(self,deadline,expected_started=None,created=False):
        template='{{json .Id}}\n{{json .Image}}\n{{json .Config.Image}}\n{{json .Config.Entrypoint}}\n{{json .State.Running}}\n{{json .State.StartedAt}}\n{{json .NetworkSettings.Networks}}\n{{json .Mounts}}\n{{json .HostConfig.ReadonlyRootfs}}\n{{json .NetworkSettings.Ports}}\n{{json .HostConfig.Tmpfs}}\n{{json .State.Status}}\n{{json .HostConfig.NetworkMode}}'
        image_id=json.loads(self._invoke(['docker','image','inspect','--format','{{json .Id}}',_NODE_IMAGE],deadline))
        if image_id!=self.image_id: raise ValueError('replica image changed')
        lines=self._invoke(['docker','inspect','--format',template,self.cid],deadline).splitlines()
        if len(lines)!=13: raise ValueError('replica inspection invalid')
        cid,image,image_ref,entry,running,started,networks,mounts,readonly,ports,tmpfs,status,network_mode=(json.loads(x) for x in lines)
        if (cid!=self.cid or image!=self.image_id or image_ref!=_NODE_IMAGE or readonly is not True or
            entry!=['node','/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/pilot/settings.js']): raise ValueError('replica identity changed')
        self._check_state(running,status,started,expected_started,created)
        self._check_network_mode(network_mode,deadline)
        if type(networks) is not dict or len(networks)!=1: raise ValueError('replica network changed')
        network=next(iter(networks.values()))
        if type(network) is not dict or network.get('NetworkID') not in (('',self.network_id) if created else (self.network_id,)): raise ValueError('replica network changed')
        if ports is not None and (type(ports) is not dict or any(v for v in ports.values())): raise ValueError('replica publishes ports')
        expected_tmpfs={'/data':'rw,nosuid,nodev,noexec,size=16m,mode=1777','/tmp':'rw,nosuid,nodev,noexec,size=16m,mode=1777'}
        if tmpfs!=expected_tmpfs: raise ValueError('replica tmpfs changed')
        if type(mounts) is not list or len(mounts)>len(self.mounts)+len(_PROFILE_MOUNTS)+2: raise ValueError('replica mounts changed')
        allowed=set(self.mounts)|_PROFILE_MOUNTS
        def valid_mount(m):
            dest=m.get('Destination')
            return (dest in allowed and m.get('Type')=='bind' and m.get('RW') is False) or (dest in expected_tmpfs and m.get('Type')=='tmpfs' and m.get('RW') is True)
        if len({m.get('Destination') for m in mounts})!=len(mounts) or any(not valid_mount(m) for m in mounts): raise ValueError('replica mounts changed')
        if not _PROFILE_MOUNTS.issubset({m.get('Destination') for m in mounts}): raise ValueError('replica profile mounts missing')
        for dest,source in self.mounts.items():
            matches=[m for m in mounts if m.get('Destination')==dest]
            if len(matches)!=1 or matches[0].get('Type')!='bind' or matches[0].get('Source')!=source or matches[0].get('RW') is not False: raise ValueError('replica mounts changed')
        return lines

    def _envoy_and_topology(self,deadline,expected_started=None,created=False):
        template='{{json .Id}}\n{{json .Image}}\n{{json .Config.Image}}\n{{json .State.Running}}\n{{json .State.StartedAt}}\n{{json .NetworkSettings.Networks}}\n{{json .NetworkSettings.Ports}}\n{{json .State.Status}}\n{{json .HostConfig.NetworkMode}}\n{{json .Mounts}}\n{{json .HostConfig.ReadonlyRootfs}}'
        image_id=json.loads(self._invoke(['docker','image','inspect','--format','{{json .Id}}',_ENVOY_IMAGE],deadline))
        if image_id!=self.envoy_image_id: raise ValueError('envoy image changed')
        lines=self._invoke(['docker','inspect','--format',template,self.envoy_cid],deadline).splitlines()
        if len(lines)!=11: raise ValueError('envoy inspection invalid')
        cid,image,ref,running,started,networks,ports,status,network_mode,mounts,readonly=(json.loads(x) for x in lines)
        if cid!=self.envoy_cid or image!=self.envoy_image_id or ref!=_ENVOY_IMAGE or readonly is not True: raise ValueError('envoy identity changed')
        self._check_state(running,status,started,expected_started,created)
        self._check_network_mode(network_mode,deadline)
        if type(mounts) is not list or len(mounts)!=len(self.envoy_mounts): raise ValueError('envoy mounts changed')
        for dest,source in self.envoy_mounts.items():
            match=[m for m in mounts if m.get('Destination')==dest]
            if len(match)!=1 or match[0].get('Type')!='bind' or match[0].get('Source')!=source or match[0].get('RW') is not False: raise ValueError('envoy mounts changed')
        if type(networks) is not dict or len(networks)!=1: raise ValueError('envoy network changed')
        network=next(iter(networks.values()))
        if type(network) is not dict or network.get('NetworkID') not in (('',self.network_id) if created else (self.network_id,)) or 'pilot-gateway' not in (network.get('Aliases') or []): raise ValueError('envoy network changed')
        if ports is not None and (type(ports) is not dict or any(v for v in ports.values())): raise ValueError('envoy publishes ports')
        if created: return lines,()
        members=json.loads(self._invoke(['docker','network','inspect','--format','{{json .Containers}}',self.network_id],deadline))
        if type(members) is not dict or not 2<=len(members)<=32 or self.cid not in members or self.envoy_cid not in members: raise ValueError('network membership changed')
        aliases=[]
        for member in sorted(members):
            if not re.fullmatch(r'[0-9a-f]{64}',member): raise ValueError('network member invalid')
            raw=self._invoke(['docker','inspect','--format','{{json .Id}}\n{{json .NetworkSettings.Networks}}',member],deadline).splitlines()
            if len(raw)!=2 or json.loads(raw[0])!=member: raise ValueError('network member invalid')
            mapping=json.loads(raw[1])
            if type(mapping) is not dict: raise ValueError('network member invalid')
            matches=[n for n in mapping.values() if n.get('NetworkID')==self.network_id]
            if len(matches)!=1: raise ValueError('network member invalid')
            if 'pilot-gateway' in (matches[0].get('Aliases') or []): aliases.append(member)
        if aliases!=[self.envoy_cid]: raise ValueError('envoy alias ambiguous')
        return lines,tuple(sorted(members))

    def _check_state(self,running,status,started,expected_started,created):
        if created:
            if running is not False or status!='created': raise ValueError('container is not newly created')
        elif running is not True or status!='running' or type(started) is not str or not re.fullmatch(r'[0-9TZ:.-]{1,64}',started) or started.startswith('0001-') or (expected_started is not None and started!=expected_started):
            raise ValueError('container start changed')

    def _check_network_mode(self,mode,deadline):
        if type(mode) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',mode) or mode in ('host','none','bridge','default'):
            raise ValueError('network mode invalid')
        if json.loads(self._invoke(['docker','network','inspect','--format','{{json .Id}}',mode],deadline))!=self.network_id:
            raise ValueError('network mode changed')

    def verify_created(self):
        deadline=time.monotonic()+30; _probe_hash()
        self._inspect(deadline,created=True); self._envoy_and_topology(deadline,created=True)

    def observe_live(self):
        deadline=time.monotonic()+30; _probe_hash()
        first=self._inspect(deadline); topology=self._envoy_and_topology(deadline)
        second=self._inspect(deadline); again=self._envoy_and_topology(deadline); _probe_hash()
        if time.monotonic()>=deadline or first!=second or topology!=again: raise ValueError('live identity changed')
        return {'replica_started':json.loads(first[5]),'envoy_started':json.loads(topology[0][4])}

    def confirm(self,expected,binding):
        if type(binding) is not dict or set(binding)!={'replica_started','envoy_started'}: raise ValueError('missing live binding')
        deadline=time.monotonic()+30
        _probe_hash(); before=self._inspect(deadline,binding['replica_started']); topology=self._envoy_and_topology(deadline,binding['envoy_started'])
        output=self._invoke(['docker','exec','--env','LD_PRELOAD=','--env','LD_LIBRARY_PATH=','--env','LD_AUDIT=','--env','LD_DEBUG=','--env','DYLD_INSERT_LIBRARIES=',self.cid,'/usr/bin/env','-i','NODE_OPTIONS=','NODE_PATH=','/usr/local/bin/node','/pilot/native_edge_probe.js'],deadline)
        after=self._inspect(deadline,binding['replica_started']); after_topology=self._envoy_and_topology(deadline,binding['envoy_started']); _probe_hash()
        if time.monotonic()>=deadline: raise TimeoutError('native confirmation deadline')
        if before!=after or topology!=after_topology or output!=expected.hex().encode('ascii')+b'\n': raise ValueError('served certificate mismatch')


class LoopbackPeer:
    """Isolated fixture only; uses a dedicated health identity, not product keys."""
    def __init__(self,ca,client_cert,client_key,port):
        if type(port) is not int or not 1024<=port<=65535: raise ValueError('invalid loopback port')
        self.port=port; self.ca=Path(ca); self.client_cert=Path(client_cert); self.client_key=Path(client_key)
    def identity(self):
        return {'kind':'loopback','port':self.port,'ca':str(self.ca.absolute()),'client_cert':str(self.client_cert.absolute()),'client_key':str(self.client_key.absolute()),'ca_digest':hashlib.sha256(_public_bytes(self.ca)).hexdigest(),'client_digest':hashlib.sha256(_public_bytes(self.client_cert)).hexdigest()}

    def confirm(self,expected):
        context=ssl.create_default_context(cafile=str(self.ca)); context.load_cert_chain(str(self.client_cert),str(self.client_key))
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        with socket.create_connection(('127.0.0.1',self.port),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname='pilot-destination') as stream:
                if hashlib.sha256(stream.getpeercert(binary_form=True)).digest()!=expected: raise ValueError('served certificate mismatch')
                stream.sendall(b'POST /pilot HTTP/1.1\r\nHost: pilot-destination\r\nContent-Type: application/json\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{"probe":true}')
                deadline=time.monotonic()+5; data=bytearray()
                while b'\r\n\r\n' not in data:
                    left=deadline-time.monotonic()
                    if left<=0: raise TimeoutError('confirmation deadline')
                    stream.settimeout(left); chunk=stream.recv(1024)
                    if not chunk: raise ValueError('confirmation response mismatch')
                    data.extend(chunk)
                    if len(data)>8192: raise ValueError('confirmation response mismatch')
                head,body=bytes(data).split(b'\r\n\r\n',1); lines=head.split(b'\r\n')
                if lines[0]!=b'HTTP/1.1 200 OK': raise ValueError('confirmation response mismatch')
                headers={}
                for line in lines[1:]:
                    name,sep,value=line.partition(b':'); name=name.strip().lower()
                    if not sep or not name or name in headers: raise ValueError('confirmation response mismatch')
                    headers[name]=value.strip()
                length=headers.get(b'content-length',b'')
                if not length.isdigit() or len(length)>3 or int(length)>128 or b'transfer-encoding' in headers: raise ValueError('confirmation response mismatch')
                size=int(length)
                if len(body)>size: raise ValueError('confirmation response mismatch')
                while len(body)<size:
                    left=deadline-time.monotonic()
                    if left<=0: raise TimeoutError('confirmation deadline')
                    stream.settimeout(left); chunk=stream.recv(size-len(body))
                    if not chunk: raise ValueError('confirmation response mismatch')
                    body+=chunk
                if body!=b'{"result":"owned-pilot-ok"}': raise ValueError('confirmation response mismatch')


class ManagedEdge:
    """Single owner. All commands re-read the durable journal under lifetime lock."""
    def __init__(self, state, published, watched, ca, ca_key, peer):
        self.state=_private_dir(state); self.published=_private_dir(published); self.watched=_private_dir(watched)
        if len({self.state,self.published,self.watched})!=3 or any(a in b.parents for a in (self.state,self.published,self.watched) for b in (self.state,self.published,self.watched) if a!=b):
            raise ValueError('managed directories overlap')
        if type(peer) not in (LoopbackPeer,NativeReplicaPeer): raise ValueError('unsupported confirmation peer')
        self.peer=peer; self.ca=Path(ca)
        if type(peer) is NativeReplicaPeer:
            if peer.envoy_mounts['/certs']!=str(self.published) or peer.envoy_mounts['/run/watch']!=str(self.watched): raise ValueError('envoy publication mounts changed')
            private_state=self.state.resolve(); private_ca=Path(ca_key).resolve()
            for source in (*peer.mounts.values(),*peer.envoy_mounts.values()):
                original=Path(source)
                if any(p.is_symlink() for p in (original,*original.parents)): raise ValueError('symlink in mount source')
                path=original.resolve()
                if path==private_state or path in private_state.parents or private_state in path.parents or path==private_ca or path in private_ca.parents: raise ValueError('private material exposed by mount')
        for secret in (Path(ca_key).resolve(),self.ca.resolve()):
            if any(root==secret or root in secret.parents for root in (self.published,self.watched)):
                raise ValueError('CA in publication tree')
        self.certs=Certificates(self.published,ca,ca_key,'pilot-destination')
        self.ca_key=Path(ca_key)
        self.identity=self._identity()
        fd=os.open(self.state/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        self.lock=os.fdopen(fd,'r+b'); self.closed=False; self.uncertain=False
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600: raise ValueError('unsafe managed lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            os.fsync(fd); _sync_dir(self.state)
            self._load()
        except BaseException:
            self.lock.close(); self.closed=True; raise

    def _identity(self):
        config={'published':str(self.published),'watched':str(self.watched),'ca':str(self.ca.absolute()),'ca_key':str(self.ca_key.absolute()),'ca_digest':hashlib.sha256(self.certs._read(self.ca)).hexdigest(),'peer':self.peer.identity()}
        return hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def close(self):
        if not self.closed: self.closed=True; self.lock.close()
    def __enter__(self): return self
    def __exit__(self,*_): self.close()

    def _load(self):
        if self.closed or self.uncertain: raise RuntimeError('owner must reopen')
        if self._identity()!=self.identity: raise ValueError('managed identity changed')
        try: raw=_regular(self.state/'journal.json',4096)
        except FileNotFoundError:
            if os.path.lexists(self.watched/'sds.json') or any(_VERSION.fullmatch(p.name) for p in self.published.iterdir()):
                raise ValueError('missing publication journal')
            return {'version':1,'identity':self.identity,'current':None,'current_commitment':None,'previous':None,'previous_commitment':None,'pending':None,'binding':None}
        def unique(pairs):
            out={}
            for key,value in pairs:
                if key in out: raise ValueError('duplicate journal key')
                out[key]=value
            return out
        data=json.loads(raw,object_pairs_hook=unique)
        if type(data) is not dict or set(data)!={'version','identity','current','current_commitment','previous','previous_commitment','pending','binding'} or type(data['version']) is not int or data['version']!=1 or data['identity']!=self.identity: raise ValueError('invalid journal')
        for field in ('current','previous'):
            if data[field] is not None and (type(data[field]) is not str or not _VERSION.fullmatch(data[field])): raise ValueError('invalid journal')
        def commitment(value):
            return type(value) is dict and set(value)=={'cert_sha256','key_spki_sha256'} and all(type(x) is str and re.fullmatch(r'[0-9a-f]{64}',x) for x in value.values())
        for field in ('current','previous'):
            value=data[field+'_commitment']
            if (data[field] is None and value is not None) or (data[field] is not None and not commitment(value)): raise ValueError('invalid version commitment')
            if data[field] is not None and self.certs.native_edge_commitment(data[field],allow_expired=True)!=value: raise ValueError('version commitment changed')
        binding=data['binding']
        if binding is not None and (type(self.peer) is not NativeReplicaPeer or type(binding) is not dict or set(binding)!={'replica_started','envoy_started'} or any(type(x) is not str or not re.fullmatch(r'[0-9TZ:.-]{1,64}',x) or x.startswith('0001-') for x in binding.values())): raise ValueError('invalid live binding')
        if type(self.peer) is NativeReplicaPeer and data['current'] is not None and binding is None: raise ValueError('missing live binding')
        pending=data['pending']
        if pending is not None and (type(pending) is not dict or set(pending)!={'candidate','kind','phase','days','commitment'} or pending['kind'] not in ('renew','rollback') or pending['phase'] not in ('reserved','staged') or (pending['kind']=='renew' and (type(pending['days']) is not int or not 1<=pending['days']<=365)) or (pending['kind']=='rollback' and (pending['days'] is not None or pending['phase']!='staged')) or type(pending['candidate']) is not str or not _VERSION.fullmatch(pending['candidate'])): raise ValueError('invalid journal')
        if pending:
            if (pending['phase']=='reserved' and pending['commitment'] is not None) or (pending['phase']=='staged' and not commitment(pending['commitment'])): raise ValueError('invalid candidate commitment')
            if pending['phase']=='staged' and self.certs.native_edge_commitment(pending['candidate'],allow_expired=True)!=pending['commitment']: raise ValueError('candidate commitment changed')
            if pending['kind']=='rollback' and pending['commitment']!=data['previous_commitment']: raise ValueError('rollback commitment mismatch')
        if data['previous'] is not None and (data['current'] is None or data['previous']==data['current']): raise ValueError('invalid journal')
        if pending and (pending['candidate']==data['current'] or (pending['kind']=='rollback' and pending['candidate']!=data['previous']) or (pending['kind']=='renew' and pending['candidate']==data['previous'])): raise ValueError('invalid journal')
        fd=os.open(self.state/'journal.json',os.O_RDONLY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
        _sync_dir(self.state)
        return data

    def _save(self,data):
        try: _replace(self.state,'journal.json',json.dumps(data,sort_keys=True,separators=(',',':')).encode('ascii'))
        except BaseException: self.uncertain=True; raise

    def _document(self,version,commitment):
        if self.certs.native_edge_commitment(version)!=commitment: raise ValueError('candidate commitment changed')
        return json.dumps({'version_info':version,'resources':[{'@type':'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret','name':'gateway','tls_certificate':{'certificate_chain':{'filename':'/certs/'+version+'/cert.pem'},'private_key':{'filename':'/certs/'+version+'/key.pem'}}}]},separators=(',',':')).encode('ascii')

    def _confirm(self,version,commitment,binding):
        if self.certs.native_edge_commitment(version)!=commitment: raise ValueError('candidate commitment changed')
        fingerprint=bytes.fromhex(commitment['cert_sha256'])
        if type(self.peer) is NativeReplicaPeer: self.peer.confirm(fingerprint,binding)
        else: self.peer.confirm(fingerprint)
        if self.certs.native_edge_commitment(version)!=commitment: raise ValueError('candidate commitment changed')

    def _publish(self,version,commitment):
        document=self._document(version,commitment)
        try: _replace(self.watched,'sds.json',document)
        except BaseException: self.uncertain=True; raise

    def _publish_and_confirm(self,data):
        if data['pending']['phase']!='staged': raise ValueError('candidate not staged')
        if type(self.peer) is NativeReplicaPeer and data['binding'] is None: raise ValueError('missing live binding')
        version=data['pending']['candidate']; commitment=data['pending']['commitment']; self._publish(version,commitment)
        self._confirm(version,commitment,data['binding'])
        data['previous']=data['current']; data['previous_commitment']=data['current_commitment']
        data['current']=version; data['current_commitment']=commitment; data['pending']=None
        self._save(data)

    def _stage_new(self,data,days):
        if sum(1 for p in self.published.iterdir() if _VERSION.fullmatch(p.name))>=_MAX_VERSIONS: raise RuntimeError('version retention limit')
        if type(days) is not int or not 1<=days<=365: raise ValueError('invalid certificate lifetime')
        if data['current'] is not None: self.certs.validate_native_edge(data['current'],allow_expired=True)
        candidate='v-'+uuid.uuid4().hex; data['pending']={'kind':'renew','candidate':candidate,'phase':'reserved','days':days,'commitment':None}; self._save(data)
        self.certs.stage_native_edge(candidate,days)
        data['pending']['commitment']=self.certs.native_edge_commitment(candidate)
        data['pending']['phase']='staged'; self._save(data)
        return candidate

    def prepare_initial(self,days=1):
        """Publish bootstrap SDS but leave it pending until a live confirmation."""
        data=self._load()
        if data['current'] is not None or data['pending'] is not None: raise RuntimeError('initial publication unavailable')
        if type(self.peer) is NativeReplicaPeer: self.peer.verify_created()
        candidate=self._stage_new(data,days)
        if type(self.peer) is NativeReplicaPeer: self.peer.verify_created()
        self._publish(candidate,data['pending']['commitment'])

    def renew(self,days=1):
        data=self._load()
        if data['pending'] is not None: raise RuntimeError('publication reconciliation required')
        if type(self.peer) is NativeReplicaPeer and data['current'] is None: raise RuntimeError('prepare_initial required')
        self._stage_new(data,days)
        self._publish_and_confirm(data)

    def _binding_file(self,name,data):
        fd=os.open(self.state/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as out:
                out.write(data); out.flush(); os.fsync(out.fileno())
            _sync_dir(self.state)
        except BaseException: self.uncertain=True; raise

    def bind_initial_peer(self):
        """Observe one live start pair; persist it before any confirmation."""
        data=self._load()
        if type(self.peer) is not NativeReplicaPeer or data['current'] is not None or not data['pending'] or data['pending']['phase']!='staged' or data['pending']['kind']!='renew': raise RuntimeError('initial binding unavailable')
        if _regular(self.watched/'sds.json',65536)!=self._document(data['pending']['candidate'],data['pending']['commitment']): raise ValueError('bootstrap SDS mismatch')
        intent=json.dumps({'version':1,'identity':self.identity},sort_keys=True,separators=(',',':')).encode('ascii')
        intent_path=self.state/'binding.intent'; result_path=self.state/'binding.result'
        if os.path.lexists(intent_path):
            if _regular(intent_path,4096)!=intent: raise ValueError('binding intent mismatch')
            try: raw=_regular(result_path,4096)
            except FileNotFoundError: raise RuntimeError('incomplete binding requires intervention') from None
            result=json.loads(raw)
            if json.dumps(result,sort_keys=True,separators=(',',':')).encode('ascii')!=raw: raise ValueError('binding result invalid')
            if type(result) is not dict or set(result)!={'identity','binding'} or result['identity']!=self.identity: raise ValueError('binding result mismatch')
            binding=result['binding']
            if type(binding) is not dict or set(binding)!={'replica_started','envoy_started'} or any(type(v) is not str or not re.fullmatch(r'[0-9TZ:.-]{1,64}',v) or v.startswith('0001-') for v in binding.values()): raise ValueError('binding result invalid')
            fd=os.open(result_path,os.O_RDONLY|os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
            _sync_dir(self.state)
            if self.peer.observe_live()!=binding: raise ValueError('live binding changed')
        else:
            if data['binding'] is not None or os.path.lexists(result_path): raise ValueError('binding artifacts inconsistent')
            self._binding_file('binding.intent',intent)
            binding=self.peer.observe_live()
            raw=json.dumps({'identity':self.identity,'binding':binding},sort_keys=True,separators=(',',':')).encode('ascii')
            self._binding_file('binding.result',raw)
        if data['binding'] is not None and data['binding']!=binding: raise ValueError('live binding changed')
        if data['binding'] is None: data['binding']=binding; self._save(data)

    def rollback(self):
        data=self._load()
        if data['pending'] is not None: raise RuntimeError('publication reconciliation required')
        if data['previous'] is None: raise ValueError('no previous edge version')
        self.certs.validate_native_edge(data['previous'])
        data['pending']={'kind':'rollback','candidate':data['previous'],'phase':'staged','days':None,'commitment':data['previous_commitment']}; self._save(data)
        self._publish_and_confirm(data)

    def reconcile(self):
        data=self._load()
        if data['pending'] is None: raise ValueError('no pending publication')
        pending=data['pending']
        if pending['phase']=='reserved':
            if not os.path.lexists(self.published/pending['candidate']): self.certs.stage_native_edge(pending['candidate'],pending['days'])
            else: self.certs.sync_native_edge(pending['candidate'])
            pending['commitment']=self.certs.native_edge_commitment(pending['candidate'])
            pending['phase']='staged'; self._save(data)
        if type(self.peer) is NativeReplicaPeer and data['current'] is None and data['binding'] is None:
            self.peer.verify_created(); self._publish(pending['candidate'],pending['commitment']); return
        self._publish_and_confirm(data)

    def renew_due(self,seconds,days=1):
        if type(seconds) is not int or seconds<0: raise ValueError('invalid renewal threshold')
        data=self._load()
        if data['pending'] is not None: raise RuntimeError('publication reconciliation required')
        if data['current'] is None:
            if type(self.peer) is NativeReplicaPeer: raise RuntimeError('prepare_initial required')
            self.renew(days); return True
        cert,_=self.certs.validate_native_edge(data['current'],allow_expired=True)
        result=subprocess.run(['openssl','x509','-in',str(cert),'-noout','-checkend',str(seconds)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        if result.returncode==0: return False
        if result.returncode!=1: raise ValueError('certificate expiry check failed')
        self.renew(days); return True
