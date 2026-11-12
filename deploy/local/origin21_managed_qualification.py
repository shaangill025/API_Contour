"""Exclusive ownership for one synthetic managed-Origin qualification.

This capability is a local routing/ownership guard, not host attestation. It
never accepts an arbitrary destination, volume or alternate managed profile.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from deploy.local import capture_renew,origin21_managed_init as init,origin21_profile as profiles,origin21_state
from deploy.pilot import origin_credentials

SOURCE='deploy/local/origin21_managed_qualification.py'
DESTINATION='tests/fixtures/managed-origin-qualification/destination.js'
PUBLISHER='tests/fixtures/managed-origin-qualification/publisher.js'
_SEAL=object()


def _bytes(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def _fixed_destination():
    path=profiles.ROOT/DESTINATION
    if any(p.is_symlink() for p in (path,*list(path.parents)[:3])) or not path.is_file(): raise ValueError('qualification destination unavailable')
    data=path.read_bytes()
    if not 1<=len(data)<=32768: raise ValueError('qualification destination invalid')
    return hashlib.sha256(data).hexdigest()


def _owned_worktree(head,receipt):
    root=profiles.ROOT; owner=root.parent
    if root.name!='worktree' or any(p.is_symlink() for p in (root,owner,*owner.parents)) or Path(receipt)!=owner/'build-receipt.json': raise ValueError('exclusive qualification worktree required')
    st=os.lstat(owner)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700: raise ValueError('qualification owner invalid')
    raw=origin_credentials._file(owner/'intent.json',4096); value=capture_renew.exact_json(raw)
    if type(value) is not dict or set(value)!={'version','head','tag','token','worktree'} or value['version']!=1 or value['head']!=head or value['worktree']!=str(root) or not re.fullmatch('[0-9a-f]{32}',value['token']) or value['tag']!='apicontour-origin21-build:'+value['token'] or _bytes(value)!=raw: raise ValueError('qualification worktree intent invalid')
    from deploy.local import qualification_git
    if qualification_git.registration_if_active(root,head): return
    data=init.origin21_transport._run(['git','worktree','list','--porcelain','-z'],'',deadline=15)
    entries=[]; item={}
    for field in data.split('\0'):
        if not field:
            if item: entries.append(item); item={}
            continue
        key,_,part=field.partition(' ')
        if key in ('worktree','HEAD'):
            if key in item: raise ValueError('ambiguous worktree registration')
            item[key]=part
    if item: entries.append(item)
    if [item for item in entries if item.get('worktree')==str(root)]!=[{'worktree':str(root),'HEAD':head}]: raise ValueError('qualification worktree registration invalid')


def _sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def require_matching(qualification):
    """Refuse a partially created qualification without its live proof."""
    base=init.BASE
    selected=qualification is not None
    if selected:
        if type(qualification) is not OwnedManagedQualification: raise ValueError('qualification proof required')
        qualification.verify()
    if os.path.lexists(base/'qualification') and not selected: raise ValueError('qualification proof required')
    for name in ('initializer.intent','volume.intent'):
        path=base/name
        if not os.path.lexists(path): continue
        raw=origin_credentials._file(path,4096); record=capture_renew.exact_json(raw)
        if type(record) is not dict or _bytes(record)!=raw: raise ValueError('managed initializer intent invalid')
        value=record.get('volume') if name=='initializer.intent' else record.get('name')
        if isinstance(value,str) and value.startswith('contour-managed-origin21-qual-'):
            if not selected or value!=qualification.volume: raise ValueError('qualification proof required')
    return qualification


class OwnedManagedQualification:
    """One exclusive, process-owned qualification identity; no record adoption."""
    __slots__=('_root_fd','_identity','_raw','_token','_head','_source','_destination_sha','_context','_closed','_ack_armed','_publish_ack','_exec_intent','_exec_ready')
    def __init__(self,seal,fd,identity,raw,token,head,source,destination_sha):
        if seal is not _SEAL: raise ValueError('qualification factory required')
        for key,value in (('_root_fd',fd),('_identity',identity),('_raw',raw),('_token',token),('_head',head),('_source',source),('_destination_sha',destination_sha),('_context',profiles.MANAGED),('_closed',False),('_ack_armed',False),('_publish_ack',None),('_exec_intent',None),('_exec_ready',None)): object.__setattr__(self,key,value)
    def __setattr__(self,name,value): raise AttributeError('qualification identity is immutable')
    @property
    def token(self): return self._token
    @property
    def volume(self): return 'contour-managed-origin21-qual-'+self._token+'-data'
    @property
    def destination(self): return profiles.ROOT/DESTINATION
    @property
    def folder(self): return init.BASE/'qualification'/self._token
    def verify(self):
        if self._closed or profiles.MANAGED is not self._context: raise ValueError('qualification closed or context changed')
        profiles.require_context(self._context)
        _owned_worktree(self._head,str(profiles.ROOT.parent/'build-receipt.json'))
        if SOURCE not in origin21_state.MANAGED_SOURCE_FILES or DESTINATION not in origin21_state.MANAGED_SOURCE_FILES: raise ValueError('qualification source not pinned')
        root=init.BASE
        if root!=profiles.MANAGED.profile.state.parent or any(p.is_symlink() for p in (root,*root.parents)): raise ValueError('qualification root changed')
        st=os.lstat(root); held=os.fstat(self._root_fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700 or (st.st_dev,st.st_ino)!=self._identity or (held.st_dev,held.st_ino)!=self._identity: raise ValueError('qualification root changed')
        for path in (root/'qualification',self.folder):
            if path.is_symlink(): raise ValueError('qualification path changed')
            capture_renew.safe_dir(path)
        if origin_credentials._file(self.folder/'qualification.intent',4096)!=self._raw or _fixed_destination()!=self._destination_sha or init._source(self._head)!=self._source: raise ValueError('qualification identity changed')
        return self
    def require_build(self,image_id,head,digest):
        self.verify()
        value=json.loads(self._raw)
        if (image_id,head,digest)!=(value['build_image'],value['head'],value['build_receipt_sha256']): raise ValueError('qualification build changed')
        return self
    def publisher_source(self):
        self.verify()
        if PUBLISHER not in origin21_state.MANAGED_SOURCE_FILES: raise ValueError('qualification publisher source not pinned')
        path=profiles.ROOT/PUBLISHER
        if any(p.is_symlink() for p in (path,*list(path.parents)[:3])) or not path.is_file(): raise ValueError('qualification publisher source unavailable')
        raw=path.read_bytes()
        if not 1<=len(raw)<=32768: raise ValueError('qualification publisher source invalid')
        return raw
    def arm_ack_loss(self):
        self.verify(); self.publisher_source()
        if self._ack_armed or self._exec_intent is not None or self._exec_ready is not None: raise ValueError('qualification publisher already armed')
        object.__setattr__(self,'_ack_armed',True)
    def consume_ack_loss(self):
        self.verify()
        armed=self._ack_armed
        if armed: object.__setattr__(self,'_ack_armed',False)
        return armed

    def _prepare_publication_intent(self,publisher,document,nonce):
        """Record only the intent whose durable file has just been committed."""
        if not self._ack_armed: return
        from deploy.gateway.managed_edge import NativeDirectoryPublisher
        if type(publisher) is not NativeDirectoryPublisher or publisher.qualification is not self or type(document) is not bytes or not re.fullmatch('[0-9a-f]{32}',nonce) or self._exec_intent is not None: raise ValueError('invalid publication execution intent')
        self.verify()
        record={'publisher':publisher.identity(),'document_sha256':hashlib.sha256(document).hexdigest(),'nonce':nonce}
        object.__setattr__(self,'_exec_intent',_bytes(record))
    def _mark_publication_exec_ready(self,publisher,digest,nonce):
        """Record one in-process timestamp immediately before the fixed exec."""
        import time
        from deploy.gateway.managed_edge import NativeDirectoryPublisher
        if type(publisher) is not NativeDirectoryPublisher or publisher.qualification is not self or self._exec_intent is None or self._exec_ready is not None: raise ValueError('publication intent unavailable')
        self.verify()
        record={'publisher':publisher.identity(),'document_sha256':digest,'nonce':nonce}
        if _bytes(record)!=self._exec_intent: raise ValueError('publication intent changed')
        started=time.monotonic()
        object.__setattr__(self,'_exec_ready',(started,self._exec_intent))
    def publication_exec_ready(self):
        """Observation only; readiness never authorizes reconciliation."""
        value=self._exec_ready
        if value is None: return None
        return {'started':value[0],'intent':json.loads(value[1])}

    def _record_publication_ack(self,publisher,document,nonce):
        from deploy.gateway.managed_edge import NativeDirectoryPublisher
        if type(publisher) is not NativeDirectoryPublisher or publisher.qualification is not self or type(document) is not bytes or not re.fullmatch('[0-9a-f]{32}',nonce): raise ValueError('invalid publication receipt')
        self.verify()
        prior=self._publish_ack
        receipt={'sequence':1 if prior is None else prior['sequence']+1,'publisher':publisher.identity(),'document_sha256':hashlib.sha256(document).hexdigest(),'nonce':nonce}
        object.__setattr__(self,'_publish_ack',receipt)
    def publication_ack(self):
        self.verify()
        return None if self._publish_ack is None else json.loads(_bytes(self._publish_ack))

    def bind_owner(self,owner):
        self.verify()
        if owner!=profiles.MANAGED.owner: raise ValueError('qualification owner changed')
        capture_renew.safe_dir(owner)
        value={'version':1,'token':self.token,'intent_sha256':hashlib.sha256(self._raw).hexdigest(),'destination':DESTINATION,'destination_sha256':self._destination_sha,'volume':self.volume}
        origin_credentials._write(owner/'qualification.intent',_bytes(value))
        self.verify_owner(owner)
    def verify_owner(self,owner):
        self.verify()
        if owner!=profiles.MANAGED.owner: raise ValueError('qualification owner changed')
        value={'version':1,'token':self.token,'intent_sha256':hashlib.sha256(self._raw).hexdigest(),'destination':DESTINATION,'destination_sha256':self._destination_sha,'volume':self.volume}
        if origin_credentials._file(owner/'qualification.intent',4096)!=_bytes(value): raise ValueError('qualification owner intent changed')
        return self

    def destination_model(self,model):
        """Select the pinned source in the one normalized companion model."""
        import copy
        self.verify()
        result=copy.deepcopy(model)
        try: volumes=result['services']['destination']['volumes']
        except (TypeError,KeyError): raise ValueError('qualification model invalid') from None
        if type(volumes) is not list: raise ValueError('qualification model invalid')
        matches=[entry for entry in volumes if type(entry) is dict and entry.get('target')=='/pilot/destination.js']
        expected=str(profiles.ROOT/'deploy/pilot/destination.js')
        if len(matches)!=1 or matches[0].get('type')!='bind' or matches[0].get('read_only') is not True or matches[0].get('source')!=expected: raise ValueError('qualification destination bind invalid')
        matches[0]['source']=str(self.destination)
        return result

    def bind_topology(self,peer,publisher):
        """Record only a twice-checked existing topology, before disposal."""
        self.verify()
        from deploy.local import origin21_managed_controller as controller
        snapshot,_=controller._topology_snapshot(peer,publisher,live_envoy=True,qualification=self)
        again,_=controller._topology_snapshot(peer,publisher,live_envoy=True,qualification=self)
        if snapshot!=again: raise ValueError('qualification topology changed')
        products=snapshot['products']; services=snapshot['companions']
        containers=[item['container_id'] for item in products]+[services[name]['id'] for name in controller.products.COMPANIONS]+[publisher.cid,snapshot['postgres_id']]
        networks=[snapshot['business_network'],snapshot['capture_network']]
        if len(containers)!=9 or len(networks)!=2 or any(type(x) is not str or not re.fullmatch('[0-9a-f]{64}',x) for x in containers+networks) or len(set(containers+networks))!=11: raise ValueError('qualification topology invalid')
        value={'version':1,'token':self.token,'intent_sha256':hashlib.sha256(self._raw).hexdigest(),'containers':containers,'networks':networks}
        origin_credentials._write(self.folder/'topology.intent',_bytes(value))
        self.verify()
        return value
    def close(self):
        if not self._closed:
            os.close(self._root_fd); object.__setattr__(self,'_closed',True)
    def __enter__(self): self.verify(); return self
    def __exit__(self,kind,error,traceback):
        try: self.close()
        except BaseException as cleanup:
            if error is not None: raise BaseExceptionGroup('qualification and owner close failures',[error,cleanup]) from None
            raise


def begin(*,image_id,head,build_receipt,build_receipt_sha256):
    """Exclusively mint the one process-owned synthetic qualification proof."""
    if os.getuid()==0: raise RuntimeError('nonroot required')
    if SOURCE not in origin21_state.MANAGED_SOURCE_FILES or DESTINATION not in origin21_state.MANAGED_SOURCE_FILES: raise RuntimeError('qualification source closure incomplete')
    root=init.BASE
    if root!=profiles.MANAGED.profile.state.parent or any(p.is_symlink() for p in (root,*root.parents)): raise ValueError('managed qualification root invalid')
    dotgit=profiles.ROOT/'.git'
    if dotgit.is_symlink() or not dotgit.is_file(): raise ValueError('fresh isolated worktree required')
    _owned_worktree(head,build_receipt)
    source=init._source(head); init._build(image_id,head,build_receipt,build_receipt_sha256)
    destination_sha=_fixed_destination()
    if os.path.lexists(root): raise FileExistsError('managed state already exists')
    os.mkdir(root,0o700); _sync_dir(root.parent)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700: raise ValueError('managed qualification root invalid')
        token=secrets.token_hex(16); parent=root/'qualification'; os.mkdir(parent,0o700); _sync_dir(root)
        folder=parent/token; os.mkdir(folder,0o700); _sync_dir(parent)
        volume='contour-managed-origin21-qual-'+token+'-data'
        value={'version':1,'kind':'synthetic','token':token,'head':head,'volume':volume,'destination':DESTINATION,'destination_sha256':destination_sha,'source_identity':source,'build_image':image_id,'build_receipt_sha256':build_receipt_sha256}
        raw=_bytes(value); origin_credentials._write(folder/'qualification.intent',raw)
        proof=OwnedManagedQualification(_SEAL,fd,(st.st_dev,st.st_ino),raw,token,head,source,destination_sha)
        proof.verify(); return proof
    except BaseException:
        os.close(fd); raise
