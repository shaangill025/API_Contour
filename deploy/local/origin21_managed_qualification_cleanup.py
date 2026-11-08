"""Dispose only a fully recorded, unused synthetic qualification volume.

No command executes on import. The qualification owns the exclusive intent and
must write its complete exact-topology cleanup record before this operation.
"""
import json
import hashlib
import os
from pathlib import Path
import re
from deploy.local import capture_renew,origin21_managed_init as init,origin21_products as products,origin21_state
from deploy.pilot import origin_credentials

SOURCE='deploy/local/origin21_managed_qualification_cleanup.py'
LABEL='org.apicontour.managed-qualification-owner'


def _read(path):
    raw=origin_credentials._file(path,4096); value=capture_renew.exact_json(raw)
    if json.dumps(value,sort_keys=True,separators=(',',':')).encode()!=raw: raise ValueError('qualification record invalid')
    return value


def _write(path,value): origin_credentials._write(path,json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def dispose_synthetic_volume(proof):
    """Delete the one synthetic volume named in its completed owned fixture."""
    if SOURCE not in origin21_state.MANAGED_SOURCE_FILES: raise RuntimeError('qualification cleanup source not pinned')
    from deploy.local.origin21_managed_qualification import OwnedManagedQualification
    if type(proof) is not OwnedManagedQualification: raise ValueError('qualification proof required')
    proof.verify(); token=proof.token; folder=proof.folder
    intent=_read(folder/'qualification.intent'); topology=_read(folder/'topology.intent'); done=_read(folder/'topology.cleaned')
    initializer=_read(init.BASE/'initializer.intent')
    if type(initializer) is not dict or set(initializer)!={'version','head','build_image','build_receipt_sha256','token','network','volume'} or initializer.get('version')!=1 or initializer.get('network')!=init.NETWORK or initializer.get('volume')!=proof.volume or initializer.get('head')!=intent['head'] or not re.fullmatch('[0-9a-f]{32}',initializer.get('token','')): raise ValueError('qualification initializer identity changed')
    name=proof.volume
    intent_sha=hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if (type(topology) is not dict or set(topology)!={'version','token','intent_sha256','containers','networks'} or topology['version']!=1 or topology['token']!=token or topology['intent_sha256']!=intent_sha): raise ValueError('qualification topology invalid')
    containers=topology['containers']; networks=topology['networks']
    if type(containers) is not list or len(containers)!=9 or type(networks) is not list or len(networks)!=2 or any(type(x) is not str or not re.fullmatch('[0-9a-f]{64}',x) for x in containers+networks) or len(set(containers+networks))!=11: raise ValueError('qualification resource identity invalid')
    if done!={'version':1,'token':token,'intent_sha256':intent_sha,'containers_removed':containers,'networks_removed':networks}: raise ValueError('qualification cleanup incomplete')
    source=init._source(intent['head'])
    def verify():
        proof.verify()
        if _read(init.BASE/'initializer.intent')!=initializer or init._source(intent['head'])!=source or _read(folder/'qualification.intent')!=intent or _read(folder/'topology.intent')!=topology or _read(folder/'topology.cleaned')!=done: raise ValueError('qualification identity changed')
        volume=products._objects(['docker','volume','inspect',name]); labels=volume.get('Labels') or {}
        if volume.get('Name')!=name or volume.get('Driver')!='local' or volume.get('Scope')!='local' or labels.get(LABEL)!=token or labels.get(init.LABEL)!=initializer['token'] or (volume.get('Options') or {}): raise ValueError('synthetic volume ownership changed')
        for cid in containers:
            if products._command(['docker','ps','-aq','--no-trunc','--filter','id='+cid],15).strip(): raise ValueError('qualification container remains')
        for nid in networks:
            if products._command(['docker','network','ls','-q','--no-trunc','--filter','id='+nid],15).strip(): raise ValueError('qualification network remains')
        if products._command(['docker','ps','-aq','--no-trunc','--filter','label='+LABEL+'='+token],15).strip(): raise ValueError('qualification ownership remains')
        if products._command(['docker','ps','-aq','--no-trunc','--filter','volume='+name],15).strip(): raise ValueError('synthetic volume still in use')
    verify(); _write(folder/'volume-dispose.intent',{'version':1,'token':token,'volume':name})
    verify()
    if products._command(['docker','volume','rm',name],30)!=name.encode('ascii'): raise RuntimeError('synthetic volume removal uncertain')
    if products._command(['docker','volume','ls','-q','--filter','name=^'+name+'$'],15).strip(): raise RuntimeError('synthetic volume remains')
    _write(folder/'volume-dispose.done',{'version':1,'token':token,'volume':name})
