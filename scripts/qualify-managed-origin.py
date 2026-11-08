#!/usr/bin/env python3
"""Build and qualify one fresh, exclusively owned managed-Origin worktree."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
HELPER=ROOT/'scripts/qualify-origin21-onboarding.py'
GLOBAL_SECONDS=3600
BUILD_SECONDS=1800
QUALIFY_SECONDS=1200


def helper():
    if any(p.is_symlink() for p in (HELPER,*HELPER.parents)) or not HELPER.is_file(): raise ValueError('qualification helper unavailable')
    for args in (['git','ls-files','--error-unmatch','scripts/qualify-origin21-onboarding.py'],['git','diff','--quiet','HEAD','--','scripts/qualify-origin21-onboarding.py']):
        result=subprocess.run(args,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=False)
        if result.returncode: raise ValueError('qualification helper not exact head')
    raw=HELPER.read_bytes(); module=runpy.run_path(str(HELPER))
    if HELPER.read_bytes()!=raw: raise ValueError('qualification helper changed')
    return module


def read_record(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>32768: raise ValueError('private record invalid')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(32769)
    finally: os.close(fd)
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value: raise ValueError('duplicate record key')
            value[key]=item
        return value
    value=json.loads(raw,object_pairs_hook=unique)
    if json.dumps(value,sort_keys=True,separators=(',',':')).encode()!=raw: raise ValueError('record encoding changed')
    return value


def cleanup_private(run,child,owner,head):
    """Delete the owned synthetic private tree only after exact resource absence."""
    owner.verify(); base=child/'.local-mvp-managed'; st=os.lstat(base)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700: raise ValueError('managed state identity invalid')
    def private_dir(path):
        item=os.lstat(path)
        if not stat.S_ISDIR(item.st_mode) or item.st_uid!=os.geteuid() or item.st_dev!=st.st_dev or stat.S_IMODE(item.st_mode)!=0o700: raise ValueError('private directory invalid')
    parent=base/'qualification'; private_dir(parent); tokens=os.listdir(parent)
    if len(tokens)!=1 or not re.fullmatch('[0-9a-f]{32}',tokens[0]): raise ValueError('qualification identity invalid')
    token=tokens[0]; folder=parent/token; private_dir(folder)
    edge_dir=base/'managed-edge'; private_dir(edge_dir); private_dir(edge_dir/'state')
    intent=read_record(folder/'qualification.intent'); topology=read_record(folder/'topology.intent'); done=read_record(folder/'topology.cleaned'); disposed=read_record(folder/'volume-dispose.done')
    raw=json.dumps(intent,sort_keys=True,separators=(',',':')).encode(); digest=hashlib.sha256(raw).hexdigest()
    volume='contour-managed-origin21-qual-'+token+'-data'
    if type(intent) is not dict or set(intent)!={'version','kind','token','head','volume','destination','destination_sha256','source_identity','build_image','build_receipt_sha256'} or intent.get('version')!=1 or intent.get('kind')!='synthetic' or intent.get('token')!=token or intent.get('head')!=head or intent.get('volume')!=volume or intent.get('destination')!='tests/fixtures/managed-origin-qualification/destination.js' or not re.fullmatch('[0-9a-f]{64}',intent.get('destination_sha256','')) or hashlib.sha256((child/intent['destination']).read_bytes()).hexdigest()!=intent['destination_sha256']: raise ValueError('qualification intent changed')
    if type(topology) is not dict or set(topology)!={'version','token','intent_sha256','containers','networks'} or topology.get('version')!=1 or topology.get('token')!=token or topology.get('intent_sha256')!=digest: raise ValueError('qualification topology changed')
    containers=topology['containers']; networks=topology['networks']
    if type(containers) is not list or len(containers)!=9 or type(networks) is not list or len(networks)!=2 or any(type(x) is not str or not re.fullmatch('[0-9a-f]{64}',x) for x in containers+networks) or len(set(containers+networks))!=11: raise ValueError('qualification resource identity invalid')
    if done!={'version':1,'token':token,'intent_sha256':digest,'containers_removed':containers,'networks_removed':networks} or disposed!={'version':1,'token':token,'volume':volume}: raise ValueError('qualification cleanup incomplete')
    initializer=read_record(base/'initializer.intent'); edge=read_record(base/'managed-edge'/'intent.json')
    if type(initializer) is not dict or set(initializer)!={'version','head','build_image','build_receipt_sha256','token','network','volume'} or initializer.get('version')!=1 or initializer.get('head')!=head or initializer.get('volume')!=volume or initializer.get('build_image')!=intent['build_image'] or initializer.get('build_receipt_sha256')!=intent['build_receipt_sha256'] or not re.fullmatch('[0-9a-f]{32}',initializer.get('token','')) or type(edge) is not dict or set(edge)!={'version','origin_token','edge_token'} or edge.get('version')!=1 or not re.fullmatch('[0-9a-f]{32}',edge.get('edge_token','')): raise ValueError('ownership identity changed')
    read_record(edge_dir/'state'/'publication.exec.intent')
    for cid in containers:
        if run(['docker','ps','-aq','--no-trunc','--filter','id='+cid],cwd=child,timeout=15).strip(): raise ValueError('owned container remains')
    for nid in networks:
        if run(['docker','network','ls','-q','--no-trunc','--filter','id='+nid],cwd=child,timeout=15).strip(): raise ValueError('owned network remains')
    for label in ('org.apicontour.managed-db-owner='+initializer['token'],'org.apicontour.managed-edge-owner='+edge['edge_token'],'com.docker.compose.project=apicontour-origin21-managed'):
        if run(['docker','ps','-aq','--no-trunc','--filter','label='+label],cwd=child,timeout=15).strip(): raise ValueError('owned inventory remains')
    if run(['docker','volume','ls','-q','--filter','name=^'+volume+'$'],cwd=child,timeout=15).strip(): raise ValueError('synthetic volume remains')
    if not shutil.rmtree.avoids_symlink_attacks: raise RuntimeError('safe private cleanup unavailable')
    for directory,dirs,files in os.walk(base,topdown=True,followlinks=False):
        path=Path(directory); current=os.lstat(path)
        if not stat.S_ISDIR(current.st_mode) or current.st_uid!=os.geteuid() or current.st_dev!=st.st_dev or stat.S_IMODE(current.st_mode)!=0o700: raise ValueError('private directory changed')
        for name in dirs+files:
            item=os.lstat(path/name)
            if item.st_uid!=os.geteuid() or item.st_dev!=st.st_dev or stat.S_ISLNK(item.st_mode) or not (stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)): raise ValueError('private artifact changed')
            if stat.S_ISREG(item.st_mode) and (item.st_nlink!=1 or stat.S_IMODE(item.st_mode)!=0o600): raise ValueError('private file changed')
    owner.verify()
    now=os.lstat(base)
    if (now.st_dev,now.st_ino)!=(st.st_dev,st.st_ino): raise ValueError('managed state replaced')
    shutil.rmtree(base)
    if os.path.lexists(base): raise RuntimeError('private state remains')


def qualify(run,owner,token,h):
    head,source=h['snapshot'](run,ROOT); child=owner.path/'worktree'; tag='apicontour-origin21-build:'+token
    if os.path.lexists(child): raise ValueError('worktree path exists')
    h['require_registration'](run,ROOT,child,head,expected=False)
    owner.write('intent.json',h['encode']({'version':1,'head':head,'tag':tag,'token':token,'worktree':str(child)})); owner.verify()
    run(['git','worktree','add','--detach',str(child),head],cwd=ROOT,timeout=120)
    h['require_registration'](run,ROOT,child,head)
    if not (child/'.git').is_file() or (child/'.git').is_symlink() or h['snapshot'](run,child)!=(head,source): raise ValueError('worktree source mismatch')
    owner.write('worktree.json',h['encode']({'head':head,'path':str(child)})); owner.verify()
    run(['docker','build','--pull=false','--label',h['OWNER_LABEL']+'='+token,'--label',h['HEAD_LABEL']+'='+head,'--tag',tag,'-f','deploy/local/Dockerfile','.'],cwd=child,timeout=BUILD_SECONDS,log=owner.path/'build.log')
    image=h['image_identity'](run,child,tag,token,head)
    receipt=h['encode']({'version':1,'head':head,'image_id':image,'status':'passed','owner_token':token,'tag':tag})
    path=owner.write('build-receipt.json',receipt); digest=hashlib.sha256(receipt).hexdigest()
    if h['snapshot'](run,ROOT)!=(head,source) or h['snapshot'](run,child)!=(head,source): raise ValueError('source changed after build')
    run([sys.executable,'scripts/test-managed-origin-qualification.py',image,head,str(path),digest],cwd=child,timeout=QUALIFY_SECONDS,log=owner.path/'qualification.log')
    if h['snapshot'](run,ROOT)!=(head,source) or h['snapshot'](run,child)!=(head,source): raise ValueError('source changed after qualification')
    if h['image_identity'](run,child,tag,token,head)!=image: raise ValueError('build image changed')
    h['require_registration'](run,ROOT,child,head)
    owner.verify(); run(['docker','image','rm',tag],cwd=child,timeout=30)
    if run(['docker','image','ls','-q','--no-trunc','--filter','reference='+tag],cwd=child,timeout=20).strip(): raise RuntimeError('build image remains')
    cleanup_private(run,child,owner,head)
    if run(['git','ls-files','--others','--ignored','--exclude-standard','-z'],cwd=child,timeout=15): raise RuntimeError('ignored worktree state retained')
    if h['snapshot'](run,ROOT)!=(head,source) or h['snapshot'](run,child)!=(head,source): raise ValueError('source changed before removal')
    h['require_registration'](run,ROOT,child,head); owner.verify()
    run(['git','worktree','remove',str(child)],cwd=ROOT,timeout=120)
    h['require_registration'](run,ROOT,child,head,expected=False)
    if os.path.lexists(child) or h['snapshot'](run,ROOT)!=(head,source): raise RuntimeError('worktree cleanup uncertain')


def main():
    if len(sys.argv)!=1: raise ValueError('no arguments accepted')
    if not callable(getattr(os,'waitid',None)) or any(not hasattr(os,name) for name in ('P_PID','WEXITED','WNOHANG','WNOWAIT')):
        print('qualification requires configured Python 3.13 with POSIX waitid/WNOWAIT',file=sys.stderr)
        raise RuntimeError('qualification runtime unavailable')
    deadline=time.monotonic()+GLOBAL_SECONDS
    h=helper(); h['require_process_primitives']()
    os.umask(0o077); folder=Path(tempfile.mkdtemp(prefix='contour-managed-origin-qualification-')).resolve(); folder.chmod(0o700)
    owner=h['OwnedDirectory'](folder); failures=[]
    try:
        run=h['Runner'](deadline,owner); qualify(run,owner,uuid.uuid4().hex,h); owner.remove()
    except BaseException as error: failures.append(error)
    try: owner.close()
    except BaseException as error: failures.append(error)
    if len(failures)==1: raise failures[0]
    if failures: raise BaseExceptionGroup('qualification and owner cleanup failures',failures)


if __name__=='__main__':
    try: main(); print('managed Origin qualification passed')
    except BaseException:
        print('managed Origin qualification failed; owned state retained',file=sys.stderr)
        raise SystemExit(1) from None
