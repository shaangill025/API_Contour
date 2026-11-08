#!/usr/bin/env python3
"""Run the full owned Origin21 qualification from an isolated exact-HEAD worktree."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
OWNER_LABEL='org.apicontour.build-owner'
HEAD_LABEL='org.apicontour.build-head'
OUTPUT_LIMIT=16_777_216
GLOBAL_SECONDS=3000
BUILD_SECONDS=1800
FULL_SECONDS=810


def checked_path(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts or any(part.is_symlink() for part in (path,*path.parents)): raise ValueError('unsafe path')
    return path


class OwnedDirectory:
    def __init__(self,path):
        self.path=checked_path(path)
        self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        st=os.fstat(self.fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:
            os.close(self.fd); raise ValueError('owner invalid')
        self.identity=(st.st_dev,st.st_ino)
        self.verify()
    def verify(self):
        checked_path(self.path); current=os.lstat(self.path); held=os.fstat(self.fd)
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev,current.st_ino)!=self.identity or (held.st_dev,held.st_ino)!=self.identity or current.st_uid!=os.geteuid() or stat.S_IMODE(current.st_mode)!=0o700: raise ValueError('owner identity changed')
    def write(self,name,data):
        if name not in ('intent.json','worktree.json','build.log','qualification.log','build-receipt.json'): raise ValueError('invalid owner record')
        self.verify()
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        with os.fdopen(fd,'wb') as out: out.write(data); out.flush(); os.fsync(out.fileno())
        os.fsync(self.fd); self.verify()
        return self.path/name
    def remove(self):
        self.verify(); allowed={'intent.json','worktree.json','build.log','qualification.log','build-receipt.json'}
        names=set(os.listdir(self.fd))
        if not names.issubset(allowed): raise ValueError('unexpected owner contents')
        for name in names:
            self.verify(); entry=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            if not stat.S_ISREG(entry.st_mode) or entry.st_uid!=os.geteuid() or stat.S_IMODE(entry.st_mode)!=0o600 or entry.st_nlink!=1: raise ValueError('unsafe owner record')
            os.unlink(name,dir_fd=self.fd)
        os.fsync(self.fd); self.verify(); os.rmdir(self.path)
    def close(self): os.close(self.fd)


def encode(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def public_child_failure_lines(data):
    """Allow only the driver's closed diagnostic grammar, never raw child output."""
    phases='fixture-setup|select-one|continuity-guard|blocked-transaction|local-death|lost-ack|foreign-tcp|fixture-final-check|full-capture|owned-cleanup'
    kinds='AssertionError|RuntimeError|TimeoutError|ValueError|PermissionError|FileNotFoundError|OSError|KeyError|IndexError|TypeError|AttributeError|ExceptionGroup|BaseExceptionGroup|CleanupFailure'
    location=r'(?:test-origin21-onboarding\.py|origin21_sql_runner\.py|origin21_transport\.py):[1-9][0-9]{0,6}'
    pattern=rb'fixture failure phase=(?:'+phases.encode()+rb') type=(?:'+kinds.encode()+rb')(?: location=(?:unavailable|'+location.encode()+rb'(?:,'+location.encode()+rb'){0,5}))?'
    result=[]
    for line in data.splitlines():
        if re.fullmatch(pattern,line) and line not in result:
            result.append(line)
            if len(result)==8: break
    return [line.decode('ascii') for line in result]


def public_failure_locations(error,depth=0):
    if depth>=8: return []
    if isinstance(error,BaseExceptionGroup):
        return [line for child in error.exceptions[:8] for line in public_failure_locations(child,depth+1)][:16]
    result=[];tb=error.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code.co_filename==__file__: result.append('FAIL: Origin21 wrapper location=qualify-origin21-onboarding.py:'+str(tb.tb_lineno))
        tb=tb.tb_next
    return result[-8:]


def observe_exit(process):
    # WNOWAIT retains our child identity through the one group-stop attempt.
    return os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)


def wait_exit(process,deadline):
    while True:
        if time.monotonic()>=deadline: raise TimeoutError('process deadline')
        observed=observe_exit(process)
        if time.monotonic()>=deadline: raise TimeoutError('process deadline')
        if observed is not None:
            if observed.si_code==os.CLD_EXITED: return observed.si_status
            if observed.si_code in (os.CLD_KILLED,os.CLD_DUMPED): return -observed.si_status
            raise RuntimeError('unknown child exit observation')
        left=deadline-time.monotonic()
        if left<=0: raise TimeoutError('process deadline')
        time.sleep(min(.025,left))


def group_members(group,deadline):
    """Bounded observation, not an atomic containment or no-fork attestation."""
    left=deadline-time.monotonic()
    if left<=0: raise TimeoutError('group inspection deadline')
    end=min(deadline,time.monotonic()+1)
    process=subprocess.Popen(['/bin/ps','-axo','pid=,pgid=,stat='],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
        env={'PATH':os.defpath,'LC_ALL':'C'})
    sel=selectors.DefaultSelector();data=bytearray();failures=[]
    try:
        for name,pipe in (('out',process.stdout),('err',process.stderr)):
            os.set_blocking(pipe.fileno(),False);sel.register(pipe,selectors.EVENT_READ,name)
        while sel.get_map():
            left=end-time.monotonic()
            if left<=0: raise TimeoutError('group inspection deadline')
            for key,_ in sel.select(left):
                try: chunk=os.read(key.fd,min(65536,1048576-len(data)+1))
                except BlockingIOError: continue
                if not chunk: sel.unregister(key.fileobj);continue
                if key.data=='err': raise RuntimeError('group inspection stderr')
                data.extend(chunk)
                if len(data)>1048576: raise RuntimeError('group inspection overflow')
        left=end-time.monotonic()
        if left<=0: raise TimeoutError('group inspection deadline')
        if process.wait(timeout=left)!=0: raise RuntimeError('group inspection failed')
        if time.monotonic()>=end: raise TimeoutError('group inspection deadline')
    except BaseException as error: failures.append(error)
    finally:
        try: sel.close()
        except BaseException as error: failures.append(error)
        try:
            if process.returncode is None: process.kill()
        except BaseException as error: failures.append(error)
        try: process.wait(timeout=max(0,deadline-time.monotonic()))
        except BaseException as error: failures.append(error)
        for pipe in (process.stdout,process.stderr):
            try: pipe.close()
            except BaseException as error: failures.append(error)
    if len(failures)==1: raise failures[0]
    if failures: raise BaseExceptionGroup('group inspection and cleanup failures',failures)
    members=set();seen=set()
    for line in data.splitlines():
        fields=line.split()
        if len(fields)!=3 or not all(re.fullmatch(rb'[0-9]{1,10}',v) for v in fields[:2]) or not re.fullmatch(rb'[A-Za-z<+]{1,24}',fields[2]): raise ValueError('group inspection invalid')
        pid,pgid=map(int,fields[:2])
        if pid in seen: raise ValueError('duplicate process observation')
        seen.add(pid)
        if pgid==group: members.add(pid)
    if group not in members: raise RuntimeError('owned leader observation missing')
    return members


class Runner:
    def __init__(self,deadline,owner=None): self.deadline=deadline; self.owner=owner
    def __call__(self,args,*,cwd,timeout,log=None):
        remaining=self.deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('absolute deadline')
        limit=min(timeout,remaining); env=os.environ.copy(); env['PYTHONDONTWRITEBYTECODE']='1'
        process=subprocess.Popen(args,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        sel=selectors.DefaultSelector(); chunks={'stdout':bytearray(),'stderr':bytearray()}; end=time.monotonic()+limit; count=0
        failures=[]; status=None
        try:
            for name,pipe in (('stdout',process.stdout),('stderr',process.stderr)):
                os.set_blocking(pipe.fileno(),False); sel.register(pipe,selectors.EVENT_READ,name)
            while sel.get_map():
                left=end-time.monotonic()
                if left<=0: raise TimeoutError('process deadline')
                events=sel.select(left)
                if not events: raise TimeoutError('process deadline')
                for key,_ in events:
                    try: chunk=os.read(key.fd,min(65536,OUTPUT_LIMIT-count+1))
                    except BlockingIOError: continue
                    if not chunk: sel.unregister(key.fileobj); continue
                    count+=len(chunk)
                    if count>OUTPUT_LIMIT: raise RuntimeError('process output bound')
                    chunks[key.data].extend(chunk)
            status=wait_exit(process,end)
            if status:
                if list(args[:3])==[sys.executable,'scripts/test-origin21-onboarding.py','--full-capture']:
                    for line in public_child_failure_lines(bytes(chunks['stdout'])+b'\n'+bytes(chunks['stderr'])): print(line,file=sys.stderr,flush=True)
                raise RuntimeError('process failed')
        except BaseException as error: failures.append(error)
        finally:
            sel.close()
            deadline=min(time.monotonic()+5,self.deadline)
            exited=False
            try: exited=observe_exit(process) is not None
            except BaseException as error: failures.append(error)
            if exited:
                try:
                    if group_members(process.pid,deadline)!={process.pid}: raise RuntimeError('descendant survived leader')
                except BaseException as error: failures.append(error)
            try:
                try: os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                except PermissionError:
                    if not exited: raise
                    # Darwin may deny a zombie-only group; only post-reap ESRCH proves absence.
                process.wait(timeout=max(0,deadline-time.monotonic()))
                while True:
                    try: os.killpg(process.pid,0)
                    except ProcessLookupError: break
                    except PermissionError:
                        if time.monotonic()>=deadline: raise
                    if time.monotonic()>=deadline: raise RuntimeError('process group remains')
                    time.sleep(min(.025,max(0,deadline-time.monotonic())))
            except BaseException as error: failures.append(error)
            for pipe in (process.stdout,process.stderr):
                try: pipe.close()
                except BaseException as error: failures.append(error)
            if log is not None:
                try:
                    if self.owner is None or log.parent!=self.owner.path: raise ValueError('log owner invalid')
                    self.owner.write(log.name,bytes(chunks['stdout'])+b'\n'+bytes(chunks['stderr']))
                except BaseException as error: failures.append(error)
        if len(failures)==1: raise failures[0]
        if failures: raise BaseExceptionGroup('process and cleanup failures',failures)
        return bytes(chunks['stdout'])



def snapshot(run,root):
    root=checked_path(root)
    def git(*args): return run(['git',*args],cwd=root,timeout=15)
    head=git('rev-parse','HEAD').decode('ascii').strip()
    if not re.fullmatch(r'[0-9a-f]{40}',head) or git('status','--porcelain','--untracked-files=all'): raise ValueError('source not clean')
    paths=git('ls-files','-z').split(b'\0'); hashes={}
    for raw in paths:
        if not raw: continue
        name=os.fsdecode(raw); rel=Path(name)
        if not name or rel.is_absolute() or '..' in rel.parts or name in hashes: raise ValueError('tracked path invalid')
        path=checked_path(root/rel)
        if not path.is_file(): raise ValueError('tracked source invalid')
        digest=hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda:source.read(1048576),b''): digest.update(chunk)
        hashes[name]=digest.hexdigest()
    if not hashes: raise ValueError('tracked source empty')
    return head,hashes


def registrations(run,root):
    data=run(['git','worktree','list','--porcelain','-z'],cwd=root,timeout=15)
    entries=[]; item={}
    for field in data.split(b'\0'):
        if not field:
            if item: entries.append(item); item={}
            continue
        key,_,value=field.partition(b' ')
        if key in (b'worktree',b'HEAD'):
            if key in item: raise ValueError('ambiguous worktree')
            item[key]=os.fsdecode(value)
    if item: entries.append(item)
    return entries


def require_registration(run,root,child,head,expected=True):
    matches=[entry for entry in registrations(run,root) if entry.get(b'worktree')==str(child)]
    if not expected:
        if matches: raise RuntimeError('worktree remains')
    elif len(matches)!=1 or matches[0].get(b'HEAD')!=head: raise ValueError('worktree ownership mismatch')


def image_identity(run,root,tag,token,head):
    data=json.loads(run(['docker','image','inspect',tag],cwd=root,timeout=20))
    if type(data) is not list or len(data)!=1 or type(data[0]) is not dict: raise ValueError('image inspection invalid')
    image=data[0]; ident=image.get('Id'); labels=(image.get('Config') or {}).get('Labels') or {}
    if not isinstance(ident,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',ident) or tag not in (image.get('RepoTags') or []) or labels.get(OWNER_LABEL)!=token or labels.get(HEAD_LABEL)!=head: raise ValueError('image ownership mismatch')
    return ident


def qualify(run,root,owner,token):
    root=checked_path(root); owner.verify()
    if not re.fullmatch(r'[0-9a-f]{32}',token): raise ValueError('owner invalid')
    head,source=snapshot(run,root); child=owner.path/'worktree'; tag='apicontour-origin21-build:'+token
    if os.path.lexists(child): raise ValueError('worktree path exists')
    require_registration(run,root,child,head,expected=False)
    owner.write('intent.json',encode({'version':1,'head':head,'tag':tag,'token':token,'worktree':str(child)}))
    owner.verify()
    run(['git','worktree','add','--detach',str(child),head],cwd=root,timeout=120)
    require_registration(run,root,child,head)
    if not (child/'.git').is_file() or (child/'.git').is_symlink() or snapshot(run,child)!=(head,source): raise ValueError('worktree source mismatch')
    owner.write('worktree.json',encode({'head':head,'path':str(child)}))
    owner.verify()
    run(['docker','build','--pull=false','--label',OWNER_LABEL+'='+token,'--label',HEAD_LABEL+'='+head,'--tag',tag,'-f','deploy/local/Dockerfile','.'],cwd=child,timeout=BUILD_SECONDS,log=owner.path/'build.log')
    image=image_identity(run,child,tag,token,head)
    receipt=encode({'version':1,'head':head,'image_id':image,'status':'passed','owner_token':token,'tag':tag})
    path=owner.write('build-receipt.json',receipt); digest=hashlib.sha256(receipt).hexdigest()
    if snapshot(run,root)!=(head,source) or snapshot(run,child)!=(head,source): raise ValueError('source changed after build')
    owner.verify()
    run([sys.executable,'scripts/test-origin21-onboarding.py','--full-capture',str(path),digest],cwd=child,timeout=FULL_SECONDS,log=owner.path/'qualification.log')
    if snapshot(run,root)!=(head,source) or snapshot(run,child)!=(head,source): raise ValueError('source changed after qualification')
    if image_identity(run,child,tag,token,head)!=image: raise ValueError('image identity changed')
    require_registration(run,root,child,head)
    ignored=run(['git','ls-files','--others','--ignored','--exclude-standard','-z'],cwd=child,timeout=15)
    if ignored: raise RuntimeError('ignored worktree state retained')
    owner.verify()
    run(['docker','image','rm',tag],cwd=child,timeout=30)
    remaining=run(['docker','image','ls','-q','--no-trunc','--filter','reference='+tag],cwd=child,timeout=20)
    if remaining.strip(): raise RuntimeError('image tag remains')
    if snapshot(run,root)!=(head,source) or snapshot(run,child)!=(head,source): raise ValueError('source changed before removal')
    require_registration(run,root,child,head)
    owner.verify()
    run(['git','worktree','remove',str(child)],cwd=root,timeout=120)
    require_registration(run,root,child,head,expected=False)
    if os.path.lexists(child): raise RuntimeError('worktree remains')
    if snapshot(run,root)!=(head,source): raise ValueError('source changed after removal')


def main():
    if len(sys.argv)!=1: raise ValueError('no arguments accepted')
    os.umask(0o077)
    folder=Path(tempfile.mkdtemp(prefix='contour-origin21-qualification-')).resolve(); folder.chmod(0o700)
    owner=OwnedDirectory(folder)
    failure=None
    try:
        run=Runner(time.monotonic()+GLOBAL_SECONDS,owner)
        qualify(run,ROOT,owner,uuid.uuid4().hex)
        owner.remove()
    except BaseException as error: failure=error
    try: owner.close()
    except BaseException as cleanup:
        if failure is not None: raise BaseExceptionGroup('qualification and owner close failures',[failure,cleanup]) from None
        raise
    if failure is not None: raise failure


if __name__=='__main__':
    try: main(); print('PASS: Origin21 full owned qualification')
    except BaseException as error:
        for line in public_failure_locations(error): print(line,file=sys.stderr)
        print('FAIL: Origin21 qualification; private state retained',file=sys.stderr)
        raise SystemExit(1) from None
