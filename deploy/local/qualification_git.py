"""Fresh, bounded facts for one standard detached linked worktree.

Data only: no qualification, ownership or source-hash authority is created.
This supports only ordinary absolute gitfile/backlink and detached SHA-1 HEAD
layouts. A trusted caller supplies a bounded Git runner and retains all other
proof and source checks. Same-UID/privileged-host ABA is outside this model.
"""
import os
from pathlib import Path
import re
import stat
import time

MAX_WORKTREES=1024
MAX_PATH=4096
MAX_REGISTRY_BYTES=4*1024*1024
MAX_STATUS=8*1024*1024
HEAD=re.compile(r'^[0-9a-f]{40}$')
_SEAL=object()


def _fail(): raise ValueError('qualification git fact unavailable')


def _path(value):
    if not isinstance(value,(str,Path)): _fail()
    text=str(value)
    try: text.encode('utf-8','strict')
    except UnicodeError: _fail()
    if (not text or not os.path.isabs(text) or os.path.normpath(text)!=text or
        len(os.fsencode(text))>MAX_PATH or any(ord(c)<32 or ord(c)==127 for c in text)): _fail()
    return Path(text)


def _check(deadline):
    if time.monotonic() >= deadline: raise TimeoutError('qualification git deadline')


def _directory_identity(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid)


def _identity(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)


def _chain(path):
    path=_path(path); result=[]
    for part in reversed((path,*path.parents)):
        st=os.lstat(part)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0,os.geteuid()) or st.st_mode & 0o022: _fail()
        result.append((st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid))
    return tuple(result)


def _read_at(parent_fd,name,limit=MAX_PATH,deadline=None):
    if not isinstance(name,str) or name in ('','.','..') or '/' in name or '\0' in name: _fail()
    if deadline is not None: _check(deadline)
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or
            before.st_mode & 0o022 or not 0<before.st_size<=limit): _fail()
        data=bytearray()
        while len(data)<before.st_size:
            if deadline is not None: _check(deadline)
            part=os.read(fd,min(65536,before.st_size-len(data)))
            if not part: _fail()
            data.extend(part)
        if _identity(os.fstat(fd))!=_identity(before) or _identity(os.stat(name,dir_fd=parent_fd,follow_symlinks=False))!=_identity(before): _fail()
        if deadline is not None: _check(deadline)
        return bytes(data),_identity(before)
    finally: os.close(fd)


def _directory(path):
    before=_chain(path)
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    st=os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or _directory_identity(st)!=before[-1]:
        os.close(fd); _fail()
    return fd,before,_directory_identity(st)


def _names(fd,deadline):
    result=[]
    with os.scandir(fd) as entries:
        for entry in entries:
            _check(deadline)
            if len(result)>=MAX_WORKTREES: _fail()
            result.append(entry.name)
    return sorted(result)


def _checked_cli(run,args,root,deadline):
    _check(deadline)
    remaining=deadline-time.monotonic()
    if remaining<=0: raise TimeoutError('qualification git deadline')
    value=run(args,cwd=root,timeout=remaining)
    _check(deadline)
    if isinstance(value,str): value=value.encode('utf-8')
    if not isinstance(value,bytes) or len(value)>MAX_STATUS: _fail()
    return value


def _cli_path(value):
    try: text=value.decode('utf-8')
    except UnicodeError: _fail()
    if text.endswith('\n'): text=text[:-1]
    return _path(text)


class Layout:
    """Bound structural paths once; re-read current registration facts on every call."""
    __slots__=('root','gitdir','common','registry','_sealed')

    def __setattr__(self,name,value):
        if getattr(self,'_sealed',False): raise AttributeError('layout is immutable')
        object.__setattr__(self,name,value)

    def __init__(self,seal,root,gitdir,common):
        if seal is not _SEAL: _fail()
        self.root=_path(root); self.gitdir=_path(gitdir); self.common=_path(common)
        if (self.common.name!='.git' or self.gitdir.parent!=self.common/'worktrees' or
            self.root==self.common.parent or self.root.name!='worktree'): _fail()
        self.registry=self.common/'worktrees'
        for path in (self.root,self.gitdir,self.common,self.registry): _chain(path)
        self._sealed=True

    @classmethod
    def capture(cls,root,run,expected_head):
        root=_path(root)
        if not isinstance(expected_head,str) or not HEAD.fullmatch(expected_head): _fail()
        deadline=time.monotonic()+15
        top=_cli_path(_checked_cli(run,['git','rev-parse','--show-toplevel'],root,deadline))
        gitdir=_cli_path(_checked_cli(run,['git','rev-parse','--absolute-git-dir'],root,deadline))
        common=_cli_path(_checked_cli(run,['git','rev-parse','--git-common-dir'],root,deadline))
        if top!=root: _fail()
        layout=cls(_SEAL,root,gitdir,common)
        _check(deadline); layout.registration(expected_head,deadline=deadline); _check(deadline)
        return layout

    def registration(self,expected_head,*,deadline=None):
        if not isinstance(expected_head,str) or not HEAD.fullmatch(expected_head): _fail()
        if deadline is None: deadline=time.monotonic()+15
        _check(deadline); handles=[]; files=[]
        try:
            rootfd,rootchain,rootstat=_directory(self.root); handles.append(rootfd)
            regfd,regchain,regstat=_directory(self.registry); handles.append(regfd)
            gitfd,gitchain,gitstat=_directory(self.gitdir); handles.append(gitfd)
            commonchain=_chain(self.common)
            pointer,pointerid=_read_at(rootfd,'.git',deadline=deadline)
            if pointer != b'gitdir: '+os.fsencode(str(self.gitdir))+b'\n': _fail()
            files.append((rootfd,'.git',pointerid))
            back,backid=_read_at(gitfd,'gitdir',deadline=deadline)
            if back != os.fsencode(str(self.root/'.git'))+b'\n': _fail()
            files.append((gitfd,'gitdir',backid))
            common,commonid=_read_at(gitfd,'commondir',deadline=deadline)
            if common != b'../..\n': _fail()
            files.append((gitfd,'commondir',commonid))
            head,headid=_read_at(gitfd,'HEAD',128,deadline=deadline)
            if head != expected_head.encode('ascii')+b'\n': _fail()
            files.append((gitfd,'HEAD',headid))
            names=_names(regfd,deadline)
            if len(names)>MAX_WORKTREES or self.gitdir.name not in names: _fail()
            matched=0; total=0; entries=[]
            for name in names:
                _check(deadline)
                if not name or name in ('.','..') or '/' in name or len(os.fsencode(name))>255: _fail()
                entry=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=regfd)
                try:
                    st=os.fstat(entry); current=os.stat(name,dir_fd=regfd,follow_symlinks=False)
                    if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o022 or _directory_identity(st)!=_directory_identity(current)): _fail()
                    raw,identity=_read_at(entry,'gitdir',deadline=deadline); total+=len(raw)
                    if total>MAX_REGISTRY_BYTES or not raw.endswith(b'\n'): _fail()
                    try: path=_path(raw[:-1].decode('utf-8','strict'))
                    except (ValueError,UnicodeError): _fail()
                    if path==self.root/'.git': matched+=1
                    entries.append((name,_directory_identity(st),identity))
                    if _identity(os.stat('gitdir',dir_fd=entry,follow_symlinks=False))!=identity or _directory_identity(os.fstat(entry))!=_directory_identity(st): _fail()
                finally: os.close(entry)
            if matched!=1: _fail()
            for name,entry_id,file_id in entries:
                _check(deadline)
                entry=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=regfd)
                try:
                    if (_directory_identity(os.fstat(entry))!=entry_id or
                        _directory_identity(os.stat(name,dir_fd=regfd,follow_symlinks=False))!=entry_id or
                        _identity(os.stat('gitdir',dir_fd=entry,follow_symlinks=False))!=file_id): _fail()
                finally: os.close(entry)
            for fd,name,identity in files:
                if _identity(os.stat(name,dir_fd=fd,follow_symlinks=False))!=identity: _fail()
            if (_names(regfd,deadline)!=names or _directory_identity(os.fstat(rootfd))!=rootstat or
                _directory_identity(os.fstat(regfd))!=regstat or _directory_identity(os.fstat(gitfd))!=gitstat or
                _chain(self.root)!=rootchain or _chain(self.registry)!=regchain or
                _chain(self.gitdir)!=gitchain or _chain(self.common)!=commonchain): _fail()
            _check(deadline)
        finally:
            for fd in reversed(handles): os.close(fd)
        _check(deadline); return True

    def clean_status(self,expected_head,run):
        """Fresh Git status only; registration must be checked separately."""
        if not isinstance(expected_head,str) or not HEAD.fullmatch(expected_head): _fail()
        deadline=time.monotonic()+15; _check(deadline)
        before=_chain(self.root)
        raw=_checked_cli(run,['git','status','--porcelain=v2','--branch','--untracked-files=all','-z'],self.root,deadline)
        if raw != b'# branch.oid '+expected_head.encode('ascii')+b'\0# branch.head (detached)\0': _fail()
        if _chain(self.root)!=before: _fail()
        _check(deadline); return True


# Qualification-scoped structural paths, never cached authority observations.
import contextlib
import contextvars

_ACTIVE=contextvars.ContextVar('apicontour_qualification_git',default=None)


def _runner(args,*,cwd,timeout):
    from deploy.local import origin21_profile,origin21_transport
    if cwd!=origin21_profile.ROOT: _fail()
    return origin21_transport._run(args,'',deadline=timeout)


@contextlib.contextmanager
def qualification_scope(proof):
    from deploy.local import origin21_managed_qualification as qualification,origin21_profile
    if type(proof) is not qualification.OwnedManagedQualification or _ACTIVE.get() is not None: _fail()
    proof.verify()
    head=proof._head
    layout=Layout.capture(origin21_profile.ROOT,_runner,head)
    proof.verify()
    token=_ACTIVE.set((proof,layout,head))
    try: yield
    finally: _ACTIVE.reset(token)


def _bound(root,head):
    current=_ACTIVE.get()
    if current is None: return None
    _,layout,expected=current
    if root!=layout.root or head!=expected: _fail()
    return layout


def registration_if_active(root,head):
    layout=_bound(root,head)
    if layout is None: return False
    layout.registration(head)
    return True


def clean_status_if_active(root,head):
    layout=_bound(root,head)
    if layout is None: return False
    layout.clean_status(head,_runner)
    return True
