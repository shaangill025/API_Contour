import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zlib

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('qualification_git',ROOT/'deploy/local/qualification_git.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def git(args,cwd,timeout=15):
    env={'PATH':os.defpath,'HOME':str(Path.home()),'GIT_CONFIG_NOSYSTEM':'1',
         'GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0', 'LC_ALL':'C'}
    result=subprocess.run(args,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,timeout=timeout,check=True)
    return result.stdout


def object_file(dotgit,kind,body):
    payload=(kind+' '+str(len(body))+'\0').encode()+body
    digest=hashlib.sha1(payload).hexdigest(); target=dotgit/'objects'/digest[:2]/digest[2:]
    target.parent.mkdir(exist_ok=True); target.write_bytes(zlib.compress(payload))
    return digest


class GitFacts(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='qualification-git-',dir=Path.home())
        self.addCleanup(self.tmp.cleanup); self.base=Path(self.tmp.name); self.base.chmod(0o700)
        self.repo=self.base/'source'; self.repo.mkdir(); template=self.base/'template'; template.mkdir()
        git(['git','init','-q','--template='+str(template),'-b','main'],self.repo)
        dotgit=self.repo/'.git'; blob=object_file(dotgit,'blob',b'initial\n')
        tree=object_file(dotgit,'tree',b'100644 file.txt\0'+bytes.fromhex(blob))
        payload=('tree '+tree+'\nauthor Fixture <fixture@example.invalid> 1700000000 +0000\n'
                 'committer Fixture <fixture@example.invalid> 1700000000 +0000\n\nfixture\n').encode()
        self.head=object_file(dotgit,'commit',payload)
        git(['git','update-ref','refs/heads/main',self.head],self.repo)
        self.owner=self.base/'owner'; self.owner.mkdir(mode=0o700); self.root=self.owner/'worktree'
        git(['git','worktree','add','--detach',str(self.root),self.head],self.repo)
        self.layout=m.Layout.capture(self.root,git,self.head)

    def test_fresh_valid_registration_and_clean_status(self):
        self.assertTrue(self.layout.registration(self.head)); self.assertTrue(self.layout.clean_status(self.head,git))
        with self.assertRaises(AttributeError): self.layout.root=self.base/'other'
        actual=git(['git','worktree','list','--porcelain','-z'],self.repo)
        self.assertIn(b'worktree '+os.fsencode(str(self.root))+b'\0HEAD '+self.head.encode()+b'\0',actual)

    def test_dirty_untracked_staged_and_wrong_head(self):
        with self.assertRaises(ValueError): self.layout.clean_status('0'*40,git)
        f=self.root/'file.txt'; f.write_text('changed\n')
        with self.assertRaises(ValueError): self.layout.clean_status(self.head,git)
        git(['git','add','file.txt'],self.root)
        with self.assertRaises(ValueError): self.layout.clean_status(self.head,git)
        git(['git','reset','-q','HEAD','--','file.txt'],self.root)
        f.write_text('initial\n'); (self.root/'new').write_text('untracked')
        with self.assertRaises(ValueError): self.layout.clean_status(self.head,git)
        git(['git','add','new'],self.root)
        with self.assertRaises(ValueError): self.layout.clean_status(self.head,git)
        with self.assertRaises(ValueError): self.layout.clean_status('0'*40,git)

    def test_pointer_backlink_commondir_and_symbolic_head(self):
        for file,bad in ((self.root/'.git',b'gitdir: /other\n'),(self.layout.gitdir/'gitdir',b'/other/.git\n'),
                         (self.layout.gitdir/'commondir',b'../elsewhere\n'),(self.layout.gitdir/'HEAD',b'ref: refs/heads/main\n')):
            with self.subTest(file=file.name):
                old=file.read_bytes(); file.write_bytes(bad)
                try:
                    with self.assertRaises(ValueError): self.layout.registration(self.head)
                finally: file.write_bytes(old)

    def test_duplicate_target_registration_rejected(self):
        duplicate=self.layout.registry/'duplicate'; duplicate.mkdir(mode=0o700)
        (duplicate/'gitdir').write_bytes(os.fsencode(str(self.root/'.git'))+b'\n')
        with self.assertRaises(ValueError): self.layout.registration(self.head)

    def test_symlink_fifo_and_hardlink_rejected(self):
        target=self.root/'.git'; original=target.read_bytes(); target.unlink()
        link=self.owner/'link-target'; link.write_bytes(original); target.symlink_to(link)
        with self.assertRaises((ValueError,OSError)): self.layout.registration(self.head)
        target.unlink(); os.mkfifo(target)
        with self.assertRaises((ValueError,OSError)): self.layout.registration(self.head)
        target.unlink(); target.write_bytes(original)
        hard=self.owner/'hardlink'; os.link(target,hard)
        with self.assertRaises(ValueError): self.layout.registration(self.head)
        hard.unlink()

    def test_replacement_after_read_detected(self):
        original=m._read_at; changed=[False]
        def replace(fd,name,limit=m.MAX_PATH):
            result=original(fd,name,limit)
            if name=='.git' and not changed[0]:
                changed[0]=True; alternate=self.owner/'replacement'; alternate.write_bytes(result[0]); os.replace(alternate,self.root/'.git')
            return result
        with patch.object(m,'_read_at',side_effect=replace):
            with self.assertRaises(ValueError): self.layout.registration(self.head)

    def test_ancestor_symlink_and_registry_limit_rejected(self):
        alias=self.base/'alias'; alias.symlink_to(self.owner,target_is_directory=True)
        with self.assertRaises(ValueError): m._chain(alias)
        with patch.object(m,'MAX_WORKTREES',0):
            with self.assertRaises(ValueError): self.layout.registration(self.head)
        with self.assertRaises(ValueError): m._path(str(self.root)+'/../worktree')
        self.owner.chmod(0o777)
        try:
            with self.assertRaises(ValueError): self.layout.registration(self.head)
        finally: self.owner.chmod(0o700)

    def test_registry_file_changed_after_observation_rejected(self):
        original=m._read_at; changed=[False]
        def replace(fd,name,limit=m.MAX_PATH):
            result=original(fd,name,limit)
            if name=='gitdir' and not changed[0]:
                changed[0]=True
                duplicate=self.layout.registry/'new-entry'; duplicate.mkdir(mode=0o700)
                (duplicate/'gitdir').write_text('/other/.git\n')
            return result
        with patch.object(m,'_read_at',side_effect=replace):
            with self.assertRaises(ValueError): self.layout.registration(self.head)

    def test_bad_cli_status_and_unsupported_layout(self):
        for raw in (b'',b'# branch.oid '+self.head.encode()+b'\0# branch.head main\0',
                    b'# branch.oid '+self.head.encode()+b'\0# branch.head (detached)\0? new\0'):
            with self.subTest(raw=raw),self.assertRaises(ValueError): self.layout.clean_status(self.head,lambda *_a,**_k:raw)
        with self.assertRaises(ValueError): m.Layout(object(),self.root,self.layout.gitdir,self.repo/'alternate')


if __name__=='__main__':unittest.main()
