import hashlib
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import time
import contextvars
import contextlib
import threading
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
        def replace(fd,name,limit=m.MAX_PATH,deadline=None):
            result=original(fd,name,limit,deadline=deadline)
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
        original=m._read_at; changed=[0]
        def replace(fd,name,limit=m.MAX_PATH,deadline=None):
            result=original(fd,name,limit,deadline=deadline)
            if name=='gitdir': changed[0]+=1
            if name=='gitdir' and changed[0]==2:
                duplicate=self.layout.registry/'new-entry'; duplicate.mkdir(mode=0o700)
                (duplicate/'gitdir').write_text('/other/.git\n')
            return result
        with patch.object(m,'_read_at',side_effect=replace):
            with self.assertRaises(ValueError): self.layout.registration(self.head)

    def test_unrelated_metadata_directory_change_does_not_invalidate_registration(self):
        original=m._read_at; changed=[False]; marker=self.layout.gitdir/'unrelated-lock'
        def create(fd,name,limit=m.MAX_PATH,deadline=None):
            result=original(fd,name,limit,deadline=deadline)
            if name=='HEAD' and not changed[0]: changed[0]=True; marker.write_bytes(b'x')
            return result
        try:
            with patch.object(m,'_read_at',side_effect=create): self.assertTrue(self.layout.registration(self.head))
        finally:
            if marker.exists(): marker.unlink()

    def test_non_utf8_backlink_fails_closed(self):
        entry=self.layout.registry/'bad-utf8'; entry.mkdir(mode=0o700)
        (entry/'gitdir').write_bytes(b'/invalid/\xff/.git\n')
        with self.assertRaises(ValueError): self.layout.registration(self.head)

    def test_deadline_checked_after_slow_filesystem_and_status(self):
        original=m._read_at
        def slow(fd,name,limit=m.MAX_PATH,deadline=None):
            result=original(fd,name,limit,deadline=deadline); time.sleep(.03); return result
        with patch.object(m,'_read_at',side_effect=slow):
            with self.assertRaises(TimeoutError): self.layout.registration(self.head,deadline=time.monotonic()+.01)
        def stalled(*_a,**_k): time.sleep(.03); return b''
        with patch.object(m.time,'monotonic',side_effect=[0.0,0.0,0.0,0.0,16.0]):
            with self.assertRaises(TimeoutError): self.layout.clean_status(self.head,stalled)

    def test_scoped_fresh_facts_and_context_isolation(self):
        calls=[]
        def runner(args,*,cwd,timeout): calls.append(args); return git(args,cwd,timeout)
        token=m._ACTIVE.set((object(),self.layout,self.head))
        try:
            with patch.object(m,'_runner',runner):
                self.assertTrue(m.registration_if_active(self.root,self.head))
                self.assertTrue(m.clean_status_if_active(self.root,self.head))
                self.assertEqual(calls,[['git','status','--porcelain=v2','--branch','--untracked-files=all','-z']])
                clean=[]; outside=threading.Thread(target=lambda:clean.append(m.registration_if_active(self.root,self.head)))
                outside.start(); outside.join(2); self.assertEqual(clean,[False])
                (self.root/'untracked').write_text('changed')
                with self.assertRaises(ValueError): m.clean_status_if_active(self.root,self.head)
                with self.assertRaises(ValueError): m.registration_if_active(self.root,'0'*40)
                observed=[]; ctx=contextvars.copy_context()
                thread=threading.Thread(target=lambda:ctx.run(lambda:observed.append(m.registration_if_active(self.root,self.head))))
                thread.start(); thread.join(2); self.assertFalse(thread.is_alive()); self.assertEqual(observed,[True])
        finally: m._ACTIVE.reset(token)
        self.assertFalse(m.registration_if_active(self.root,self.head))

    def test_existing_owner_and_intent_guards_remain_with_scoped_registration(self):
        from deploy.local import qualification_git as bound,origin21_profile,origin21_managed_qualification as proof,origin21_transport
        token='a'*32; tag='apicontour-origin21-build:'+token
        intent={'version':1,'head':self.head,'tag':tag,'token':token,'worktree':str(self.root)}
        intent_file=self.owner/'intent.json'; intent_file.write_bytes(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()); intent_file.chmod(0o600)
        with patch.object(origin21_profile,'ROOT',self.root),patch.object(origin21_transport,'_run') as run:
            scope=bound._ACTIVE.set((object(),self.layout,self.head))
            try:
                proof._owned_worktree(self.head,str(self.owner/'build-receipt.json'))
                run.assert_not_called()
                duplicate=self.layout.registry/'duplicate'; duplicate.mkdir(mode=0o700)
                (duplicate/'gitdir').write_bytes(os.fsencode(str(self.root/'.git'))+b'\n')
                with self.assertRaises(ValueError): proof._owned_worktree(self.head,str(self.owner/'build-receipt.json'))
                (duplicate/'gitdir').unlink(); duplicate.rmdir()
                intent['head']='0'*40
                intent_file.write_bytes(json.dumps(intent,sort_keys=True,separators=(',',':')).encode())
                with self.assertRaises(ValueError): proof._owned_worktree(self.head,str(self.owner/'build-receipt.json'))
            finally: bound._ACTIVE.reset(scope)

    def test_managed_source_keeps_all_hash_work_in_both_modes(self):
        from deploy.local import qualification_git as bound,origin21_managed_init as init,origin21_state,origin21_transport
        import hashlib as hashmod
        actual_sha=hashmod.sha256
        with patch.object(init,'_settings'),patch.object(origin21_state,'_source_identity',return_value='source'), \
             patch.object(bound,'clean_status_if_active',return_value=True),patch.object(origin21_transport,'_run') as run, \
             patch.object(init.hashlib,'sha256',wraps=actual_sha) as digest:
            fresh=init._source(self.head); run.assert_not_called(); self.assertGreaterEqual(digest.call_count,15)
        with patch.object(init,'_settings'),patch.object(origin21_state,'_source_identity',return_value='source'), \
             patch.object(bound,'clean_status_if_active',return_value=False),patch.object(origin21_transport,'_run',side_effect=[self.head,'']) as run:
            legacy=init._source(self.head); self.assertEqual(run.call_count,2)
        self.assertEqual(fresh,legacy)

    def test_scope_binds_after_existing_proof_and_resets_on_failure(self):
        from deploy.local import qualification_git as bound,origin21_managed_qualification as qualification,origin21_profile
        class Proof:
            def __init__(self): self._head='a'*40; self.checks=0
            def verify(self): self.checks+=1
        proof=Proof(); fake_layout=object()
        with patch.object(qualification,'OwnedManagedQualification',Proof),patch.object(origin21_profile,'ROOT',self.root), \
             patch.object(bound.Layout,'capture',return_value=fake_layout):
            with self.assertRaisesRegex(RuntimeError,'stop'):
                with bound.qualification_scope(proof):
                    self.assertEqual(bound._ACTIVE.get(),(proof,fake_layout,proof._head))
                    raise RuntimeError('stop')
            self.assertIsNone(bound._ACTIVE.get()); self.assertEqual(proof.checks,2)

    def test_explicit_flag_propagation_and_original_deadlines(self):
        spec=importlib.util.spec_from_file_location('fresh_source_wrapper',ROOT/'scripts/qualify-managed-origin.py')
        wrapper=importlib.util.module_from_spec(spec); spec.loader.exec_module(wrapper)
        self.assertEqual(wrapper.QUALIFY_SECONDS,1200)
        for enabled in (False,True):
            with tempfile.TemporaryDirectory(dir=Path.home()) as d:
                folder=Path(d); calls=[]
                class Owner:
                    path=folder
                    def verify(self): pass
                    def write(self,name,data):
                        p=self.path/name; p.write_bytes(data); return p
                def run(args,**_kwargs):
                    calls.append(args)
                    if args[:3]==['git','worktree','add']:
                        child=Path(args[-2]); child.mkdir(); (child/'.git').write_text('gitdir: owned')
                    if len(args)>1 and args[1]=='scripts/test-managed-origin-qualification.py': raise RuntimeError('stop')
                    return b''
                helper={'snapshot':lambda *_:('b'*40,{'fixed':'hash'}),'require_registration':lambda *_a,**_k:None,
                        'encode':lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode(),
                        'OWNER_LABEL':'owner','HEAD_LABEL':'head','image_identity':lambda *_:'sha256:'+'c'*64}
                with self.assertRaisesRegex(RuntimeError,'stop'):
                    wrapper.qualify(run,Owner(),'a'*32,helper,fresh_source=enabled)
                argv=next(a for a in calls if len(a)>1 and a[1]=='scripts/test-managed-origin-qualification.py')
                self.assertEqual('--fresh-source' in argv,enabled)
        from deploy.local import origin21_state
        self.assertIn('deploy/local/qualification_git.py',origin21_state.SOURCE_FILES)
        self.assertIn('tests/fixtures/qualification-git/test_git.py',origin21_state.MANAGED_SOURCE_FILES)

    def test_inner_scope_follows_original_begin_and_resets(self):
        spec=importlib.util.spec_from_file_location('fresh_source_driver',ROOT/'scripts/test-managed-origin-qualification.py')
        driver=importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
        from deploy.local import origin21_managed_qualification as qualification,origin21_managed_init as init
        proof=unittest.mock.MagicMock(); order=[]
        @contextlib.contextmanager
        def scope(value):
            self.assertIs(value,proof); order.append('scope'); yield
        def begin(**_): order.append('begin'); return proof
        def stop(**_): order.append('initialize'); raise RuntimeError('stop')
        with patch.object(driver,'_source_guard',return_value='source'),patch.object(qualification,'begin',side_effect=begin), \
             patch.object(driver.qualification_git,'qualification_scope',side_effect=scope),patch.object(init,'initialize',side_effect=stop):
            with self.assertRaisesRegex(RuntimeError,'stop'):
                driver.main(['image','head','receipt','digest','--fresh-source'])
        self.assertEqual(order,['begin','scope','initialize']); proof.close.assert_called_once()
        with patch.object(driver,'_source_guard') as source:
            with self.assertRaises(ValueError): driver.main(['a','b','c','d','--fresh-source','--fresh-source'])
            source.assert_not_called()

    def test_bad_cli_status_and_unsupported_layout(self):
        for raw in (b'',b'# branch.oid '+self.head.encode()+b'\0# branch.head main\0',
                    b'# branch.oid '+self.head.encode()+b'\0# branch.head (detached)\0? new\0'):
            with self.subTest(raw=raw),self.assertRaises(ValueError): self.layout.clean_status(self.head,lambda *_a,**_k:raw)
        with self.assertRaises(ValueError): m.Layout(object(),self.root,self.layout.gitdir,self.repo/'alternate')


if __name__=='__main__':unittest.main()
