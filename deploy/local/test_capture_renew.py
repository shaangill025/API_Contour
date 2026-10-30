"""Ephemeral signer and fault-injected renewal state; no database or network."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

PATH=Path(__file__).with_name('capture_renew.py')
spec=importlib.util.spec_from_file_location('capture_renew',PATH)
r=importlib.util.module_from_spec(spec); spec.loader.exec_module(r)

class Renewal(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.capture=Path(self.temp.name)/'capture'; self.capture.mkdir(mode=0o700)
        self.private=self.capture/'private'; self.private.mkdir(mode=0o700)
        self.runtime=self.capture/'runtime'; self.runtime.mkdir(mode=0o700)
        self.key=self.private/'policy.key'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(self.key)],check=True,capture_output=True,timeout=10)
        self.key.chmod(0o600)
        pub=subprocess.run(['openssl','pkey','-in',str(self.key),'-pubout','-outform','DER'],check=True,capture_output=True,timeout=10).stdout
        (self.runtime/'policy.raw').write_bytes(pub[-32:]); (self.runtime/'policy.raw').chmod(0o600)
        self.now=datetime.datetime.now(datetime.timezone.utc)
        stamp=lambda t:t.isoformat(timespec='microseconds').replace('+00:00','Z')
        old=dict(r.FIELDS,revision=1,issued_at=stamp(self.now-datetime.timedelta(minutes=10)),expires_at=stamp(self.now-datetime.timedelta(minutes=1)))
        with mock.patch.object(r,'CAPTURE',self.capture):
            raw=json.dumps(old,separators=(',',':')).encode()
            sig=r.crypt('sign',self.key.read_bytes(),r.DOMAIN+raw)
        self.base=json.dumps(dict(key_id='local',signature_profile='ed25519-v1',payload_base64url=r.encoded(raw),signature_base64url=r.encoded(sig)),separators=(',',':')).encode()
        self.policy=self.private/'policy.json'; self.policy.write_bytes(self.base); self.policy.chmod(0o600)
        self.head=[1,self.base]; self.seen=[]

    def db(self,base,old,new,revision,issued,expires):
        self.seen.append((base,old,new,revision))
        if self.head==[old,base]: self.head[:]=[revision,new]
        elif self.head!=[revision,new]: raise ValueError('head drift')

    def state(self,base,old,new,revision,issued,expires):
        if self.head==[revision,new]: return 'committed'
        if self.head!=[old,base]: raise ValueError('head drift')
        expiry=datetime.datetime.fromisoformat(expires.replace('Z','+00:00'))
        return 'base_expired' if self.now>=expiry else 'base_live'

    def run_renew(self,db=None,state=None):
        with mock.patch.object(r,'CAPTURE',self.capture), mock.patch.object(r,'database_commit',side_effect=db or self.db), \
             mock.patch.object(r,'database_state',side_effect=state or self.state):
            r.renew(self.now)

    def test_expired_old_policy_renews_and_keeps_head_identity(self):
        self.run_renew()
        self.assertEqual(self.head[0],2); self.assertEqual(self.policy.read_bytes(),self.head[1])
        self.assertFalse((self.private/'renew.pending').exists())
        self.assertEqual(self.seen[0][:2],(self.base,1))

    def test_uncertain_commit_reuses_exact_proposal_and_reconciles(self):
        def unknown(*args): self.db(*args); raise TimeoutError()
        with self.assertRaises(TimeoutError): self.run_renew(unknown)
        self.assertEqual(self.policy.read_bytes(),self.base)
        pending=(self.private/'renew.pending').read_bytes()
        self.run_renew()
        self.assertEqual(self.seen[0][2],self.seen[1][2]); self.assertEqual(self.head[0],2)
        self.assertEqual(self.policy.read_bytes(),self.head[1]); self.assertFalse((self.private/'renew.pending').exists())
        self.assertTrue(pending)

    def test_before_commit_and_post_commit_publish_failures_reconcile(self):
        with self.assertRaises(TimeoutError): self.run_renew(lambda *args: (_ for _ in ()).throw(TimeoutError()))
        self.assertEqual(self.head[0],1); self.run_renew(); self.assertEqual(self.head[0],2)
        # A second renewal fails only after DB has committed and journal exists.
        real=r.replace_durable
        def fail_file(path,data):
            if path.name=='policy.json': raise OSError('fixture')
            return real(path,data)
        with mock.patch.object(r,'CAPTURE',self.capture), mock.patch.object(r,'database_commit',side_effect=self.db), mock.patch.object(r,'database_state',side_effect=self.state), mock.patch.object(r,'replace_durable',side_effect=fail_file):
            with self.assertRaises(OSError): r.renew(self.now)
        saved=self.seen[-1][2]
        self.run_renew(); self.assertEqual(self.seen[-1][2],saved); self.assertEqual(self.head[0],3)

    def test_crash_after_file_publication_reconciles_without_new_revision(self):
        with mock.patch.object(r,'CAPTURE',self.capture), mock.patch.object(r,'database_commit',side_effect=self.db), mock.patch.object(r,'database_state',side_effect=self.state), \
             mock.patch.object(r,'remove_durable',side_effect=OSError('fixture')):
            with self.assertRaises(OSError): r.renew(self.now)
        published=self.policy.read_bytes()
        self.assertEqual(published,self.head[1]); self.assertTrue((self.private/'renew.pending').exists())
        self.run_renew()
        self.assertEqual(self.head,[2,published]); self.assertEqual(self.seen[-1][2],published)
        self.assertFalse((self.private/'renew.pending').exists())

    def test_expired_uncommitted_proposal_is_replaced_only_after_locked_base_check(self):
        with self.assertRaises(TimeoutError): self.run_renew(lambda *args: (_ for _ in ()).throw(TimeoutError()))
        journal=self.private/'renew.pending'; old=journal.read_bytes()
        self.now+=datetime.timedelta(minutes=16)
        self.run_renew()
        self.assertEqual(self.head[0],2); self.assertNotEqual(self.head[1],r.decoded(json.loads(old)['proposal']))
        self.assertFalse(journal.exists())

    def test_expired_committed_proposal_reconciles_same_bytes_without_advancing(self):
        def unknown(*args): self.db(*args); raise TimeoutError()
        with self.assertRaises(TimeoutError): self.run_renew(unknown)
        committed=self.head[1]; self.now+=datetime.timedelta(minutes=16)
        self.run_renew()
        self.assertEqual(self.head,[2,committed]); self.assertEqual(self.policy.read_bytes(),committed)
        self.assertFalse((self.private/'renew.pending').exists())

    def test_intervening_head_after_preflight_preserves_replacement_and_refuses(self):
        with self.assertRaises(TimeoutError): self.run_renew(lambda *args: (_ for _ in ()).throw(TimeoutError()))
        journal=self.private/'renew.pending'; previous=journal.read_bytes()
        self.now+=datetime.timedelta(minutes=16)
        def changed_after_check(*args):
            state=self.state(*args); self.head[:]=[9,b'competing']; return state
        with self.assertRaises(ValueError): self.run_renew(state=changed_after_check)
        self.assertNotEqual(journal.read_bytes(),previous)
        self.assertEqual(self.policy.read_bytes(),self.base); self.assertEqual(self.head,[9,b'competing'])

    def test_expired_journal_replacement_failure_preserves_original(self):
        with self.assertRaises(TimeoutError): self.run_renew(lambda *args: (_ for _ in ()).throw(TimeoutError()))
        journal=self.private/'renew.pending'; previous=journal.read_bytes()
        self.now+=datetime.timedelta(minutes=16)
        with mock.patch.object(r,'CAPTURE',self.capture), mock.patch.object(r,'database_commit',side_effect=self.db), \
             mock.patch.object(r,'database_state',side_effect=self.state), mock.patch.object(r,'replace_durable',side_effect=OSError('fixture')):
            with self.assertRaises(OSError): r.renew(self.now)
        self.assertEqual(journal.read_bytes(),previous); self.assertEqual(self.head,[1,self.base])

    def test_validly_signed_narrowed_scope_rejected(self):
        envelope=json.loads(self.base)
        policy=json.loads(r.decoded(envelope['payload_base64url']))
        policy['parser_profiles']=['different']
        payload=json.dumps(policy,separators=(',',':')).encode()
        with mock.patch.object(r,'CAPTURE',self.capture):
            signature=r.crypt('sign',self.key.read_bytes(),r.DOMAIN+payload)
        envelope['payload_base64url']=r.encoded(payload); envelope['signature_base64url']=r.encoded(signature)
        self.policy.write_bytes(json.dumps(envelope,separators=(',',':')).encode())
        with self.assertRaises(ValueError): self.run_renew()
        self.assertEqual(self.seen,[])

    def test_changed_head_or_corrupt_journal_preserves_pending(self):
        with self.assertRaises(TimeoutError): self.run_renew(lambda *args: (_ for _ in ()).throw(TimeoutError()))
        self.head[:]=[99,b'other']
        with self.assertRaises(ValueError): self.run_renew()
        journal=self.private/'renew.pending'; self.assertTrue(journal.exists())
        journal.write_bytes(b'{bad')
        with self.assertRaises(ValueError): self.run_renew()
        self.assertEqual(journal.read_bytes(),b'{bad')

    def test_tampered_signed_payload_and_scope_rejected(self):
        envelope=json.loads(self.base)
        signature=r.decoded(envelope['signature_base64url'])
        envelope['signature_base64url']=r.encoded(bytes([signature[0]^1])+signature[1:])
        self.policy.write_text(json.dumps(envelope,separators=(',',':')))
        with self.assertRaises(ValueError): self.run_renew()
        self.assertEqual(self.seen,[])
        self.assertFalse((self.private/'renew.pending').exists())

    def test_disabled_or_narrowed_head_keeps_journal(self):
        for reason in ['disabled','revoked','narrowed']:
            with self.subTest(reason=reason):
                def reject(*args): raise ValueError('authorization drift')
                with self.assertRaises(ValueError): self.run_renew(reject)
                self.assertTrue((self.private/'renew.pending').exists())
                self.assertEqual(self.head,[1,self.base])
                (self.private/'renew.pending').unlink()

    def test_sql_locks_before_checks_and_uses_exact_head_cas(self):
        calls=[]
        with mock.patch.object(r.p.base,'psql',side_effect=lambda sql:calls.append(sql)):
            r.database_commit(self.base,1,b'next',2,'2026-10-30T00:00:00Z','2026-10-30T00:14:00Z')
        sql=calls[0]
        with mock.patch.object(r.p.base,'psql',return_value='base_expired') as preflight:
            self.assertEqual(r.database_state(self.base,1,b'next',2,'2026-10-30T00:00:00Z','2026-10-30T00:14:00Z'),'base_expired')
        query=preflight.call_args.args[0]
        self.assertLess(query.index('contour.lock_collector'),query.index('IF NOT EXISTS'))
        self.assertIn('revision=2',query)
        self.assertIn('proposal revision exists',query)
        self.assertIn('base_expired',query)
        self.assertLess(sql.index('contour.lock_collector'),sql.index('IF NOT EXISTS'))
        for token in ['enabled AND revoked_at IS NULL','source_authorization','source_instance_bindings',
                      'workload_assignments','current_revision=1','current_envelope=decode',
                      'active_revision=1','affected<>1','current_revision=2',"clock_timestamp()",'COMMIT;']:
            self.assertIn(token,sql)

    def test_wrong_signer_signature_and_symlink_rejected_before_mutation(self):
        (self.runtime/'policy.raw').write_bytes(b'x'*32)
        with self.assertRaises(ValueError): self.run_renew()
        self.assertEqual(self.seen,[])
        (self.runtime/'policy.raw').unlink(); (self.runtime/'policy.raw').symlink_to(self.key)
        with self.assertRaises(OSError): self.run_renew()
        self.assertEqual(self.head,[1,self.base])

if __name__=='__main__': unittest.main()
