"""Offline origin renewal tests with disposable signing keys and simulated DB."""
import datetime
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from deploy.local import capture_profiles, capture_renew
from deploy.pilot import origin_enrollment, origin_renewal, origin_setup, origin_setup_state


class Renewal(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'origin'; (self.root/'capture/private').mkdir(parents=True,mode=0o700)
        (self.root/'capture/runtime').mkdir(mode=0o700)
        self.root.chmod(0o700); (self.root/'capture').chmod(0o700)
        base=capture_profiles.ORIGIN_PILOT
        self.profile=base._replace(state=self.root,capture=base.capture._replace(capture=self.root/'capture'))
        patch=mock.patch.object(capture_profiles,'ORIGIN_PILOT',self.profile); patch.start(); self.addCleanup(patch.stop)
        private=self.root/'capture/private'; key=private/'policy.key'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,capture_output=True,timeout=10)
        os.chmod(key,0o600)
        pub=subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'],check=True,capture_output=True,timeout=10).stdout
        target=self.root/'capture/runtime/policy.raw'; target.write_bytes(pub[-32:]); target.chmod(0o600)
        self.now=datetime.datetime.now(datetime.timezone.utc)
        stamp=lambda value:value.isoformat(timespec='microseconds').replace('+00:00','Z')
        data=dict(capture_renew.FIELDS,collector_id=self.profile.capture.collector,
                  approved_names=list(self.profile.capture.approved_names),approved_route_segments=list(self.profile.capture.approved_route_segments),
                  revision=1,issued_at=stamp(self.now-datetime.timedelta(minutes=20)),expires_at=stamp(self.now-datetime.timedelta(minutes=6)))
        payload=json.dumps(data,separators=(',',':')).encode()
        sig=capture_renew.crypt('sign',key.read_bytes(),capture_renew.DOMAIN+payload,profile=self.profile.capture,scratch=tempfile.gettempdir())
        raw=json.dumps(dict(key_id='local',signature_profile='ed25519-v1',payload_base64url=capture_renew.encoded(payload),signature_base64url=capture_renew.encoded(sig)),separators=(',',':')).encode()
        path=private/'observer-policy.json'; path.write_bytes(raw); path.chmod(0o600)
        self.initial=raw; self.rows=[raw]

    def sql(self,query):
        match=re.search(r'AND revision>([0-9]+).*?LIMIT ([0-9]+)',query,re.S)
        if not match: raise AssertionError('unexpected history page query')
        cursor,limit=map(int,match.groups())
        return json.dumps(dict(enabled=True,revoked=False,head=str(len(self.rows)),count=str(len(self.rows)),
            rows=[[str(i),raw.hex()] for i,raw in list(enumerate(self.rows,1))[cursor:cursor+limit]]))

    def test_expired_committed_base_and_ack_loss_reconcile(self):
        calls=[]
        def commit(profile,psql,base,old,proposal,new,preflight):
            calls.append((base,proposal,preflight))
            if len(self.rows)==1:
                self.rows.append(proposal)
                raise RuntimeError('lost ack')
            self.assertEqual(self.rows[-1],proposal)
        with mock.patch.object(origin_renewal,'_locked_cas',side_effect=commit):
            with self.assertRaisesRegex(RuntimeError,'lost ack'):
                origin_renewal.renew_locked(self.profile,self.sql,self.now)
            self.assertTrue((self.root/origin_renewal.PENDING).exists())
            result=origin_renewal.renew_locked(self.profile,self.sql,self.now)
        self.assertEqual(result['revision'],2)
        self.assertEqual(calls[0][1],calls[1][1])
        self.assertEqual((self.root/'capture/private/observer-policy.json').read_bytes(),self.initial)
        self.assertFalse((self.root/origin_renewal.PENDING).exists())
        self.assertEqual(origin_renewal.history(self.profile,self.sql).count,2)

    def test_scope_signature_history_and_unknown_head_refused(self):
        self.assertEqual(origin_renewal.history(self.profile,self.sql).initial,self.initial)
        bad=self.initial[:-1]+b'X'; self.rows=[bad]
        with self.assertRaises((ValueError,RuntimeError)): origin_renewal.history(self.profile,self.sql)
        self.rows=[self.initial,self.initial]
        with self.assertRaises(ValueError): origin_renewal.history(self.profile,self.sql)
        self.rows=[self.initial]
        def revoked(_): return json.dumps(dict(enabled=True,revoked=True,head='1',count='1',rows=[['1',self.initial.hex()]]))
        with self.assertRaises(ValueError): origin_renewal.history(self.profile,revoked)

    def test_stale_pending_proposal_is_retained_during_replacement(self):
        oldtime=self.now-datetime.timedelta(hours=1)
        def interrupted(profile,psql,base,old,proposal,new,preflight): raise RuntimeError('before commit')
        with mock.patch.object(origin_renewal,'_locked_cas',side_effect=interrupted):
            with self.assertRaises(RuntimeError): origin_renewal.renew_locked(self.profile,self.sql,oldtime)
        _,pending=origin_renewal.artifacts(self.profile)
        stale=pending[2][0][0]
        def retry(profile,psql,base,old,proposal,new,preflight):
            if preflight: return 'base_expired'
            _,current=origin_renewal.artifacts(self.profile)
            self.assertEqual(current[2][0][0],stale)
            self.assertEqual(len(current[2]),2)
            self.rows.append(proposal)
        with mock.patch.object(origin_renewal,'_locked_cas',side_effect=retry):
            origin_renewal.renew_locked(self.profile,self.sql,self.now)
        self.assertEqual(len(self.rows),2)

    def test_origin_cas_guards_database_scope_and_history_under_lock(self):
        sql=mock.Mock(return_value='base_live')
        old={'revision':1}; new={'revision':2,'issued_at':'2026-01-01T00:00:00.000000Z','expires_at':'2026-01-01T00:14:00.000000Z'}
        origin_renewal._locked_cas(self.profile,sql,b'base',old,b'proposal',new,True)
        statement=sql.call_args.args[0]
        self.assertIn("current_database()<>'contour_local'",statement)
        self.assertLess(statement.index('contour.lock_collector'),statement.index('policy history drift'))
        self.assertIn('active_revision',statement)
        self.assertIn('signed_envelope',statement)

    def test_over_1024_history_and_renewal_boundary(self):
        # Page mechanics use a stub verifier; the separate signed tests above
        # exercise actual Ed25519. Every entry must still be visited in order.
        self.rows=[self.initial]+[('fixture-%d'%i).encode() for i in range(2,1025)]
        now=self.now; issued=(now-datetime.timedelta(seconds=30)).isoformat(timespec='microseconds').replace('+00:00','Z')
        expires=(now+datetime.timedelta(minutes=14)).isoformat(timespec='microseconds').replace('+00:00','Z')
        visits=[]
        def valid(profile,raw,public=None):
            revision=1 if raw==self.initial else int(raw.decode().split('-')[1])
            visits.append(revision)
            return dict(revision=revision,issued_at=issued,expires_at=expires)
        def commit(profile,psql,base,old,proposal,new,preflight):
            self.assertFalse(preflight); self.assertEqual(old['revision'],1024); self.rows.append(proposal)
        with mock.patch.object(origin_renewal,'_valid',side_effect=valid), \
             mock.patch.object(origin_renewal,'_public',wraps=origin_renewal._public) as signer, \
             mock.patch.object(capture_renew,'signed_policy',return_value=b'fixture-1025'), \
             mock.patch.object(origin_renewal,'_locked_cas',side_effect=commit):
            result=origin_renewal.renew_locked(self.profile,self.sql,self.now)
            self.assertEqual(result['revision'],1025)
            signer.reset_mock(); visits.clear()
            history=origin_renewal.history(self.profile,self.sql)
            self.assertEqual(history.count,1025)
            self.assertEqual(visits,list(range(1,1026)))
            signer.assert_called_once()

    def test_missing_page_gap_and_head_change_refuse(self):
        self.rows=[self.initial]+[('fixture-%d'%i).encode() for i in range(2,260)]
        def valid(profile,raw,public=None):
            return {'revision':1 if raw==self.initial else int(raw.decode().split('-')[1])}
        for case in ('missing','gap','head','final'):
            calls=[]
            def changed(query):
                value=json.loads(self.sql(query)); calls.append(1)
                if case=='missing' and len(calls)==2: value['rows'].pop()
                if case=='gap' and len(calls)==2: value['rows'][0][0]='130'
                if case=='head' and len(calls)==2: value['head']='260'; value['count']='260'
                if case=='final' and not value['rows']: value['head']='260'; value['count']='260'
                return json.dumps(value)
            with self.subTest(case=case),mock.patch.object(origin_renewal,'_valid',side_effect=valid):
                with self.assertRaises(ValueError): origin_renewal.history(self.profile,changed)

    def test_history_deadline_fails_closed(self):
        with mock.patch.object(origin_renewal.time,'monotonic',side_effect=[0,61]):
            with self.assertRaisesRegex(ValueError,'deadline'): origin_renewal.history(self.profile,self.sql)

    def test_history_does_not_control_caller_transaction(self):
        statements=[]
        def transaction_read(query):
            statements.append(query)
            self.assertIsNone(re.search(r'\b(?:BEGIN|COMMIT|ROLLBACK)\b',query,re.I))
            return self.sql(query)
        self.assertEqual(origin_renewal.history(self.profile,transaction_read).count,1)
        self.assertGreaterEqual(len(statements),2)

    def test_reconciled_expired_commit_does_not_claim_current_lease(self):
        policy={'revision':2,'issued_at':'2025-01-01T00:00:00.000000Z','expires_at':'2025-01-01T00:14:00.000000Z'}
        sql=mock.Mock(return_value='false')
        with mock.patch.object(origin_setup,'_prepare',return_value=policy):
            result=origin_setup.renew_enrolled(self.profile,'ca','key',psql=sql,
                sensitive_execute=mock.Mock(),authenticate=mock.Mock())
        self.assertEqual(result,{'renewal_reconciled':True,'policy_current':False,'pilot_ready':False})
        self.assertIn('pg_catalog.clock_timestamp()',sql.call_args.args[0])

    def test_renewal_refuses_missing_setup_journal_before_creation(self):
        operations={name:mock.Mock() for name in origin_setup_state.ENROLLMENT_PHASES}
        with self.assertRaisesRegex(ValueError,'committed origin setup required'):
            origin_setup_state.run(self.profile,operations,through_credentials=True,through_logins=True,through_enrollment=True,require_enrolled=True)
        self.assertFalse((self.root/'setup.json').exists())


if __name__=='__main__': unittest.main()
