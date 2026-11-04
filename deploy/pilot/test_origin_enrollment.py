"""Offline enrollment guard/dispatch checks; no DB or signature claims."""
import datetime
import hashlib
import tempfile
from pathlib import Path
import unittest
from unittest import mock
from deploy.local import capture_profiles
from deploy.pilot import origin_enrollment as enrollment, origin_setup_state as journal


class Enrollment(unittest.TestCase):
    def setUp(self):
        self.profile=capture_profiles.ORIGIN_PILOT
        self.sql=mock.Mock(return_value='ABSENT')

    def test_closed_initial_timestamp_grammar(self):
        self.assertEqual(enrollment._local_timestamp('2026-11-03T12:34:56.123456Z').microsecond,123456)
        for value in ('2026-11-03 12:34:56.123456Z','2026-11-03T12:34:56.123456789Z',
                      '2026-11-03T12:34:56Z','2026-02-30T12:34:56.123456Z',
                      '2026-11-03T12:34:60.123456Z','2026-11-03T12:34:56.123456+00:00'):
            with self.subTest(value=value), self.assertRaises(ValueError): enrollment._local_timestamp(value)

    def test_leaf_reads_only_fixed_profile_relative_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'state'; root.mkdir(mode=0o700)
            replica=root/'replica1'; replica.mkdir(mode=0o700)
            leaf=replica/'client.crt.der'; leaf.write_bytes(b'synthetic-leaf'); leaf.chmod(0o600)
            # An absolute path embedded in a slot is intentionally ignored.
            first=self.profile.origins[0]._replace(leaf_der=Path('/outside-must-not-be-read'))
            profile=self.profile._replace(state=root,origins=(first,self.profile.origins[1]))
            with mock.patch.object(capture_profiles,'ORIGIN_PILOT',profile):
                fact=enrollment.Fact(profile,self.sql,first,'credential')
                self.assertEqual(fact._leaf(),hashlib.sha256(b'synthetic-leaf').hexdigest())
                with self.assertRaises(ValueError):
                    enrollment.Fact(profile,self.sql,first._replace(credential='other'),'credential')

    def test_expired_uncommitted_policy_does_not_execute_sql(self):
        now=datetime.datetime.now(datetime.timezone.utc)
        policy=(b'signed',{'issued_at':(now-datetime.timedelta(minutes=16)).isoformat(),
                           'expires_at':(now-datetime.timedelta(minutes=1)).isoformat()})
        observer=enrollment.Observer(self.profile,self.sql)
        with mock.patch.object(observer,'policy',return_value=policy), mock.patch.object(observer,'_new_policy') as mint:
            with self.assertRaisesRegex(RuntimeError,'not current'): observer.apply()
            mint.assert_not_called(); self.sql.assert_not_called()

    def test_public_origin_entrypoints_keep_separate_transactions(self):
        slot=self.profile.origins[0]
        for kind,signature in (('lifecycle','contour.enroll_origin('),
                               ('credential','contour.enroll_origin_credential('),
                               ('grant','contour.grant_origin_observer(')):
            op=enrollment.Fact(self.profile,self.sql,slot,kind)
            with mock.patch.object(op,'_leaf',return_value='ab'*32): op.apply()
            statement=self.sql.call_args.args[0]
            self.assertIn(signature,statement)
            self.assertTrue(statement.startswith('BEGIN;'))
            self.assertNotIn('begin_origin_operation',statement)
            self.assertNotIn('lock_origin_collector',statement)

    def test_observer_uses_existing_c_lock_and_never_locks_q(self):
        now=datetime.datetime.now(datetime.timezone.utc)
        policy=(b'signed',{'issued_at':(now-datetime.timedelta(seconds=30)).isoformat(),
                           'expires_at':(now+datetime.timedelta(minutes=1)).isoformat()})
        op=enrollment.Observer(self.profile,self.sql)
        with mock.patch.object(op,'policy',return_value=policy): op.apply()
        statement=self.sql.call_args.args[0]
        self.assertLess(statement.index('contour.lock_collector'),statement.index('INSERT INTO contour.collectors'))
        self.assertIn('contour.register_instance_source',statement)
        self.assertNotIn('begin_origin_operation',statement)
        self.assertNotIn('lock_origin_collector',statement)

    def test_fixed_assertions_distinct_and_not_platform_attestation(self):
        one,two=self.profile.origins
        self.assertNotEqual(enrollment.assertion(one),enrollment.assertion(two))
        self.assertEqual(len(enrollment.assertion(one)),64)

    def test_partial_status_does_not_adopt_unknown_result(self):
        self.sql.return_value='unexpected'
        with self.assertRaises(RuntimeError): enrollment.Target(self.profile,self.sql,self.profile.origins[0]).inspect()


if __name__=='__main__': unittest.main()
