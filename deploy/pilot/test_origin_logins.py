"""Offline login state/guard tests; no password authentication claim."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from deploy.local import capture_profiles
from deploy.pilot import origin_logins, origin_setup_state as journal


class Logins(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)/'origin'; (root/'capture/runtime').mkdir(parents=True,mode=0o700)
        self.profile=capture_profiles.ORIGIN_PILOT._replace(state=root)
        patch=mock.patch.object(capture_profiles,'ORIGIN_PILOT',self.profile); patch.start(); self.addCleanup(patch.stop)
        for name,content in (('ingress',b'a'*32),('worker',b'b'*32)):
            p=root/('capture/runtime/'+name+'.password'); p.write_bytes(content); p.chmod(0o600)
        self.sql=mock.Mock(return_value='EXACT'); self.auth=mock.Mock(return_value=True)
        self.sensitive=mock.Mock()
        self.op=origin_logins.Logins(self.profile,self.sql,self.sensitive,self.auth)

    def test_scram_sha256_fixed_vector(self):
        # Independent PBKDF2-HMAC block/XOR derivation for the fixed fixture:
        # password pencil, salt 0123456789abcdef, 4096 iterations.
        expected=('SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg=='
                  '$nQpbZ77WudtqufPwikHXGRt6g2QJ4zns8bZLw273DRM=:'
                  'jn2amWP1q1h+jgjy0YTO14S6/F02SV7taipOeB7ef20=')
        self.assertEqual(origin_logins.scram_verifier('pencil',b'0123456789abcdef'),expected)

    def test_exact_requires_both_independent_authenticated_callbacks(self):
        self.assertEqual(self.op.inspect(),journal.EXACT)
        self.assertEqual([c.args[0] for c in self.auth.call_args_list], [x[0] for x in origin_logins.ROLES])
        self.assertNotEqual(self.auth.call_args_list[0].args[1],self.auth.call_args_list[1].args[1])
        self.auth.side_effect=[True,False]
        self.assertEqual(self.op.inspect(),journal.DRIFT)

    def test_absent_partial_unknown_or_callback_error_fails_closed(self):
        for value in ('ABSENT','DRIFT'):
            self.sql.return_value=value
            self.assertEqual(self.op.inspect(),value)
        self.auth.assert_not_called()
        self.sql.return_value='unexpected'
        with self.assertRaises(RuntimeError): self.op.inspect()
        self.sql.return_value='EXACT'; self.auth.side_effect=ValueError('secret fixture marker')
        with self.assertRaisesRegex(RuntimeError,'login authentication check failed') as error: self.op.inspect()
        self.assertNotIn('secret fixture marker',str(error.exception))
        with self.assertRaises(ValueError): origin_logins.Logins(self.profile,self.sql,self.sensitive,None)
        with self.assertRaises(ValueError): origin_logins.Logins(self.profile,self.sql,self.sql,self.auth)

    def test_creation_is_one_transaction_with_independent_passwords(self):
        self.op.apply()
        self.assertEqual(self.sensitive.call_count,1)
        self.sql.assert_not_called()
        statement=self.sensitive.call_args.args[0]
        self.assertNotIn('a'*32,statement); self.assertNotIn('b'*32,statement)
        self.assertEqual(statement.count('SCRAM-SHA-256$'),2)
        self.assertTrue(statement.startswith('BEGIN;'))
        self.assertIn('pg_advisory_xact_lock',statement)
        self.assertEqual(statement.count('CREATE ROLE'),2)
        self.assertEqual(statement.count('GRANT CONNECT ON DATABASE'),1)
        self.assertEqual(statement.count('WITH ADMIN FALSE, INHERIT TRUE, SET TRUE'),2)
        self.assertNotIn('ALTER ROLE',statement)

    def test_reject_shared_password_before_database(self):
        p=self.profile.state/'capture/runtime/worker.password'; p.write_bytes(b'a'*32)
        with self.assertRaises(ValueError): self.op.apply()
        self.sql.assert_not_called()
        self.sensitive.assert_not_called()


if __name__ == '__main__': unittest.main()
