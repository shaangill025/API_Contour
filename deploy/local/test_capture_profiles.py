"""Closed profile and journaled pilot-renewal checks using ephemeral keys."""
import datetime
import ast
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from deploy.local import capture_renew as renew
from deploy.local import capture_init as init
profiles = renew.capture_profiles


class Profiles(unittest.TestCase):
    def test_renewal_cli_dispatches_closed_profile(self):
        source = Path(renew.__file__).read_text()
        tree = ast.parse(source)
        guard = next(node for node in tree.body if isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'")
        script = compile(ast.Module(body=[guard], type_ignores=[]), renew.__file__, 'exec')
        for args, expected in [([], profiles.DEFAULT), (['--profile','default'], profiles.DEFAULT), (['--profile','pilot'], profiles.PILOT)]:
            main = mock.Mock()
            with mock.patch('sys.argv', ['capture_renew.py', *args]):
                exec(script, {'__name__':'__main__', 'main':main, 'capture_profiles':profiles, 'sys':__import__('sys')})
            main.assert_called_once_with(expected)
        main = mock.Mock()
        with mock.patch('sys.argv', ['capture_renew.py', '--profile', 'unexpected']):
            with self.assertRaises(ValueError):
                exec(script, {'__name__':'__main__', 'main':main, 'capture_profiles':profiles, 'sys':__import__('sys')})
        main.assert_not_called()
    def test_closed_selection_and_fixed_scope(self):
        self.assertIs(profiles.arguments([]), profiles.DEFAULT)
        self.assertIs(profiles.arguments(['--profile', 'pilot']), profiles.PILOT)
        for argv in [['pilot'], ['--profile', '../../x'], ['--profile', 'pilot', 'extra']]:
            with self.assertRaises(ValueError): profiles.arguments(argv)
        self.assertEqual(profiles.PILOT.collector[-3:], '301')
        self.assertEqual((profiles.PILOT.source[-3:], profiles.PILOT.deployment[-3:], profiles.PILOT.instance[-3:], profiles.PILOT.nonce[-3:]), ('302','303','304','305'))
        self.assertEqual(profiles.PILOT.approved_names, ('POST','probe','result'))
        self.assertEqual(profiles.PILOT.approved_route_segments, ('pilot',))
        self.assertEqual(profiles.DEFAULT.approved_route_segments, ('orders',))

    def test_pilot_sql_uses_locked_identity_and_exact_head(self):
        with mock.patch.object(renew.p.base, 'psql', return_value='base_live') as query:
            renew.database_state(b'old', 1, b'new', 2, '2026-10-30T00:00:00Z', '2026-10-30T00:14:00Z', profile=profiles.PILOT)
        sql = query.call_args.args[0]
        for value in [profiles.PILOT.collector, profiles.PILOT.source, profiles.PILOT.deployment, profiles.PILOT.instance, profiles.PILOT.nonce]:
            self.assertIn(value, sql)
        self.assertNotIn(profiles.DEFAULT.collector, sql)
        self.assertLess(sql.index('contour.lock_collector'), sql.index('IF NOT EXISTS'))
        self.assertIn('current_envelope=decode', sql)
        self.assertIn('proposal revision exists', sql)

    def test_pilot_provision_refuses_pending_and_expiry_before_database(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)/'capture'; capture.mkdir()
            private = capture/'private'; private.mkdir()
            runtime = capture/'runtime'; runtime.mkdir()
            for name in ['server.crt.der','server.key.der','collector.crt.der','ca.der','policy.raw','ingress.password','worker.password']:
                (runtime/name).write_text('synthetic')
            profile = profiles.PILOT._replace(capture=capture)
            now = datetime.datetime.now(datetime.timezone.utc)
            payload = json.dumps({'revision':1,'expires_at':(now-datetime.timedelta(seconds=1)).isoformat()}).encode()
            (private/'policy.json').write_text(json.dumps({'payload_base64url':renew.encoded(payload)}))
            (private/'policy.json').chmod(0o600)
            with mock.patch.object(profiles,'PILOT',profile), mock.patch.object(renew.p,'verify_pilot_policy',return_value=json.loads(payload)), mock.patch.object(renew.p.base,'psql') as database:
                (private/'renew.pending').write_text('pending')
                with self.assertRaisesRegex(RuntimeError,'reconciliation'): renew.p.main(profile)
                (private/'renew.pending').unlink()
                with self.assertRaisesRegex(RuntimeError,'expired'): renew.p.main(profile)
                database.assert_not_called()
            with mock.patch.object(profiles,'PILOT',profile), mock.patch.object(renew.p,'verify_pilot_policy',side_effect=ValueError('signature')), mock.patch.object(renew.p.base,'psql') as database:
                with self.assertRaisesRegex(ValueError,'signature'): renew.p.main(profile)
                database.assert_not_called()

    def test_pilot_provision_uses_closed_ids_and_existing_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)/'capture'; capture.mkdir()
            private = capture/'private'; private.mkdir()
            runtime = capture/'runtime'; runtime.mkdir()
            for name in ['server.crt.der','server.key.der','collector.crt.der','ca.der','policy.raw','ingress.password','worker.password']:
                (runtime/name).write_text('synthetic')
            profile = profiles.PILOT._replace(capture=capture)
            expires = (datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5)).isoformat()
            payload = json.dumps({'revision':1,'expires_at':expires}).encode()
            (private/'policy.json').write_text(json.dumps({'payload_base64url':renew.encoded(payload)}))
            (private/'policy.json').chmod(0o600)
            calls=[]
            def sql(statement):
                calls.append(statement)
                if statement.startswith('SELECT count(*) FROM pg_roles WHERE rolname IN'): return '3'
                if statement.startswith('SELECT count(*) FROM pg_roles WHERE rolname='): return '1'
                if statement.startswith('SELECT r.rolname FROM pg_roles'):
                    return 'contour_ingestion\ncontour_runtime' if "'contour_local_ingress'" in statement else 'contour_catalog_worker'
                if statement.startswith('SELECT (rolcanlogin'): return 'true'
                if statement.startswith('SELECT count(*) FROM contour.collectors'): return '0'
                if statement.startswith('BEGIN;'): return ''
                if statement.startswith('SELECT EXISTS'): return 'true'
                if statement.startswith('SELECT ((SELECT count(*) FROM contour.sources'): return 'true'
                raise AssertionError('unexpected query')
            with mock.patch.object(profiles,'PILOT',profile), mock.patch.object(renew.p,'verify_pilot_policy',return_value=json.loads(payload)), mock.patch.object(renew.p.base,'psql',side_effect=sql), mock.patch.object(renew.p.base,'private_file',return_value='synthetic'), mock.patch('builtins.print'):
                renew.p.main(profile)
            enrollment=next(s for s in calls if s.startswith('BEGIN;'))
            for value in [profile.collector,profile.source,profile.deployment,profile.instance,profile.nonce]: self.assertIn(value,enrollment)
            self.assertNotIn(profiles.DEFAULT.collector,enrollment)
            self.assertFalse(any('CREATE ROLE' in statement for statement in calls))

    def test_pilot_init_copies_existing_role_secrets_and_never_replaces_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory); pilot=state/'pilot'; pilot.mkdir()
            default_runtime=state/'capture'/'runtime'; default_runtime.mkdir(parents=True)
            for name in ['ca.key','ca.crt']: (state/name).write_bytes(b'synthetic')
            for name in ['ingress','worker']:
                path=default_runtime/(name+'.password'); path.write_bytes(('synthetic-'+name).encode()); path.chmod(0o600)
            profile=profiles.PILOT._replace(capture=pilot/'capture')
            def fake_run(*args):
                args=list(map(str,args))
                for flag in ['-out','-keyout']:
                    if flag in args:
                        path=Path(args[args.index(flag)+1]); path.write_bytes(('synthetic-'+path.name).encode())
                return b'x'*44 if args[0]=='pkey' else b''
            with mock.patch.object(profiles,'PILOT',profile), mock.patch.object(init,'STATE',state), mock.patch.object(init,'run',side_effect=fake_run), mock.patch('builtins.print'):
                init.main(profile)
                runtime=profile.capture/'runtime'
                self.assertEqual((runtime/'ingress.password').read_bytes(), b'synthetic-ingress')
                self.assertEqual((runtime/'worker.password').read_bytes(), b'synthetic-worker')
                envelope=json.loads((profile.capture/'private'/'policy.json').read_bytes())
                policy=json.loads(renew.decoded(envelope['payload_base64url']))
                self.assertEqual(policy['collector_id'],profile.collector)
                self.assertEqual(policy['approved_names'],['POST','probe','result'])
                self.assertEqual(policy['approved_route_segments'],['pilot'])
                original=(runtime/'policy.raw').read_bytes()
                with self.assertRaises(FileExistsError): init.main(profile)
                self.assertEqual((runtime/'policy.raw').read_bytes(),original)

    def test_pilot_renewal_retains_exact_pending_proposal_after_uncertain_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)/'capture'; capture.mkdir(mode=0o700)
            private = capture/'private'; private.mkdir(mode=0o700)
            runtime = capture/'runtime'; runtime.mkdir(mode=0o700)
            profile = profiles.PILOT._replace(capture=capture)
            key = private/'policy.key'
            subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)], check=True, capture_output=True, timeout=10)
            os.chmod(key, 0o600)
            pub = subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'], check=True, capture_output=True, timeout=10).stdout
            (runtime/'policy.raw').write_bytes(pub[-32:]); os.chmod(runtime/'policy.raw',0o600)
            now = datetime.datetime.now(datetime.timezone.utc)
            stamp = lambda d: d.isoformat(timespec='microseconds').replace('+00:00','Z')
            fields = dict(renew.FIELDS, collector_id=profile.collector, approved_names=list(profile.approved_names), approved_route_segments=list(profile.approved_route_segments))
            policy = dict(fields, revision=1, issued_at=stamp(now-datetime.timedelta(minutes=10)), expires_at=stamp(now-datetime.timedelta(minutes=1)))
            raw = json.dumps(policy,separators=(',',':')).encode()
            with mock.patch.object(profiles, 'PILOT', profile):
                sig = renew.crypt('sign', key.read_bytes(), renew.DOMAIN+raw, profile=profile)
                envelope = json.dumps(dict(key_id='local',signature_profile='ed25519-v1',payload_base64url=renew.encoded(raw),signature_base64url=renew.encoded(sig)),separators=(',',':')).encode()
                target = private/'policy.json'; target.write_bytes(envelope); target.chmod(0o600)
                verified = renew.p.verify_pilot_policy(profile, private, runtime, envelope)
                self.assertEqual(verified['collector_id'], profile.collector)
                (runtime/'policy.raw').write_bytes(b'x'*32)
                with self.assertRaisesRegex(RuntimeError, 'signer drift'):
                    renew.p.verify_pilot_policy(profile, private, runtime, envelope)
                (runtime/'policy.raw').write_bytes(pub[-32:])
                calls=[]
                def unknown(*args, **kwargs): calls.append(args); raise TimeoutError()
                with mock.patch.object(renew,'database_commit',side_effect=unknown):
                    with self.assertRaises(TimeoutError): renew.renew(now, profile)
                journal = (private/'renew.pending').read_bytes()
                def committed(*args, **kwargs): return 'committed'
                def repeat(*args, **kwargs): calls.append(args)
                with mock.patch.object(renew,'database_state',side_effect=committed), mock.patch.object(renew,'database_commit',side_effect=repeat):
                    renew.renew(now, profile)
                self.assertEqual(calls[0][2], calls[1][2])
                self.assertEqual(target.read_bytes(), calls[0][2])
                self.assertTrue(journal)
                self.assertFalse((private/'renew.pending').exists())


if __name__ == '__main__': unittest.main()
