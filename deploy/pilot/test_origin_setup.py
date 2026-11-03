"""Offline checks for schema-only operators and transaction guards."""
import unittest
from unittest import mock
from deploy.pilot import origin_setup as setup, origin_setup_state as journal


class Operators(unittest.TestCase):
    def test_migrations_fail_closed_on_partial_and_recognize_later_schema(self):
        psql = mock.Mock()
        op = setup.Migration(psql, 15)
        with mock.patch.object(setup, '_ledger', return_value=14), mock.patch.object(setup, '_groups', return_value=journal.EXACT), mock.patch.object(setup, '_stage_objects', side_effect=[journal.ABSENT, journal.DRIFT]):
            self.assertEqual(op.inspect(), journal.DRIFT)
        with mock.patch.object(setup, '_ledger', return_value=17), mock.patch.object(setup, '_groups', return_value=journal.EXACT), mock.patch.object(setup, '_stage_objects', return_value=journal.EXACT), mock.patch.object(setup.origin_schema, 'require_ready') as ready:
            self.assertEqual(op.inspect(), journal.EXACT)
            ready.assert_called_once_with(psql, expected_origin_login=False)
        with mock.patch.object(setup, '_ledger', return_value=15), mock.patch.object(setup, '_groups', return_value=journal.EXACT), mock.patch.object(setup, '_stage_objects', return_value=journal.EXACT), mock.patch.object(setup, '_partial_guards', return_value=False):
            self.assertEqual(op.inspect(), journal.DRIFT)
        psql.assert_not_called()

    def test_apply_has_atomic_group_and_migration_ledger_guard(self):
        psql = mock.Mock()
        setup.Groups(psql).apply()
        sql = psql.call_args.args[0]
        self.assertEqual(sql.count('CREATE ROLE'), 2)
        self.assertTrue(sql.startswith('BEGIN;'))
        self.assertIn('pg_advisory_xact_lock', sql)
        self.assertIn("current_database()<>'contour_local'", sql)
        self.assertIn('IS DISTINCT FROM', sql)
        for version in (15,16,17):
            op = setup.Migration(psql,version)
            op.source = setup.MIGRATIONS[version].read_bytes()
            op.apply()
            sql = psql.call_args.args[0]
            self.assertEqual(sql.count('BEGIN;\nSELECT pg_catalog.pg_advisory_xact_lock'), 1)
            self.assertIn('generate_series(1,'+str(version-1)+')', sql)
            self.assertIn("current_database()<>'contour_local'",sql)

    def test_migration_executes_bound_bytes_without_rereading_path(self):
        psql = mock.Mock()
        op = setup.Migration(psql, 15)
        source = setup.MIGRATIONS[15].read_bytes()
        op.source = source.replace(b'-- Opt-in registry only.', b'-- frozen fixture bytes.')
        with mock.patch.object(type(setup.MIGRATIONS[15]), 'read_text', side_effect=AssertionError('path reread')):
            op.apply()
        self.assertIn('-- frozen fixture bytes.', psql.call_args.args[0])

    def test_wrong_database_stops_before_journal(self):
        with mock.patch.object(journal,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'wrong local database'):
                setup._prepare(setup.capture_profiles.ORIGIN_PILOT,mock.Mock(return_value='other'))
            run.assert_not_called()

    def test_pending_login_context_requires_complete_verified_postcondition(self):
        credential=mock.Mock(); credential.inspect.return_value=journal.EXACT; credential.commitment.return_value='a'*64
        login=mock.Mock(); login.inspect.return_value=journal.ABSENT
        def exercise(profile, ops, **kwargs):
            context=kwargs['set_context']
            pending={'completed':len(journal.CREDENTIAL_PHASES),'pending':'logins','credential_digest':'a'*64}
            context(pending)
            self.assertFalse(ops['groups'].context['login'])
            login.inspect.return_value=journal.DRIFT
            with self.assertRaisesRegex(ValueError,'login context drift'): context(pending)
            self.assertFalse(ops['groups'].context['login'])
            login.inspect.return_value=journal.EXACT
            credential.commitment.return_value='b'*64
            with self.assertRaisesRegex(ValueError,'credential drift'): context(pending)
            self.assertFalse(ops['groups'].context['login'])
            credential.commitment.return_value='a'*64
            context(pending)
            self.assertTrue(ops['groups'].context['login'])
        with mock.patch.object(journal,'run',side_effect=exercise):
            setup._prepare(setup.capture_profiles.ORIGIN_PILOT,mock.Mock(return_value='contour_local'),credential,login)

    def test_unknown_ledger_and_partial_groups_are_drift(self):
        psql = mock.Mock(return_value='1\n14')
        self.assertEqual(setup.Groups(psql).inspect(), journal.DRIFT)
        with mock.patch.object(setup, '_ledger', return_value=14), mock.patch.object(setup, '_groups', return_value=journal.DRIFT):
            self.assertEqual(setup.Groups(psql).inspect(), journal.DRIFT)


if __name__ == '__main__': unittest.main()
