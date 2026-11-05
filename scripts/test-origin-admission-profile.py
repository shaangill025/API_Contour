"""Offline check for disposable full-profile provisioning order."""
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = runpy.run_path(str(ROOT / 'scripts/origin-admission-profile.py'))


class ProfileTest(unittest.TestCase):
    def test_contiguous_profile_uses_real_sources(self):
        statements = []
        def execute(sql):
            statements.append(sql)
            if sql == PROFILE['CATALOG_QUERY']:
                return 'resolver-properties'
            if sql == PROFILE['BOUNDARY_QUERY']:
                return 't'
            if sql == PROFILE['VERIFIER_QUERY']:
                return 'verifier-properties'
            if sql.startswith('SELECT array_agg(version'):
                return '{' + ','.join(map(str, range(1, 22))) + '}'
            return ''
        PROFILE['apply_base'](execute)
        PROFILE['apply_opt_ins'](execute)
        session = runpy.run_path(str(ROOT / 'scripts/test-postgres-causal-sessions.py'))
        self.assertEqual(statements[0], (ROOT / 'db/bootstrap.sql').read_text())
        expected = [(ROOT / ('db/provision_' + n + '.sql')).read_text() for n in session['PROVISIONS']]
        expected += [(ROOT / ('db/migrations/' + n + '.sql')).read_text() for n in session['MIGRATIONS']]
        expected += [(ROOT / ('db/opt-in-migrations/' + n + '.sql')).read_text() for n in (*session['OPT_INS'], '0020_causal_inbox', '0021_origin_admission')]
        actual=[sql for sql in statements[1:] if sql not in (PROFILE['CATALOG_QUERY'],PROFILE['BOUNDARY_QUERY'],PROFILE['VERIFIER_QUERY']) and not sql.startswith('SELECT array_agg(version')]
        self.assertEqual(actual, expected)

    def test_incorrect_ledger_is_rejected(self):
        def execute(sql):
            return 'resolver-properties' if sql == PROFILE['CATALOG_QUERY'] else 't' if sql == PROFILE['BOUNDARY_QUERY'] else 'verifier-properties' if sql == PROFILE['VERIFIER_QUERY'] else ''
        with self.assertRaisesRegex(RuntimeError, 'ledger mismatch'):
            PROFILE['apply_opt_ins'](execute)

    def test_changed_resolver_catalog_is_rejected(self):
        calls=iter(['before','after'])
        with self.assertRaisesRegex(RuntimeError, 'catalog changed'):
            PROFILE['apply_21'](lambda sql: next(calls) if sql == PROFILE['CATALOG_QUERY'] else 't' if sql == PROFILE['BOUNDARY_QUERY'] else 'verifier-properties' if sql == PROFILE['VERIFIER_QUERY'] else '')


if __name__ == '__main__':
    unittest.main()
