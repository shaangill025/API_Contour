"""Offline source-shape checks; never connects to PostgreSQL or runs SQL."""
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SQL = (ROOT / 'db/opt-in-migrations/0026_causal_evidence_enrollment.sql').read_text()
FIXTURE = (ROOT / 'db/tests/causal_evidence_enrollment.sql').read_text()

class Shape(unittest.TestCase):
    def test_atomic_migration_and_guards(self):
        text = re.sub(r'^--.*$', '', SQL, flags=re.M).strip()
        self.assertTrue(text.startswith('BEGIN;'))
        self.assertTrue(text.endswith('COMMIT;'))
        self.assertEqual(text.count('$$') % 2, 0)
        for guard in ("generate_series(1,25)", "current_setting('row_security') <> 'on'", "current_setting('transaction_isolation') <> 'read committed'", "locktype='advisory'", "rolsuper"):
            self.assertIn(guard, text)
        self.assertNotIn('incomplete gateway enrollment sketch', text)
    def test_no_receiver_api_or_external_execution(self):
        self.assertNotRegex(SQL, r'(?i)CREATE\s+FUNCTION\s+contour\.[a-z_]*receiver')
        self.assertNotRegex(SQL, r'(?i)\b(COPY\s+.*\bPROGRAM|CREATE\s+EXTENSION|ALTER\s+SYSTEM)\b')
        self.assertIn("'receiver_backend','receiver_evidence'", SQL)
    def test_fixture_covers_named_paths(self):
        for label in ('runtime source accepted as gateway', 'disabled policy leaked receipt', 'new nonce accepted for active gateway', 'clock rollback leaked receipt', 'expired lease returned receipt', 'quota failure accepted', 'closure changed prepaid quota', 'exact retry changed lease'):
            self.assertIn(label, FIXTURE)
        self.assertIn('ROLLBACK;', FIXTURE)

if __name__ == '__main__':
    unittest.main()
