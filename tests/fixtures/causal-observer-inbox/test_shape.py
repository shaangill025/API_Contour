"""Offline source checks only; this does not parse or execute PostgreSQL."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[3]
SQL = (ROOT/'db/opt-in-migrations/0027_causal_observer_inbox.sql').read_text()
FIXTURE = (ROOT/'db/tests/causal_observer_inbox.sql').read_text()
class Shape(unittest.TestCase):
    def test_boundaries_are_present(self):
        for token in ('generate_series(1,26)', "current_setting('row_security')<>'on'", "current_setting('transaction_isolation')<>'read committed'", "locktype='advisory'", 'contour.human_observation_origin', 'contour.causal_session_locked', 'contour.causal_marker_product_current', 'contour.gateway_claim_current', 'contour.origin_logical_usage'):
            self.assertIn(token,SQL)
        self.assertNotIn('CREATE EXTENSION',SQL)
        self.assertNotRegex(SQL,r'(?i)CREATE\s+FUNCTION\s+contour\.[a-z_]*(receiver|edge)')
        self.assertEqual(SQL.count('$$') % 2,0)
        self.assertIn('CREATE UNIQUE INDEX causal_observer_one_successor',SQL)
        self.assertIn('WHERE retry_of IS NOT NULL',SQL)
        self.assertIn('ancestor_count+descendant_count+1>64',SQL)
        self.assertIn('a.depth<64',SQL)
        self.assertIn('d.depth<64',SQL)
    def test_fixture_requires_real_seed(self):
        self.assertIn('trusted synthetic observer seed required',FIXTURE)
        self.assertIn('exact retry changed receipt',FIXTURE)
        self.assertIn('wrong key admitted',FIXTURE)
        # Composite row variables cannot be mixed with scalar targets in PL/pgSQL INTO.
        self.assertNotRegex(FIXTURE, r'(?i)INTO\s+STRICT\s+r\s*,\s*p\b')
if __name__=='__main__': unittest.main()
