import unittest
import json
from pathlib import Path
from deploy.local import origin21_profile as profiles, provision


class MembershipTest(unittest.TestCase):
    def test_fixed_issuer_scope_and_quoted_verified_subjects(self):
        subjects = {'owner': "owner'quoted", 'viewer': 'viewer'}
        normal = provision._human_statements(subjects, 0)
        human = provision._human_statements(subjects, 0, selected=profiles.HUMAN)
        self.assertIn("'https://localhost:8444/realms/apicontour-local'", normal)
        self.assertIn("'https://idp.mvp.localhost:18444/realms/apicontour-mvp'", human)
        self.assertIn("'owner''quoted'", human)
        self.assertIn("'service_owner'", human)
        self.assertIn("'viewer'", human)
        self.assertEqual(normal.replace(provision.ISSUER, 'https://idp.mvp.localhost:18444/realms/apicontour-mvp'), human)
        self.assertNotIn('INSERT INTO contour.human_actors', provision._human_statements(subjects, 2, selected=profiles.HUMAN))
        with self.assertRaises(ValueError): provision._human_statements(subjects, 1, selected=profiles.HUMAN)
        with self.assertRaises(ValueError): provision._human_statements({'owner':'same','viewer':'same'}, 0, selected=profiles.HUMAN)
        with self.assertRaises(ValueError): provision._human_statements(subjects, 0, selected=profiles.HUMAN._replace())

    def test_normal_sql_matches_parent_revision_for_fresh_and_existing_actors(self):
        expected = json.loads((Path(__file__).parent/'legacy-membership.json').read_text())
        subjects = {'owner': "owner'quoted", 'viewer': 'viewer'}
        for count in (0, 2):
            self.assertEqual(provision._human_statements(subjects, count).encode(), expected[str(count)].encode())

    def test_human_rejects_dollar_delimiter_before_sql_construction(self):
        from unittest.mock import patch
        for role in ('owner', 'viewer'):
            subjects = {'owner': 'owner', 'viewer': 'viewer'}
            subjects[role] = "subject'$$injection"
            with self.subTest(role=role), patch.object(provision, 'sql_quote') as quote:
                with self.assertRaises(ValueError):
                    provision._human_statements(subjects, 0, selected=profiles.HUMAN)
                quote.assert_not_called()
