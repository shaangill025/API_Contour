"""Offline migration dispatch and readiness-contract checks."""
import unittest
import sqlite3
import re
from unittest import mock

from deploy.local import provision
from deploy.pilot import origin_schema


class OriginSchemaTests(unittest.TestCase):
    def test_explicit_complete_ledger_is_read_only_and_requires_readiness(self):
        versions = list(range(1, 15)); installed = list(range(1, 18))
        ledger = '\n'.join(map(str, installed))
        with mock.patch.object(provision, 'psql', side_effect=['true', ledger]) as query:
            provision.apply_migrations(installed, versions)
        self.assertEqual(query.call_count, 2)
        self.assertEqual(query.call_args_list[0].args[0], origin_schema.readiness_sql())
        with mock.patch.object(provision, 'psql', return_value='false') as query:
            with self.assertRaisesRegex(RuntimeError, 'readiness drift'):
                provision.apply_migrations(installed, versions)
            self.assertEqual(query.call_count, 1)

    def test_partial_and_unknown_ledgers_fail_without_sql(self):
        versions = list(range(1, 15))
        for ledger in (list(range(1, 16)), list(range(1, 17)), list(range(1, 19)), list(range(1, 14))+[15]):
            with self.subTest(ledger=ledger), mock.patch.object(provision, 'psql') as query:
                with self.assertRaisesRegex(RuntimeError, 'unexpected migration ledger'):
                    provision.apply_migrations(ledger, versions)
                query.assert_not_called()

    def test_default_prefix_installs_only_default_migrations(self):
        versions = list(range(1, 15))
        with mock.patch.object(provision, 'psql', side_effect=['', '\n'.join(map(str, versions))]) as query:
            provision.apply_migrations(versions[:-1], versions)
        self.assertEqual(query.call_args_list[0].args[0], provision.MIGRATIONS[-1].read_text())
        with mock.patch.object(provision, 'psql', return_value='\n'.join(map(str, versions))) as query:
            provision.apply_migrations(versions, versions)
        self.assertEqual(query.call_count, 1)

    def test_incoming_membership_rejection_uses_two_valued_exception(self):
        # Execute the exact generated exception in a SQL engine, including the
        # unexpected-origin edge that previously became UNKNOWN via IN (NULL).
        connection = sqlite3.connect(':memory:')
        self.addCleanup(connection.close)
        for permitted in (False, True):
            sql = origin_schema.readiness_sql(expected_origin_login=permitted)
            match = re.search(r"WHERE target\.rolname IN \('contour_v2_ingress','contour_origin_ingress'\)\s+AND NOT \((.*?)\)\)", sql)
            self.assertIsNotNone(match)
            expression = match.group(1)
            for group, member, admin, inherit, set_role, expected in (
                ('contour_origin_ingress','unexpected',0,1,1,False),
                ('contour_v2_ingress','contour_local_origin_ingress',0,1,1,False),
                ('contour_origin_ingress','contour_local_origin_ingress',0,1,1,permitted),
                ('contour_origin_ingress','contour_local_origin_ingress',1,1,1,False),
                ('contour_origin_ingress','contour_local_origin_ingress',0,0,1,False),
                ('contour_origin_ingress','contour_local_origin_ingress',0,1,0,False),
            ):
                query = ('SELECT ('+expression+') FROM (SELECT ? AS rolname) target '
                         'CROSS JOIN (SELECT ? AS rolname) member '
                         'CROSS JOIN (SELECT ? AS admin_option, ? AS inherit_option, ? AS set_option) m')
                value = connection.execute(query, (group, member, admin, inherit, set_role)).fetchone()[0]
                self.assertIsNotNone(value)
                self.assertEqual(bool(value), expected)

    def test_non_true_readiness_never_advances_or_writes(self):
        installed = list(range(1, 18)); versions = list(range(1, 15))
        for result in ('', None, 'unknown', 'NULL', 'false', 'TRUE'):
            with self.subTest(result=result), mock.patch.object(provision, 'psql', return_value=result) as query:
                with self.assertRaisesRegex(RuntimeError, 'readiness drift'):
                    provision.apply_migrations(installed, versions)
                self.assertEqual(query.call_count, 1)
                self.assertEqual(query.call_args.args[0], origin_schema.readiness_sql())


if __name__ == '__main__': unittest.main()
