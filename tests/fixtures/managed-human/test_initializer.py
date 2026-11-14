import unittest
from unittest.mock import patch
from deploy.local import origin21_managed_init as init, origin21_profile as profiles


class InitializerContextTest(unittest.TestCase):
    def test_fixed_distinct_database_ownership(self):
        base, network, project, volume = init._settings(profiles.HUMAN)
        self.assertEqual(base, profiles.HUMAN.profile.state.parent)
        self.assertEqual(network, 'apicontour-origin21-managed-human-db_default')
        self.assertEqual(project, 'apicontour-origin21-managed-human-db')
        self.assertEqual(volume, 'apicontour-origin21-managed-human-db-data')
        self.assertEqual(init._selected_volume(None, selected=profiles.HUMAN), volume)
        with self.assertRaises(ValueError):
            init._settings(profiles.HUMAN._replace())
        with self.assertRaises(ValueError):
            init._selected_volume(object(), selected=profiles.HUMAN)

    def test_credential_is_committed_before_base_logins_phase(self):
        from deploy.local import origin21_managed_human_secret as secret
        events = []
        def phase(base, name, runner, sql, check_source):
            events.append('sql')
            self.assertEqual(name, 'base-logins')
            self.assertIn("CREATE ROLE contour_app LOGIN", sql)
            self.assertIn("PASSWORD '" + 'a'*64 + "'", sql)
        def create():
            events.append('persist')
            return 'a'*64
        def read():
            events.append('verify')
            return 'a'*64
        with patch.object(secret, 'create_fresh', side_effect=create), patch.object(secret, 'read_committed', side_effect=read), patch.object(init, '_phase', side_effect=phase):
            init._base_logins(profiles.HUMAN.profile.state.parent, object(), lambda: True, selected=profiles.HUMAN)
        self.assertEqual(events, ['persist', 'verify', 'sql'])
        events.clear()
        with patch.object(secret, 'create_fresh', side_effect=create), patch.object(secret, 'read_committed', return_value='b'*64), patch.object(init, '_phase') as phase_mock:
            with self.assertRaises(ValueError):
                init._base_logins(profiles.HUMAN.profile.state.parent, object(), lambda: True, selected=profiles.HUMAN)
            phase_mock.assert_not_called()
