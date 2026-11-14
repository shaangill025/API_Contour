import unittest
from deploy.local import origin21_profile as profiles, origin21_sql_runner as runner


class SqlRoleTest(unittest.TestCase):
    def test_app_auth_is_only_allowed_for_exact_human_context(self):
        runner._validate_mode_role('auth', 'contour_app', selected=profiles.HUMAN)
        for context in (None, profiles.MANAGED, profiles.STATIC, profiles.HUMAN._replace()):
            with self.assertRaises(ValueError):
                runner._validate_mode_role('auth', 'contour_app', selected=context)
        with self.assertRaises(ValueError):
            runner._validate_mode_role('sql', 'contour_app', selected=profiles.HUMAN)

    def test_app_intent_cannot_be_replayed_in_legacy_context(self):
        target = {'container_id':'a'*64,'image_id':'sha256:'+'b'*64,'network_id':'c'*64}
        intent = {'version':1,'nonce':'d'*32,'target':target,'payload_sha256':'e'*64,
                  'identity':None,'mode':'auth','role':'contour_app'}
        self.assertEqual(runner._validate_intent(intent,target,selected=profiles.HUMAN), intent)
        with self.assertRaises(ValueError): runner._validate_intent(intent,target)
