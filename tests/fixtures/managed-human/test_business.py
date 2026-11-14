import unittest
from unittest.mock import patch
from deploy.local import origin21_managed_human_business as business


class BusinessTest(unittest.TestCase):
    def test_untrusted_transport_rejected_before_oidc_or_sql(self):
        with patch.object(business.check_oidc, 'main') as oidc:
            with self.assertRaises(ValueError): business.prepare(object())
            oidc.assert_not_called()

    def test_failed_app_authentication_prevents_membership_and_config_writes(self):
        from deploy.local import origin21_profile, origin21_transport, provision
        transport = origin21_transport.ManagedTransport(origin21_transport._MANAGED_SEAL, object(), {}, '', '', '', '', selected=origin21_profile.HUMAN)
        def admin(sql):
            if 'schema_migrations' in sql: return '\n'.join(map(str,range(1,22)))
            if 'FROM pg_auth_members' in sql or "pg_has_role('contour_app'" in sql: return '\n'.join(sorted(provision.GROUPS))
            if 'SELECT (rolcanlogin' in sql: return 'true'
            if 'SELECT rolname FROM pg_roles' in sql: return ''
            raise AssertionError('membership SQL must not run')
        with patch.object(origin21_transport.ManagedTransport, 'verify'), \
             patch.object(origin21_transport.ManagedTransport, 'admin', side_effect=admin), \
             patch.object(origin21_transport.ManagedTransport, 'authenticate_app', return_value=False), \
             patch.object(business.origin21_schema, 'require_reference'), patch.object(business.origin21_schema, 'require_ready'), \
             patch.object(business.check_oidc, 'main'), patch.object(business.origin_credentials, '_file', return_value=b'{"owner":"o","viewer":"v"}'), \
             patch.object(business.origin21_managed_human_secret, 'read_committed', return_value='a'*64), patch.object(business, '_persist') as persist:
            with self.assertRaises(ValueError): business.prepare(transport)
            persist.assert_not_called()
