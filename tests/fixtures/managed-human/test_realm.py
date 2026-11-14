import unittest
from unittest.mock import patch
from deploy.local import origin21_managed_human_identity as identity


class RealmTest(unittest.TestCase):
    def test_fixed_pkce_and_callbacks_and_only_two_accounts(self):
        data = identity._realm({'owner': 'a'*32, 'viewer': 'b'*32})
        self.assertEqual(data['realm'], 'apicontour-mvp')
        self.assertFalse(data['registrationAllowed'])
        client = data['clients'][0]
        self.assertEqual(client['redirectUris'], ['https://mvp.localhost:19443/auth/callback'])
        self.assertEqual(client['webOrigins'], ['https://mvp.localhost:19443'])
        self.assertEqual(client['attributes']['pkce.code.challenge.method'], 'S256')
        self.assertFalse(client['directAccessGrantsEnabled'])
        self.assertEqual([item['username'] for item in data['users']], ['owner', 'viewer'])
        with self.assertRaises(ValueError): identity._realm({'owner': 'a'*32, 'viewer': 'a'*32})
        with self.assertRaises(ValueError): identity._realm({'owner': 'a'*32})

    def test_unsafe_state_fails_before_directory_creation(self):
        with patch('deploy.pilot.origin_credentials._dir', side_effect=ValueError('unsafe')), patch('os.mkdir') as mkdir:
            with self.assertRaises(ValueError): identity.initialize()
            mkdir.assert_not_called()
