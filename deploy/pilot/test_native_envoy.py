import unittest
from deploy.pilot.native_envoy import config


class NativeEnvoyTests(unittest.TestCase):
    def test_roles_are_mutually_authenticated_and_fixed(self):
        result = config()
        chain = result['static_resources']['listeners'][0]['filter_chains'][0]
        down = chain['transport_socket']['typed_config']
        self.assertTrue(down['require_client_certificate'])
        self.assertEqual(down['common_tls_context']['validation_context']['trusted_ca']['filename'],
                         '/run/forwarder/pilot-ca.pem')
        manager = chain['filters'][0]['typed_config']
        self.assertEqual(manager['forward_client_cert_details'], 'SANITIZE')
        cluster = result['static_resources']['clusters'][0]
        upstream = cluster['transport_socket']['typed_config']
        self.assertEqual(upstream['sni'], 'native-gateway.test')
        context = upstream['common_tls_context']
        self.assertEqual(context['validation_context']['match_typed_subject_alt_names'][0]['matcher']['exact'],
                         'native-gateway.test')
        self.assertEqual(context['tls_certificates'][0]['private_key']['filename'],
                         '/run/forwarder/forwarder.key')
        endpoint = cluster['load_assignment']['endpoints'][0]['lb_endpoints'][0]['endpoint']['address']['socket_address']
        self.assertEqual((endpoint['address'], endpoint['port_value']), ('native-gateway', 9443))


if __name__ == '__main__':
    unittest.main()
