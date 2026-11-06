import unittest
from deploy.pilot.native_envoy import config


class NativeEnvoyTests(unittest.TestCase):
    def test_origin_profile_adds_exact_overwrite_only_when_selected(self):
        def route(value):
            return value['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']['route_config']
        self.assertNotIn('request_headers_to_add', route(config()))
        self.assertEqual(route(config(origin_v2=True))['request_headers_to_add'], [{
            'header': {'key': 'x-contour-origin-witness', 'value': '%DOWNSTREAM_PEER_FINGERPRINT_256%'},
            'append_action': 'OVERWRITE_IF_EXISTS_OR_ADD', 'keep_empty_value': True}])
        with self.assertRaises(ValueError): config(origin_v2='v2')

    def test_http1_trailers_enabled_without_other_codec_relaxations(self):
        for profile in (False, True):
            result = config(origin_v2=profile)
            chain = result['static_resources']['listeners'][0]['filter_chains'][0]
            manager = chain['filters'][0]['typed_config']
            self.assertEqual(manager['codec_type'], 'HTTP1')
            self.assertEqual(manager['http_protocol_options'], {'enable_trailers': True})
            cluster = result['static_resources']['clusters'][0]
            self.assertEqual(cluster['typed_extension_protocol_options'], {
                'envoy.extensions.upstreams.http.v3.HttpProtocolOptions': {
                    '@type': 'type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions',
                    'explicit_http_config': {'http_protocol_options': {'enable_trailers': True}}}})
            self.assertEqual(cluster['transport_socket']['typed_config']['common_tls_context']['alpn_protocols'], ['http/1.1'])
            self.assertEqual(manager['stream_idle_timeout'], '10s')
            self.assertEqual(manager['request_headers_timeout'], '5s')
            self.assertEqual(cluster['connect_timeout'], '3s')

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
