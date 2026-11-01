import unittest
from deploy.pilot.native_gateway_config import config


class NativeGatewayConfigTests(unittest.TestCase):
    def values(self):
        ids = [f'00000000-0000-4000-8000-{n:012d}' for n in range(1, 8)]
        return dict(upstream_ip='192.0.2.1', delivery_ip='192.0.2.2',
                    delivery_name='ingress.test', tenant=ids[0], collector=ids[1],
                    source=ids[2], workload=ids[3:], policy_key_id='fixture')

    def test_fixed_addresses_and_scope(self):
        result = config(**self.values())
        self.assertEqual(result['upstream_address'], '192.0.2.1:9443')
        self.assertEqual(result['delivery_address'], '192.0.2.2:9445')
        self.assertEqual((result['method'], result['path'], result['route']), ('POST', '/pilot', '/pilot'))
        self.assertEqual(result['upstream_name'], 'pilot-destination')
        self.assertEqual(result['forwarder_leaf_der'], '/run/native/forwarder.der')

    def test_accepts_configured_hostname_and_rejects_invalid_scope(self):
        value = self.values()
        value['upstream_ip'] = 'not-an-ip.test'
        self.assertEqual(config(**value)['upstream_address'], 'not-an-ip.test:9443')
        value['upstream_ip'] = 'bad/name'
        with self.assertRaises(ValueError):
            config(**value)
        value = self.values()
        value['source'] = 'invalid'
        with self.assertRaises(ValueError):
            config(**value)


if __name__ == '__main__':
    unittest.main()
