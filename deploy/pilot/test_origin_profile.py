"""Offline contract for the unexposed origin pilot configuration."""
import copy
import unittest
import uuid

from deploy.local import capture_profiles as profiles, capture_provision
from deploy.pilot import native_envoy, native_prepare, origin_profile


class OriginProfileTests(unittest.TestCase):
    def test_closed_distinct_identity_and_owned_leaf_paths(self):
        profile = profiles.ORIGIN_PILOT
        capture = profile.capture
        ids = [capture.collector, capture.source, capture.deployment, capture.instance, capture.nonce]
        for slot in profile.origins:
            ids.extend([slot.deployment, slot.instance, slot.lifecycle, slot.credential, slot.grant])
            self.assertEqual(slot.leaf_der.parent.parent, profile.state)
            self.assertEqual(slot.leaf_der.name, 'client.crt.der')
        self.assertEqual(len(profile.origins), 2)
        self.assertEqual(len(ids), len(set(ids)))
        for value in ids:
            self.assertEqual(str(uuid.UUID(value)), value)
        for legacy in (profiles.DEFAULT, profiles.PILOT):
            self.assertTrue(set(ids).isdisjoint({legacy.collector, legacy.source, legacy.deployment, legacy.instance, legacy.nonce}))
            self.assertNotEqual(capture.capture, legacy.capture)
        self.assertEqual(profile.state, profiles.STATE/'origin-pilot')
        self.assertNotEqual(profile.ingress_login, profile.worker_login)
        self.assertEqual((profile.ingress_group, profile.worker_group), ('contour_origin_ingress', 'contour_catalog_worker'))
        for argv in (['--profile', 'origin-pilot'],):
            with self.assertRaises(ValueError): profiles.arguments(argv)

    def test_paired_wire_and_role_configuration(self):
        profile = profiles.ORIGIN_PILOT
        result = origin_profile.configs()
        ingress, worker = result['capture']['ingress.json'], result['capture']['worker.json']
        self.assertEqual(ingress['ingestion_profile'], 'origin_v2')
        self.assertEqual(ingress['database_user'], 'contour_local_origin_ingress')
        self.assertEqual(worker['database_user'], 'contour_local_origin_worker')
        self.assertNotEqual(ingress['password_file'], worker['password_file'])
        self.assertEqual(ingress['collector'], profile.capture.collector)
        self.assertEqual(worker['collector'], profile.capture.collector)
        gateway = result['gateway']
        self.assertEqual(gateway['capture_wire_version'], 'v2')
        self.assertEqual((gateway['collector'], gateway['source']), (profile.capture.collector, profile.capture.source))
        self.assertEqual(gateway['workload'][-1], profile.capture.deployment)
        route = result['envoy']['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']['route_config']
        header = route['request_headers_to_add'][0]
        self.assertEqual(header['header']['value'], '%DOWNSTREAM_PEER_FINGERPRINT_256%')
        self.assertEqual(header['append_action'], 'OVERWRITE_IF_EXISTS_OR_ADD')
        self.assertEqual(result['envoy'], native_envoy.config(origin_v2=True))

    def test_unsupported_profile_and_legacy_builders_unchanged(self):
        before_capture = copy.deepcopy(capture_provision.runtime_configs(profiles.PILOT.collector))
        before_gateway = copy.deepcopy(native_prepare.gateway_config())
        before_envoy = copy.deepcopy(native_envoy.config())
        for profile in (profiles.PILOT, profiles.DEFAULT, profiles.ORIGIN_PILOT._replace(ingress_login='other'), None):
            with self.assertRaises(ValueError): origin_profile.configs(profile)
        origin_profile.configs()
        self.assertEqual(capture_provision.runtime_configs(profiles.PILOT.collector), before_capture)
        self.assertEqual(native_prepare.gateway_config(), before_gateway)
        self.assertEqual(native_envoy.config(), before_envoy)
        self.assertNotIn('ingestion_profile', before_capture['ingress.json'])
        self.assertNotIn('capture_wire_version', before_gateway)


if __name__ == '__main__': unittest.main()
