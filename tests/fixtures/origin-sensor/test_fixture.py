"""Offline assertions on generated origin sensor fixture, without Docker or listeners."""
import importlib.util
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('sensor_fixture', ROOT/'scripts/test-postgres-origin-sensor.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

class Fixture(unittest.TestCase):
    def test_source_check_uses_the_fixture_checkout_from_another_cwd(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as other:
            try:
                os.chdir(other)
                with mock.patch.object(fixture.subprocess, 'check_output', side_effect=['', 'a'*40]) as call:
                    self.assertEqual(fixture.checked_source_head(), 'a'*40)
                    self.assertEqual(call.call_count, 2)
                    for invocation in call.call_args_list:
                        self.assertEqual(invocation.kwargs['cwd'], fixture.ROOT)
            finally:
                os.chdir(previous)
    def test_inherited_image_cannot_activate_the_sensor_mode(self):
        environment = runpy.run_path(str(ROOT/'scripts/test-postgres-tls.py'))['fixture_environment']
        with mock.patch.dict(os.environ, {'CONTOUR_ORIGIN_SENSOR_IMAGE':'contour-origin-sensor-fixture:stale'}):
            ordinary = environment('inert', '/tmp/unused-target')
            self.assertNotIn('CONTOUR_ORIGIN_SENSOR_IMAGE', ordinary)
            selected = environment('inert', '/tmp/unused-target', 'contour-origin-sensor-fixture:selected')
            self.assertEqual(selected['CONTOUR_ORIGIN_SENSOR_IMAGE'], 'contour-origin-sensor-fixture:selected')
            self.assertEqual(os.environ['CONTOUR_ORIGIN_SENSOR_IMAGE'], 'contour-origin-sensor-fixture:stale')
    def test_generated_production_envoy_keeps_exact_overwrite(self):
        cfg = fixture.generated_edge(12345)
        listener = cfg['static_resources']['listeners'][0]['filter_chains'][0]
        manager = listener['filters'][0]['typed_config']
        self.assertEqual(manager['route_config']['request_headers_to_add'], [{
            'header': {'key':'x-contour-origin-witness','value':'%DOWNSTREAM_PEER_FINGERPRINT_256%'},
            'append_action':'OVERWRITE_IF_EXISTS_OR_ADD','keep_empty_value':True}])
        self.assertEqual(manager['forward_client_cert_details'], 'SANITIZE')
        self.assertTrue(listener['transport_socket']['typed_config']['require_client_certificate'])
        self.assertEqual(cfg['static_resources']['clusters'][0]['transport_socket']['typed_config']['sni'], 'native-gateway.test')
    def test_proof_tuple_is_fail_closed(self):
        item=fixture.ITEM; digest='a'*64; ids=('i','l','c','g'); service='other-service'; deployment='other-deployment'
        row=[digest,*ids,item,item,item,item,item,service,item,deployment,'record','response','POST','200','source','http_json_v1',2,'verified_origin_v1']
        fixture.assert_proofs([row],{digest:ids},service,deployment,'source')
        for index, value in [(0,'b'*64),(1,'wrong'),(5,'wrong'),(10,'wrong'),(14,'unknown'),(15,'GET'),(16,'500'),(17,'wrong'),(18,'wrong'),(19,1)]:
            changed=list(row); changed[index]=value
            with self.assertRaises(AssertionError): fixture.assert_proofs([changed],{digest:ids},service,deployment,'source')
    def test_unattributed_rows_cannot_have_a_proof(self):
        item=fixture.ITEM
        row=[None]*5+[item]*4+[None]*4+['record','request','POST',None,'source','http_json_v1',2,'unattributed']
        fixture.assert_proofs([row],{},'service','deployment','source')
        row[1]='forged'
        with self.assertRaises(AssertionError): fixture.assert_proofs([row],{},'service','deployment','source')
    def test_transition_rejects_delayed_extra_and_foreign_records(self):
        def row(record,direction,digest):
            value=[None]*21; value[0]=digest; value[13]=record; value[14]=direction; return value
        old=row('old','request','a'); request=row('request','request','a'); response=row('response','response','a')
        self.assertEqual(fixture.assert_transition([old,request,response],{'old'},'a'),{'old','request','response'})
        for rows in ([request], [request,response,row('late','response','a')], [request,row('response','response','b')]):
            with self.assertRaises(AssertionError): fixture.assert_transition(rows,set(),'a')
        unattributed=[row('request','request',None),row('response','response',None)]
        fixture.assert_transition(unattributed,set(),'a',allow_unattributed=True)
        with self.assertRaises(AssertionError): fixture.assert_transition(unattributed,set(),'a')
    def test_stock_flow_has_fixed_identity_and_target(self):
        nodes={node['id']:node for node in fixture.flows('b'*64)}
        self.assertEqual(nodes['send']['url'],'https://127.0.0.1:9443/pilot')
        self.assertEqual(nodes['send']['tls'],'tls')
        self.assertEqual(nodes['tls']['cert'],'/fixture/client.crt')
        self.assertIn('x-contour-origin-witness',nodes['make']['func'])

if __name__ == '__main__': unittest.main()
