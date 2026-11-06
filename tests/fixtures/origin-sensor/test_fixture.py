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
        with mock.patch.dict(os.environ, {'CONTOUR_ORIGIN_SENSOR_IMAGE':'contour-origin-sensor-fixture:stale', 'CONTOUR_HUMAN_ORIGIN_FIXTURE':'1', 'CONTOUR_ORIGIN_REPLACEMENT_FIXTURE':'1', 'CONTOUR_ORIGIN_ADMISSION_FIXTURE':'1', 'CONTOUR_TLS_DISCOVERY_MATRIX':'1'}):
            ordinary = environment('inert', '/tmp/unused-target')
            self.assertNotIn('CONTOUR_ORIGIN_SENSOR_IMAGE', ordinary)
            self.assertNotIn('CONTOUR_HUMAN_ORIGIN_FIXTURE', ordinary)
            self.assertNotIn('CONTOUR_ORIGIN_REPLACEMENT_FIXTURE', ordinary)
            self.assertNotIn('CONTOUR_ORIGIN_ADMISSION_FIXTURE', ordinary)
            self.assertNotIn('CONTOUR_TLS_DISCOVERY_MATRIX', ordinary)
            selected = environment('inert', '/tmp/unused-target', 'contour-origin-sensor-fixture:selected')
            self.assertEqual(selected['CONTOUR_ORIGIN_SENSOR_IMAGE'], 'contour-origin-sensor-fixture:selected')
            self.assertNotIn('CONTOUR_HUMAN_ORIGIN_FIXTURE', selected)
            self.assertNotIn('CONTOUR_ORIGIN_REPLACEMENT_FIXTURE', selected)
            self.assertNotIn('CONTOUR_ORIGIN_ADMISSION_FIXTURE', selected)
            self.assertNotIn('CONTOUR_TLS_DISCOVERY_MATRIX', selected)
            self.assertEqual(os.environ['CONTOUR_ORIGIN_SENSOR_IMAGE'], 'contour-origin-sensor-fixture:stale')
    def test_discovery_matrix_requires_exact_directions_and_shapes(self):
        shapes={'request':{'kind':'object','fields':{'probe':{'kind':'boolean'}},'additional':None},
                'response':{'kind':'object','fields':{'id':{'kind':'integer'}},'additional':None}}
        def row(record,direction):
            r=[None]*22; r[0]='a'; r[13]=record; r[14]=direction; r[16]='200' if direction=='response' else None; r[21]=shapes[direction]; return r
        request=row('request','request'); response=row('response','response')
        fixture.assert_discovery_case([request,response],set(),'a',('request','response'))
        fixture.assert_discovery_case([request],set(),'a',('request',))
        conflict=row('conflict','response'); conflict[16]='409'
        fixture.assert_discovery_case([conflict],set(),'a',('response',),409)
        with self.assertRaises(AssertionError): fixture.assert_discovery_case([conflict],set(),'a',('response',))
        wrong_request=row('bad-request','request'); wrong_request[16]='200'
        with self.assertRaises(AssertionError): fixture.assert_discovery_case([wrong_request],set(),'a',('request',))
        fixture.assert_discovery_case([],set(),'a',())
        with self.assertRaises(AssertionError): fixture.assert_discovery_case([],{'missing'},'a',())
        for rows, directions in [([request],('request','response')),([request,response],('request',)),([request,request],('request','response'))]:
            with self.assertRaises(AssertionError): fixture.assert_discovery_case(rows,set(),'a',directions)
        wrong=row('bad','request'); wrong[21]={'kind':'unknown'}
        with self.assertRaises(AssertionError): fixture.assert_discovery_case([wrong],set(),'a',('request',))
        wrong=row('bad','request'); wrong[0]='b'
        with self.assertRaises(AssertionError): fixture.assert_discovery_case([wrong],set(),'a',('request',))
        self.assertEqual(fixture.DISCOVERY_CASES[0],fixture.DISCOVERY_CASES[-1])
        self.assertEqual(len(fixture.DISCOVERY_CASES),13)

    def test_matrix_loss_deltas_and_acknowledgements_are_exact(self):
        total=fixture.parse_matrix_drain('MATRIX 0 2',0,0,2)
        total=fixture.parse_matrix_drain('MATRIX 1 1',total,1,1)
        total=fixture.parse_matrix_drain('MATRIX 1 0',total,0,0)
        self.assertEqual(fixture.parse_matrix_drain('MATRIX 1 2',total,0,2),1)
        for line,previous,loss,records in [('MATRIX 2 1',1,0,1),('MATRIX 0 1',1,0,1),('MATRIX 1 0',0,1,1),('MATRIX 1 1',1,0,0),('DRAIN 0 0',0,0,0),('MATRIX -1 0',0,0,0)]:
            with self.assertRaises(AssertionError): fixture.parse_matrix_drain(line,previous,loss,records)

    def test_discovery_driver_aborts_on_case_failure(self):
        seen=[]
        def run(case, directions):
            seen.append(case)
            if case == 'response-malformed': raise RuntimeError('controlled failure')
        with self.assertRaisesRegex(RuntimeError,'controlled failure'):
            fixture.run_discovery_cases(run)
        self.assertEqual(seen,['normal','request-malformed','response-malformed'])
        self.assertNotIn('request-compressed',seen)

    def test_discovery_catalog_requires_full_provenance(self):
        row=[None]*27; row[22:27]=['batch','first','last','queued','expires']; row[5:9]=['p','s','e','d']; row[13:20]=['id','response','POST','200','source','http_json_v1',2]; row[21]={'kind':'boolean'}
        item=['id','complete','structure',200,{'kind':'boolean'},'source','p','s','e','d','http_json_v1',2,False,[],['tenant','p','s','e','http','response','POST','/pilot'],'batch',1,1,1,'first','last','queued','expires']
        fixture.assert_discovery_catalog([item],[row],'tenant')
        for index in range(1,len(item)):
            bad=item.copy(); bad[index]=None
            with self.assertRaises(AssertionError): fixture.assert_discovery_catalog([bad],[row],'tenant')
        with self.assertRaises(AssertionError): fixture.assert_discovery_catalog([], [row], 'tenant')
        with self.assertRaises(AssertionError): fixture.assert_discovery_catalog([item,item], [row], 'tenant')

    def test_shared_orderly_shutdown_rejects_errors_and_leaks(self):
        def processes():
            gateway=mock.Mock(returncode=0); origin=mock.Mock(returncode=0); origin.stderr.read.return_value=''; return gateway,origin
        gateway,origin=processes()
        fixture.orderly_shutdown(gateway,origin,lambda *_:'STOPPED',lambda _:'0')
        gateway.stdin.write.assert_called_once_with('STOP\n'); origin.stdin.close.assert_called_once()
        for kind in ('gateway','marker','origin','stderr','leak'):
            gateway,origin=processes()
            if kind=='gateway': gateway.returncode=1
            if kind=='origin': origin.returncode=1
            if kind=='stderr': origin.stderr.read.return_value='failure'
            with self.assertRaises(AssertionError):
                fixture.orderly_shutdown(gateway,origin,lambda *_:'bad' if kind=='marker' else 'STOPPED',lambda _:'1' if kind=='leak' else '0',clock=iter([0,11]).__next__,pause=lambda _:None)

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
    def test_replacement_ownership_and_history_fail_closed(self):
        info={'Id':'a'*64,'Name':'/owned','Config':{'Labels':{'org.apicontour.origin-replacement':'label'}}}
        fixture.assert_owned_replacement(info,'owned','label')
        for bad in ({**info,'Id':'truncated'}, {**info,'Name':'/foreign'}, {**info,'Config':{'Labels':{}}}):
            with self.assertRaises(AssertionError): fixture.assert_owned_replacement(bad,'owned','label')
        def row(leaf,record):
            result=[None]*22; result[0]=leaf; result[13]=record; return result
        old=row('old','one'); peer=row('peer','two'); new=row('new','three')
        fixture.assert_replacement_history([old,peer,new],{'one':old,'two':peer},{'one','two','three'},'old')
        with self.assertRaises(AssertionError): fixture.assert_replacement_history([old,peer,new,row('old','four')],{'one':old}, {'one','two','three'},'old')
        altered=old.copy(); altered[1]='changed'
        with self.assertRaises(AssertionError): fixture.assert_replacement_history([altered,peer,new],{'one':old}, {'one','two','three'},'old')
        with self.assertRaises(AssertionError): fixture.assert_replacement_history([peer,new],{'one':old}, {'one','two','three'},'old')

    def test_history_record_id_filter_freezes_the_original_set(self):
        a='00000000-0000-4000-8000-000000000001'
        b='00000000-0000-4000-8000-000000000002'
        later='00000000-0000-4000-8000-000000000003'
        frozen=fixture.history_record_ids_sql([b,a])
        self.assertEqual(frozen,"'%s'::uuid,'%s'::uuid" % (a,b))
        self.assertNotIn(later,frozen)
        for invalid in ([],[a,a],["not-a-uuid"]):
            with self.assertRaises(ValueError): fixture.history_record_ids_sql(invalid)

    def test_cleanup_reconciles_late_creation_and_fails_if_absence_uncertain(self):
        name = 'owned'; label = 'label'; ident = 'a' * 64
        info = {'Id':ident,'Name':'/'+name,'Config':{'Labels':{'org.apicontour.origin-replacement':label}}}
        checks = iter([None, info])
        removed = []
        fixture.cleanup_fixture_containers([{'name':name,'id':None}], label,
            lambda _: next(checks), removed.append, lambda _: False,
            attempts=2, pause=lambda: None)
        self.assertEqual(removed, [ident])
        with self.assertRaisesRegex(RuntimeError, 'uncertain'):
            fixture.cleanup_fixture_containers([{'name':name,'id':None}], label,
                lambda _: None, removed.append, lambda _: False,
                attempts=2, pause=lambda: None)

    def test_cleanup_requires_owned_identity_and_continues_after_failure(self):
        ident = 'a' * 64
        info = {'Id':ident,'Name':'/owned','Config':{'Labels':{'org.apicontour.origin-replacement':'label'}}}
        removed = []
        resources = [{'name':'owned','id':ident}, {'name':'foreign','id':'b'*64}]
        with self.assertRaisesRegex(RuntimeError, 'uncertain or failed'):
            fixture.cleanup_fixture_containers(resources, 'label', lambda _: info,
                removed.append, lambda _: False, attempts=1)
        self.assertEqual(removed, [ident])
        with self.assertRaisesRegex(RuntimeError, 'uncertain or failed'):
            fixture.cleanup_fixture_containers([{'name':'owned','id':'b'*64}], 'label',
                lambda _: info, removed.append, lambda _: False, attempts=1)
        self.assertEqual(removed, [ident])

    def test_admission_diagnostic_requires_exact_bounded_shape(self):
        self.assertEqual(fixture.parse_admission_diagnostic('ADMISSION deferred_discard_invalid 0 2 0 0'),
                         ('deferred_discard_invalid',0,2,0,0))
        self.assertEqual(fixture.parse_admission_diagnostic('ADMISSION deferred_retry 0 0 0 2'),
                         ('deferred_retry',0,0,0,2))
        fixture.require_terminal_admission(('deferred_discard_invalid',0,2,0,0))
        for wrong in (('deferred_retry',0,2,0,0), ('deferred_discard_invalid',1,2,0,0),
                      ('deferred_discard_invalid',0,1,0,0), ('deferred_discard_invalid',0,2,1,0),
                      ('deferred_discard_invalid',0,2,0,1)):
            with self.assertRaises(RuntimeError): fixture.require_terminal_admission(wrong)
        for bad in ('ADMISSION unknown 0 2 0 0', 'ADMISSION deferred_retry -1 0 0 2',
                    'ADMISSION deferred_retry 0 0 0 2 secret', 'DIAG deferred_retry 0 0',
                    'ADMISSION deferred_retry 18446744073709551616 0 0 2'):
            with self.assertRaises(ValueError): fixture.parse_admission_diagnostic(bad)

    def test_diagnostic_protocol_is_strict_and_safe(self):
        self.assertEqual(fixture.parse_drain_diagnostic('DIAG deferred_discard_invalid 0 1'), ('deferred_discard_invalid', 0, 1))
        self.assertEqual(fixture.parse_drain_diagnostic('DIAG ok 0 2'), ('ok', 0, 2))
        for bad in ('DIAG unknown 0 1', 'DIAG deferred_discard_invalid 0 -1',
                    'DIAG ok 0 1 secret', 'DIAG ok 1 2', 'DRAIN 0 0 1',
                    'DIAG owner_transport 0 18446744073709551616'):
            with self.assertRaises(ValueError): fixture.parse_drain_diagnostic(bad)

    def test_pg_diagnostic_reap_timeout_is_bounded_and_sanitized(self):
        process=mock.Mock()
        process.poll.return_value=None
        process.wait.side_effect=fixture.subprocess.TimeoutExpired('secret-sentinel',2)
        selector=mock.Mock()
        selector.get_map.return_value={1:True}
        selector.select.return_value=[]
        with mock.patch.object(fixture.subprocess,'Popen',return_value=process), \
             mock.patch.object(fixture.selectors,'DefaultSelector',return_value=selector):
            with self.assertRaisesRegex(RuntimeError, 'diagnostic cleanup failed') as caught:
                fixture.read_pg_diagnostic('owned',{},'fixture_marker_0123456789abcdef')
        process.kill.assert_called_once()
        process.wait.assert_called_once_with(timeout=2)
        process.stdout.close.assert_called_once()
        self.assertNotIn('secret-sentinel',str(caught.exception))

    def test_pg_diagnostic_waits_for_verbose_readback(self):
        execute=mock.Mock(side_effect=['','t','default','verbose'])
        with mock.patch.object(fixture.time,'sleep'):
            fixture.configure_pg_diagnostic(execute)
        self.assertEqual(execute.call_args_list[0], mock.call("ALTER SYSTEM SET log_error_verbosity = 'verbose';"))
        self.assertEqual(execute.call_args_list[1], mock.call('SELECT pg_reload_conf();'))
        self.assertEqual(execute.call_args_list[2].args, ('SHOW log_error_verbosity;',))
        self.assertEqual(execute.call_count,4)

    def test_pg_diagnostic_redacts_and_requires_new_marker(self):
        marker = 'fixture_marker_0123456789abcdef'
        log = ('2026-11-05 12:00:00 UTC [10] ERROR:  23514: old secret\n'
               '2026-11-05 12:00:01 UTC [10] LOG:  00000: ' + marker + '\n'
               '2026-11-05 12:00:02 UTC [11] ERROR:  23514: origin unavailable\n'
               '2026-11-05 12:00:02 UTC [11] STATEMENT:  secret-sentinel\n'
               '2026-11-05 12:00:03 UTC [11] ERROR:  22000: secret-sentinel\n')
        result = fixture.parse_pg_diagnostic(log, marker)
        self.assertEqual(result[0], ('23514', 'origin_unavailable', None))
        self.assertEqual(result[1][0:2], ('22000', 'unrecognized'))
        self.assertNotIn('secret-sentinel', repr(result))
        self.assertEqual(len(result[1][2]), 64)
        self.assertEqual(fixture.parse_pg_diagnostic(log.split('2026-11-05 12:00:02')[0], marker), [])
        excess = log + '2026-11-05 12:00:04 UTC [11] ERROR:  23514: origin unavailable\n' * 33
        with self.assertRaises(ValueError): fixture.parse_pg_diagnostic(excess, marker)
        for malformed in ('', log.replace(marker, 'other'), log + log, log.replace('23514: origin unavailable', 'xxxxx: origin unavailable')):
            with self.assertRaises(ValueError): fixture.parse_pg_diagnostic(malformed, marker)

    def test_stock_flow_has_fixed_identity_and_target(self):
        nodes={node['id']:node for node in fixture.flows('b'*64, 'a')}
        self.assertEqual(nodes['send']['url'],'https://127.0.0.1:9443/pilot')
        self.assertEqual(nodes['send']['tls'],'tls')
        self.assertEqual(nodes['tls']['cert'],'/fixture/client.crt')
        self.assertIn('x-contour-origin-witness',nodes['make']['func'])
        self.assertIn('{probe:[true]}', nodes['make']['func'])
        other={node['id']:node for node in fixture.flows('a'*64, 'b')}
        self.assertIn('{probe:{id:1}}', other['make']['func'])
        with self.assertRaises(ValueError): fixture.flows('a'*64, 'unknown')

    def test_concurrent_shape_attribution_is_fail_closed(self):
        def obj(fields): return {'kind':'object','fields':fields,'additional':None}
        def row(record, leaf, direction, shape):
            value=[None]*22; value[0]=leaf; value[13]=record; value[14]=direction; value[21]=shape
            return value
        rows=[
            row('ar','a','request',obj({'probe':{'kind':'array','items':{'kind':'boolean'}}})),
            row('br','b','request',obj({'probe':obj({'id':{'kind':'integer'}})})),
            row('as','a','response',obj({'id':{'kind':'boolean'}})),
            row('bs','b','response',obj({'quantity':{'kind':'array','items':{'kind':'integer'}}})),
        ]
        old=row('old','foreign','request',{})
        fixture.assert_concurrent([old,*rows],{'old'},'a','b')
        for first, second in [(0,1),(2,3)]:
            changed=[r.copy() for r in rows]
            changed[first][0],changed[second][0]=changed[second][0],changed[first][0]
            with self.assertRaises(AssertionError): fixture.assert_concurrent(changed,set(),'a','b')
        duplicate=[r.copy() for r in rows]; duplicate[1]=duplicate[0].copy(); duplicate[1][13]='duplicate'
        foreign=[r.copy() for r in rows]; foreign[0][0]='foreign'
        for changed in (rows[:-1], [*rows,row('extra','a','request',{})], duplicate, foreign):
            with self.assertRaises(AssertionError): fixture.assert_concurrent(changed,set(),'a','b')

if __name__ == '__main__': unittest.main()
