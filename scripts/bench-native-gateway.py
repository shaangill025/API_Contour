#!/usr/bin/env python3
"""Aggregate sanitized, paired synthetic measurements; never claim SLA acceptance.

This is an offline report component, not a fixture orchestrator. Input JSON is
read from stdin. See tests/fixtures/native-perf/README.md for the schema.
"""
import importlib.util
import json
import shutil
from pathlib import Path
import math
import sys
import unittest
from unittest import mock
sys.dont_write_bytecode = True


# Import the repository generators, not an independently reconstructed edge.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from deploy.pilot import native_envoy
from deploy.gateway import config as gateway_config


def direct_envoy_config():
    """Same downstream edge, direct destination with independent mTLS identity."""
    result = native_envoy.config()
    direct = gateway_config.config('pilot-destination', 9443, 'pilot-destination',
                                   ca='/run/perf/destination-ca.pem', listen_port=9443)
    cluster = direct['static_resources']['clusters'][0]
    upstream = cluster['transport_socket']['typed_config']['common_tls_context']
    upstream['tls_certificates'] = [{
        'certificate_chain': {'filename': '/run/perf/destination-client.pem'},
        'private_key': {'filename': '/run/perf/destination-client.key'}}]
    upstream['alpn_protocols'] = ['http/1.1']
    result['static_resources']['clusters'][0] = cluster
    result['admin']={'address':{'socket_address':{'address':'127.0.0.1','port_value':9901}}}
    return result


def block_summary(block):
    if set(block) != {'attempted', 'success_ms', 'errors', 'timeouts', 'elapsed_ms'}:
        raise ValueError('invalid block fields')
    n, errors, timeouts = (block[k] for k in ('attempted', 'errors', 'timeouts'))
    samples, elapsed = block['success_ms'], block['elapsed_ms']
    if any(type(x) is not int or x < 0 for x in (n, errors, timeouts)) or n < 1:
        raise ValueError('invalid counts')
    if not isinstance(samples, list) or len(samples) + errors + timeouts != n:
        raise ValueError('inconsistent counts')
    if (type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed <= 0 or
        any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in samples)):
        raise ValueError('invalid timing')
    ordered = sorted(samples)
    return {'attempted': n, 'successes': len(samples), 'errors': errors, 'timeouts': timeouts,
            'error_fraction': (errors + timeouts) / n,
            'p99_ms': ordered[math.ceil(.99 * len(ordered)) - 1] if ordered else None,
            'throughput_success_per_second': len(samples) * 1000 / elapsed}


def report(data):
    if set(data) != {'blocks', 'capture', 'gateway_pid1_vmhwm_kib_by_block'} or not data['blocks']:
        raise ValueError('invalid report')
    blocks = []
    for pair in data['blocks']:
        if set(pair) != {'A', 'B', 'C'}:
            raise ValueError('unpaired block')
        row = {lane: block_summary(pair[lane]) for lane in ('A', 'B', 'C')}
        if len({row[lane]['attempted'] for lane in row}) != 1:
            raise ValueError('unequal samples')
        a, b, c = (row[x] for x in ('A', 'B', 'C'))
        def difference(x, y):
            return None if x['p99_ms'] is None or y['p99_ms'] is None else y['p99_ms'] - x['p99_ms']
        def loss(x, y):
            baseline = x['throughput_success_per_second']
            return None if baseline == 0 else 1 - y['throughput_success_per_second'] / baseline
        blocks.append({'lanes': row, 'A_to_C_p99_difference_ms': difference(a,c),
                       'A_to_C_throughput_loss_fraction': loss(a,c),
                       'A_to_B_p99_difference_ms': difference(a,b),
                       'B_to_C_p99_difference_ms': difference(b,c),
                       'A_to_B_throughput_loss_fraction': loss(a,b),
                       'B_to_C_throughput_loss_fraction': loss(b,c)})
    capture = data['capture']
    if set(capture) != {'successful_C_requests', 'persisted_request_observations', 'persisted_response_observations', 'drain_seconds'}:
        raise ValueError('invalid capture coverage')
    total = sum(block['lanes']['C']['successes'] for block in blocks)
    if capture['successful_C_requests'] != total or any(type(capture[k]) is not int or capture[k] < 0 for k in ('successful_C_requests','persisted_request_observations','persisted_response_observations')):
        raise ValueError('invalid capture counts')
    drain = capture['drain_seconds']
    if type(drain) not in (int,float) or not math.isfinite(drain) or drain <= 0:
        raise ValueError('invalid drain')
    hwm = data['gateway_pid1_vmhwm_kib_by_block']
    if not isinstance(hwm,list) or len(hwm)!=len(blocks) or any(
        value is not None and (type(value) is not int or value <= 0) for value in hwm):
        raise ValueError('invalid PID1 VmHWM samples')
    counts = dict(capture)
    for direction in ('request', 'response'):
        count = capture['persisted_' + direction + '_observations']
        counts[direction + '_difference_from_successful_requests'] = count - total
        counts[direction + '_count_ratio_to_successful_requests'] = count / total if total else None
    return {'classification':'SCREEN_ONLY', 'blocks':blocks, 'capture':counts,
            'capture_interpretation':'Matching aggregate scoped counts cannot establish per-request coverage or continuous authority; readiness and failed attempts may cross windows.',
            'gateway_pid1_process_lifetime_vmhwm_kib_by_block':hwm,
            'gateway_pid1_process_lifetime_vmhwm_kib_overall':max(hwm) if all(x is not None for x in hwm) else None,
            'gateway_pid1_process_lifetime_vmhwm_complete':all(x is not None for x in hwm),
            'limitations':['Not target acceptance; no callback timing or causal attribution',
              'Fixed A→B→C order can be affected by drift',
              'For 50 successes nearest-rank p99 is the maximum',
              'Concurrency one, fresh client connections and one successful readiness request per lane; warmup is not representative',
              'Closed-loop achieved rate is not saturated capacity and may omit coordinated delay',
              'All errors and timeouts are counted; capture differences are unexplained',
              'Per-request capture coverage and continuous authority are unverified',
              'PID1 process-lifetime VmHWM is not stack RSS or target proof',
              'The report helper does not independently verify measurement provenance or conditions']}


def load_driver():
    spec = importlib.util.spec_from_file_location('native_perf_driver', ROOT/'tests/fixtures/native-perf/driver.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_screen():
    required = (ROOT/'.local-mvp/pilot/native/gateway/gateway.json',
        ROOT/'.local-mvp/pilot/native/gateway/upstream-ca.der',
        ROOT/'.local-mvp/pilot/native/gateway/upstream-client.der',
        ROOT/'.local-mvp/pilot/native/gateway/upstream-client-key.der',
        ROOT/'.local-mvp/pilot/native/forwarder/envoy.json',
        ROOT/'.local-mvp/pilot/capture/runtime/server.crt.der',
        ROOT/'.local-mvp/ca.crt')
    if not all(path.is_file() for path in required) or not shutil.which('docker') or not shutil.which('openssl'):
        raise RuntimeError('missing synthetic TLS fixture, Docker, or OpenSSL prerequisite')
    module = load_driver()
    driver = module.Driver(sys.modules[__name__])
    module.pilot.with_restoration(driver.run,driver.cleanup)
    print(json.dumps(driver.result,allow_nan=False,sort_keys=True),flush=True)


class Tests(unittest.TestCase):
    def test_direct_edge_preserves_auth_and_verifies_exact_destination(self):
        native = native_envoy.config()
        direct = direct_envoy_config()
        self.assertEqual(native['static_resources']['listeners'], direct['static_resources']['listeners'])
        edge = direct['static_resources']['listeners'][0]['filter_chains'][0]['transport_socket']['typed_config']
        self.assertTrue(edge['require_client_certificate'])
        cluster = direct['static_resources']['clusters'][0]
        socket = cluster['load_assignment']['endpoints'][0]['lb_endpoints'][0]['endpoint']['address']['socket_address']
        self.assertEqual(socket, {'address':'pilot-destination','port_value':9443})
        tls = cluster['transport_socket']['typed_config']
        self.assertEqual(tls['sni'], 'pilot-destination')
        common = tls['common_tls_context']
        self.assertEqual(common['tls_params'], {'tls_minimum_protocol_version':'TLSv1_2', 'tls_maximum_protocol_version':'TLSv1_3'})
        self.assertEqual(common['alpn_protocols'], ['http/1.1'])
        self.assertEqual(common['validation_context'], {'trusted_ca':{'filename':'/run/perf/destination-ca.pem'},
            'match_typed_subject_alt_names':[{'san_type':'DNS','matcher':{'exact':'pilot-destination'}}]})
        self.assertEqual(common['tls_certificates'], [{'certificate_chain':{'filename':'/run/perf/destination-client.pem'},
            'private_key':{'filename':'/run/perf/destination-client.key'}}])
        self.assertNotEqual(common['tls_certificates'], native['static_resources']['clusters'][0]['transport_socket']['typed_config']['common_tls_context']['tls_certificates'])

    def test_lane_switch_uses_owned_commands_and_distinct_runners(self):
        module=load_driver()
        driver=module.Driver.__new__(module.Driver)
        driver.screen=sys.modules[__name__]
        driver.overlay={'services':{'native-gateway':{}}}
        driver.set_envoy=mock.Mock()
        driver.write_overlay=mock.Mock()
        driver.compose=mock.Mock()
        driver.service_id=mock.Mock(return_value='id')
        driver.verify_container=mock.Mock()
        driver.network='private-capture'; driver.frontend='private-frontend'
        for lane, runner in [('A','native_perf_paused'),('B','native_perf_paused'),('C','native_perf_online')]:
            driver.lane(lane)
            self.assertEqual(driver.overlay['services']['native-gateway']['entrypoint'][0],'/usr/local/bin/'+runner)
            self.assertIn('--no-deps',driver.compose.call_args.args[1])
        self.assertEqual(driver.set_envoy.call_args.args[0],native_envoy.config())
        with self.assertRaises(module.pilot.Failure): driver.lane('bad')

    def test_overlay_inherits_owned_networks_and_mounts_same_client(self):
        import tempfile
        module=load_driver()
        with tempfile.TemporaryDirectory() as folder:
            driver=module.Driver.__new__(module.Driver)
            driver.folder=Path(folder); driver.markers=[b'request',b'response']
            driver.shutdown_negative=False; driver.network='owned-capture'; driver.frontend='owned-front'
            driver.project='owned-project'; driver.image='owned-image:unique'; driver.override=driver.folder/'overlay.json'
            driver.setup_overlay()
            self.assertTrue(driver.overlay['networks']['default']['internal'])
            self.assertTrue(driver.overlay['networks']['capture']['internal'])
            self.assertEqual(driver.overlay['networks']['capture']['name'],'owned-capture')
            self.assertNotIn('ports',driver.overlay['services']['postgres'])
            self.assertEqual(driver.overlay['services']['postgres']['networks'],['capture'])
            self.assertTrue(any(x.startswith('/var/lib/postgresql/data:') for x in driver.overlay['services']['postgres']['tmpfs']))
            for replica in ('replica1','replica2'):
                self.assertTrue(any(x.endswith(':/pilot/perf-client.js:ro') for x in driver.overlay['services'][replica]['volumes']))
            for service in ('native-gateway','pilot-capture-ingress','pilot-capture-worker'):
                self.assertEqual(driver.overlay['services'][service]['image'],'owned-image:unique')
            self.assertNotIn('apicontour-local_default',json.dumps(driver.overlay))

    def test_owned_cleanup_runs_parent_and_removes_only_converted_files(self):
        import tempfile
        module=load_driver()
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'owned.pem'; path.write_text('synthetic')
            driver=module.Driver.__new__(module.Driver); driver.converted=[path]; driver.verifier_intent=False
            with mock.patch.object(module.privacy.Driver,'cleanup') as cleanup:
                driver.cleanup()
            cleanup.assert_called_once_with()
            self.assertFalse(path.exists())

    def test_stalled_owned_sidecar_is_removed_before_network_teardown(self):
        import tempfile
        module=load_driver()
        with tempfile.TemporaryDirectory() as folder:
            key=Path(folder)/'converted.key'; key.write_text('synthetic')
            driver=module.Driver.__new__(module.Driver)
            driver.converted=[key]; driver.verifier='owned-verifier'; driver.verifier_intent=True
            driver.base=mock.Mock(env={}); state={'sidecar':True}; events=[]
            def names():
                events.append('inspect')
                return ['unrelated-verifier']+(['owned-verifier'] if state['sidecar'] else [])
            def remove(args, env, **kwargs):
                self.assertEqual(args,['docker','rm','-f','owned-verifier'])
                events.append('remove'); state['sidecar']=False
            def parent(instance):
                self.assertIs(instance,driver)
                self.assertFalse(state['sidecar'], 'network namespace is still held')
                self.assertFalse(instance.verifier_intent)
                events.append('project teardown')
            driver.verifier_names=names
            with mock.patch.object(module.privacy,'bounded',side_effect=remove), \
                 mock.patch.object(module.privacy.Driver,'cleanup',autospec=True,side_effect=parent):
                driver.cleanup()
            self.assertEqual(events,['inspect','remove','inspect','project teardown'])
            self.assertFalse(key.exists())

    def test_sidecar_parent_and_key_cleanup_failures_are_all_retained(self):
        module=load_driver()
        driver=module.Driver.__new__(module.Driver); driver.verifier='owned-verifier'; driver.verifier_intent=True
        driver.base=mock.Mock(env={}); driver.verifier_names=mock.Mock(return_value=['owned-verifier'])
        key=mock.Mock(); key.unlink.side_effect=RuntimeError('converted key cleanup failed'); driver.converted=[key]
        with mock.patch.object(module.privacy,'bounded',side_effect=RuntimeError('sidecar removal failed')), \
             mock.patch.object(module.privacy.Driver,'cleanup',side_effect=RuntimeError('parent teardown failed')) as parent:
            with self.assertRaises(BaseExceptionGroup) as caught: driver.cleanup()
        self.assertEqual([str(e) for e in caught.exception.exceptions],
                         ['sidecar removal failed','parent teardown failed','converted key cleanup failed'])
        parent.assert_called_once(); key.unlink.assert_called_once_with(missing_ok=True)
        self.assertTrue(driver.verifier_intent)

    def test_tls_negative_requires_fresh_typed_evidence(self):
        module=load_driver()
        san=module.COUNTERS['name']; ca=module.COUNTERS['ca']
        baseline={san:0,ca:0}
        unavailable={'success_ms':[],'errors':1,'timeouts':0}
        with self.assertRaisesRegex(module.pilot.Failure,'no typed TLS verification rejection'):
            module.require_tls_rejection('name',unavailable,baseline,dict(baseline))
        with self.assertRaisesRegex(module.pilot.Failure,'missing TLS'):
            module.require_tls_rejection('name',unavailable,{}, {san:1})
        module.require_tls_rejection('name',unavailable,baseline,{san:1,ca:0})
        module.require_tls_rejection('ca',unavailable,baseline,{san:0,ca:1})
        with self.assertRaises(module.pilot.Failure):
            module.require_tls_rejection('name',{'success_ms':[1],'errors':0,'timeouts':0},baseline,{san:1,ca:0})

    def test_unavailable_control_is_bracketed_and_cannot_count_as_tls_rejection(self):
        module=load_driver()
        driver=module.Driver.__new__(module.Driver); driver.screen=sys.modules[__name__]
        driver.lane=mock.Mock(); driver.ready=mock.Mock(); driver.edge_ready=mock.Mock()
        driver.service_id=mock.Mock(return_value='same-container')
        san=module.COUNTERS['name']; ca=module.COUNTERS['ca']
        zero={san:0,ca:0}
        driver.tls_counters=mock.Mock(side_effect=[zero,{san:1,ca:0},zero,{san:0,ca:1},zero,zero])
        driver.sample=mock.Mock(return_value={'success_ms':[],'errors':1,'timeouts':0})
        driver.negative_direct()
        self.assertEqual(driver.ready.call_count,6)
        self.assertEqual(driver.edge_ready.call_count,3)
        self.assertEqual(driver.sample.call_count,3)
        for call in driver.tls_counters.call_args_list:
            self.assertEqual(call.args,('same-container',))
        driver.tls_counters.side_effect=[zero,{san:1,ca:0},zero,{san:0,ca:1},zero,{san:1,ca:0}]
        with self.assertRaisesRegex(module.pilot.Failure,'unavailable control changed TLS counters'):
            driver.negative_direct()

    def test_matched_counts_do_not_claim_authority_and_missing_hwm_is_not_peak(self):
        def b(): return {'attempted':1,'success_ms':[1],'errors':0,'timeouts':0,'elapsed_ms':1}
        data={'blocks':[{'A':b(),'B':b(),'C':b()},{'A':b(),'B':b(),'C':b()}],
              'capture':{'successful_C_requests':2,'persisted_request_observations':2,'persisted_response_observations':2,'drain_seconds':5},
              'gateway_pid1_vmhwm_kib_by_block':[100,None]}
        result=report(data)
        self.assertIn('per-request coverage or continuous authority',result['capture_interpretation'])
        self.assertEqual(result['gateway_pid1_process_lifetime_vmhwm_kib_by_block'],[100,None])
        self.assertIsNone(result['gateway_pid1_process_lifetime_vmhwm_kib_overall'])
        self.assertFalse(result['gateway_pid1_process_lifetime_vmhwm_complete'])
        limits=' '.join(result['limitations'])
        for term in ('Fixed A→B→C', 'p99 is the maximum', 'Concurrency one', 'not saturated capacity', 'coordinated delay', 'warmup'):
            self.assertIn(term,limits)

    def test_metric_snapshots_are_fresh_numeric_and_monotonic(self):
        module=load_driver()
        def metric(sequence, **changes):
            v={'sequence':sequence,'losses':0,'ack':0,'deferred':0,'error':0,'empty':0,
               'slots':4,'records_per_slot':128,'bytes_per_slot':262144}
            v.update(changes); return v
        def line(value): return module.METRIC_PREFIX+json.dumps(value).encode()+b'\n'
        first=metric(1,losses=2); second=metric(2,losses=3,ack=4)
        previous=module.metric_entries(line(first))
        current=module.metric_entries(line(first)+line(second))
        self.assertEqual(module.fresh_snapshot(previous,current),second)
        self.assertIsNone(module.fresh_snapshot(previous,previous))
        self.assertEqual(module.counter_delta(first,second),{'losses':1,'ack':4,'deferred':0,'error':0,'empty':0})
        for raw in (line(metric(2)),line(first)+line(metric(1)),line(first)+line(metric(2,losses=1)),
                    line(metric(1,slots=True)),line(metric(1,records_per_slot=0)),
                    module.METRIC_PREFIX+b'{broken}\n',module.METRIC_PREFIX+b'{\"sequence\":1,\"sequence\":1}\n',line(metric(1,extra=1)),
                    line(first)+line(metric(2,slots=3))):
            with self.assertRaises(module.pilot.Failure): module.metric_entries(raw)
        with self.assertRaises(module.pilot.Failure): module.fresh_snapshot(current,previous)
        with self.assertRaises(module.pilot.Failure): module.counter_delta(second,first)
        maximum=2**64-1
        with self.assertRaisesRegex(module.pilot.Failure,'saturated'):
            module.counter_delta(metric(1,losses=maximum),metric(2,losses=maximum))
        with self.assertRaisesRegex(module.pilot.Failure,'saturated'):
            module.counter_delta(metric(1,ack=maximum-1),metric(2,ack=maximum))

    def test_snapshot_deadline_and_container_replacement_never_produce_zero(self):
        module=load_driver(); driver=module.Driver.__new__(module.Driver)
        driver.base=mock.Mock(env={}); driver.service_id=mock.Mock(return_value='owned')
        with mock.patch.object(module.privacy,'bounded',return_value=b''), \
             mock.patch.object(module.time,'monotonic',side_effect=[0,1,1,6]), \
             mock.patch.object(module.time,'sleep'):
            with self.assertRaisesRegex(module.pilot.Failure,'deadline'):
                driver.metrics_snapshot('owned',timeout=5)
        driver.service_id=mock.Mock(side_effect=['owned','replacement'])
        with mock.patch.object(module.privacy,'bounded',return_value=b''):
            with self.assertRaisesRegex(module.pilot.Failure,'container changed'):
                driver.metrics_snapshot('owned')

    def test_snapshot_uses_exact_owned_container_and_requires_fresh_line(self):
        module=load_driver(); driver=module.Driver.__new__(module.Driver)
        driver.base=mock.Mock(env={}); driver.service_id=mock.Mock(return_value='owned')
        value={'sequence':1,'losses':0,'ack':1,'deferred':0,'error':0,'empty':0,
               'slots':4,'records_per_slot':128,'bytes_per_slot':262144}
        line=module.METRIC_PREFIX+json.dumps(value).encode()+b'\n'
        def bounded(args, env, **kwargs):
            if args[:2]==['docker','kill']:
                self.assertEqual(args,['docker','kill','--signal','USR1','owned']); return b''
            self.assertEqual(args,['docker','logs','owned'])
            bounded.calls+=1
            return b'' if bounded.calls==1 else line
        bounded.calls=0
        with mock.patch.object(module.privacy,'bounded',side_effect=bounded):
            self.assertEqual(driver.metrics_snapshot('owned'),value)

    def test_cohort_query_returns_scoped_numeric_counts_only(self):
        module=load_driver(); driver=module.Driver.__new__(module.Driver)
        driver.sql=mock.Mock(return_value=b'101|6|2|99\n')
        self.assertEqual(driver.cohort(),{'ingested_records':101,'processed_batches':6,'pending_batches':2,'projected_windows':99})
        query=driver.sql.call_args.args[0]
        for table in ('contour.ingestion_batches','contour.catalog_processed_batches','contour.observation_windows'):
            self.assertIn(table,query)
        self.assertIn('record_count',query); self.assertIn(module.pilot.SOURCE,query)
        driver.sql.return_value=b'1|2|bad|4'
        with self.assertRaises(ValueError): driver.cohort()

    def test_quantile_and_error_denominator(self):
        r = block_summary({'attempted':102,'success_ms':list(range(100)),'errors':1,'timeouts':1,'elapsed_ms':1000})
        self.assertEqual(r['p99_ms'],98)
        self.assertEqual(r['error_fraction'],2/102)
        self.assertEqual(r['throughput_success_per_second'],100)
    def test_paired_baseline_and_missing_samples(self):
        def b(ms): return {'attempted':1,'success_ms':[ms],'errors':0,'timeouts':0,'elapsed_ms':ms}
        data={'blocks':[{'A':b(1),'B':b(2),'C':b(4)}], 'capture':{'successful_C_requests':1,'persisted_request_observations':0,'persisted_response_observations':0,'drain_seconds':5},'gateway_pid1_vmhwm_kib_by_block':[None]}
        r=report(data); row=r['blocks'][0]
        self.assertEqual(r['classification'],'SCREEN_ONLY')
        self.assertEqual(row['A_to_C_p99_difference_ms'],3)
        self.assertEqual(row['A_to_C_throughput_loss_fraction'],.75)
        self.assertEqual(r['capture']['request_difference_from_successful_requests'],-1)
        self.assertEqual(r['capture']['request_count_ratio_to_successful_requests'],0)
        data['blocks'][0]['C']['attempted']=2
        with self.assertRaises(ValueError): report(data)
    def test_invalid_nan_and_inconsistent_counts(self):
        for b in ({'attempted':1,'success_ms':[float('nan')],'errors':0,'timeouts':0,'elapsed_ms':1},
                  {'attempted':1,'success_ms':[],'errors':0,'timeouts':0,'elapsed_ms':1}):
            with self.assertRaises(ValueError): block_summary(b)

if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]])
    elif sys.argv[1:] == ['--report']:
        try:
            print(json.dumps(report(json.load(sys.stdin)), allow_nan=False, sort_keys=True))
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            sys.exit('invalid sanitized screen input')
    elif not sys.argv[1:]:
        try: run_screen()
        except BaseException as exc:
            print('native performance screen failed: '+str(exc) if isinstance(exc, RuntimeError) and str(exc).startswith('missing synthetic') else 'native performance screen failed; no results emitted', file=sys.stderr)
            sys.exit(1)
    else:
        sys.exit('unsupported argument')
