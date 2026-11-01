"""Owned local screen orchestration. Invoked only by the operator."""
import base64
import datetime
import importlib.util
import json
import os
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('native_privacy', ROOT/'scripts/test-native-privacy.py')
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)
pilot = privacy.pilot


COUNTERS={'name':'cluster.upstream.ssl.fail_verify_san',
          'ca':'cluster.upstream.ssl.fail_verify_error'}

def require_tls_rejection(kind, outcome, before, after):
    if kind not in COUNTERS or set(before)!=set(COUNTERS.values()) or set(after)!=set(COUNTERS.values()):
        raise pilot.Failure('missing TLS verification counters')
    if any(type(v) is not int or v<0 for v in (*before.values(),*after.values())):
        raise pilot.Failure('invalid TLS verification counters')
    if outcome['success_ms'] or outcome['errors']+outcome['timeouts'] != 1:
        raise pilot.Failure('TLS negative did not fail closed')
    if any(after[key]<before[key] for key in before) or after[COUNTERS[kind]]<=before[COUNTERS[kind]]:
        raise pilot.Failure('no typed TLS verification rejection')


METRIC_PREFIX=b'NATIVE_PERF_METRICS '
COUNTER_FIELDS=('losses','ack','deferred','error','empty')
QUEUE_FIELDS=('slots','records_per_slot','bytes_per_slot')
METRIC_FIELDS=('sequence',)+COUNTER_FIELDS+QUEUE_FIELDS
def unique_object(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise ValueError('duplicate field')
        value[key]=item
    return value

def metric_entries(raw):
    entries=[]
    for line in raw.splitlines():
        if not line.startswith(METRIC_PREFIX): continue
        try: value=json.loads(line[len(METRIC_PREFIX):],object_pairs_hook=unique_object)
        except (ValueError,UnicodeError): raise pilot.Failure('invalid metrics snapshot') from None
        if not isinstance(value,dict) or set(value)!=set(METRIC_FIELDS) or any(
            type(value[k]) is not int or not 0<=value[k]<=2**64-1 for k in METRIC_FIELDS):
            raise pilot.Failure('invalid metrics snapshot')
        if value['sequence'] != len(entries)+1:
            raise pilot.Failure('metrics sequence replay or gap')
        if not (1<=value['slots']<=8 and 1<=value['records_per_slot']<=500 and 1<=value['bytes_per_slot']<=268435456):
            raise pilot.Failure('invalid queue configuration snapshot')
        if entries and (any(value[k]<entries[-1][k] for k in COUNTER_FIELDS) or
                        any(value[k]!=entries[-1][k] for k in QUEUE_FIELDS)):
            raise pilot.Failure('metrics counter decreased')
        entries.append(value)
    return entries

def fresh_snapshot(previous, current):
    if len(current)<len(previous) or current[:len(previous)]!=previous:
        raise pilot.Failure('metrics log changed or replayed')
    if len(current)==len(previous): return None
    if len(current)!=len(previous)+1: raise pilot.Failure('unexpected metrics snapshot count')
    return current[-1]

def counter_delta(before,after):
    if any(before[k]==2**64-1 or after[k]==2**64-1 for k in COUNTER_FIELDS):
        raise pilot.Failure('metrics counter saturated; delta unknown')
    if (after['sequence']!=before['sequence']+1 or any(after[k]<before[k] for k in COUNTER_FIELDS) or
        any(after[k]!=before[k] for k in QUEUE_FIELDS)):
        raise pilot.Failure('metrics snapshots not consecutive or counters decreased')
    return {key:after[key]-before[key] for key in COUNTER_FIELDS}



class Driver(privacy.Driver):
    def __init__(self, screen):
        super().__init__()
        self.screen = screen
        self.expiry = None
        self.converted = []
        original = self.base.run
        def build(name, args, seconds):
            if name == 'privacy-image-build':
                args = list(args)
                args[args.index('-f')+1] = str(ROOT/'tests/fixtures/native-perf/Dockerfile')
            return original(name,args,seconds)
        self.base.run = build

    def policy(self):
        envelope = super().policy()
        payload = json.loads(envelope)['payload_base64url']
        value = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload)%4)))
        self.expiry = datetime.datetime.fromisoformat(value['expires_at'].replace('Z','+00:00'))
        return envelope

    def setup_overlay(self):
        super().setup_overlay()
        overlay = json.loads(self.override.read_text())
        for replica in ('replica1','replica2'):
            overlay['services'][replica]['volumes'].extend([str(ROOT/'tests/fixtures/native-perf/client.js')+':/pilot/perf-client.js:ro',
                str(ROOT/'tests/fixtures/native-perf/edge-ready.js')+':/pilot/perf-edge-ready.js:ro'])
        overlay['services']['native-envoy'].setdefault('volumes', []).extend([
            str(self.folder/'envoy.json')+':/run/forwarder/envoy.json:ro',
            str(self.folder/'destination-ca.pem')+':/run/perf/destination-ca.pem:ro',
            str(self.folder/'destination-client.pem')+':/run/perf/destination-client.pem:ro',
            str(self.folder/'destination-client.key')+':/run/perf/destination-client.key:ro'])
        self.overlay = overlay

    def write_overlay(self):
        self.override.write_text(json.dumps(self.overlay))

    def prepare_credentials(self):
        # Convert exactly the configured gateway upstream DER identity and trust;
        # the worker never reads key contents or emits command output.
        source = ROOT/'.local-mvp/pilot/native/gateway'
        gateway=json.loads((source/'gateway.json').read_text())
        expected={'upstream_address':'pilot-destination:9443','upstream_name':'pilot-destination',
                  'upstream_ca_der':'/run/native/upstream-ca.der',
                  'upstream_client_certificate_der':'/run/native/upstream-client.der',
                  'upstream_client_key_der':'/run/native/upstream-client-key.der'}
        if any(gateway.get(key)!=value for key,value in expected.items()):
            raise pilot.Failure('gateway upstream configuration drift')
        original=json.loads((ROOT/'.local-mvp/pilot/native/forwarder/envoy.json').read_text())
        if original != self.screen.native_envoy.config(): raise pilot.Failure('edge configuration drift')
        for inp, out, command in (
            ('upstream-ca.der','destination-ca.pem',['x509','-inform','DER']),
            ('upstream-client.der','destination-client.pem',['x509','-inform','DER']),
            ('upstream-client-key.der','destination-client.key',['pkey','-inform','DER'])):
            target=self.folder/out
            self.converted.append(target)
            privacy.bounded(['openssl',*command,'-in',str(source/inp),'-out',str(target)],self.base.env)
            os.chmod(target,0o600)
        self.converted.append(self.folder/'envoy.json')
        self.set_envoy(self.screen.direct_envoy_config())
        self.write_overlay()

    def set_envoy(self, config):
        # Atomic replacement is visible after the container is recreated.
        (self.folder/'envoy.json').write_text(json.dumps(config,separators=(',',':')))
        os.chmod(self.folder/'envoy.json',0o600)

    def lane(self, lane, *, direct_override=None):
        if lane not in ('A','B','C'): raise pilot.Failure('invalid screen lane')
        config = direct_override if direct_override is not None else (
            self.screen.direct_envoy_config() if lane == 'A' else self.screen.native_envoy.config())
        self.set_envoy(config)
        self.overlay['services']['native-gateway']['entrypoint'] = [
            '/usr/local/bin/native_perf_paused' if lane in ('A','B') else '/usr/local/bin/native_perf_online',
            '/run/native/gateway.json']
        self.write_overlay()
        self.compose('screen-gateway-'+lane,['up','-d','--pull','never','--no-deps','--force-recreate','native-gateway'],90)
        self.compose('screen-edge-'+lane,['up','-d','--pull','never','--no-deps','--force-recreate','native-envoy'],90)
        self.verify_container('native-gateway',self.service_id('native-gateway'),{self.network,self.frontend})
        self.verify_container('native-envoy',self.service_id('native-envoy'),{self.frontend})

    def sample(self, n):
        raw = self.compose('screen-sample',['exec','-T','replica1','node','/pilot/perf-client.js',str(n)],max(30,n*5))
        value=json.loads(raw)
        self.screen.block_summary(value)
        return value

    def ready(self):
        deadline=time.monotonic()+35
        while True:
            sample=self.sample(1)
            if len(sample['success_ms'])==1: return
            if time.monotonic()>=deadline: raise pilot.Failure('screen lane unavailable')
            time.sleep(.5)

    def edge_ready(self):
        deadline=time.monotonic()+20
        while True:
            raw=self.compose('screen-edge-probe',['exec','-T','replica1','node','/pilot/perf-edge-ready.js'],10)
            if raw.strip()==b'ready': return
            if time.monotonic()>=deadline: raise pilot.Failure('edge handshake unavailable')
            time.sleep(.5)

    def tls_counters(self, container):
        if self.service_id('native-envoy') != container:
            raise pilot.Failure('edge container changed during TLS control')
        raw=privacy.bounded(['docker','run','--pull','never','--rm','--name',self.verifier,
            '--network','container:'+container,'--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--user',str(os.getuid())+':'+str(os.getgid()),
            '--volume',str(ROOT/'tests/fixtures/native-perf/admin-stats.js')+':/fixture/stats.js:ro',
            '--entrypoint','node',pilot.IMAGES[0],'/fixture/stats.js'],self.base.env,seconds=15)
        counters=json.loads(raw)
        if self.service_id('native-envoy') != container:
            raise pilot.Failure('edge container changed during TLS control')
        if not isinstance(counters,dict): raise pilot.Failure('invalid TLS verification counters')
        return counters

    def negative_direct(self):
        for kind in ('name','ca','unavailable'):
            # A fresh successful forwarding check brackets every mutation.
            self.lane('A'); self.ready()
            cfg=self.screen.direct_envoy_config()
            cluster=cfg['static_resources']['clusters'][0]
            tls=cluster['transport_socket']['typed_config']
            if kind=='name':
                tls['sni']='wrong-name.invalid'
                tls['common_tls_context']['validation_context']['match_typed_subject_alt_names'][0]['matcher']['exact']='wrong-name.invalid'
            elif kind=='ca':
                tls['common_tls_context']['validation_context']['trusted_ca']['filename']='/run/perf/destination-client.pem'
            else:
                address=cluster['load_assignment']['endpoints'][0]['lb_endpoints'][0]['endpoint']['address']['socket_address']
                address.update(address='127.0.0.1',port_value=1)
            self.lane('A',direct_override=cfg)
            self.edge_ready()
            container=self.service_id('native-envoy')
            before=self.tls_counters(container)
            outcome=self.sample(1)
            after=self.tls_counters(container)
            if kind=='unavailable':
                # A transport error with no TLS verification event must be rejected.
                if outcome['success_ms'] or outcome['errors']+outcome['timeouts'] != 1:
                    raise pilot.Failure('unavailable control did not fail closed')
                if after != before: raise pilot.Failure('unavailable control changed TLS counters')
                try: require_tls_rejection('name',outcome,before,after)
                except pilot.Failure as exc:
                    if str(exc) != 'no typed TLS verification rejection': raise
                else: raise pilot.Failure('unavailable control falsely accepted as TLS rejection')
            else:
                require_tls_rejection(kind,outcome,before,after)
            self.lane('A'); self.ready()

    def counts(self):
        request=pilot.operation_key('request'); response=pilot.operation_key('response')
        common="w.visibility='structure' AND w.completeness='complete' AND NOT w.route_uncertain AND v.parser_profile='http_json_v1'"
        req="("+common+" AND o.canonical_key=convert_to('"+request+"','UTF8') AND w.status_code IS NULL AND convert_from(v.structure_wire,'UTF8')::jsonb='"+privacy.REQUEST_SHAPE+"'::jsonb)"
        resp="("+common+" AND o.canonical_key=convert_to('"+response+"','UTF8') AND w.status_code=200 AND convert_from(v.structure_wire,'UTF8')::jsonb='"+pilot.RESPONSE+"'::jsonb)"
        query=("SELECT coalesce(sum(w.observation_count) FILTER (WHERE "+req+"),0),"
               "coalesce(sum(w.observation_count) FILTER (WHERE "+resp+"),0),"
               "count(*) FILTER (WHERE NOT COALESCE(("+req+" OR "+resp+"),false)) "
               "FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id) "
               "JOIN contour.operations o ON o.tenant_id=w.tenant_id AND o.operation_id=w.operation_id WHERE "+pilot.SCOPE+
               " AND w.source_id='"+pilot.SOURCE+"' AND w.project_id='"+pilot.PROJECT+"' AND w.service_id='"+pilot.SERVICE+
               "' AND w.environment_id='"+pilot.ENVIRONMENT+"' AND w.deployment_id='"+pilot.DEPLOYMENT+"';")
        values=tuple(map(int,self.sql(query).strip().split(b'|')))
        if len(values)!=3 or values[2]: raise pilot.Failure('unexpected capture projection')
        return values[:2]

    def cohort(self):
        # Unique collector/database: all ingestion batches belong to this owned run.
        batch_scope="b.tenant_id='"+pilot.TENANT+"' AND b.collector_id='00000000-0000-4000-8000-000000000301'"
        window_scope=(pilot.SCOPE+" AND w.source_id='"+pilot.SOURCE+"' AND w.project_id='"+pilot.PROJECT+
            "' AND w.service_id='"+pilot.SERVICE+"' AND w.environment_id='"+pilot.ENVIRONMENT+
            "' AND w.deployment_id='"+pilot.DEPLOYMENT+"'")
        query=("SELECT coalesce(sum(b.record_count),0), count(*) FILTER (WHERE p.batch_id IS NOT NULL), "
               "count(*) FILTER (WHERE p.batch_id IS NULL), (SELECT count(*) FROM contour.observation_windows w WHERE "+window_scope+
               ") FROM contour.ingestion_batches b LEFT JOIN contour.catalog_processed_batches p USING(tenant_id,collector_id,batch_id) WHERE "+batch_scope+";")
        values=tuple(map(int,self.sql(query).strip().split(b'|')))
        if len(values)!=4 or any(v<0 for v in values): raise pilot.Failure('invalid cohort counts')
        return dict(zip(('ingested_records','processed_batches','pending_batches','projected_windows'),values))

    def metrics_snapshot(self, container, *, timeout=5):
        if self.service_id('native-gateway')!=container: raise pilot.Failure('gateway container changed')
        previous=metric_entries(privacy.bounded(['docker','logs',container],self.base.env,seconds=2))
        privacy.bounded(['docker','kill','--signal','USR1',container],self.base.env,seconds=5)
        deadline=time.monotonic()+timeout
        while True:
            if self.service_id('native-gateway')!=container: raise pilot.Failure('gateway container changed')
            remaining=deadline-time.monotonic()
            if remaining<=0: raise pilot.Failure('metrics snapshot deadline')
            current=metric_entries(privacy.bounded(['docker','logs',container],self.base.env,seconds=min(2,remaining)))
            result=fresh_snapshot(previous,current)
            if result is not None: return result
            time.sleep(min(.1,max(0,deadline-time.monotonic())))

    def drain(self, before, expected, seconds=20):
        deadline=time.monotonic()+seconds
        last=None; stable_since=time.monotonic()
        while True:
            now=self.counts()
            if now != last:
                last=now; stable_since=time.monotonic()
            delta=tuple(a-b for a,b in zip(now,before))
            if any(x < 0 for x in delta): raise pilot.Failure('capture counts decreased')
            if (all(x>=expected for x in delta) and time.monotonic()-stable_since>=2) or time.monotonic()>=deadline: return delta
            time.sleep(.5)

    def lease_room(self, seconds):
        if self.expiry is None or datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=seconds)>=self.expiry:
            raise pilot.Failure('screen policy lease too short')

    def hwm(self):
        raw=self.compose('screen-hwm',['exec','-T','native-gateway','awk','$1 == "VmHWM:" {print $2}','/proc/1/status'],15).strip()
        return int(raw) if raw.isdigit() and int(raw)>0 else None

    def run(self):
        self.setup_overlay()
        self.prepare_credentials()
        self.prepare_database()
        privacy.bounded(['docker','run','--pull','never','--rm','--name',self.verifier,
            '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--entrypoint','/bin/sh',self.image,'-c',
            'test -x /usr/local/bin/native_perf_paused && test -x /usr/local/bin/native_perf_online'],self.base.env,seconds=30)
        self.compose('screen-start',['up','-d','--pull','never','--no-recreate',*privacy.SERVICES],90)
        self.started_services()
        self.lane('A'); self.ready(); self.negative_direct()
        blocks=[]; capture=[0,0]; capture_by_block=[]; hwm=[]; diagnostics=[]
        for _ in range(3):
            block={}
            for lane in ('A','B','C'):
                lane_started=time.monotonic()
                self.lane(lane)
                if lane=='C':
                    self.lease_room(90)
                    before=self.counts()
                self.ready()
                if lane=='C':
                    # Wait for readiness observations before the measured count baseline.
                    if min(self.drain(before,1)) < 1:
                        raise pilot.Failure('C authority readiness not persisted')
                    before=self.counts()
                    gateway_container=self.service_id('native-gateway')
                    metrics_before=self.metrics_snapshot(gateway_container)
                    cohort_before=self.cohort()
                started=time.monotonic()
                block[lane]=self.sample(50)
                if lane=='C':
                    if time.monotonic()-lane_started>=120 or time.monotonic()-started>=60:
                        raise pilot.Failure('C block exceeded lease budget')
                    self.lease_room(20)
                    delta=self.drain(before,len(block[lane]['success_ms']))
                    capture=[a+b for a,b in zip(capture,delta)]
                    capture_by_block.append({'successful_C_requests':len(block[lane]['success_ms']),
                        'persisted_request_observations':delta[0],'persisted_response_observations':delta[1]})
                    hwm.append(self.hwm())
                    metrics_after=self.metrics_snapshot(gateway_container)
                    diagnostics.append({'metrics_before':metrics_before,'metrics_after':metrics_after,
                        'metrics_delta':counter_delta(metrics_before,metrics_after),
                        'cohort_before':cohort_before,'cohort_after':self.cohort()})
            blocks.append(block)
        ctotal=sum(len(b['C']['success_ms']) for b in blocks)
        result=self.screen.report({'blocks':blocks,'capture':{'successful_C_requests':ctotal,
            'persisted_request_observations':capture[0],'persisted_response_observations':capture[1],
            'drain_seconds':20},'gateway_pid1_vmhwm_kib_by_block':hwm})
        result['capture_by_block'] = capture_by_block
        result['diagnostics_by_block'] = diagnostics
        result['gateway_queue_config_by_block'] = [{key:entry['metrics_before'][key] for key in QUEUE_FIELDS} for entry in diagnostics]
        result['capture_interpretation'] = ('Matching aggregate scoped counts; per-request coverage and continuous authority unverified. Readiness and failed-attempt observations may cross windows.'
            if all(row['persisted_request_observations']==row['successful_C_requests'] and
                   row['persisted_response_observations']==row['successful_C_requests'] for row in capture_by_block)
            else 'Aggregate scoped counts differ; per-request coverage and continuous authority unverified. Readiness and failed-attempt observations may cross windows.')
        self.result=result

    def cleanup(self):
        failures=[]
        # A timed-out docker CLI may leave this exact owned sidecar alive in
        # Envoy's network namespace. Remove it before project/network teardown.
        if self.verifier_intent:
            try:
                if self.verifier in self.verifier_names():
                    privacy.bounded(['docker','rm','-f',self.verifier],self.base.env,seconds=30)
                # Verify removal, including the lost-acknowledgement case.
                if self.verifier in self.verifier_names():
                    raise pilot.Failure('screen verifier cleanup incomplete')
                self.verifier_intent=False
            except BaseException as exc:
                # Parent cleanup still runs and retains its own retry path.
                failures.append(exc)
        try: super().cleanup()
        except BaseException as exc: failures.append(exc)
        for path in self.converted:
            try: path.unlink(missing_ok=True)
            except BaseException as exc: failures.append(exc)
        if failures: raise BaseExceptionGroup('screen cleanup failed',failures)
