#!/usr/bin/env python3
"""Owned synthetic sink qualification; does not inspect Native volatile memory."""
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('native_pilot', ROOT/'scripts/test-native-pilot.py')
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)
MAX = 1024 * 1024
MAX_BATCHES = 256
SERVICES = ('replica1', 'replica2', 'destination', 'native-envoy', 'native-gateway', 'pilot-capture-ingress', 'pilot-capture-worker')
REQUEST_SHAPE = '{"kind":"object","fields":{"probe":{"kind":"string"}},"additional":null}'


class MarkerFound(pilot.Failure):
    pass


def scan(data, markers):
    if len(data) > MAX:
        raise pilot.Failure('privacy evidence limit')
    if any(not marker or marker in data for marker in markers):
        raise MarkerFound('privacy marker observed')


def bounded(args, env, *, input_bytes=None, seconds=30):
    """Keep evidence in memory, cap bytes and absolute time, kill owned group."""
    proc = subprocess.Popen(args, cwd=ROOT, env=env, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    selector = selectors.DefaultSelector()
    deadline = time.monotonic()+seconds
    output = bytearray()
    try:
        if input_bytes is not None:
            if len(input_bytes) > 65536: raise pilot.Failure('privacy query limit')
            os.set_blocking(proc.stdin.fileno(), False)
            selector.register(proc.stdin, selectors.EVENT_WRITE, 'stdin')
        selector.register(proc.stdout, selectors.EVENT_READ, 'stdout')
        written = 0
        while selector.get_map():
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise pilot.Failure('privacy evidence deadline')
            for key, _ in selector.select(min(remaining, .2)):
                if key.data == 'stdin':
                    if written == len(input_bytes):
                        selector.unregister(proc.stdin); proc.stdin.close(); continue
                    count = os.write(proc.stdin.fileno(), input_bytes[written:written+4096])
                    written += count
                    continue
                data = os.read(key.fileobj.fileno(), min(65536, MAX+1-len(output)))
                if not data: selector.unregister(key.fileobj); continue
                output.extend(data)
                if len(output) > MAX: raise pilot.Failure('privacy evidence limit')
        remaining = deadline-time.monotonic()
        if remaining <= 0 or proc.wait(timeout=remaining): raise pilot.Failure('privacy evidence command failed')
        return bytes(output)
    finally:
        selector.close()
        if proc.poll() is None: pilot.kill_group(proc.pid); proc.wait(timeout=5)
        proc.stdout.close()
        if proc.stdin is not None and not proc.stdin.closed: proc.stdin.close()


def id_list(raw):
    lines = raw.decode('ascii').splitlines()
    if len(lines) > MAX_BATCHES: raise pilot.Failure('privacy batch limit')
    if len(set(lines)) != len(lines): raise pilot.Failure('duplicate privacy batch id')
    for item in lines:
        if str(uuid.UUID(item)) != item: raise pilot.Failure('invalid privacy batch id')
    return set(lines)


def decode_projection(raw, expected):
    """All selected rows and each bytea value are hex, never printed or saved."""
    seen = set()
    blobs = []
    for line in raw.splitlines():
        fields = line.split(b'|')
        if len(fields) < 3: raise pilot.Failure('invalid privacy projection')
        kind = fields[0].decode('ascii'); batch = fields[1].decode('ascii')
        if kind not in ('batch', 'payload', 'window') or batch not in expected: raise pilot.Failure('unscoped privacy projection')
        try: blobs.extend(bytes.fromhex(value.decode('ascii')) for value in fields[2:])
        except (ValueError, UnicodeError): raise pilot.Failure('invalid privacy projection encoding') from None
        seen.add((kind,batch))
    if any((kind,batch) not in seen for batch in expected for kind in ('batch','payload','window')):
        raise pilot.Failure('missing privacy projection')
    return blobs


def prepare_flow(source, marker):
    flow=json.loads(source)
    found=0
    for node in flow:
        if node.get('id') == 'pilot-fixed':
            rules=[rule for rule in node['rules'] if rule.get('p') == 'payload' and rule.get('t') == 'set']
            if len(rules)!=1: raise pilot.Failure('unexpected pilot flow')
            rules[0]['to']=json.dumps({'probe':marker},separators=(',',':'))
            found += 1
    if found != 1: raise pilot.Failure('unexpected pilot flow')
    return json.dumps(flow,separators=(',',':')).encode()


class Driver:
    def __init__(self, *, shutdown_negative=False):
        self.shutdown_negative = shutdown_negative
        self.base = pilot.Driver()
        self.folder = self.base.folder
        self.markers = [('SYNTHETIC_REQUEST_'+uuid.uuid4().hex).encode(), ('SYNTHETIC_RESPONSE_'+uuid.uuid4().hex).encode()]
        self.override = self.folder/'privacy-overlay.json'
        self.containers = {}

    def setup_overlay(self):
        p=self.folder
        pilot.private_write(p/'privacy.json',json.dumps({'request':self.markers[0].decode(), 'response':self.markers[1].decode()}).encode())
        pilot.private_write(p/'flows.json',prepare_flow((ROOT/'deploy/pilot/flows.json').read_text(),self.markers[0].decode()))
        fixture=ROOT/'tests/fixtures/native-privacy'
        mounts = lambda name: [str(p/'flows.json')+':/pilot/flows.json:ro',str(p/'privacy.json')+':/pilot/privacy.json:ro',str(fixture/'probe.js')+':/pilot/privacy-probe.js:ro']
        override={'services':{'replica1':{'volumes':mounts('replica1')},'replica2':{'volumes':mounts('replica2')},
            'destination':{'volumes':[str(fixture/'destination.js')+':/pilot/destination.js:ro',str(p/'privacy.json')+':/pilot/privacy.json:ro']}}}
        if self.shutdown_negative:
            override['services']['destination']['environment']={'PRIVACY_TEST_SHUTDOWN_MARKER':'1'}
        pilot.private_write(self.override,json.dumps(override).encode())

    def compose(self, name, args, seconds=90):
        return self.base.compose(name,args,seconds,extra_config=self.override)

    def sql(self, query):
        if any(marker.decode() in query for marker in self.markers): raise pilot.Failure('marker in privacy query')
        return bounded(self.base.base.COMPOSE+['exec','-T','-u','postgres','postgres','psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_local'],
                       self.base.env,input_bytes=query.encode(),seconds=30)

    def existing_batches(self):
        return id_list(self.sql("SELECT batch_id::text FROM contour.ingestion_batches WHERE tenant_id='"+pilot.TENANT+"' AND collector_id='00000000-0000-4000-8000-000000000301' ORDER BY 1 LIMIT "+str(MAX_BATCHES+1)+";"))

    def ids(self):
        return id_list(self.sql("SELECT DISTINCT w.batch_id::text FROM contour.observation_windows w JOIN contour.operations o ON o.tenant_id=w.tenant_id AND o.operation_id=w.operation_id WHERE "+pilot.SCOPE+
            " AND w.source_id='"+pilot.SOURCE+"' AND w.project_id='"+pilot.PROJECT+"' AND w.service_id='"+pilot.SERVICE+"' AND w.environment_id='"+pilot.ENVIRONMENT+"' AND w.deployment_id='"+pilot.DEPLOYMENT+"' AND o.canonical_key IN (convert_to('"+pilot.operation_key('request')+"','UTF8'),convert_to('"+pilot.operation_key('response')+"','UTF8')) ORDER BY 1 LIMIT "+str(MAX_BATCHES+1)+";"))

    def selected(self, ids):
        if not ids: raise pilot.Failure('missing new privacy batches')
        return ','.join("'"+str(uuid.UUID(item))+"'" for item in sorted(ids))

    def assert_shapes(self, ids):
        selected=self.selected(ids)
        scope=("w.source_id='"+pilot.SOURCE+"' AND w.project_id='"+pilot.PROJECT+
               "' AND w.service_id='"+pilot.SERVICE+"' AND w.environment_id='"+pilot.ENVIRONMENT+
               "' AND w.deployment_id='"+pilot.DEPLOYMENT+"' AND w.visibility='structure' AND w.completeness='complete' AND NOT w.route_uncertain AND v.parser_profile='http_json_v1'")
        request="("+scope+" AND o.canonical_key=convert_to('"+pilot.operation_key('request')+"','UTF8') AND convert_from(v.structure_wire,'UTF8')::jsonb='"+REQUEST_SHAPE+"'::jsonb AND w.status_code IS NULL)"
        response="("+scope+" AND o.canonical_key=convert_to('"+pilot.operation_key('response')+"','UTF8') AND convert_from(v.structure_wire,'UTF8')::jsonb='"+pilot.RESPONSE+"'::jsonb AND w.status_code=200)"
        query=("SELECT count(*) FILTER (WHERE "+request+"),count(*) FILTER (WHERE "+response+"),count(*) FILTER (WHERE NOT COALESCE(("+request+" OR "+response+"),false)) FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id) JOIN contour.operations o ON o.tenant_id=w.tenant_id AND o.operation_id=w.operation_id WHERE "+pilot.SCOPE+" AND w.batch_id IN ("+selected+");")
        values=self.sql(query).strip().split(b'|')
        if len(values)!=3 or int(values[0])<2 or int(values[1])<2 or int(values[2])!=0: raise pilot.Failure('privacy shapes not complete')

    def projections(self, ids):
        selected=self.selected(ids)
        where="tenant_id='"+pilot.TENANT+"' AND collector_id='00000000-0000-4000-8000-000000000301' AND batch_id IN ("+selected+")"
        # Row JSON covers every scalar; separately decode all bytea columns.
        payload="SELECT 'payload|'||p.batch_id::text||'|'||encode(convert_to(row_to_json(p)::text,'UTF8'),'hex')||'|'||encode(p.checked_batch,'hex') FROM contour.ingestion_payloads p WHERE "+where
        windows="SELECT 'window|'||w.batch_id::text||'|'||encode(convert_to(row_to_json(w)::text,'UTF8'),'hex')||'|'||encode(w.request_header_names,'hex')||'|'||encode(w.response_header_names,'hex')||'|'||encode(w.query_parameter_names,'hex')||'|'||encode(convert_to(row_to_json(v)::text,'UTF8'),'hex')||'|'||encode(v.structure_wire,'hex')||'|'||encode(v.canonical_structure,'hex')||'|'||encode(convert_to(row_to_json(o)::text,'UTF8'),'hex')||'|'||encode(o.canonical_key,'hex') FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id) JOIN contour.operations o ON o.tenant_id=w.tenant_id AND o.operation_id=w.operation_id WHERE "+pilot.SCOPE+" AND w.batch_id IN ("+selected+")"
        batches="SELECT 'batch|'||b.batch_id::text||'|'||encode(convert_to(row_to_json(b)::text,'UTF8'),'hex')||'|'||encode(b.request_digest,'hex') FROM contour.ingestion_batches b WHERE "+where
        for blob in decode_projection(self.sql(batches+' UNION ALL '+payload+' UNION ALL '+windows+';'),ids): scan(blob,self.markers)

    def started_services(self):
        for service in SERVICES:
            value=self.compose('privacy-container-'+service,['ps','-q',service],30).decode().strip()
            if len(value)!=64 or any(c not in '0123456789abcdef' for c in value): raise pilot.Failure('missing privacy container')
            metadata=json.loads(bounded(['docker','inspect','--format','{{json .HostConfig.LogConfig}}',value],self.base.env,seconds=15))
            if metadata.get('Type') not in ('json-file','local') or metadata.get('Config',{}).get('max-size') not in (None,'-1') or metadata.get('Type')=='local':
                raise pilot.Failure('unbounded log retention not established')
            self.containers[service]=value

    def logs(self):
        if set(self.containers)!=set(SERVICES): raise pilot.Failure('missing privacy log sources')
        for service,container in self.containers.items():
            current=self.compose('privacy-current-'+service,['ps','--all','-q',service],30).decode().strip()
            if current != container: raise pilot.Failure('privacy container replaced')
            scan(bounded(['docker','logs',container],self.base.env,seconds=20),self.markers)

    def product(self):
        for replica in ('replica1','replica2'):
            value=json.loads(self.compose('privacy-product-'+replica,['exec','-T',replica,'node','/pilot/privacy-probe.js'],15))
            if value != {'ok':True}: raise pilot.Failure('privacy product failed')

    def stop_and_scan(self, before, ids):
        # Keep containers and logs until every process has exited, including
        # shutdown handlers that may write after the last request completes.
        self.compose('privacy-stop-all',['stop','--timeout','10',*SERVICES],90)
        if set(self.containers) != set(SERVICES): raise pilot.Failure('missing privacy containers')
        for service, container in self.containers.items():
            current=self.compose('privacy-stopped-'+service,['ps','--all','-q',service],30).decode().strip()
            if current != container: raise pilot.Failure('privacy container replaced')
            state=json.loads(bounded(['docker','inspect','--format','{{json .State}}',container],self.base.env,seconds=15))
            if state.get('Running') is not False or state.get('Status') != 'exited':
                raise pilot.Failure('privacy container not stopped')
        if self.existing_batches()-before != ids: raise pilot.Failure('privacy accepted set changed')
        self.projections(ids)
        self.logs()
        if self.existing_batches()-before != ids or self.ids()-before != ids:
            raise pilot.Failure('privacy accepted set changed')

    def run(self):
        self.base.provision()
        self.setup_overlay()
        before=self.existing_batches()
        self.base.started=True
        self.compose('privacy-start',['up','-d','--pull','never','--force-recreate'],90)
        self.started_services()
        deadline=time.monotonic()+35
        while True:
            try: self.product(); break
            except (pilot.Failure,ValueError):
                if time.monotonic()>=deadline: raise
                time.sleep(.5)
        previous=None
        stable_since=time.monotonic()
        while True:
            ids=self.existing_batches()-before
            observed=self.ids()-before
            if ids != previous:
                previous=ids; stable_since=time.monotonic()
            try:
                if not ids or observed != ids: raise pilot.Failure('privacy batches not projected')
                self.assert_shapes(ids)
                if time.monotonic()-stable_since >= 3: break
            except pilot.Failure:
                if time.monotonic()>=deadline: raise
            if time.monotonic()>=deadline: raise pilot.Failure('privacy batches did not settle')
            time.sleep(.5)
        self.stop_and_scan(before, ids)
        print('native synthetic reachable logs and scoped persisted projections: passed',flush=True)
        print('native volatile queue, process memory, dumps and other sinks: uninspected',flush=True)


def main():
    if sys.argv[1:] == ['--self-test']:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OfflineTests))
        return 0 if result.wasSuccessful() else 1
    if sys.argv[1:] not in ([], ['--shutdown-negative']): raise pilot.Failure('unsupported argument')
    driver=Driver(shutdown_negative=sys.argv[1:] == ['--shutdown-negative'])
    pilot.with_restoration(driver.run,driver.base.cleanup)
    return 0


class OfflineTests(unittest.TestCase):
    def test_shutdown_marker_scanned_after_all_services_stop(self):
        driver=Driver.__new__(Driver)
        driver.base=mock.Mock(env={})
        driver.containers={name:'a'*64 for name in SERVICES}
        driver.markers=[b'request-marker',b'response-marker']
        events=[]
        state={'stopped':False, 'log':b''}
        def compose(name, args, seconds=90):
            if args[0]=='stop':
                self.assertEqual(tuple(args[3:]),SERVICES)
                state['stopped']=True
                state['log'] += b'request-marker'
                events.append('stop')
                return b''
            self.assertTrue(state['stopped'])
            return b'a'*64+b'\n'
        def inspect(args, env, **kwargs):
            self.assertTrue(state['stopped'])
            return b'{"Running":false,"Status":"exited"}'
        driver.compose=compose
        driver.existing_batches=lambda: {'batch'}
        driver.ids=lambda: {'batch'}
        driver.projections=lambda ids: events.append('projections')
        def logs():
            events.append('logs')
            scan(state['log'],driver.markers)
        driver.logs=logs
        with mock.patch(__name__+'.bounded',side_effect=inspect):
            with self.assertRaises(MarkerFound): driver.stop_and_scan(set(),{'batch'})
        self.assertEqual(events,['stop','projections','logs'])

    def test_default_fixture_has_no_shutdown_negative_control(self):
        source=(ROOT/'tests/fixtures/native-privacy/destination.js').read_text()
        self.assertIn("process.env.PRIVACY_TEST_SHUTDOWN_MARKER === '1'",source)
        self.assertNotIn('PRIVACY_TEST_SHUTDOWN_MARKER',(ROOT/'deploy/pilot/destination.js').read_text())

    def test_scanners_fail_positive_and_oversized(self):
        markers=[b'request-marker',b'response-marker']
        for marker in markers:
            with self.assertRaises(pilot.Failure): scan(b'prefix'+marker+b'suffix',markers)
            for kind in ('batch','payload','window'):
                batch='00000000-0000-4000-8000-000000000001'
                rows=[]
                for candidate in ('batch','payload','window'):
                    value=marker if candidate == kind else b'clean'
                    rows.append(candidate+'|'+batch+'|'+value.hex())
                blobs=decode_projection(('\n'.join(rows)+'\n').encode(),{batch})
                with self.assertRaises(pilot.Failure):
                    for blob in blobs: scan(blob,markers)
        scan(b'clean',markers)
        with self.assertRaises(pilot.Failure): scan(b'x'*(MAX+1),markers)

    def test_bounded_runner_rejects_overflow_and_deadline(self):
        self.assertEqual(bounded([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],dict(os.environ),input_bytes=b'ok',seconds=3),b'ok')
        with self.assertRaises(pilot.Failure):
            bounded([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"x"*1048577)'],dict(os.environ),seconds=3)
        with self.assertRaises(pilot.Failure):
            bounded([sys.executable,'-c','import time;time.sleep(2)'],dict(os.environ),seconds=.1)

    def test_projection_requires_every_kind_and_valid_hex(self):
        batch='00000000-0000-4000-8000-000000000001'
        data=('batch|'+batch+'|6566\npayload|'+batch+'|6162\nwindow|'+batch+'|6364\n').encode()
        self.assertEqual(decode_projection(data,{batch}),[b'ef',b'ab',b'cd'])
        for bad in (b'',data.replace(b'6364',b'zz'),data.splitlines()[0]+b'\n'):
            with self.assertRaises(pilot.Failure): decode_projection(bad,{batch})
    def test_flow_only_changes_fixed_payload(self):
        source=(ROOT/'deploy/pilot/flows.json').read_text(); before=json.loads(source)
        after=json.loads(prepare_flow(source,'fixture'))
        target=next(n for n in after if n.get('id')=='pilot-fixed')
        self.assertEqual(json.loads(target['rules'][0]['to']),{'probe':'fixture'})
        target['rules'][0]['to']=next(n for n in before if n.get('id')=='pilot-fixed')['rules'][0]['to']
        self.assertEqual(after,before)
    def test_ids_reject_missing_invalid_duplicate_and_overflow(self):
        value='00000000-0000-4000-8000-000000000001'
        self.assertEqual(id_list((value+'\n').encode()),{value})
        for raw in (b'bad\n',(value+'\n'+value+'\n').encode()):
            with self.assertRaises((pilot.Failure,ValueError)): id_list(raw)
        with self.assertRaises(pilot.Failure): id_list(('\n'.join(str(uuid.UUID(int=i+1)) for i in range(MAX_BATCHES+1))).encode())

if __name__=='__main__':
    try: code=main()
    except MarkerFound:
        print('native privacy marker detected',file=sys.stderr); code=1
    except BaseException:
        print('native privacy qualification failed',file=sys.stderr); code=1
    sys.exit(code)
