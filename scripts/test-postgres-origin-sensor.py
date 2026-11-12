"""Owned two-instance origin sensor fixture, called only by the isolated PG TLS lane.

No existing profiles or keys are used. This module does not launch on import.
"""
import hashlib
import copy
import datetime
import uuid
import json
import os
from pathlib import Path
import queue
import re
import secrets
import selectors
import shutil
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
NODE = 'docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'
ENVOY = 'envoyproxy/envoy:v1.37.11@sha256:7765ad61185fca9c9a770c9e2cad640d085d708ae9c22f3741345e88331472a4'
ITEM = '00000000-0000-0000-0000-000000000001'
HEADER = 'x-contour-origin-witness'
sys.path.insert(0, str(ROOT))
from deploy.pilot import native_envoy


def checked_source_head():
    options = dict(cwd=ROOT, text=True, timeout=15)
    if subprocess.check_output(['git','status','--porcelain','--untracked-files=all'], **options).strip():
        raise AssertionError('origin fixture run requires a frozen clean checkout')
    return subprocess.check_output(['git','rev-parse','HEAD'], **options).strip()


def flows(other_fingerprint, name):
    """Each process has a fixed TLS identity and target; trigger data cannot change them."""
    if name not in ('a', 'b'): raise ValueError('invalid fixture instance')
    function = '''const mode = msg.req.query.mode || "normal";
msg.headers = {"content-type":"application/json"};
if (mode === "spoof") msg.headers["x-contour-origin-witness"] = "%s";
if (mode === "xfcc") msg.headers["x-forwarded-client-cert"] = "Hash=%s";
if (mode === "connection") { msg.headers["connection"] = "x-contour-origin-witness"; msg.headers["x-contour-origin-witness"] = "%s"; }
msg.payload = mode === "concurrent" ? %s : {probe:true}; return msg;''' % (*((other_fingerprint,) * 3), '{probe:[true]}' if name == 'a' else '{probe:{id:1}}')
    return [
        {'id':'tab','type':'tab','label':'synthetic'},
        {'id':'tls','type':'tls-config','name':'instance identity','cert':'/fixture/client.crt','key':'/fixture/client.key','ca':'/fixture/ca.crt','certType':'files','servername':'pilot-destination','verifyservercert':True},
        {'id':'input','type':'http in','z':'tab','url':'/trigger','method':'get','wires':[['make']]},
        {'id':'make','type':'function','z':'tab','func':function,'outputs':1,'wires':[['send']]},
        {'id':'send','type':'http request','z':'tab','method':'POST','ret':'obj','paytoqs':'ignore','url':'https://127.0.0.1:9443/pilot','tls':'tls','persist':False,'senderr':True,'wires':[['response']]},
        {'id':'response','type':'http response','z':'tab','statusCode':'','headers':{},'wires':[]},
        {'id':'catch','type':'catch','z':'tab','scope':['send'],'uncaught':False,'wires':[['failure']]},
        {'id':'failure','type':'function','z':'tab','func':'msg.statusCode=502;msg.payload={error:"upstream"};return msg;','outputs':1,'wires':[['response']]},
    ]


def generated_edge(gateway_port):
    config = native_envoy.config(origin_v2=True)
    listener = config['static_resources']['listeners'][0]['filter_chains'][0]
    tls = listener['transport_socket']['typed_config']['common_tls_context']
    tls['tls_certificates'] = [{'certificate_chain':{'filename':'/fixture/edge.crt'}, 'private_key':{'filename':'/fixture/edge.key'}}]
    tls['validation_context'] = {'trusted_ca':{'filename':'/fixture/ca.crt'}}
    cluster = config['static_resources']['clusters'][0]
    addr = cluster['load_assignment']['endpoints'][0]['lb_endpoints'][0]['endpoint']['address']['socket_address']
    addr.update(address='127.0.0.1', port_value=gateway_port)
    config['static_resources']['listeners'][0]['address']['socket_address']['address']='127.0.0.1'
    ctx = cluster['transport_socket']['typed_config']['common_tls_context']
    ctx['validation_context']['trusted_ca']['filename'] = '/fixture/ca.crt'
    ctx['tls_certificates'] = [{'certificate_chain':{'filename':'/fixture/forwarder.crt'}, 'private_key':{'filename':'/fixture/forwarder.key'}}]
    return config


def assert_proofs(rows, expected, origin_service, origin_deployment, source, response_statuses=('200',)):
    for row in rows:
        if row[5:9] != [ITEM]*4 or row[15] != 'POST' or row[17] != source or row[18] != 'http_json_v1' or row[19] != 2:
            raise AssertionError('observation tuple mismatch')
        if row[14] not in ('request','response') or (row[14] == 'request' and row[16] is not None) or (row[14] == 'response' and row[16] not in response_statuses):
            raise AssertionError('origin record direction/status mismatch')
        if row[20] == 'unattributed':
            if any(x is not None for x in row[:5] + row[9:13]): raise AssertionError('unattributed record has proof')
        elif row[20] == 'verified_origin_v1':
            if row[0] not in expected or tuple(row[1:5]) != expected[row[0]] or row[9:13] != [ITEM,origin_service,ITEM,origin_deployment]:
                raise AssertionError('origin proof tuple mismatch')
        else: raise AssertionError('unknown attribution class')


def assert_transition(rows, before, fingerprint, allow_unattributed=False):
    fresh=[row for row in rows if row[13] not in before]
    if len(fresh)!=2 or {row[14] for row in fresh}!={'request','response'}:
        raise AssertionError('single request must create exactly request and response records')
    allowed={fingerprint, None} if allow_unattributed else {fingerprint}
    if any(row[0] not in allowed for row in fresh): raise AssertionError('request attributed to another instance')
    if len({row[0] for row in fresh}) != 1: raise AssertionError('request and response attribution differ')
    return {row[13] for row in rows}


def assert_concurrent(rows, before, a, b):
    primitive = lambda kind: {'kind':kind}
    obj = lambda fields: {'kind':'object','fields':fields,'additional':None}
    shapes = {
        (a,'request'): obj({'probe':{'kind':'array','items':primitive('boolean')}}),
        (b,'request'): obj({'probe':obj({'id':primitive('integer')})}),
        (a,'response'): obj({'id':primitive('boolean')}),
        (b,'response'): obj({'quantity':{'kind':'array','items':primitive('integer')}}),
    }
    fresh=[row for row in rows if row[13] not in before]
    if len(fresh)!=4: raise AssertionError('concurrent pair must create four records')
    observed={}
    for row in fresh:
        key=(row[0],row[14])
        if key in observed or key not in shapes: raise AssertionError('concurrent attribution mismatch')
        observed[key]=row[21]
    if observed != shapes: raise AssertionError('concurrent shape attribution mismatch')



# Malformed and oversized bodies produce typed unknown observations. Unsupported
# request-level encoding/trailers suppress response capture too.
DISCOVERY_CASES = (
    ('normal', ('request','response')),
    ('request-malformed', ('request','response')), ('response-malformed', ('request','response')),
    ('request-compressed', ()), ('response-compressed', ('request',)),
    ('request-oversized', ('request','response')), ('response-oversized', ('request','response')),
    ('request-chunked', ('request','response')), ('response-chunked', ('request','response')),
    ('request-progress', ('request','response')), ('response-progress', ('request','response')),
    ('request-trailer', ()), ('response-trailer', ('request',)),
    ('response-409', ('request','response')),
    ('normal', ('request','response')),
)

def assert_discovery_case(rows, before, fingerprint, directions, response_status=200, case='normal', history=None):
    if case not in dict(DISCOVERY_CASES):
        raise AssertionError('invalid matrix case')
    shape = lambda field, kind: {'kind':'object','fields':{field:{'kind':kind}},'additional':None}
    expected = {'request':('complete', [], shape('probe','boolean')),
                'response':('complete', [], shape('id','integer'))}
    if case in ('request-malformed','response-malformed','request-oversized','response-oversized'):
        direction, kind = case.split('-')
        reason = 'malformed' if kind == 'malformed' else 'limit'
        expected[direction] = ('unavailable' if reason == 'malformed' else 'partial',
                               [reason], {'kind':'unknown','reason':reason})
    ids = [r[13] for r in rows]
    if len(ids) != len(set(ids)) or not before.issubset(ids):
        raise AssertionError('matrix history changed')
    if history is not None:
        prior = {r[13]:r for r in history}
        current = {r[13]:r for r in rows if r[13] in before}
        if set(prior) != before or current != prior:
            raise AssertionError('matrix history changed')
    fresh = [r for r in rows if r[13] not in before]
    if len(fresh) != len(directions) or {r[14] for r in fresh} != set(directions):
        raise AssertionError('matrix direction or record count mismatch')
    for r in fresh:
        completeness, reasons, structure = expected[r[14]]
        if (len(r) < 36 or r[0] != fingerprint or r[20] != 'verified_origin_v1'
            or r[29] != {'kind':'downstream_mtls_leaf_sha256_v1','leaf_sha256':fingerprint}
            or r[21] != structure or r[27] != completeness or r[28] != reasons
            or r[30:36] != [1,1,1,'structure','/pilot','http']
            or r[16] != (None if r[14]=='request' else str(response_status))):
            raise AssertionError('matrix attribution or structure mismatch')


def matrix_expected_loss(case):
    if case not in dict(DISCOVERY_CASES):
        raise ValueError('invalid matrix case')
    return 0

def run_discovery_cases(run_case):
    # Fail immediately on any case; enclosing owned-resource finally performs cleanup.
    for case, directions in DISCOVERY_CASES:
        run_case(case, directions)

def parse_matrix_drain(line, previous, expected_loss, record_count):
    parts=line.split()
    if len(parts)!=3 or parts[0]!='MATRIX' or not all(x.isascii() and x.isdigit() for x in parts[1:]):
        raise AssertionError('invalid matrix drain')
    losses,acks=map(int,parts[1:])
    if losses != previous + expected_loss or (acks != 0 if record_count == 0 else not 1 <= acks <= record_count):
        raise AssertionError('matrix loss or acknowledgement mismatch')
    return losses

MATRIX_DIAGNOSTICS = frozenset({'server_tls','server_request_metadata','server_request_bytes','server_request_trailers',
    'client_setup','client_tls','client_status','client_response_metadata','client_response_bytes','client_response_trailers','transport'})

def matrix_diagnostics(*outputs):
    # Never expose unexpected output, exception messages, traffic or credentials.
    labels=set()
    for output in outputs:
        if len(output)>16384: continue
        for line in output.splitlines():
            if line.startswith(b'DIAG '):
                try: label=line[5:].decode('ascii')
                except UnicodeDecodeError: continue
                if label in MATRIX_DIAGNOSTICS: labels.add(label)
    return tuple(sorted(labels))

def assert_discovery_catalog(catalog, rows, tenant):
    expected = {}
    for r in rows:
        key = [tenant, *r[5:8], 'http', r[14], r[15], '/pilot']
        expected[r[13]] = (r[27],'structure',int(r[16]) if r[16] is not None else None,
                           r[21],r[17],*r[5:9],r[18],r[19],False,r[28],key,r[22],1,1,1,*r[23:27])
    if len(catalog) != len(expected) or {r[0]:tuple(r[1:]) for r in catalog} != expected:
        raise AssertionError('catalog projection mismatch')


def orderly_shutdown(gateway, origin, line, execute, clock=time.monotonic, pause=time.sleep):
    gateway.stdin.write('STOP\n'); gateway.stdin.flush(); gateway.wait(timeout=5)
    if gateway.returncode: raise AssertionError('gateway shutdown failed')
    origin.stdin.write('\n'); origin.stdin.flush()
    if line(origin,10) != 'STOPPED': raise AssertionError('origin HTTP shutdown failed')
    origin.stdin.write('\n'); origin.stdin.flush(); origin.stdin.close()
    origin.wait(timeout=10)
    if origin.returncode or origin.stderr.read(): raise AssertionError('origin HTTP cleanup failed')
    until=clock()+10
    while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_origin_ingress_test';") != '0':
        if clock()>=until: raise AssertionError('origin database connections leaked')
        pause(.1)

def assert_owned_replacement(info, name, label):
    if (not re.fullmatch('[0-9a-f]{64}',info.get('Id','')) or info.get('Name')!='/'+name
        or (info.get('Config',{}).get('Labels') or {}).get('org.apicontour.origin-replacement')!=label):
        raise AssertionError('replacement container ownership mismatch')


def cleanup_fixture_containers(resources, label, inspect, remove, remains, attempts=20, pause=lambda: time.sleep(.1)):
    errors = []
    for resource in reversed(resources):
        try:
            name, known_id = resource['name'], resource['id']
            info = None
            for attempt in range(attempts):
                info = inspect(name)
                if info is not None: break
                if known_id is not None: break
                if attempt + 1 < attempts: pause()
            if info is None:
                if known_id is None:
                    raise RuntimeError('fixture container creation uncertain: ' + name)
                if remains(known_id): raise RuntimeError('fixture container remained')
                continue
            assert_owned_replacement(info, name, label)
            if known_id is not None and info['Id'] != known_id:
                raise RuntimeError('fixture container identity changed')
            remove(info['Id'])
            if remains(info['Id']): raise RuntimeError('fixture container remained')
        except Exception as exc:
            errors.append(exc)
    if errors: raise RuntimeError('fixture container cleanup uncertain or failed') from errors[0]


def parse_admission_diagnostic(value):
    fields = value.split()
    categories = {'deferred_discard_invalid','deferred_retry','deferred_renew_authorized_enrollment',
        'deferred_stop_conflict','deferred_require_split','deferred_stop_rejected',
        'deferred_stop_configuration','deferred_expired','acknowledged','empty',
        'deadline','owner_paused','owner_history_limit','owner_queue','owner_transport','owner_retry'}
    if (len(fields)!=6 or fields[0]!='ADMISSION' or fields[1] not in categories
        or any(not re.fullmatch(r'[0-9]{1,20}',x) or int(x)>2**64-1 for x in fields[2:])):
        raise ValueError('invalid admission diagnostic')
    return (fields[1],*(int(x) for x in fields[2:]))


def require_terminal_admission(diagnostic):
    if diagnostic != ('deferred_discard_invalid',0,2,0,0):
        raise RuntimeError('admission drain diagnostic reported failure')


def parse_drain_diagnostic(value):
    categories = {'ok', 'loss', 'deadline', 'empty', 'owner_paused', 'owner_history_limit',
        'owner_queue', 'owner_transport', 'owner_retry', 'deferred_retry',
        'deferred_discard_invalid', 'deferred_renew_authorized_enrollment',
        'deferred_stop_conflict', 'deferred_require_split', 'deferred_stop_rejected',
        'deferred_stop_configuration', 'deferred_expired'}
    fields = value.split()
    if (len(fields) != 4 or fields[0] != 'DIAG' or fields[1] not in categories
        or any(not re.fullmatch(r'[0-9]{1,20}', x) or int(x) > 2**64-1 for x in fields[2:])):
        raise ValueError('invalid drain diagnostic')
    category, losses, acknowledgements = fields[1], int(fields[2]), int(fields[3])
    if (category == 'ok' and losses != 0) or (category == 'loss' and losses == 0):
        raise ValueError('invalid drain diagnostic')
    return category, losses, acknowledgements


def parse_pg_diagnostic(log, marker):
    if not re.fullmatch(r'fixture_marker_[0-9a-f]{16}', marker):
        raise ValueError('invalid diagnostic marker')
    prefix = r'^[0-9][0-9T: .+\-]* [A-Z]+ \[\d+\] '
    marker_line = re.compile(prefix + r'LOG:  00000: ' + re.escape(marker) + r'\s*$')
    error_line = re.compile(prefix + r'ERROR:  ([0-9A-Z]{5}): (.*)$')
    lines = log.splitlines()
    markers = [i for i, line in enumerate(lines) if marker_line.fullmatch(line)]
    if len(markers) != 1: raise ValueError('diagnostic marker unavailable or ambiguous')
    records = []
    for line in lines[markers[0]+1:]:
        if re.match(prefix + r'ERROR:', line):
            match = error_line.fullmatch(line)
            if not match: raise ValueError('invalid diagnostic error')
            state, message = match.groups()
            if message == 'origin unavailable':
                records.append((state, 'origin_unavailable', None))
            else:
                records.append((state, 'unrecognized', hashlib.sha256(message.encode()).hexdigest()))
            if len(records) > 32: raise ValueError('too many diagnostic errors')
    return records


def configure_pg_diagnostic(execute):
    execute("ALTER SYSTEM SET log_error_verbosity = 'verbose';")
    if execute('SELECT pg_reload_conf();') != 't':
        raise RuntimeError('PostgreSQL diagnostic reload failed')
    deadline = time.monotonic() + 5
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise RuntimeError('PostgreSQL diagnostic verbosity unavailable')
        value = execute('SHOW log_error_verbosity;', timeout=min(2, remaining))
        if time.monotonic() >= deadline: raise RuntimeError('PostgreSQL diagnostic verbosity unavailable')
        if value == 'verbose': return
        time.sleep(min(.1, max(0, deadline-time.monotonic())))


def read_pg_diagnostic(container, environment, marker):
    # Bound both retained output and execution time; never persist or emit raw logs.
    process = subprocess.Popen(['docker','logs','--tail','2000',container], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=environment, cwd=ROOT)
    selector = selectors.DefaultSelector()
    data = bytearray()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 10
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise RuntimeError('PostgreSQL diagnostic unavailable')
            if not selector.select(remaining): raise RuntimeError('PostgreSQL diagnostic unavailable')
            chunk = os.read(process.stdout.fileno(), min(65536, 1048577-len(data)))
            if not chunk:
                selector.unregister(process.stdout)
                break
            data.extend(chunk)
            if len(data) > 1048576: raise RuntimeError('PostgreSQL diagnostic exceeded bound')
        if process.wait(timeout=max(.01, deadline-time.monotonic())) != 0:
            raise RuntimeError('PostgreSQL diagnostic unavailable')
        return parse_pg_diagnostic(data.decode('utf-8', errors='strict'), marker)
    finally:
        selector.close()
        try:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
        except Exception:
            raise RuntimeError('PostgreSQL diagnostic cleanup failed') from None
        finally:
            process.stdout.close()


def history_record_ids_sql(record_ids):
    # The IDs come from verified persisted fixture rows, never request input.
    # Validate and freeze the exact original set before constructing SQL.
    ids=sorted({str(uuid.UUID(value)) for value in record_ids})
    if not ids or len(ids)!=len(record_ids): raise ValueError('invalid historical record IDs')
    return ','.join("'%s'::uuid" % value for value in ids)


def assert_replacement_history(rows, prior, before_old_attempt, old_leaf):
    if any(row[0]==old_leaf for row in rows if row[13] not in before_old_attempt):
        raise AssertionError('closed lifecycle received new proof')
    actual={row[13]:row for row in rows}
    if any(actual.get(key)!=value for key,value in prior.items()):
        raise AssertionError('historical proof changed')


def run_cases(container, execute, setup, directory, environment):
    """Requires migrations 1,2,3,4,13-17 and origin login, and built origin_sensor_probe."""
    matrix = environment.get('CONTOUR_TLS_DISCOVERY_MATRIX') == '1'
    replacement = environment.get('CONTOUR_ORIGIN_REPLACEMENT_FIXTURE') == '1'
    admission = environment.get('CONTOUR_ORIGIN_ADMISSION_FIXTURE') == '1'
    fixture_image = environment['CONTOUR_ORIGIN_SENSOR_IMAGE']
    if not fixture_image.startswith('contour-origin-sensor-fixture:'):
        raise ValueError('fixture image tag invalid')
    resources, processes, readers, outputs = [], [], [], {}
    prefix = 'contour-origin-sensor-' + secrets.token_hex(8)
    folder = directory / prefix
    folder.mkdir(mode=0o700)
    count = 0
    def run(args, seconds=30):
        nonlocal count
        count += 1
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=seconds, env=environment, cwd=ROOT)
        if p.returncode:
            raise RuntimeError('fixture command failed: ' + args[0])
        return p.stdout.decode().strip()
    def docker(*args, seconds=30):
        return run(['docker', *args], seconds)
    def openssl(*args):
        return run(['openssl', *map(str,args)])
    def write(name, value):
        path = folder/name
        path.write_text(value)
        path.chmod(0o644)
        return path
    def start(args, env=None):
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env or environment, cwd=ROOT)
        processes.append(p)
        lines = queue.Queue()
        outputs[p] = lines
        def pump():
            for line in p.stdout:
                lines.put(line)
            lines.put(None)
        thread = threading.Thread(target=pump, daemon=False)
        readers.append(thread); thread.start()
        return p
    def line(p, seconds=15):
        value = outputs[p].get(timeout=seconds)
        if value is None: raise RuntimeError('fixture process exited before response')
        return value.strip()
    def ready(p, seconds=15):
        value = line(p,seconds).split()
        if len(value) != 2 or value[0] != 'READY':
            raise RuntimeError('fixture process did not become ready')
        return int(value[1])
    def command(p, text, seconds=15):
        p.stdin.write(text+'\n'); p.stdin.flush()
        return line(p, seconds)
    def certificate(name, san, usage):
        cfg = write(name+'.ext', 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:'+san+'\n')
        openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=synthetic','-keyout',folder/(name+'.key'),'-out',folder/(name+'.csr'))
        openssl('x509','-req','-in',folder/(name+'.csr'),'-CA',directory/'ca.crt','-CAkey',directory/'ca.key','-CAcreateserial','-days','1','-sha256','-extfile',cfg,'-out',folder/(name+'.crt'))
        openssl('x509','-in',folder/(name+'.crt'),'-outform','DER','-out',folder/(name+'.der'))
        openssl('pkcs8','-topk8','-nocrypt','-in',folder/(name+'.key'),'-outform','DER','-out',folder/(name+'-key.der'))
        for suffix in ['.key','.crt','.der','-key.der']: (folder/(name+suffix)).chmod(0o644)
    def cert_hash(name):
        return hashlib.sha256((folder/(name+'.der')).read_bytes()).hexdigest()
    def mount(source, target):
        return ['-v', str(source)+':'+target+':ro']
    try:
        for image in [NODE, ENVOY, fixture_image]: docker('image','inspect',image)
        source = checked_source_head()
        image_info = json.loads(docker('image','inspect',fixture_image))[0]
        if image_info['Config']['Labels'].get('org.apicontour.fixture.source') != source:
            raise AssertionError('origin fixture image source mismatch')
        network_info = json.loads(docker('inspect',container))[0]['NetworkSettings']['Networks']
        if len(network_info) != 1 or not all(json.loads(docker('network','inspect',name))[0]['Internal'] for name in network_info):
            raise AssertionError('origin fixture requires its owned internal PostgreSQL namespace')
        for name, san, usage in [('edge','pilot-destination','serverAuth'),('server','native-gateway.test','serverAuth'),('destination','pilot-destination','serverAuth'),('forwarder','envoy-forwarder','clientAuth'),('upstream','observer-upstream','clientAuth'),('http-client','collector','clientAuth'),('a','instance-a','clientAuth'),('b','instance-b','clientAuth')]:
            certificate(name, san, usage)
        for name in ['ca.crt','signer.raw']:
            shutil.copyfile(directory/name, folder/name)
        for name in ['ca','server']:
            openssl('x509','-in',directory/(name+'.crt'),'-outform','DER','-out',folder/(name+'.crt.der'))
        openssl('pkcs8','-topk8','-nocrypt','-in',directory/'server.key','-outform','DER','-out',folder/'server.key.der')
        shutil.copyfile(folder/'http-client.der', folder/'http-client.crt.der')
        def policy(p):
            p.update(approved_names=['POST','probe','id','quantity'],approved_route_segments=['pilot'],queue_bytes=1048576,queue_ttl_seconds=60)
        raw, collector, source = setup('origin_sensor', change=policy)
        tenant = raw['tenant_id']
        origin_service = '00000000-0000-0000-0000-00000000d001'
        origin_deployment = '00000000-0000-0000-0000-00000000d002'
        execute("INSERT INTO contour.services VALUES ('%s','%s','%s'); INSERT INTO contour.deployments VALUES ('%s','%s','%s','%s','%s');" % (tenant, origin_service, ITEM, tenant, origin_deployment, ITEM, origin_service, ITEM))
        expected = {}
        for i, name in enumerate(['a','b']):
            instance,lifecycle,credential,grant = ['00000000-0000-0000-0000-%012x' % (0xd100+i*16+n) for n in range(4)]
            fingerprint = cert_hash(name)
            execute("SELECT set_config('apicontour.tenant_id','%s',false); INSERT INTO contour.workload_instances VALUES ('%s','%s','%s','%s','%s','%s'); SELECT contour.enroll_origin('%s','%s','%s','%s','%s','%s','%s','trusted_platform_v1',decode(repeat('aa',32),'hex')); SELECT contour.enroll_origin_credential('%s','%s','%s',decode('%s','hex')); SELECT contour.grant_origin_observer('%s','%s','%s','%s','%s','%s','%s','%s','%s');" % (tenant,tenant,ITEM,origin_service,ITEM,origin_deployment,instance, tenant,lifecycle,ITEM,origin_service,ITEM,origin_deployment,instance,tenant,credential,lifecycle,fingerprint,tenant,grant,lifecycle,collector,source,ITEM,ITEM,ITEM,ITEM))
            expected[fingerprint] = (instance,lifecycle,credential,grant)
        def all_durable():
            tables=('ingestion_batches','ingestion_payloads','ingestion_v2_metadata','origin_proofs','origin_batch_proof_completion','origin_logical_usage','origin_tenant_state','origin_ingress_context','origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events')
            ledger=execute("SELECT coalesce(json_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::json)::text FROM contour.schema_migrations x;")
            return [ledger]+[execute("SELECT coalesce(json_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::json)::text FROM contour.%s x WHERE tenant_id='%s';" % (table,tenant)) for table in tables]
        if admission:
            direct_leaves={}
            for i, kind in enumerate(('lifecycle_closed','credential_revoked','grant_revoked')):
                instance,lifecycle,credential,grant = ['00000000-0000-0000-0000-%012x' % (0xe100+i*16+n) for n in range(4)]
                leaf=hashlib.sha256(('fixture-direct-'+kind).encode()).hexdigest()
                prefix_sql="SELECT set_config('apicontour.tenant_id','%s',false); " % tenant
                execute(prefix_sql+"INSERT INTO contour.workload_instances VALUES ('%s','%s','%s','%s','%s','%s');" % (tenant,ITEM,origin_service,ITEM,origin_deployment,instance))
                execute(prefix_sql+"SELECT contour.enroll_origin('%s','%s','%s','%s','%s','%s','%s','trusted_platform_v1',decode(repeat('aa',32),'hex'));" % (tenant,lifecycle,ITEM,origin_service,ITEM,origin_deployment,instance))
                execute(prefix_sql+"SELECT contour.enroll_origin_credential('%s','%s','%s',decode('%s','hex'));" % (tenant,credential,lifecycle,leaf))
                execute(prefix_sql+"SELECT contour.grant_origin_observer('%s','%s','%s','%s','%s','%s','%s','%s','%s');" % (tenant,grant,lifecycle,source,collector,ITEM,ITEM,ITEM,ITEM))
                target={'lifecycle_closed':lifecycle,'credential_revoked':credential,'grant_revoked':grant}[kind]
                execute(prefix_sql+"SELECT contour.end_origin('%s','%s','%s');" % (tenant,kind,target))
                direct_leaves[kind]=leaf
            settings={'tenant':tenant,'collector':collector,'source':source,'active':cert_hash('a'),
                      'closed':direct_leaves['lifecycle_closed'],'credential_revoked':direct_leaves['credential_revoked'],
                      'grant_revoked':direct_leaves['grant_revoked']}
            sql=''.join("SELECT set_config('origin_admission_test.%s','%s',false);" % pair for pair in settings.items())
            before_sql=all_durable()
            context_key=execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='contour.origin_ingress_context'::regclass AND conname='origin_ingress_context_pkey';")
            if not context_key: raise AssertionError('origin context constraint unavailable')
            execute(sql+(ROOT/'db/tests/origin_admission_classification.sql').read_text(),timeout=120)
            if all_durable()!=before_sql or execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='contour.origin_ingress_context'::regclass AND conname='origin_ingress_context_pkey';")!=context_key:
                raise AssertionError('direct SQL tests changed durable state or schema')
        common=['--label','org.apicontour.origin-replacement='+prefix,'--pull','never','--network','container:'+container,'--user',f'{os.getuid()}:{os.getgid()}','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','256m','--log-driver','local']
        def child(name, mounts, image, argv, env_names=(), entrypoint=None):
            cname=prefix+'-'+name
            args=['docker','run','-i','--name',cname,*common]
            for key in env_names: args += ['-e',key]
            if entrypoint: args += ['--entrypoint',entrypoint]
            resources.append({'name':cname,'id':None})
            return start([*args,*mounts,image,*argv]),cname
        def files(*names):
            return sum((mount(folder/n,'/fixture/'+n) for n in names),[])
        # Both probes share only the owned PostgreSQL network namespace; DB and
        # gateway endpoints remain loopback inside that namespace.
        origin_env=dict(environment,CONTOUR_ORIGIN_DATABASE_USER='contour_origin_ingress_test')
        environment=origin_env
        origin,_=child('origin',files('ca.crt','ca.crt.der','server.crt.der','server.key.der','http-client.crt.der','signer.raw'),fixture_image,['/usr/local/bin/origin_https_probe','5432','/fixture',tenant,collector,'5000'],['CONTOUR_FIXTURE_PASSWORD','CONTOUR_ORIGIN_DATABASE_USER'])
        origin_port=ready(origin)
        destination_script = 'discovery-matrix.js' if matrix else 'destination.js'
        destination_mounts=files('destination.crt','destination.key','ca.crt')+mount(ROOT/('tests/fixtures/origin-sensor/'+destination_script),'/fixture/destination.js')
        environment=dict(environment,EXPECTED_CLIENT_SHA256=cert_hash('upstream'))
        destination,destination_name=child('destination',destination_mounts,NODE,['/fixture/destination.js',*(['server'] if matrix else [])],['EXPECTED_CLIENT_SHA256'],'node')
        if ready(destination)!=9444: raise AssertionError('destination listener mismatch')
        config = dict(server_certificate_der='/fixture/server.der',server_key_der='/fixture/server-key.der',forwarder_ca_der='/fixture/ca.crt.der',forwarder_leaf_der='/fixture/forwarder.der',upstream_address='127.0.0.1:9444',upstream_name='pilot-destination',upstream_ca_der='/fixture/ca.crt.der',upstream_client_certificate_der='/fixture/upstream.der',upstream_client_key_der='/fixture/upstream-key.der',delivery_address='127.0.0.1:%d'%origin_port,delivery_name='localhost',delivery_ca_der='/fixture/ca.crt.der',delivery_client_certificate_der='/fixture/http-client.der',delivery_client_key_der='/fixture/http-client-key.der',tenant=tenant,collector=collector,source=source,workload=[ITEM]*4,policy_key_id='fixture',policy_key_file='/fixture/signer.raw')
        cfg=write('gateway.json',json.dumps(config))
        gateway,_=child('gateway',files('server.der','server-key.der','ca.crt.der','forwarder.der','upstream.der','upstream-key.der','http-client.der','http-client-key.der','signer.raw','gateway.json'),fixture_image,['/usr/local/bin/origin_sensor_probe','/fixture/gateway.json',*(['--discovery-matrix'] if matrix else ['--admission-diagnostic'] if admission else ['--replacement-diagnostic'] if replacement else [])])
        gateway_port=ready(gateway)
        edgecfg=write('envoy.json',json.dumps(generated_edge(gateway_port)))
        edge=prefix+'-edge'
        edge_mounts = files('edge.crt','edge.key','forwarder.crt','forwarder.key','ca.crt','envoy.json')
        resources.append({'name':edge,'id':None})
        resources[-1]['id']=docker('run','-d','--name',edge,*common,*edge_mounts,ENVOY,'envoy','-c','/fixture/envoy.json','--log-level','error','--concurrency','1')
        nodes=[]
        for name,other,port in [('a','b',1880),('b','a',1881)]:
            flow=write('flows-'+name+'.json',json.dumps(flows(cert_hash(other),name)))
            cname=prefix+'-'+name
            mounts=mount(flow,'/fixture/flows.json')+mount(ROOT/'tests/fixtures/origin-sensor/settings.js','/fixture/settings.js')+mount(ROOT/'tests/fixtures/origin-sensor/trigger.js','/fixture/trigger.js')+mount(ROOT/'tests/fixtures/origin-sensor/discovery-matrix.js','/fixture/discovery-matrix.js')+mount(folder/(name+'.crt'),'/fixture/client.crt')+mount(folder/(name+'.key'),'/fixture/client.key')+mount(folder/'ca.crt','/fixture/ca.crt')
            resources.append({'name':cname,'id':None})
            resources[-1]['id']=docker('run','-d','--name',cname,*common,'-e','FIXTURE_PORT='+str(port),'--tmpfs','/data:rw,nosuid,nodev,noexec,size=16m,mode=1777','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777',*mounts,'--entrypoint','node',NODE,'/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/fixture/settings.js')
            nodes.append((cname,port))
        def trigger(node,mode,port,extra=''):
            result=docker('exec',node,'node','/fixture/trigger.js',mode,str(port),extra,seconds=10)
            if result != ('READY' if mode=='ready' else 'OK'): raise AssertionError('fixture trigger mismatch')
        control_record_ids=set()
        def snapshot():
            sql = """SELECT coalesce(json_agg(json_build_array(encode(p.leaf_sha256,'hex'),p.instance_id,p.lifecycle_id,p.credential_id,p.grant_id,m.project_id,m.service_id,m.environment_id,m.deployment_id,p.origin_project_id,p.origin_service_id,p.origin_environment_id,p.origin_deployment_id,m.record_id,r.value->'record'->>'direction',r.value->'record'->>'operation',r.value->'record'->>'status_code',m.source_id,m.parser_profile,m.policy_revision,m.attribution_class,r.value->'record'->'structure',m.batch_id,r.value->'record'->>'first_seen',r.value->'record'->>'last_seen',r.value->'record'->>'queued_at',r.value->'record'->>'expires_at',r.value->'record'->>'completeness',r.value->'record'->'reasons',r.value->'origin_witness',r.value->'record'->'count',r.value->'record'->'sample_numerator',r.value->'record'->'sample_denominator',r.value->'record'->>'visibility',r.value->'record'->>'route_template',r.value->'record'->>'protocol')), '[]'::json)
FROM contour.ingestion_v2_metadata m JOIN contour.ingestion_payloads b USING (tenant_id,collector_id,batch_id)
LEFT JOIN contour.origin_proofs p USING (tenant_id,collector_id,batch_id,record_id)
CROSS JOIN LATERAL jsonb_array_elements(convert_from(b.checked_batch,'UTF8')::jsonb->'records') r(value)
WHERE m.tenant_id='%s' AND m.collector_id='%s' AND r.value->'record'->>'record_id'=m.record_id::text;""" % (tenant,collector)
            return [row for row in json.loads(execute(sql)) if row[13] not in control_record_ids]
        def drain():
            value=command(gateway,'DRAIN',15).split()
            if len(value)!=4 or value[:3]!=['DRAIN','0','0'] or not value[3].isdigit():
                raise AssertionError('gateway drain failed: ' + (' '.join(value) if len(value)==4 and value[0]=='DRAIN' and all(x.isdigit() for x in value[1:]) else 'invalid diagnostic'))
        def after_request(before, fingerprint, allow_unattributed=False):
            drain()
            rows=snapshot(); assert_proofs(rows, expected, origin_service, origin_deployment, source)
            return assert_transition(rows,before,fingerprint,allow_unattributed)
        drain()
        if snapshot(): raise AssertionError('unexpected records before first request')
        for node,port in nodes:
            until=time.monotonic()+30
            while True:
                try: trigger(node,'ready',port); break
                except RuntimeError:
                    if time.monotonic()>=until: raise AssertionError('Node-RED listener unavailable')
                    time.sleep(.1)
        if matrix:
            projected=set()
            matrix_losses=0
            def project_and_check(rows):
                batches=json.loads(execute("SELECT coalesce(json_agg(DISTINCT batch_id),'[]'::json) FROM contour.ingestion_v2_metadata WHERE tenant_id='%s' AND collector_id='%s';" % (tenant,collector)))
                for batch in batches:
                    if batch in projected: continue
                    uuid.UUID(batch)
                    proc,_=child('catalog-'+str(len(projected)),files('ca.crt'),fixture_image,
                        ['/usr/local/bin/catalog_probe','5432','/fixture/ca.crt',batch,'Processed',tenant,collector,'5000'],['CONTOUR_FIXTURE_PASSWORD'])
                    if line(proc,15) != 'Processed': raise AssertionError('catalog projection failed')
                    proc.stdin.write('OK\n'); proc.stdin.flush()
                    if proc.wait(timeout=15) != 0: raise AssertionError('catalog probe failed')
                    projected.add(batch)
                sql="""SELECT coalesce(json_agg(json_build_array(w.record_id,w.completeness,w.visibility,w.status_code,convert_from(v.structure_wire,'UTF8')::jsonb,w.source_id,w.project_id,w.service_id,w.environment_id,w.deployment_id,v.parser_profile,v.policy_revision,w.route_uncertain,to_jsonb(w.reasons),convert_from(o.canonical_key,'UTF8')::jsonb,w.batch_id,w.observation_count,w.sample_numerator,w.sample_denominator,w.first_seen,w.last_seen,w.queued_at,w.expires_at)),'[]'::json)
FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id)
JOIN contour.operations o USING(tenant_id,operation_id)
WHERE w.tenant_id='%s' AND w.collector_id='%s';""" % (tenant,collector)
                assert_discovery_catalog(json.loads(execute(sql)),rows,tenant)
            def run_matrix_case(case, directions):
                nonlocal matrix_losses
                history=snapshot()
                before={row[13] for row in history}
                result=subprocess.run(['docker','exec',nodes[0][0],'node','/fixture/discovery-matrix.js','client',case],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,env=environment,cwd=ROOT)
                if result.returncode or result.stdout != b'OK\n' or result.stderr:
                    try:
                        logs=subprocess.run(['docker','logs','--tail','50',destination_name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env=environment,cwd=ROOT)
                        outputs=(result.stdout,result.stderr,logs.stdout,logs.stderr) if logs.returncode==0 else (result.stdout,result.stderr)
                    except (OSError,subprocess.TimeoutExpired): outputs=(result.stdout,result.stderr)
                    labels=matrix_diagnostics(*outputs)
                    print('Matrix diagnostic: '+(','.join(labels) if labels else 'unavailable'),flush=True)
                    raise AssertionError('matrix forwarding mismatch: '+case)
                expected_loss = matrix_expected_loss(case)
                matrix_losses=parse_matrix_drain(command(gateway,'MATRIX_DRAIN',15),matrix_losses,expected_loss,len(directions))
                rows=snapshot(); assert_proofs(rows,expected,origin_service,origin_deployment,source,('200','409'))
                assert_discovery_case(rows,before,cert_hash('a'),directions,409 if case=='response-409' else 200,case,history)
                project_and_check(rows)
                leak=execute("SELECT count(*) FROM contour.ingestion_payloads WHERE tenant_id='%s' AND position('synthetic-secret-sentinel-' in convert_from(checked_batch,'UTF8'))>0;" % tenant)
                if leak != '0': raise AssertionError('matrix sentinel persisted')
                print('PASS TLS discovery '+case,flush=True)
            run_discovery_cases(run_matrix_case)
            orderly_shutdown(gateway,origin,line,execute)
            print('LIMITATION unavailable plaintext detection not exercised',flush=True)
            return
        for (node,port),name in zip(nodes,['a','b']):
            before={row[13] for row in snapshot()}
            trigger(node,'normal',port)
            after_request(before,cert_hash(name))
        # Each fixed flow emits a different approved request shape. The destination
        # waits for both before responding with a corresponding distinct shape.
        # Its PAIR acknowledgment establishes overlap independently of capture.
        for _ in range(3):
            before={row[13] for row in snapshot()}
            barrier=threading.Barrier(3, timeout=5)
            failures=queue.Queue()
            def concurrent_trigger(node, port, name):
                try:
                    barrier.wait()
                    trigger(node,'concurrent',port,name)
                except BaseException as exc:
                    failures.put(exc)
            workers=[threading.Thread(target=concurrent_trigger,args=(node,port,name))
                     for (node,port),name in zip(nodes,['a','b'])]
            for worker in workers: worker.start()
            try:
                barrier.wait()
            finally:
                for worker in workers: worker.join(timeout=12)
            if any(worker.is_alive() for worker in workers):
                raise AssertionError('concurrent trigger thread leaked')
            if not failures.empty(): raise AssertionError('concurrent trigger failed') from failures.get()
            if line(destination, 5) != 'PAIR a b': raise AssertionError('destination overlap not established')
            drain()
            rows=snapshot(); assert_proofs(rows,expected,origin_service,origin_deployment,source)
            assert_concurrent(rows,before,cert_hash('a'),cert_hash('b'))
        before={row[13] for row in snapshot()}
        trigger(nodes[0][0],'wrong-forwarder',gateway_port)
        drain()
        if {row[13] for row in snapshot()} != before: raise AssertionError('wrong forwarder produced observation')
        before={row[13] for row in snapshot()}
        trigger(nodes[0][0],'duplicate',9443,cert_hash('b'))
        after_request(before,cert_hash('a'))
        for (node,port),name in zip(nodes,['a','b']):
            for mode in ['spoof','xfcc']:
                before={row[13] for row in snapshot()}
                trigger(node,mode,port)
                after_request(before,cert_hash(name))
        for (node,port),name in zip(nodes,['a','b']):
            before={row[13] for row in snapshot()}
            trigger(node,'connection',port)
            after_request(before,cert_hash(name),allow_unattributed=True)
        drain()
        final_rows=snapshot(); assert_proofs(final_rows,expected,origin_service,origin_deployment,source)
        if len(final_rows) != 30: raise AssertionError('final record count mismatch')
        if replacement:
            # Controlled operator transition: Docker inspection is fixture evidence,
            # not platform attestation or proof of host PID/IP allocator reuse.
            def inspected(name):
                result=json.loads(docker('inspect',name))
                if len(result)!=1: raise AssertionError('ambiguous container inspection')
                return result[0]
            old=inspected(nodes[0][0]); assert_owned_replacement(old,nodes[0][0],prefix)
            peer=inspected(nodes[1][0]); assert_owned_replacement(peer,nodes[1][0],prefix)
            namespace=inspected(container)
            addresses={name:network['IPAddress'] for name,network in namespace['NetworkSettings']['Networks'].items()}
            if len(addresses)!=1 or not all(addresses.values()): raise AssertionError('missing shared network address')
            oldrows={row[13]:row for row in final_rows if row[0] in (cert_hash('a'),cert_hash('b'))}
            original_ids=history_record_ids_sql(oldrows)
            def durable_history():
                return json.loads(execute("""SELECT coalesce(json_agg(json_build_array(p.record_id,to_jsonb(p),to_jsonb(b),encode(d.checked_batch,'hex'),to_jsonb(m)) ORDER BY p.record_id),'[]'::json)
FROM contour.origin_proofs p JOIN contour.ingestion_batches b USING (tenant_id,collector_id,batch_id)
JOIN contour.ingestion_payloads d USING (tenant_id,collector_id,batch_id)
JOIN contour.ingestion_v2_metadata m USING (tenant_id,collector_id,batch_id,record_id)
WHERE p.tenant_id='%s' AND p.collector_id='%s' AND p.leaf_sha256 IN (decode('%s','hex'),decode('%s','hex')) AND p.record_id IN (%s);""" % (tenant,collector,cert_hash('a'),cert_hash('b'),original_ids)))
            durable_before=durable_history()
            if ({row[0] for row in durable_before} != set(oldrows) or len(durable_before)!=len(oldrows)
                or not {cert_hash('a'),cert_hash('b')} <= {row[0] for row in oldrows.values()}):
                raise AssertionError('missing original proofs')
            if admission:
                def control(body, name):
                    controlfile=write(name+'.json',json.dumps(body,separators=(',',':')))
                    mounts=files('ca.crt','http-client.crt','http-client.key')+mount(controlfile,'/fixture/control.json')+mount(ROOT/'tests/fixtures/origin-sensor/admission-control.js','/fixture/control.js')
                    process,_=child(name,mounts,NODE,['/fixture/control.js',str(origin_port)],entrypoint='node')
                    result=line(process,10).split()
                    process.wait(timeout=10)
                    if process.returncode or len(result)!=5 or result[0]!='CONTROL': raise RuntimeError('origin admission control failed')
                    return result[1:]
                historical_hex=execute("SELECT encode(d.checked_batch,'hex') FROM contour.ingestion_payloads d JOIN contour.origin_proofs p USING(tenant_id,collector_id,batch_id) WHERE p.tenant_id='%s' AND p.collector_id='%s' AND p.leaf_sha256=decode('%s','hex') ORDER BY d.batch_id LIMIT 1;" % (tenant,collector,cert_hash('a')))
                historical=json.loads(bytes.fromhex(historical_hex))
                historical_before=control(historical,'control-history-before')
                if historical_before[:3]!=['200','duplicate','false']: raise AssertionError('historical receipt unavailable before closure')
            old_lifecycle=expected[cert_hash('a')][1]
            execute("SELECT set_config('apicontour.tenant_id','%s',false); SELECT contour.end_origin('%s','lifecycle_closed','%s');" % (tenant,tenant,old_lifecycle))
            if admission:
                historical_after=control(historical,'control-history-after')
                if historical_after!=historical_before: raise AssertionError('historical duplicate receipt changed after closure')
            docker('rm','-f',old['Id']); resources.remove(next(resource for resource in resources if resource['name']==nodes[0][0]))
            certificate('c','instance-c','clientAuth')
            if cert_hash('c') in expected: raise AssertionError('replacement leaf reused')
            instance,lifecycle,credential,grant=['00000000-0000-0000-0000-%012x' % (0xd120+n) for n in range(4)]
            execute("SELECT set_config('apicontour.tenant_id','%s',false); INSERT INTO contour.workload_instances VALUES ('%s','%s','%s','%s','%s','%s'); SELECT contour.enroll_origin('%s','%s','%s','%s','%s','%s','%s','trusted_platform_v1',decode(repeat('cc',32),'hex')); SELECT contour.enroll_origin_credential('%s','%s','%s',decode('%s','hex')); SELECT contour.grant_origin_observer('%s','%s','%s','%s','%s','%s','%s','%s','%s');" % (tenant,tenant,ITEM,origin_service,ITEM,origin_deployment,instance,tenant,lifecycle,ITEM,origin_service,ITEM,origin_deployment,instance,tenant,credential,lifecycle,cert_hash('c'),tenant,grant,lifecycle,collector,source,ITEM,ITEM,ITEM,ITEM))
            expected[cert_hash('c')]=(instance,lifecycle,credential,grant)
            def replacement_node(name,leaf,port):
                cname=prefix+'-'+name
                flow=write('flows-'+name+'.json',json.dumps(flows(cert_hash('b'),'a')))
                mounts=mount(flow,'/fixture/flows.json')+mount(ROOT/'tests/fixtures/origin-sensor/settings.js','/fixture/settings.js')+mount(ROOT/'tests/fixtures/origin-sensor/trigger.js','/fixture/trigger.js')+mount(folder/(leaf+'.crt'),'/fixture/client.crt')+mount(folder/(leaf+'.key'),'/fixture/client.key')+mount(folder/'ca.crt','/fixture/ca.crt')
                resources.append({'name':cname,'id':None})
                resources[-1]['id']=docker('run','-d','--name',cname,*common,'-e','FIXTURE_PORT='+str(port),'--tmpfs','/data:rw,nosuid,nodev,noexec,size=16m,mode=1777','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777',*mounts,'--entrypoint','node',NODE,'/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/fixture/settings.js')
                until=time.monotonic()+30
                while True:
                    try: trigger(cname,'ready',port); break
                    except RuntimeError:
                        if time.monotonic()>=until: raise AssertionError('replacement listener unavailable')
                        time.sleep(.1)
                return cname
            newname=replacement_node('c','c',1880); new=inspected(newname); assert_owned_replacement(new,newname,prefix)
            if old['Id']==new['Id'] or old['State']['StartedAt']==new['State']['StartedAt'] or old['HostConfig']['NetworkMode']!=new['HostConfig']['NetworkMode'] or new['HostConfig']['NetworkMode']!='container:'+container:
                raise AssertionError('replacement process identity or network mismatch')
            if {name:network['IPAddress'] for name,network in inspected(container)['NetworkSettings']['Networks'].items()}!=addresses: raise AssertionError('shared address changed')
            before={row[13] for row in snapshot()}; trigger(newname,'normal',1880); after_request(before,cert_hash('c'))
            before={row[13] for row in snapshot()}; trigger(nodes[1][0],'normal',1881); after_request(before,cert_hash('b'))
            oldprobe=replacement_node('old-leaf','a',1882)
            if admission:
                def control_body(leaf):
                    body=copy.deepcopy(historical)
                    body['batch_id']=str(uuid.uuid4())
                    body['records']=body['records'][:1]
                    now=datetime.datetime.now(datetime.timezone.utc)
                    iso=lambda value: value.isoformat(timespec='microseconds').replace('+00:00','Z')
                    body['created_at']=iso(now)
                    body['records'][0]['record'].update(record_id=str(uuid.uuid4()),queued_at=iso(now),first_seen=iso(now),last_seen=iso(now),expires_at=iso(now+datetime.timedelta(seconds=30)))
                    body['records'][0]['origin_witness']={'kind':'downstream_mtls_leaf_sha256_v1','leaf_sha256':leaf}
                    return body
                good=control_body(cert_hash('c'))
                control_record_ids.add(good['records'][0]['record']['record_id'])
                first=control(good,'control-good')
                duplicate=control(good,'control-duplicate')
                if first[:3]!=['200','accepted','false'] or duplicate[:3]!=['200','duplicate','false'] or first[3]!=duplicate[3]:
                    raise AssertionError('control receipt/duplicate mismatch')
                stale=control_body(cert_hash('a'))
                # Include every row, including control rows and quota, in the
                # before/after comparison; no failure may count as a denial.
                durable_at_control=all_durable()
                rejected=control(stale,'control-stale')
                print('Stale control: ' + ' '.join(rejected[:3]),flush=True)
                if all_durable()!=durable_at_control: raise AssertionError('stale control mutated durable state')
            configure_pg_diagnostic(execute)
            before={row[13] for row in snapshot()}
            marker='fixture_marker_'+secrets.token_hex(8)
            execute("DO $$ BEGIN RAISE LOG '%s'; END $$;" % marker)
            if admission and command(gateway,'ADMISSION_BASELINE',10) != 'BASELINE 0':
                raise RuntimeError('admission baseline unavailable')
            trigger(oldprobe,'normal',1882)
            try:
                try:
                    if admission:
                        category, losses, purged, acknowledged, pending = parse_admission_diagnostic(command(gateway,'ADMISSION_DRAIN',15))
                        print(f'Admission drain diagnostic: {category} capture_losses={losses} purged={purged} acknowledged_records={acknowledged} pending={pending}',flush=True)
                        require_terminal_admission((category,losses,purged,acknowledged,pending))
                    else:
                        category, losses, acknowledgements = parse_drain_diagnostic(command(gateway,'DRAIN_DIAGNOSTIC',15))
                        print(f'Replacement drain diagnostic: {category} losses={losses} acknowledgements={acknowledgements}',flush=True)
                        if (category,losses,acknowledgements) != ('ok',0,0): raise RuntimeError('replacement drain diagnostic reported failure')
                except ValueError:
                    raise RuntimeError('invalid replacement drain diagnostic') from None
            except Exception:
                try:
                    records=read_pg_diagnostic(container, environment, marker)
                    for state, kind, digest in records:
                        print(f'PostgreSQL diagnostic: sqlstate={state} kind={kind}' + (f' message_sha256={digest}' if digest else ''),flush=True)
                    if not records: print('PostgreSQL diagnostic: no new error records',flush=True)
                except Exception:
                    print('PostgreSQL diagnostic: unavailable or ambiguous',flush=True)
                raise
            if admission and rejected[:3]!=['422','not_admissible','false']:
                raise AssertionError('stale control expected 422 not_admissible')
            rows=snapshot(); assert_proofs(rows,expected,origin_service,origin_deployment,source)
            assert_replacement_history(rows,oldrows,before,cert_hash('a'))
            fresh=[row for row in rows if row[13] not in before]
            if admission:
                if fresh or all_durable()!=durable_at_control: raise AssertionError('discard changed durable state')
            else:
                if len(fresh)!=2 or any(row[20]!='unattributed' for row in fresh):
                    raise RuntimeError('stale-leaf ingress outcome unavailable: explicit resolution diagnostic required')
                assert_transition(rows,before,cert_hash('a'),allow_unattributed=True)
            if durable_history()!=durable_before: raise AssertionError('durable historical evidence changed')
            before={row[13] for row in rows}; trigger(newname,'normal',1880); after_request(before,cert_hash('c'))
            if admission:
                before={row[13] for row in snapshot()}; trigger(nodes[1][0],'normal',1881); after_request(before,cert_hash('b'))
            print('Operator-controlled replacement retained historical attribution on the same shared namespace/address/port; allocator and host PID reuse not tested',flush=True)
        # Both paths require the same orderly process and DB connection checks.
        orderly_shutdown(gateway,origin,line,execute)
        print('Two stock Node-RED instances reached origin HTTPS and retained distinct proofs',flush=True)
    finally:
        prior = sys.exc_info()[1]
        errors=[]
        # Remove only containers created by this fixture before waiting for
        # attached Docker clients. Container PID 1 need not handle SIGTERM.
        def inspect_resource(name):
            result=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=30,env=environment,cwd=ROOT)
            if result.returncode:
                if re.fullmatch(r'Error: No such object: '+re.escape(name)+r'\s*',result.stderr): return None
                raise RuntimeError('fixture container inspection failed')
            infos=json.loads(result.stdout)
            if len(infos)!=1: raise RuntimeError('ambiguous fixture container')
            return infos[0]
        try:
            cleanup_fixture_containers(resources, prefix, inspect_resource,
                lambda ident: docker('rm','-f',ident),
                lambda ident: bool(docker('ps','-aq','--no-trunc','--filter','id='+ident)))
        except Exception as exc: errors.append(exc)
        try:
            remaining=set(docker('ps','-a','--format','{{.Names}}').splitlines())
            if any(resource['name'] in remaining for resource in resources):
                errors.append(RuntimeError('fixture container remained'))
        except Exception as exc: errors.append(exc)
        for p in reversed(processes):
            try:
                if p.poll() is None: p.wait(timeout=5)
            except Exception as exc:
                p.kill(); p.wait(timeout=3); errors.append(exc)
            for stream in (p.stdin,p.stderr):
                if stream and not stream.closed: stream.close()
        for thread in readers:
            thread.join(timeout=3)
            if thread.is_alive(): errors.append(RuntimeError('fixture stdout reader leaked'))
        for p in processes:
            if p.stdout and not p.stdout.closed: p.stdout.close()
        if errors:
            failure = RuntimeError('origin sensor fixture cleanup failed or container creation uncertain')
            if prior is not None: raise BaseExceptionGroup('fixture and cleanup failed', [prior, failure])
            raise failure from errors[0]
