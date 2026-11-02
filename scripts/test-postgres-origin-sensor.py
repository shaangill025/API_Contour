"""Owned two-instance origin sensor fixture, called only by the isolated PG TLS lane.

No existing profiles or keys are used. This module does not launch on import.
"""
import hashlib
import json
import os
from pathlib import Path
import queue
import secrets
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


def assert_proofs(rows, expected, origin_service, origin_deployment, source):
    for row in rows:
        if row[5:9] != [ITEM]*4 or row[15] != 'POST' or row[17] != source or row[18] != 'http_json_v1' or row[19] != 2:
            raise AssertionError('observation tuple mismatch')
        if row[14] not in ('request','response') or (row[14] == 'response' and row[16] != '200'):
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


def run_cases(container, execute, setup, directory, environment):
    """Requires migrations 1,2,3,4,13-17 and origin login, and built origin_sensor_probe."""
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
        common=['--pull','never','--network','container:'+container,'--user',f'{os.getuid()}:{os.getgid()}','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','256m','--log-driver','local']
        def child(name, mounts, image, argv, env_names=(), entrypoint=None):
            cname=prefix+'-'+name; resources.append(('container',cname))
            args=['docker','run','-i','--name',cname,*common]
            for key in env_names: args += ['-e',key]
            if entrypoint: args += ['--entrypoint',entrypoint]
            return start([*args,*mounts,image,*argv]),cname
        def files(*names):
            return sum((mount(folder/n,'/fixture/'+n) for n in names),[])
        # Both probes share only the owned PostgreSQL network namespace; DB and
        # gateway endpoints remain loopback inside that namespace.
        origin_env=dict(environment,CONTOUR_ORIGIN_DATABASE_USER='contour_origin_ingress_test')
        environment=origin_env
        origin,_=child('origin',files('ca.crt','ca.crt.der','server.crt.der','server.key.der','http-client.crt.der','signer.raw'),fixture_image,['/usr/local/bin/origin_https_probe','5432','/fixture',tenant,collector,'5000'],['CONTOUR_FIXTURE_PASSWORD','CONTOUR_ORIGIN_DATABASE_USER'])
        origin_port=ready(origin)
        destination_mounts=files('destination.crt','destination.key','ca.crt')+mount(ROOT/'tests/fixtures/origin-sensor/destination.js','/fixture/destination.js')
        environment=dict(environment,EXPECTED_CLIENT_SHA256=cert_hash('upstream'))
        destination,_=child('destination',destination_mounts,NODE,['/fixture/destination.js'],['EXPECTED_CLIENT_SHA256'],'node')
        if ready(destination)!=9444: raise AssertionError('destination listener mismatch')
        config = dict(server_certificate_der='/fixture/server.der',server_key_der='/fixture/server-key.der',forwarder_ca_der='/fixture/ca.crt.der',forwarder_leaf_der='/fixture/forwarder.der',upstream_address='127.0.0.1:9444',upstream_name='pilot-destination',upstream_ca_der='/fixture/ca.crt.der',upstream_client_certificate_der='/fixture/upstream.der',upstream_client_key_der='/fixture/upstream-key.der',delivery_address='127.0.0.1:%d'%origin_port,delivery_name='localhost',delivery_ca_der='/fixture/ca.crt.der',delivery_client_certificate_der='/fixture/http-client.der',delivery_client_key_der='/fixture/http-client-key.der',tenant=tenant,collector=collector,source=source,workload=[ITEM]*4,policy_key_id='fixture',policy_key_file='/fixture/signer.raw')
        cfg=write('gateway.json',json.dumps(config))
        gateway,_=child('gateway',files('server.der','server-key.der','ca.crt.der','forwarder.der','upstream.der','upstream-key.der','http-client.der','http-client-key.der','signer.raw','gateway.json'),fixture_image,['/usr/local/bin/origin_sensor_probe','/fixture/gateway.json'])
        gateway_port=ready(gateway)
        edgecfg=write('envoy.json',json.dumps(generated_edge(gateway_port)))
        edge=prefix+'-edge'; resources.append(('container',edge))
        edge_mounts = files('edge.crt','edge.key','forwarder.crt','forwarder.key','ca.crt','envoy.json')
        docker('run','-d','--name',edge,*common,*edge_mounts,ENVOY,'envoy','-c','/fixture/envoy.json','--log-level','error','--concurrency','1')
        nodes=[]
        for name,other,port in [('a','b',1880),('b','a',1881)]:
            flow=write('flows-'+name+'.json',json.dumps(flows(cert_hash(other),name)))
            cname=prefix+'-'+name; resources.append(('container',cname))
            mounts=mount(flow,'/fixture/flows.json')+mount(ROOT/'tests/fixtures/origin-sensor/settings.js','/fixture/settings.js')+mount(ROOT/'tests/fixtures/origin-sensor/trigger.js','/fixture/trigger.js')+mount(folder/(name+'.crt'),'/fixture/client.crt')+mount(folder/(name+'.key'),'/fixture/client.key')+mount(folder/'ca.crt','/fixture/ca.crt')
            docker('run','-d','--name',cname,*common,'-e','FIXTURE_PORT='+str(port),'--tmpfs','/data:rw,nosuid,nodev,noexec,size=16m,mode=1777','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777',*mounts,'--entrypoint','node',NODE,'/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/fixture/settings.js')
            nodes.append((cname,port))
        def trigger(node,mode,port,extra=''):
            result=docker('exec',node,'node','/fixture/trigger.js',mode,str(port),extra,seconds=10)
            if result != ('READY' if mode=='ready' else 'OK'): raise AssertionError('fixture trigger mismatch')
        def snapshot():
            sql = """SELECT coalesce(json_agg(json_build_array(encode(p.leaf_sha256,'hex'),p.instance_id,p.lifecycle_id,p.credential_id,p.grant_id,m.project_id,m.service_id,m.environment_id,m.deployment_id,p.origin_project_id,p.origin_service_id,p.origin_environment_id,p.origin_deployment_id,m.record_id,r.value->'record'->>'direction',r.value->'record'->>'operation',r.value->'record'->>'status_code',m.source_id,m.parser_profile,m.policy_revision,m.attribution_class,r.value->'record'->'structure')), '[]'::json)
FROM contour.ingestion_v2_metadata m JOIN contour.ingestion_payloads b USING (tenant_id,collector_id,batch_id)
LEFT JOIN contour.origin_proofs p USING (tenant_id,collector_id,batch_id,record_id)
CROSS JOIN LATERAL jsonb_array_elements(convert_from(b.checked_batch,'UTF8')::jsonb->'records') r(value)
WHERE m.tenant_id='%s' AND m.collector_id='%s' AND r.value->'record'->>'record_id'=m.record_id::text;""" % (tenant,collector)
            return json.loads(execute(sql))
        def drain():
            value=command(gateway,'DRAIN',15).split()
            if len(value)!=4 or value[:3]!=['DRAIN','0','0'] or not value[3].isdigit():
                raise AssertionError('gateway did not drain without loss')
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
        # Stop the gateway before shutting down the origin HTTP server, then
        # demand its normal two-phase cancellation and database cleanup.
        gateway.stdin.write('STOP\n'); gateway.stdin.flush(); gateway.wait(timeout=5)
        if gateway.returncode: raise AssertionError('gateway shutdown failed')
        origin.stdin.write('\n'); origin.stdin.flush()
        if line(origin,10) != 'STOPPED': raise AssertionError('origin HTTP shutdown failed')
        origin.stdin.write('\n'); origin.stdin.flush(); origin.stdin.close()
        origin.wait(timeout=10)
        if origin.returncode or origin.stderr.read(): raise AssertionError('origin HTTP cleanup failed')
        until=time.monotonic()+10
        while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_origin_ingress_test';") != '0':
            if time.monotonic()>=until: raise AssertionError('origin database connections leaked')
            time.sleep(.1)
        print('Two stock Node-RED instances reached origin HTTPS and retained distinct proofs',flush=True)
    finally:
        prior = sys.exc_info()[1]
        errors=[]
        for p in reversed(processes):
            try:
                if p.poll() is None: p.terminate(); p.wait(timeout=5)
            except Exception as exc:
                p.kill(); p.wait(timeout=3); errors.append(exc)
            for stream in (p.stdin,p.stderr):
                if stream and not stream.closed: stream.close()
        for thread in readers:
            thread.join(timeout=3)
            if thread.is_alive(): errors.append(RuntimeError('fixture stdout reader leaked'))
        for p in processes:
            if p.stdout and not p.stdout.closed: p.stdout.close()
        for kind,name in reversed(resources):
            try:
                if kind == 'container': docker('rm','-f',name)
                else: docker('network','rm',name)
            except Exception as exc: errors.append(exc)
        if errors:
            failure = RuntimeError('origin sensor fixture cleanup failed')
            if prior is not None: raise BaseExceptionGroup('fixture and cleanup failed', [prior, failure])
            raise failure from errors[0]
