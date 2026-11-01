"""Actual mTLS HTTP to PostgreSQL origin role; invoked by the owned TLS fixture.

Call run_cases after opt-in migrations and contour_origin_ingress_test setup.
The executable is the built contour-ingress origin_https_probe example.
"""
import contextlib
import copy
import http.client
import json
import queue
import secrets
import ssl
import subprocess
import threading
import uuid

ITEM = '00000000-0000-0000-0000-000000000001'


def run_cases(execute, setup, pg_port, directory, environment, probe):
    def command(args):
        result = subprocess.run(args, capture_output=True, timeout=15)
        if result.returncode:
            raise AssertionError('origin HTTPS certificate fixture failed')

    (directory/'origin-http.cnf').write_text('[req]\ndistinguished_name=dn\n[dn]\n')
    (directory/'origin-http-ext').write_text('basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n')
    for name in ['ca', 'server']:
        command(['openssl','x509','-in',str(directory/(name+'.crt')),'-outform','DER','-out',str(directory/(name+'.crt.der'))])
    command(['openssl','pkcs8','-topk8','-nocrypt','-in',str(directory/'server.key'),'-outform','DER','-out',str(directory/'server.key.der')])
    for name, issuer in [('http-client','ca'), ('http-other','ca'), ('http-untrusted','untrusted')]:
        command(['openssl','req','-new','-newkey','rsa:2048','-nodes','-sha256','-config',str(directory/'origin-http.cnf'),'-subj','/CN=inert origin fixture','-keyout',str(directory/(name+'.key')),'-out',str(directory/(name+'.csr'))])
        command(['openssl','x509','-req','-sha256','-in',str(directory/(name+'.csr')),'-CA',str(directory/(issuer+'.crt')),'-CAkey',str(directory/(issuer+'.key')),'-CAcreateserial','-days','1','-extfile',str(directory/'origin-http-ext'),'-out',str(directory/(name+'.crt'))])
        command(['openssl','x509','-in',str(directory/(name+'.crt')),'-outform','DER','-out',str(directory/(name+'.crt.der'))])

    def context(client):
        ctx = ssl.create_default_context(cafile=str(directory/'ca.crt'))
        if client:
            ctx.load_cert_chain(directory/(client+'.crt'), directory/(client+'.key'))
        return ctx

    @contextlib.contextmanager
    def server(body, user='contour_origin_ingress_test'):
        env = dict(environment, CONTOUR_ORIGIN_DATABASE_USER=user)
        process = subprocess.Popen([str(probe),str(pg_port),str(directory),body['tenant_id'],body['collector_id'],'5000'], stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        markers = queue.Queue()
        reader = threading.Thread(target=lambda: [markers.put(process.stdout.readline()) for _ in range(2)], daemon=True)
        reader.start()
        try:
            ready = markers.get(timeout=15).split()
            if len(ready) != 2 or ready[0] != 'READY':
                raise AssertionError('origin HTTPS server startup failed')
            yield int(ready[1])
        finally:
            try:
                if process.poll() is not None:
                    raise AssertionError('origin HTTPS server exited early')
                process.stdin.write('\n'); process.stdin.flush()
                if markers.get(timeout=10).strip() != 'STOPPED':
                    raise AssertionError('origin HTTPS server did not stop')
                output, errors = process.communicate(input='\n', timeout=10)
                if process.returncode or output or errors:
                    raise AssertionError('origin HTTPS server cleanup failed')
            finally:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=3)
                reader.join(2)
                for stream in [process.stdin, process.stdout, process.stderr]: stream.close()

    def request(port, body, status, path='/v2/batches', client='http-client', headers=None, method='POST'):
        raw = json.dumps(body).encode() if isinstance(body,dict) else body
        connection = http.client.HTTPSConnection('localhost',port,context=context(client),timeout=8)
        try:
            connection.request(method,path,raw,headers or {'Content-Type':'application/json'})
            response = connection.getresponse()
            payload = response.read(8*1048576+1)
            if response.status != status:
                raise AssertionError('origin HTTPS status expected %d got %d: %s' % (status,response.status,payload[:300]))
            value = json.loads(payload)
            if status != 200:
                assert set(value) == {'code','message','request_id','retryable'}
                assert b'SYNTHETIC_SECRET' not in payload
            return value
        finally:
            connection.close()

    raw, collector, source = setup('origin_http')
    tenant = raw['tenant_id']
    instance, lifecycle, credential, grant = ['00000000-0000-0000-0000-%012x' % x for x in [0xb101,0xb102,0xb103,0xb104]]
    fingerprint = '33'*32
    execute("SELECT set_config('apicontour.tenant_id','%s',false); INSERT INTO contour.workload_instances VALUES ('%s','%s','%s','%s','%s','%s');" % (tenant,tenant,ITEM,ITEM,ITEM,ITEM,instance))
    execute("SELECT set_config('apicontour.tenant_id','%s',false); SELECT contour.enroll_origin('%s','%s','%s','%s','%s','%s','%s','trusted_platform_v1',decode(repeat('aa',32),'hex'));" % (tenant,tenant,lifecycle,ITEM,ITEM,ITEM,ITEM,instance))
    execute("SELECT set_config('apicontour.tenant_id','%s',false); SELECT contour.enroll_origin_credential('%s','%s','%s',decode('%s','hex'));" % (tenant,tenant,credential,lifecycle,fingerprint))
    execute("SELECT set_config('apicontour.tenant_id','%s',false); SELECT contour.grant_origin_observer('%s','%s','%s','%s','%s','%s','%s','%s','%s');" % (tenant,tenant,grant,lifecycle,collector,source,ITEM,ITEM,ITEM,ITEM))
    body = copy.deepcopy(raw)
    body['wire_version'] = 2
    body['records'] = [dict(record=record, origin_witness={'kind':'downstream_mtls_leaf_sha256_v1','leaf_sha256':fingerprint}) for record in raw['records']]
    scope = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (tenant,collector,body['batch_id'])
    with server(body) as port:
        challenge = secrets.token_hex(32)
        refreshed = request(port,dict(wire_version=1,challenge=challenge,source_ids=[source]),200,path='/v1/collector-authority')
        signed = json.loads(bytes.fromhex(execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE tenant_id='%s' AND collector_id='%s' AND revision=(SELECT active_revision FROM contour.collector_authorization WHERE tenant_id='%s' AND collector_id='%s');" % (tenant,collector,tenant,collector))))
        assert refreshed['challenge'] == challenge and refreshed['signed_policy'] == signed
        assert (refreshed['tenant_id'],refreshed['collector_id']) == (tenant,collector)
        first = request(port,body,200)
        assert first['status'] == 'accepted'
        assert execute('SELECT count(*) FROM contour.origin_proofs WHERE '+scope+';') == '1'
        second = request(port,body,200,headers={'Content-Type':'application/json','X-Contour-Tenant':'forged','X-Contour-Collector':'forged'})
        assert second['status'] == 'duplicate' and all(first[k] == second[k] for k in ['batch_id','receipt_id','accepted_at'])
        changed = copy.deepcopy(body); changed['records'][0]['record']['count'] += 1
        assert request(port,changed,409)['code'] == 'batch_conflict'
        spoof = copy.deepcopy(body); spoof['tenant_id'] = 'bbbbbbbb-0000-0000-0000-000000000000'
        assert request(port,spoof,403)['code'] == 'not_authorized'
        request(port,body,403,client='http-other')
        for client in [None,'http-untrusted']:
            try: request(port,body,200,client=client)
            except (OSError,http.client.HTTPException): pass
            else: raise AssertionError('untrusted TLS peer accepted')
        request(port,body,404,path='/v1/batches')
        request(port,body,404,path='/v2/batches?role=origin')
        request(port,raw,400)
        request(port,b'{"SYNTHETIC_SECRET":',400)
        request(port,b' ' * 1048577,413)
        request(port,body,415,headers={'Content-Type':'application/json','Content-Encoding':'gzip'})
        request(port,body,405,method='GET')
        execute("BEGIN; ALTER TABLE contour.origin_proofs DISABLE TRIGGER origin_proof_immutable; DELETE FROM contour.origin_proofs WHERE %s; ALTER TABLE contour.origin_proofs ENABLE TRIGGER origin_proof_immutable; COMMIT;" % scope)
        error = request(port,body,503)
        assert error['code'] == 'database_unavailable'
        assert execute('SELECT count(*) FROM contour.origin_proofs WHERE '+scope+';') == '0'
        quota = copy.deepcopy(body); quota['batch_id'] = str(uuid.uuid4())
        previous = int(execute("SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s';" % tenant))
        execute("UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id='%s';" % tenant)
        try:
            error = request(port,quota,423)
            assert error['code'] == 'logical_quota' and error['retryable'] is False
            assert execute("SELECT count(*) FROM contour.ingestion_batches WHERE tenant_id='%s' AND collector_id='%s' AND batch_id='%s';" % (tenant,collector,quota['batch_id'])) == '0'
        finally:
            execute("UPDATE contour.origin_logical_usage SET used_bytes=%d WHERE tenant_id='%s';" % (previous,tenant))
    # The origin profile rejects a basic ingestion login even when it has SQL privileges.
    with server(body,'contour_tls') as port:
        assert request(port,body,403)['code'] == 'not_authorized'
        assert request(port,dict(wire_version=1,challenge=secrets.token_hex(32),source_ids=[source]),403,path='/v1/collector-authority')['code'] == 'not_authorized'
    execute("GRANT contour_v2_ingress TO contour_origin_ingress_test;")
    try:
        with server(body) as port:
            assert request(port,body,403)['code'] == 'not_authorized'
            assert request(port,dict(wire_version=1,challenge=secrets.token_hex(32),source_ids=[source]),403,path='/v1/collector-authority')['code'] == 'not_authorized'
    finally:
        execute("REVOKE contour_v2_ingress FROM contour_origin_ingress_test;")
    print('Actual origin HTTPS receipt/replay/proofs, signed refresh, role/identity/version, bounds and quota passed',flush=True)
