"""Real operator-mapped mTLS HTTP/1 to the existing restricted PostgreSQL fixture."""
import contextlib
import copy
import datetime
import http.client
import json
import queue
import socket
import ssl
import subprocess
import threading
import time
import uuid
import runpy
from pathlib import Path


def run_cases(container, execute, setup, probe, pg_port, directory, environment):
    print('Starting actual operator-mapped HTTPS ingestion fixture',flush=True)
    (directory/'http-request.cnf').write_text('[req]\ndistinguished_name=dn\n[dn]\n')
    def command(argv, timeout=10):
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
        if result.returncode:
            raise AssertionError('HTTPS fixture command failed')
        return result.stdout

    for name in ['ca', 'server']:
        command(['openssl','x509','-in',str(directory/(name+'.crt')),'-outform','DER','-out',str(directory/(name+'.crt.der'))])
    command(['openssl','pkcs8','-topk8','-nocrypt','-in',str(directory/'server.key'),'-outform','DER','-out',str(directory/'server.key.der')])
    (directory/'http-extensions').write_text('basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n')
    for name, issuer in [('http-client','ca'), ('http-other','ca'), ('http-untrusted','untrusted')]:
        command(['openssl','req','-new','-newkey','rsa:2048','-nodes','-sha256','-config',str(directory/'http-request.cnf'),'-subj','/CN=inert HTTPS fixture','-keyout',str(directory/(name+'.key')),'-out',str(directory/(name+'.csr'))])
        command(['openssl','x509','-req','-sha256','-in',str(directory/(name+'.csr')),'-CA',str(directory/(issuer+'.crt')),'-CAkey',str(directory/(issuer+'.key')),'-CAcreateserial','-days','1','-extfile',str(directory/'http-extensions'),'-out',str(directory/(name+'.crt'))])
        command(['openssl','x509','-in',str(directory/(name+'.crt')),'-outform','DER','-out',str(directory/(name+'.crt.der'))])

    def context(client='http-client'):
        result = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        result.minimum_version = ssl.TLSVersion.TLSv1_2
        result.load_verify_locations(cafile=str(directory/'ca.crt'))
        if client:
            result.load_cert_chain(directory/(client+'.crt'),directory/(client+'.key'))
        return result

    def timestamp(text):
        # Python 3.9 fromisoformat accepts fewer fractional widths than RFC3339.
        pattern = '%Y-%m-%dT%H:%M:%S.%f%z' if '.' in text else '%Y-%m-%dT%H:%M:%S%z'
        return datetime.datetime.strptime(text, pattern)

    @contextlib.contextmanager
    def server(body, backend=None, deadline=3000, stopped=None):
        process = subprocess.Popen([probe,str(backend or pg_port),str(directory),body['tenant_id'],body['collector_id'],str(deadline)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        markers = queue.Queue()
        reader = threading.Thread(target=lambda: [markers.put(process.stdout.readline()) for _ in range(2)],daemon=True)
        reader.start()
        try:
            marker = markers.get(timeout=12).strip().split()
            if len(marker)!=2 or marker[0]!='READY':
                raise AssertionError('HTTPS server startup failed')
            yield int(marker[1])
        finally:
            try:
                if process.poll() is None:
                    process.stdin.write('\n')
                    process.stdin.flush()
                    if markers.get(timeout=5).strip()!='STOPPED':
                        raise AssertionError('HTTPS server did not join owned connections')
                    started = time.monotonic()
                    until = started+deadline/1000+2
                    def observe(sql):
                        remaining = until-time.monotonic()
                        if remaining<=0:
                            raise AssertionError('HTTP shutdown cleanup observation deadline')
                        value = execute(sql,timeout=min(5,remaining))
                        if time.monotonic()>until:
                            raise AssertionError('HTTP shutdown cleanup observation deadline')
                        return value
                    if stopped is not None:
                        stopped()
                    state = observe("SELECT state||'/'||coalesce(wait_event,'none') FROM pg_stat_activity WHERE usename='contour_tls';")
                    if state:
                        print('HTTP local shutdown backend state: '+state,flush=True)
                    while observe("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls';")!='0':
                        time.sleep(min(0.02,max(0,until-time.monotonic())))
                    if state:
                        print('HTTP backend released after local STOPPED in %.2fs' % (time.monotonic()-started),flush=True)
                    if process.poll() is not None:
                        raise AssertionError('HTTPS runtime exited before cleanup proof')
                    out, errors = process.communicate(input='\n',timeout=5)
                    if process.returncode or out or errors:
                        raise AssertionError('HTTPS server shutdown failed')
                else:
                    raise AssertionError('HTTPS server exited before shutdown')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                reader.join(2)
                for pipe in [process.stdin,process.stdout,process.stderr]:
                    pipe.close()

    def request(port, body, wanted=200, client='http-client', headers=None, method='POST', target='/v1/batches'):
        connection = http.client.HTTPSConnection('localhost',port,context=context(client),timeout=8)
        try:
            raw = json.dumps(body).encode() if isinstance(body,dict) else body
            connection.request(method,target,raw,headers or {'Content-Type':'application/json'})
            response = connection.getresponse()
            payload = response.read(4096)
            if response.status!=wanted:
                raise AssertionError('HTTPS response status mismatch: expected %d, got %d' % (wanted,response.status))
            value = json.loads(payload)
            if wanted==200:
                if set(value)!=set(['batch_id','status','receipt_id','accepted_at']) or value['status'] not in ['accepted','duplicate']:
                    raise AssertionError('invalid HTTPS receipt schema')
                uuid.UUID(value['batch_id'])
                uuid.UUID(value['receipt_id'])
                timestamp(value['accepted_at'])
            else:
                if set(value)!=set(['code','message','request_id','retryable']) or uuid.UUID(value['request_id']).version!=4:
                    raise AssertionError('invalid safe HTTP error schema')
                if 'SYNTHETIC_SECRET' in payload.decode():
                    raise AssertionError('HTTP error leaked metadata')
            return value
        finally:
            connection.close()

    def receipt_identity(value):
        return (value['batch_id'],value['receipt_id'],value['accepted_at'])

    def scope(body):
        return "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (body['tenant_id'],body['collector_id'],body['batch_id'])

    def micros(instant):
        delta = instant-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
        return (delta.days*86400+delta.seconds)*1000000+delta.microseconds

    def database_now(timeout=30):
        return int(execute('SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;',timeout=timeout))

    def future_expiry():
        # Both configured connect and submit budgets are3s; allow setup margin too.
        instant = datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)+datetime.timedelta(microseconds=database_now()+10000000)
        return instant.isoformat(timespec='microseconds').replace('+00:00','Z')

    def wait_expired(text):
        expiry = micros(timestamp(text))
        until = time.monotonic()+15
        while True:
            remaining = until-time.monotonic()
            if remaining<=0:
                raise AssertionError('bounded actual database expiry wait failed')
            now = database_now(timeout=min(5,remaining))
            if time.monotonic()>until:
                raise AssertionError('bounded actual database expiry wait failed')
            if now>=expiry:
                return
            time.sleep(min(0.1,max(0,until-time.monotonic())))

    def persisted(body, receipt):
        row = execute("SELECT receipt_id::text,floor(extract(epoch FROM accepted_at)*1000000)::bigint FROM contour.ingestion_batches WHERE %s;" % scope(body))
        if row!='%s|%d' % (receipt['receipt_id'],micros(timestamp(receipt['accepted_at']))):
            raise AssertionError('HTTPS receipt changed stored ID or acceptance time')

    aggregate, _, _ = setup('https_aggregate',current=116,history=tuple(range(100,117)),padded=True)
    original = aggregate['records'][0]
    aggregate['records'] = [dict(original,record_id='00000000-0000-0000-0000-%012x' % revision,policy_revision=revision) for revision in range(100,117)]
    with server(aggregate) as port:
        limit = request(port,aggregate,413)
        if limit['code']!='authority_too_large' or limit['retryable']:
            raise AssertionError('deterministic authority bound requested unchanged retry')
        if execute('SELECT count(*) FROM contour.ingestion_batches WHERE '+scope(aggregate)+';')!='0':
            raise AssertionError('oversized authority committed an inbox row')
    print('HTTP aggregate authority split-required bound passed',flush=True)

    body, _, _ = setup('https_valid')
    with server(body) as port:
        first = request(port,body)
        if first['status']!='accepted':
            raise AssertionError('HTTPS first insert was not accepted')
        replay = request(port,body)
        if replay['status']!='duplicate' or receipt_identity(first)!=receipt_identity(replay):
            raise AssertionError('HTTPS replay changed committed receipt')
        stored = execute("SELECT receipt_id::text FROM contour.ingestion_batches WHERE tenant_id='%s' AND collector_id='%s' AND batch_id='%s';" % (body['tenant_id'],body['collector_id'],body['batch_id']))
        if stored!=first['receipt_id']:
            raise AssertionError('HTTPS 200 preceded persisted receipt')
        persisted(body,first)
        conflict = copy.deepcopy(body)
        conflict['records'][0]['count']+=1
        request(port,conflict,409)
        spoof = copy.deepcopy(body)
        spoof['tenant_id']='bbbbbbbb-0000-0000-0000-000000000000'
        replay = request(port,body,headers={'Content-Type':'application/json','X-Contour-Tenant':spoof['tenant_id'],'X-Contour-Collector':'forged'})
        if receipt_identity(replay)!=receipt_identity(first):
            raise AssertionError('HTTP identity headers controlled principal')
        for client in [None,'http-untrusted']:
            try:
                request(port,body,client=client)
            except (ssl.SSLError,ConnectionError,http.client.HTTPException):
                pass
            else:
                raise AssertionError('unverified HTTPS client reached handler')
        request(port,body,415,headers={'Content-Type':'application/json','Content-Encoding':'gzip'})
        request(port,body,405,method='GET')
        request(port,body,404,target='/v1/batches?tenant=forged')
        lost = copy.deepcopy(body)
        lost['batch_id']=str(uuid.uuid4())
        raw = json.dumps(lost).encode()
        with context().wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost') as stream:
            stream.sendall(b'POST /v1/batches HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: '+str(len(raw)).encode()+b'\r\n\r\n'+raw)
            until = time.monotonic()+5
            while execute('SELECT count(*) FROM contour.ingestion_batches WHERE '+scope(lost)+';')!='1':
                if time.monotonic()>until:
                    raise AssertionError('discarded HTTPS acknowledgement did not commit')
                time.sleep(0.02)
            # Deliberately never read the HTTPS application response after real COMMIT.
        replay = request(port,lost)
        if replay['status']!='duplicate':
            raise AssertionError('lost HTTPS application acknowledgement was not duplicate')
        persisted(lost,replay)
        candidate = copy.deepcopy(body)
        candidate['batch_id']=str(uuid.uuid4())
        outcomes = queue.Queue()
        def concurrent():
            try:
                outcomes.put(request(port,candidate))
            except Exception as error:
                outcomes.put(error)
        workers = [threading.Thread(target=concurrent,daemon=True) for _ in range(2)]
        for worker in workers:
            worker.start()
        try:
            results = [outcomes.get(timeout=12) for _ in workers]
            if any(isinstance(result,Exception) for result in results):
                raise AssertionError('concurrent HTTPS request failed')
            if {result['status'] for result in results}!={'accepted','duplicate'} or receipt_identity(results[0])!=receipt_identity(results[1]):
                raise AssertionError('concurrent HTTPS receipt mismatch')
        finally:
            for worker in workers:
                worker.join(10)
                if worker.is_alive():
                    raise AssertionError('HTTPS request thread leaked')

        with context().wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost') as stream:
            stream.settimeout(5)
            stream.sendall(b'POST /v1/batches HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n'+b'x'*1048576+b'\r\n')
            stream.sendall(b'1\r\nx\r\n0\r\n\r\n')
            response = http.client.HTTPResponse(stream)
            response.begin()
            if response.status!=413:
                raise AssertionError('actual chunked body bound was not enforced')
            response.read(4096)
        with context().wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost') as stream:
            stream.settimeout(5)
            head = b'POST /v1/batches HTTP/1.1\r\nHost: localhost\r\nX-Large: '+b'a'*17000+b'\r\n\r\n'
            for offset in range(0,len(head),256):
                stream.sendall(head[offset:offset+256])
            response = http.client.HTTPResponse(stream)
            response.begin()
            if response.status!=431:
                raise AssertionError('fragmented header bound was not enforced')
            response.read(4096)
        raw = json.dumps(body).encode()
        for head, wanted in [
            (b'POST /v1/batches HTTP/1.1\r\nHost: localhost\r\n'+b'X-Pad: a\r\n'*65+b'\r\n',431),
            (b'POST /v1/batches HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n'+('%x\r\n' % len(raw)).encode()+raw+b'\r\n0\r\nX-Trailer: unsupported\r\n\r\n',400),
        ]:
            with context().wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost') as stream:
                stream.sendall(head)
                response = http.client.HTTPResponse(stream)
                response.begin()
                if response.status!=wanted:
                    raise AssertionError('HTTP header-count/trailer bound failed')
                response.read(4096)

    with socket.socket() as backend:
        backend.bind(('127.0.0.1',0))
        backend.listen(1)
        backend.settimeout(0.2)
        with server(body,backend=backend.getsockname()[1]) as port:
            request(port,spoof,403,headers={'Content-Type':'application/json','X-Contour-Tenant':body['tenant_id']})
            request(port,body,403,client='http-other')
            request(port,b'{"SYNTHETIC_SECRET":',400)
            try:
                contact, _ = backend.accept()
            except socket.timeout:
                pass
            else:
                contact.close()
                raise AssertionError('denied HTTP identity/body contacted database endpoint')

    expired, _, _ = setup('https_expired_retry')
    print('HTTP durable receipts, concurrent duplicate, identity and streaming bounds passed',flush=True)
    expired['records'][0]['expires_at']=future_expiry()
    with server(expired) as port:
        first = request(port,expired)
        wait_expired(expired['records'][0]['expires_at'])
        replay = request(port,expired)
        if replay['status']!='duplicate' or receipt_identity(first)!=receipt_identity(replay):
            raise AssertionError('HTTP prematurely rejected expired committed retry')

    for state in ['disabled','revoked','expired']:
        change = None
        expiry = []
        if state=='expired':
            def change(value):
                expiry.append(future_expiry())
                value.update(expires_at=expiry[0])
        candidate, _, _ = setup('https_'+state,change)
        with server(candidate) as port:
            first = request(port,candidate)
            if state=='expired':
                wait_expired(expiry[0])
            else:
                update = 'enabled=false' if state=='disabled' else 'enabled=false,revoked_at=clock_timestamp()'
                execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.collector_authorization SET %s WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (candidate['tenant_id'],candidate['tenant_id'],candidate['collector_id'],update,candidate['tenant_id'],candidate['collector_id']))
            request(port,candidate,403)
            persisted(candidate,first)

    denied, _, _ = setup('wrong_signer')
    with server(denied) as port:
        request(port,denied,403)
    invalid, _, _ = setup('https_all_record_atomic')
    last = dict(invalid['records'][0],record_id=str(uuid.uuid4()),operation='SYNTHETIC_SECRET')
    invalid['records'].append(last)
    with server(invalid) as port:
        request(port,invalid,422)
        if execute('SELECT count(*) FROM contour.ingestion_batches WHERE '+scope(invalid)+';')!='0':
            raise AssertionError('HTTP committed a subset of an inadmissible batch')

    module = runpy.run_path(str(Path(__file__).with_name('test-postgres-recovery.py')))
    print('HTTP committed retry expiry, current authority and all-record checks passed',flush=True)
    for mode, wanted in [('drop',503),('cleanup',200)]:
        candidate, _, _ = setup('https_commit_'+mode)
        proxy = module['CommitProxy'](pg_port,directory,mode)
        try:
            with server(candidate,backend=proxy.port) as port:
                result = request(port,candidate,wanted)
                if mode=='drop' and (result['code']!='outcome_unknown' or not result['retryable']):
                    raise AssertionError('HTTP unknown COMMIT acknowledged success')
                if mode=='cleanup' and result['status']!='accepted':
                    raise AssertionError('HTTP lost known COMMIT after cleanup failure')
            proxy.finish()
        finally:
            proxy.close()
        with server(candidate) as port:
            replay = request(port,candidate)
            if replay['status']!='duplicate':
                raise AssertionError('actual HTTP commit fault retry was not duplicate')
            persisted(candidate,replay)
            if mode=='cleanup' and receipt_identity(result)!=receipt_identity(replay):
                raise AssertionError('known HTTP COMMIT cleanup changed receipt')

    print('HTTP observed COMMIT acknowledgement faults and exact replay passed',flush=True)
    for partial in [b'POST /v1/batches HTTP/1.1\r\nHost:',b'POST /v1/batches HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\nx']:
        with server(body,deadline=600) as port:
            with context().wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=3),server_hostname='localhost') as stream:
                stream.settimeout(2)
                stream.sendall(partial)
                if stream.recv(1)!=b'':
                    raise AssertionError('absolute post-TLS header/body deadline did not close socket')

    for mode in ['deadline','shutdown']:
        candidate, _, _ = setup('https_owned_'+mode)
        holder = subprocess.Popen(['docker','exec','-i',container,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_fixture','-At'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        markers = queue.Queue()
        reader = threading.Thread(target=lambda: [markers.put(line.strip()) for line in holder.stdout],daemon=True)
        outcomes = queue.Queue()
        def stopped():
            if outcomes.get(timeout=2)!='closed':
                raise AssertionError('HTTP shutdown did not close client before remote cleanup')
            print('HTTP local STOPPED/client EOF observed while runtime alive',flush=True)
        manager = server(candidate,deadline=1500 if mode=='deadline' else 10000,stopped=stopped if mode=='shutdown' else None)
        active = False
        worker = None
        try:
            holder.stdin.write("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s');\n\\echo HELD\n" % (candidate['tenant_id'],candidate['tenant_id'],candidate['collector_id']))
            holder.stdin.flush()
            reader.start()
            until = time.monotonic()+5
            while markers.get(timeout=max(0.01,until-time.monotonic()))!='HELD':
                pass
            port = manager.__enter__()
            active = True
            def blocked():
                try:
                    outcomes.put(request(port,candidate))
                except (ConnectionError,http.client.HTTPException,ssl.SSLError):
                    outcomes.put('closed')
                except Exception as error:
                    outcomes.put(error)
            worker = threading.Thread(target=blocked,daemon=True)
            worker.start()
            until = time.monotonic()+3
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls' AND wait_event='advisory';")!='1':
                if time.monotonic()>until or not outcomes.empty():
                    raise AssertionError('HTTPS cancellation did not reach real collector lock')
                time.sleep(0.01)
            if mode=='shutdown':
                active = False
                manager.__exit__(None,None,None)
            if mode=='deadline' and outcomes.get(timeout=5)!='closed':
                raise AssertionError('blocked HTTPS request survived deadline/shutdown')
            until = time.monotonic()+5
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls';")!='0':
                if time.monotonic()>until:
                    raise AssertionError('HTTPS cancellation retained owned database driver')
                time.sleep(0.02)
            pairs = execute('SELECT (SELECT count(*) FROM contour.ingestion_batches WHERE %s),(SELECT count(*) FROM contour.ingestion_payloads WHERE %s);' % (scope(candidate),scope(candidate)))
            if pairs!='0|0':
                raise AssertionError('precommit HTTP cancellation retained an inbox pair')
        finally:
            try:
                if active:
                    manager.__exit__(None,None,None)
            finally:
                try:
                    if holder.poll() is None:
                        holder.stdin.write('ROLLBACK;\n\\q\n')
                        holder.stdin.flush()
                        holder.wait(timeout=3)
                finally:
                    if holder.poll() is None:
                        holder.kill()
                        holder.wait(timeout=3)
                    if reader.ident is not None:
                        reader.join(2)
                    for pipe in [holder.stdin,holder.stdout,holder.stderr]:
                        pipe.close()
                    if worker is not None:
                        worker.join(10)
                        if worker.is_alive():
                            raise AssertionError('blocked HTTPS client thread leaked')

    with server(body,deadline=600) as port:
        sockets = []
        try:
            for _ in range(2):
                sockets.append(socket.create_connection(('127.0.0.1',port),timeout=3))
            time.sleep(0.05)
            extra = socket.create_connection(('127.0.0.1',port),timeout=3)
            sockets.append(extra)
            extra.settimeout(0.3)
            if extra.recv(1)!=b'':
                raise AssertionError('connection cap did not close excess socket')
            for stream in sockets[:2]:
                stream.settimeout(2)
                if stream.recv(1)!=b'':
                    raise AssertionError('absolute TLS stall deadline did not close socket')
        finally:
            for stream in sockets:
                stream.close()
    print('Actual mTLS HTTPS-to-restricted-PostgreSQL accepted/duplicate/concurrent/fault and authorization assertions passed')
    print('HTTP chunked/header bounds, expired committed replay and owned connection/deadline cleanup passed')
