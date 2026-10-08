"""Real owner -> online mTLS authority -> memory queue -> HTTPS/Postgres receipt.
A trusted local fault relay damages real authority replies for negative cases.
"""
import base64
import contextlib
import datetime
import http.client
import http.server
import json
import queue
import socket
import ssl
import subprocess
import threading
import time


def run_cases(execute, setup, server, directory, environment, probe):
    subprocess.run(['openssl','pkcs8','-topk8','-nocrypt','-in',str(directory/'http-client.key'),'-outform','DER','-out',str(directory/'http-client.key.der')],check=True,capture_output=True,timeout=10)

    subprocess.run(['openssl','x509','-in',str(directory/'untrusted.crt'),'-outform','DER','-out',str(directory/'untrusted.crt.der')],check=True,capture_output=True,timeout=10)

    @contextlib.contextmanager
    def owner(body, port, mode='valid'):
        path=directory/'owner-input.json'; path.write_text(json.dumps(body))
        process=subprocess.Popen([probe,str(directory),str(path),str(port),mode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        replies=queue.Queue()
        reader=threading.Thread(target=lambda: [replies.put(line) for line in process.stdout],daemon=True); reader.start()
        def call(action, **kwargs):
            process.stdin.write(json.dumps(dict(action=action,**kwargs))+'\n'); process.stdin.flush()
            try: line=replies.get(timeout=6)
            except queue.Empty: raise AssertionError('owner command timed out')
            return json.loads(line)
        try: yield call
        finally:
            try:
                process.stdin.close(); process.wait(timeout=5); reader.join(2)
                assert process.returncode==0, 'owner fixture exited unsuccessfully: '+process.stderr.read(1024)
            finally:
                if process.poll() is None: process.kill(); process.wait(timeout=3)
                for pipe in [process.stdout,process.stderr]: pipe.close()

    def scope(body): return "tenant_id='%s' AND collector_id='%s'" % (body['tenant_id'],body['collector_id'])
    def change(body, statement):
        execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); %s; COMMIT;" % (body['tenant_id'],body['tenant_id'],body['collector_id'],statement))
    def signed_policy(body, revision, mutate=lambda p:None, padding=0):
        raw=bytes.fromhex(execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE "+scope(body)+" AND revision=1;"))
        envelope=json.loads(raw); encoded=envelope['payload_base64url']
        policy=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4))); policy['revision']=revision; mutate(policy)
        payload=json.dumps(policy,separators=(',',':')).encode().ljust(padding,b' ')
        (directory/'owner-message').write_bytes(b'apicontour/policy/1\n'+payload)
        subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(directory/'signer.key'),'-in',str(directory/'owner-message'),'-out',str(directory/'owner-signature')],check=True,capture_output=True,timeout=5)
        encode=lambda raw:base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
        envelope.update(payload_base64url=encode(payload),signature_base64url=encode((directory/'owner-signature').read_bytes()))
        return json.dumps(envelope,separators=(',',':')).encode()
    def install(body, revision, mutate=lambda p:None, padding=0):
        raw=signed_policy(body,revision,mutate,padding)
        change(body,"INSERT INTO contour.policy_revisions VALUES ('%s','%s',%d,decode('%s','hex'))" % (body['tenant_id'],body['collector_id'],revision,raw.hex()))
    def good(value):
        assert 'error' not in value['result'], 'owner unexpectedly denied: '+str(value)
        return value
    def denied(value):
        assert 'error' in value['result'] and not value['live'], 'owner unexpectedly live: '+str(value)
        return value

    body,_,_=setup('owner_success',current=1,history=(1,))
    with server(body) as port, owner(body,port) as call:
        assert denied(call('admit'))['bytes']==0
        denied(call('freeze')); denied(call('send'))
        assert good(call('refresh'))['live']
        charged=good(call('admit')); assert charged['bytes']>0 and charged['records']==1
        assert good(call('freeze'))['bytes']==charged['bytes']
        result=good(call('send')); assert result['bytes']==0 and result['records']==0 and result['acknowledged']==1
        receipt=execute('SELECT receipt_id FROM contour.ingestion_batches WHERE '+scope(body)+';')
        assert receipt==result['result']['receipt_id'], 'checked receipt did not match durable row'
        assert execute('SELECT count(*) FROM contour.ingestion_payloads WHERE '+scope(body)+';')=='1'
    for mode in ['bad-root','bad-name']:
        with server(body) as port, owner(body,port,mode) as call: denied(call('refresh')); denied(call('admit'))
    # A fresh object never bootstraps from the prior success.
    with server(body) as port, owner(body,port) as call: denied(call('send'))

    body,_,_=setup('owner_narrow',current=1,history=(1,))
    install(body,2,lambda p:p.update(denied_templates=['/orders/{id}']))
    with server(body) as port, owner(body,port) as call:
        good(call('refresh')); good(call('admit')); good(call('freeze'))
        change(body,'UPDATE contour.collector_authorization SET active_revision=2 WHERE '+scope(body))
        result=good(call('refresh')); assert result['records']==0 and result['bytes']==0 and result['purged']==1
        assert good(call('send'))['result']=={'empty':True}
        assert execute('SELECT count(*) FROM contour.ingestion_batches WHERE '+scope(body))=='0'

    body,_,_=setup('owner_denied',current=1,history=(1,))
    with server(body) as port, owner(body,port) as call:
        good(call('refresh')); charged=good(call('admit')); good(call('freeze'))
        change(body,'UPDATE contour.collector_authorization SET enabled=false WHERE '+scope(body))
        denied(call('refresh')); assert denied(call('send'))['bytes']==charged['bytes']
        change(body,'UPDATE contour.collector_authorization SET enabled=true WHERE '+scope(body))
        good(call('refresh')); assert good(call('send'))['bytes']==0  # 403 was not permanent revoke

    expiry=[None]
    def short_lease(policy):
        expiry[0]=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=3)
        policy['expires_at']=expiry[0].isoformat(timespec='microseconds').replace('+00:00','Z')
    body,_,_=setup('owner_retained_history',current=1,history=(1,2),change=short_lease)
    with server(body) as port, owner(body,port) as call:
        good(call('refresh')); charged=good(call('admit')); good(call('freeze'))
        change(body,'UPDATE contour.collector_authorization SET active_revision=2 WHERE '+scope(body))
        assert good(call('refresh'))['bytes']==charged['bytes']
        time.sleep(max(0,(expiry[0]-datetime.datetime.now(datetime.timezone.utc)).total_seconds())+0.02)
        result=good(call('send')); assert result['bytes']==0 and result['acknowledged']==1
        assert execute('SELECT receipt_id FROM contour.ingestion_batches WHERE '+scope(body))==result['result']['receipt_id']

    # Signed padding exercises the aggregate envelope budget with only nine
    # retained revisions. Every retained policy still backs one admitted record.
    body,_,_=setup('owner_history',current=1,history=(1,))
    for revision in range(2,11): install(body,revision,padding=720000)
    with server(body) as port, owner(body,port) as call:
        for revision in range(2,10):
            change(body,'UPDATE contour.collector_authorization SET active_revision=%d WHERE ' % revision+scope(body))
            good(call('refresh')); retained=good(call('admit',revision=revision,record_id='00000000-0000-4000-8000-%012x' % revision))
        assert retained['records']==8
        change(body,'UPDATE contour.collector_authorization SET active_revision=10 WHERE '+scope(body))
        result=denied(call('refresh')); assert result['result']['error']=='HistoryLimit'
        assert result['records']==8 and result['bytes']==retained['bytes'] and result['purged']==0
        denied(call('send')); assert good(call('expire'))['records']==8

    @contextlib.contextmanager
    def relay(upstream, mode, evidence=None):
        evidence={} if evidence is None else evidence
        challenges=set(); errors=[]; finished=threading.Event()
        control=socket.socket(); control.bind(('127.0.0.1',0)); control.listen(1); control.settimeout(3); evidence['control']=control.getsockname()[1]
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args): pass
            def do_POST(self):
                self.connection.settimeout(3)
                try:
                    raw=self.rfile.read(int(self.headers['Content-Length']))
                    if self.path=='/v1/collector-authority':
                        challenge=json.loads(raw)['challenge']
                        assert len(challenge)==64 and challenge not in challenges
                        challenges.add(challenge)
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.load_verify_locations(str(directory/'ca.crt'))
                    context.load_cert_chain(directory/'http-client.crt',directory/'http-client.key')
                    connection=http.client.HTTPSConnection('localhost',upstream,context=context,timeout=3)
                    try:
                        connection.request('POST',self.path,raw,{'Content-Type':'application/json'})
                        response=connection.getresponse(); payload=response.read(8*1048576+1)
                        assert response.status==200 and len(payload)<=8*1048576
                        value=json.loads(payload)
                    finally: connection.close()
                    if self.path=='/v1/batches':
                        evidence['sends']=evidence.get('sends',0)+1
                        evidence['receipt']=value['receipt_id']
                        if mode.startswith('retry') and (mode!='retry503' or evidence['sends']==1):
                            self.send_response(int(mode[5:])); self.send_header('Retry-After','1'); self.send_header('Content-Length','0'); self.end_headers(); return
                        if mode=='send-cancel':
                            self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(payload))); self.end_headers()
                            self.wfile.write(payload[:5]); self.wfile.flush()
                            with control.accept()[0] as signal: signal.sendall(b'C')
                            assert self.connection.recv(1)==b'', 'cancelled owner kept transport alive'
                            evidence['eof']=True
                            return
                    if mode in ['same-revision','rollback'] and len(challenges)==2: value['signed_policy']=evidence['changed']
                    if mode=='challenge': value['challenge']='0'*64
                    if mode=='source': value['sources'][0]['source_id']='ffffffff-ffff-ffff-ffff-ffffffffffff'
                    if mode=='identity': value['collector_id']='ffffffff-ffff-ffff-ffff-ffffffffffff'
                    if mode=='profiles': value['sources'][0]['parser_profiles']=['']*200000
                    if mode=='sources': value['sources']=value['sources']*501
                    if mode=='profile-length': value['sources'][0]['parser_profiles']=['x'*65]
                    if mode=='late':
                        encoded=value['signed_policy']['payload_base64url']; policy=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
                        expiry=datetime.datetime.strptime(policy['expires_at'],'%Y-%m-%dT%H:%M:%S.%fZ')
                        value['checked_at']=(expiry-datetime.timedelta(milliseconds=50)).isoformat(timespec='microseconds')+'Z'
                        time.sleep(0.15)
                    if mode=='cancel': time.sleep(0.3)
                    payload=json.dumps(value).encode()
                    self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(payload))); self.send_header('Connection','close'); self.end_headers()
                    try: self.wfile.write(payload[:5] if mode=='truncated' else payload)
                    except (BrokenPipeError,ConnectionResetError,ssl.SSLError):
                        assert mode=='cancel'
                except Exception as error: errors.append(error)
                finally: finished.set()
        service=http.server.HTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(directory/'server.crt',directory/'server.key')
        context.load_verify_locations(str(directory/'ca.crt')); context.verify_mode=ssl.CERT_REQUIRED; context.set_alpn_protocols(['http/1.1'])
        service.socket=context.wrap_socket(service.socket,server_side=True)
        thread=threading.Thread(target=service.serve_forever,daemon=True); thread.start()
        try: yield service.server_port
        finally:
            service.shutdown(); service.server_close(); control.close(); thread.join(3)
            assert not thread.is_alive() and not errors and finished.is_set(), 'authority fault relay failed'
            assert len(challenges)==2, 'refresh did not obtain fresh per-request challenge'

    body,_,_=setup('owner_cancel_send',current=1,history=(1,))
    install(body,2,lambda p:p.update(denied_templates=['/orders/{id}']))
    evidence={}
    with server(body) as upstream, relay(upstream,'send-cancel',evidence) as port, owner(body,port) as call:
        good(call('refresh')); charged=good(call('admit')); good(call('freeze'))
        result=good(call('cancel-send',control=evidence['control'])); assert result['result']=={'cancelled':True} and not result['live']
        assert result['bytes']==charged['bytes']; denied(call('send'))
        until=time.monotonic()+3
        while not evidence.get('eof') and time.monotonic()<until: time.sleep(0.01)
        assert evidence.get('eof'), 'send cancellation did not drop real I/O'
        change(body,'UPDATE contour.collector_authorization SET active_revision=2 WHERE '+scope(body))
        assert good(call('refresh'))['bytes']==0
        assert good(call('send'))['result']=={'empty':True} and evidence['sends']==1
        assert execute('SELECT receipt_id FROM contour.ingestion_batches WHERE '+scope(body))==evidence['receipt']

    for mode in ['retry503','retry409','retry413','same-revision','rollback']:
        body,_,_=setup('owner_'+mode,current=2 if mode=='rollback' else 1,history=(1,))
        evidence={'changed':json.loads(signed_policy(body,1,lambda p:p.update(queue_ttl_seconds=400) if mode=='same-revision' else None))} if mode in ['same-revision','rollback'] else {}
        with server(body) as upstream, relay(upstream,mode,evidence) as port, owner(body,port) as call:
            good(call('refresh')); charged=good(call('admit',revision=2 if mode=='rollback' else 1)); good(call('freeze'))
            if mode in ['same-revision','rollback']:
                result=denied(call('refresh')); assert result['bytes']==charged['bytes'] and 'Revision' in result['result']['error']
                continue
            started=time.monotonic(); first=good(call('send'))
            assert first['bytes']==charged['bytes'] and 'deferred' in first['result']
            good(call('refresh')); assert good(call('send'))['result']==first['result'] and evidence['sends']==1
            if mode=='retry503':
                assert good(call('wait'))['result']=={'wait':'Ready'}
                result=good(call('send')); assert result['bytes']==0 and time.monotonic()-started>=1 and evidence['sends']==2
            else: assert first['result']['deferred']==('StopConflict' if mode=='retry409' else 'RequireSplit')

    for mode in ['challenge','source','identity','profiles','sources','profile-length','truncated','late','cancel']:
        body,_,_=setup('owner_'+mode,current=1,history=(1,))
        with server(body) as upstream, relay(upstream,mode) as port, owner(body,port) as call:
            for _ in range(2):
                result=call('cancel-refresh' if mode=='cancel' else 'refresh')
                if mode=='cancel': assert result['result']=={'cancelled':True} and not result['live']
                else: denied(result)
                denied(call('admit')); assert denied(call('send'))['bytes']==0
                if mode=='cancel': time.sleep(0.35)
        assert execute('SELECT count(*) FROM contour.ingestion_batches WHERE '+scope(body))=='0'
    print('Collector owner actual online mTLS/PG receipt, pause/renewal/narrowing/highwater and challenge/source/identity/late/cancel negatives passed',flush=True)
