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

    @contextlib.contextmanager
    def owner(body, port):
        path=directory/'owner-input.json'; path.write_text(json.dumps(body))
        process=subprocess.Popen([probe,str(directory),str(path),str(port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
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
    # A fresh object never bootstraps from the prior success.
    with server(body) as port, owner(body,port) as call: denied(call('send'))

    body,_,_=setup('owner_narrow',current=2,history=(1,),change=lambda p:p.update(denied_templates=['/orders/{id}']))
    change(body,'UPDATE contour.collector_authorization SET active_revision=1 WHERE '+scope(body))
    with server(body) as port, owner(body,port) as call:
        good(call('refresh')); good(call('admit')); good(call('freeze'))
        change(body,'UPDATE contour.collector_authorization SET active_revision=2 WHERE '+scope(body))
        result=good(call('refresh')); assert result['records']==0 and result['bytes']==0 and result['purged']==1
        assert good(call('send'))['result']=={'empty':True}
        change(body,'UPDATE contour.collector_authorization SET active_revision=1 WHERE '+scope(body))
        denied(call('refresh'))  # queue/highwater survives refresh, not recreated
        assert execute('SELECT count(*) FROM contour.ingestion_batches WHERE '+scope(body))=='0'

    body,_,_=setup('owner_denied',current=1,history=(1,))
    with server(body) as port, owner(body,port) as call:
        good(call('refresh')); charged=good(call('admit')); good(call('freeze'))
        change(body,'UPDATE contour.collector_authorization SET enabled=false WHERE '+scope(body))
        denied(call('refresh')); assert denied(call('send'))['bytes']==charged['bytes']
        change(body,'UPDATE contour.collector_authorization SET enabled=true WHERE '+scope(body))
        good(call('refresh')); assert good(call('send'))['bytes']==0  # 403 was not permanent revoke

    @contextlib.contextmanager
    def relay(upstream, mode):
        challenges=set(); errors=[]; finished=threading.Event()
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args): pass
            def do_POST(self):
                try:
                    raw=self.rfile.read(int(self.headers['Content-Length']))
                    challenge=json.loads(raw)['challenge']
                    assert len(challenge)==64 and challenge not in challenges
                    challenges.add(challenge)
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.load_verify_locations(str(directory/'ca.crt'))
                    context.load_cert_chain(directory/'http-client.crt',directory/'http-client.key')
                    connection=http.client.HTTPSConnection('localhost',upstream,context=context,timeout=3)
                    try:
                        connection.request('POST','/v1/collector-authority',raw,{'Content-Type':'application/json'})
                        response=connection.getresponse(); payload=response.read(8*1048576+1)
                        assert response.status==200 and len(payload)<=8*1048576
                        value=json.loads(payload)
                    finally: connection.close()
                    if mode=='challenge': value['challenge']='0'*64
                    if mode=='source': value['sources'][0]['source_id']='ffffffff-ffff-ffff-ffff-ffffffffffff'
                    if mode=='identity': value['collector_id']='ffffffff-ffff-ffff-ffff-ffffffffffff'
                    if mode=='late':
                        encoded=value['signed_policy']['payload_base64url']; policy=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
                        expiry=datetime.datetime.strptime(policy['expires_at'],'%Y-%m-%dT%H:%M:%S.%fZ')
                        value['checked_at']=(expiry-datetime.timedelta(milliseconds=50)).isoformat(timespec='microseconds')+'Z'
                        time.sleep(0.15)
                    if mode=='cancel': time.sleep(0.3)
                    payload=json.dumps(value).encode()
                    self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(payload))); self.send_header('Connection','close'); self.end_headers()
                    try: self.wfile.write(payload)
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
            service.shutdown(); service.server_close(); thread.join(3)
            assert not thread.is_alive() and not errors and finished.is_set(), 'authority fault relay failed'
            assert len(challenges)==2, 'refresh did not obtain fresh per-request challenge'

    for mode in ['challenge','source','identity','late','cancel']:
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
