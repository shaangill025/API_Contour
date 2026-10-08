"""Actual queue → verified HTTPS → restricted PostgreSQL → checked receipt.
Fault relay commits through the real server before damaging its response; other
scripted receipts are explicitly transport faults, not database commit evidence.
"""
import contextlib
import hashlib
import email.utils
import runpy
import http.client
import http.server
import json
from pathlib import Path
import queue
import ssl
import socket
import subprocess
import threading
import time


def run_cases(execute, setup, server, directory, environment, probe):
    def command(args):
        subprocess.run(args, check=True, capture_output=True, timeout=10)
    command(['openssl','pkcs8','-topk8','-nocrypt','-in',str(directory/'http-client.key'),'-outform','DER','-out',str(directory/'http-client.key.der')])
    command(['openssl','x509','-in',str(directory/'untrusted.crt'),'-outform','DER','-out',str(directory/'untrusted.crt.der')])
    def context():
        c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.minimum_version=ssl.TLSVersion.TLSv1_2
        c.load_verify_locations(str(directory/'ca.crt'))
        c.load_cert_chain(directory/'http-client.crt',directory/'http-client.key')
        return c

    @contextlib.contextmanager
    def relay(upstream, mode, evidence, signals):
        stop=threading.Event()
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*_): pass
            def retry_reply(self):
                code=int(mode[6:]) if mode[6:].isdigit() else (429 if mode=='retry-cap' else 503)
                self.send_response(code)
                value={'retry-seconds':'1','retry-date':email.utils.formatdate(time.time()+2,usegmt=True),'retry-cap':'999999999999999999999999','retry-malformed':'not-a-date','retry-duplicate':'1','retry-ttl':'10','retry-revoke':'300','retry-cancel':'300'}.get(mode)
                if value is not None: self.send_header('Retry-After',value)
                if mode=='retry-duplicate': self.send_header('Retry-After','2')
                # Incomplete oversized HTML error body must not control status decisions.
                self.send_header('Content-Type','text/html')
                self.send_header('Content-Length','1000000')
                self.end_headers()
                if self.connection.recv(1)!=b'': raise AssertionError('error response socket remained owned')
                signals['eof'].set()
                self.close_connection=True
            def do_POST(self):
                length=int(self.headers['Content-Length'])
                if not 1<=length<=1048576: raise AssertionError('relay body bound')
                raw=self.rfile.read(length)
                if len(raw)!=length: raise AssertionError('relay truncated request')
                if mode.startswith('retry-') and mode not in ['retry-seconds','retry-date','retry-lost']:
                    self.retry_reply();return
                connection=http.client.HTTPConnection('localhost',upstream,timeout=2)
                try:
                    raw_socket=socket.socket()
                    raw_socket.settimeout(2)
                    service.remember('upstream',raw_socket)
                    raw_socket.connect(('127.0.0.1',upstream))
                    stream=context().wrap_socket(raw_socket,server_hostname='localhost',do_handshake_on_connect=False)
                    service.remember('upstream',stream)
                    stream.do_handshake()
                    connection.sock=stream
                    connection.request('POST','/v1/batches',raw,{'Content-Type':'application/json'})
                    response=connection.getresponse()
                    payload=response.read(4097)
                    assert response.status==200 and len(payload)<=4096
                    receipt=json.loads(payload)
                    evidence.update(receipt)
                finally:
                    connection.close()
                    with service.active_lock:
                        if service.upstream is not None: service.upstream.close()
                        service.upstream=None
                if mode in ['retry-seconds','retry-date']:
                    self.retry_reply();return
                if mode in ['lost','retry-lost']:
                    self.close_connection=True
                    return
                if mode=='mismatch': receipt['batch_id']='ffffffff-ffff-ffff-ffff-ffffffffffff'
                if mode=='unknown': receipt['extra']=True
                if mode=='bad-uuid': receipt['receipt_id']='not-a-uuid'
                if mode=='bad-time': receipt['accepted_at']='not-a-time'
                if mode=='bad-status': receipt['status']='committed'
                if mode=='missing': del receipt['receipt_id']
                payload=json.dumps(receipt).encode()
                if mode=='duplicate-field': payload=payload[:-1]+b',"status":"accepted"}'
                if mode=='oversize': payload=b' '*4097
                self.send_response(503 if mode=='non200' else 200)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(payload)))
                self.send_header('Connection','close')
                self.end_headers()
                self.wfile.write(payload[:5] if mode in ['truncated','stall','cancel','late'] else payload)
                if mode=='late':
                    self.wfile.flush()
                    signals['phase'].set()
                    if not signals['release'].wait(10): raise AssertionError('late receipt release missing')
                    self.wfile.write(payload[5:]);self.wfile.flush()
                    signals['sent'].set()
                if mode=='cancel':
                    self.wfile.flush()
                    signals['phase'].set()
                    if self.connection.recv(1)!=b'': raise AssertionError('cancelled client socket stayed open')
                    signals['eof'].set()
                if mode=='stall':
                    self.wfile.flush()
                    stop.wait(6)
                self.close_connection=True
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version=ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(directory/'server.crt',directory/'server.key')
        tls.load_verify_locations(str(directory/'ca.crt'))
        tls.verify_mode=ssl.CERT_REQUIRED
        tls.set_alpn_protocols(['http/1.1'])
        class OwnedServer(http.server.HTTPServer):
            active=None
            upstream=None
            active_lock=threading.Lock()
            def remember(self,name,stream):
                with self.active_lock:
                    if stop.is_set():
                        stream.close()
                        raise OSError('owned relay stopped')
                    setattr(self,name,stream)
            def get_request(self):
                raw,address=self.socket.accept()
                raw.settimeout(2)
                self.remember('active',raw)
                try:
                    stream=tls.wrap_socket(raw,server_side=True,do_handshake_on_connect=False)
                    self.remember('active',stream)
                    stream.do_handshake()
                    return stream,address
                except Exception:
                    with self.active_lock:
                        if self.active is not None: self.active.close()
                        self.active=None
                    raise
            def close_request(self,request):
                super().close_request(request)
                with self.active_lock:
                    if self.active is request: self.active=None
        service=OwnedServer(('127.0.0.1',0),Handler)
        service.timeout=0.2
        def serve():
            while not stop.is_set():
                try: service.handle_request()
                except (OSError,ValueError):
                    if not stop.is_set(): raise
        worker=threading.Thread(target=serve)
        worker.start()
        try: yield service.server_port
        finally:
            stop.set()
            with service.active_lock:
                for stream in [service.active,service.upstream]:
                    if stream is not None:
                        try: stream.shutdown(socket.SHUT_RDWR)
                        except OSError: pass
                        stream.close()
            service.server_close()
            worker.join(2)
            assert not worker.is_alive(), 'owned fault relay did not stop'

    for mode in ['success','bad-ca','bad-name','lost','truncated','mismatch','unknown','duplicate-field','oversize','bad-uuid','bad-time','bad-status','missing','non200','stall','cancel','late']:
        print('Delivery case: '+mode,flush=True)
        body,collector,_=setup('delivery_'+mode,current=1,history=(1,))
        identity="tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (body['tenant_id'],collector,body['batch_id'])
        body_path=directory/'delivery-input.json';body_path.write_text(json.dumps(body))
        policy=execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE tenant_id='%s' AND collector_id='%s' AND revision=1;" % (body['tenant_id'],collector))
        policy_path=directory/'delivery-policy.json';policy_path.write_bytes(bytes.fromhex(policy))
        evidence={}
        signals={name:threading.Event() for name in ['phase','eof','release','sent']}
        with server(body,deadline=5000) as upstream:
            with contextlib.ExitStack() as owned:
                first=upstream if mode in ['success','bad-ca','bad-name'] else owned.enter_context(relay(upstream,mode,evidence,signals))
                stages=('good:%d' % upstream) if mode=='success' else '%s:%d,good:%d' % (mode,first,upstream)
                arguments=[probe,str(directory),str(body_path),str(policy_path),stages]
                if mode in ['cancel','late']:
                    listener=owned.enter_context(socket.socket())
                    listener.settimeout(10)
                    listener.bind(('127.0.0.1',0));listener.listen(1)
                    arguments.append(str(listener.getsockname()[1]))
                process=subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
                lines=queue.Queue()
                def read_lines():
                    for line in process.stdout: lines.put(line)
                    lines.put(None)
                reader=threading.Thread(target=read_lines,daemon=True);reader.start()
                def marker():
                    try: line=lines.get(timeout=10)
                    except queue.Empty:
                        if process.poll() is None: raise AssertionError('delivery attempt marker timed out')
                        line=None
                    if line is None:
                        process.wait(timeout=2)
                        raise AssertionError('delivery probe exited: '+process.stderr.read().strip())
                    return json.loads(line)
                try:
                    if mode!='success':
                        if mode in ['cancel','late']:
                            control,_=listener.accept();control.settimeout(2);owned.enter_context(control)
                            assert signals['phase'].wait(10), 'cancel relay did not reach committed partial response'
                            control.sendall(b'P' if mode=='late' else b'C')
                            if mode=='late':
                                assert control.recv(1)==b'A', 'probe did not confirm paused owned future'
                                signals['release'].set()
                                assert signals['sent'].wait(2), 'late full receipt not sent'
                                time.sleep(5.1)  # Future is explicitly paused; response is already complete.
                                control.sendall(b'R')
                        failure=marker()
                        if mode=='cancel':
                            assert signals['eof'].wait(2) and process.poll() is None, 'cancelled socket did not close while probe runtime alive'
                        assert failure.get('failure') and failure['charge']>0, 'fault acknowledged queue'
                        committed=execute('SELECT count(*) FROM contour.ingestion_batches WHERE '+identity+';')
                        assert committed==('0' if mode in ['bad-ca','bad-name'] else '1'), 'actual commit evidence mismatch'
                        if mode not in ['bad-ca','bad-name']: assert evidence.get('status')=='accepted', 'committed relay evidence mismatch: mode=%s failure=%s status=%s' % (mode,failure.get('failure'),evidence.get('status'))
                        process.stdin.write('\n');process.stdin.flush()
                    receipt=marker()
                    _,error=process.communicate(timeout=3)
                    assert process.returncode==0 and not error, 'delivery probe failed: '+error
                    assert receipt['status']==('accepted' if mode in ['success','bad-ca','bad-name'] else 'duplicate')
                    if evidence:
                        assert receipt['receipt_id']==evidence['receipt_id'] and receipt['accepted_at']==evidence['accepted_at'], 'duplicate receipt identity changed'
                    wire=(directory/'delivery-wire.json').read_bytes()
                    row=execute("SELECT encode(b.request_digest,'hex') || '|' || encode(p.checked_batch,'hex') || '|' || b.receipt_id::text FROM contour.ingestion_batches b JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE b."+identity.replace(' AND ',' AND b.')+';')
                    digest,payload,receipt_id=row.split('|')
                    canonical=json.dumps(json.loads(wire),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
                    expected_digest=hashlib.sha256(b'apicontour/batch/1\n'+canonical).hexdigest()
                    assert digest==(directory/'delivery-digest.txt').read_text()==expected_digest and bytes.fromhex(payload)==wire and receipt_id==receipt['receipt_id'], 'persisted request/receipt mismatch'
                finally:
                    if process.poll() is None: process.kill();process.wait(timeout=3)
                    reader.join(2)
                    for pipe in [process.stdin,process.stdout,process.stderr]:pipe.close()
    print('Actual exact-full queue → verified HTTPS → restricted PostgreSQL → checked receipt → zero charge passed')
    print('Bad trust/name retained queue without commit; committed lost/truncated/mismatched/unknown/duplicate-field/oversized receipt retries preserved bytes and duplicate receipt identity')

    runpy.run_path(str(Path(__file__).with_name('test-collector-retry.py')))['run_cases'](execute,setup,server,relay,directory,environment,probe)

    runpy.run_path(str(Path(__file__).with_name('test-collector-bounded.py')))['run_cases'](execute,setup,server,relay,directory,environment,probe)
