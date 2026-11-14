#!/usr/bin/env python3
"""Complete synthetic causal HTTPS qualification; no production activation.

Uses current-source offline Cargo, actual loopback mTLS and PostgreSQL TLS.
An unread application response is not proof of zero network bytes. No ambiguous
COMMIT fault, producer attestation or retention behavior is qualified.
"""
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT=Path(__file__).absolute().parent.parent


def safe_source(relative):
    path=ROOT/relative
    for part in (path,*path.parents):
        if part.is_symlink(): raise ValueError('symlink in qualification source')
    if not path.is_file(): raise ValueError('qualification source unavailable')
    return path


def load_helpers():
    names=('scripts/test-postgres-causal-bridge.py','scripts/test-postgres-causal-inbox.py')
    paths=[safe_source(name) for name in names]
    before={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in zip(names,paths)}
    modules=[runpy.run_path(str(path)) for path in paths]
    if any(hashlib.sha256(safe_source(name).read_bytes()).hexdigest()!=before[name] for name in names):
        raise RuntimeError('qualification helper changed while loading')
    return modules[0],modules[1],before


class ProbeProcess:
    """Own one child and continuously drain bounded, never-printed output."""
    def __init__(self,args,env):
        self.child=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
        self.buffers={'out':bytearray(),'err':bytearray()}; self.lock=threading.Lock(); self.overflow=False
        self.kill_lock=threading.Lock(); self.group_terminated=False; self.group_absent=False; self.group_signal_failure=False
        self.threads=[]
        try:
            for key,stream in (('out',self.child.stdout),('err',self.child.stderr)):
                thread=threading.Thread(target=self._drain,args=(key,stream),daemon=True); thread.start(); self.threads.append(thread)
        except BaseException:
            self._kill_group()
            self.child.wait(timeout=5)
            for thread in self.threads: thread.join(timeout=5)
            for stream in (self.child.stdin,self.child.stdout,self.child.stderr):
                if stream is not None and not stream.closed: stream.close()
            raise
    def _drain(self,key,stream):
        while True:
            try: chunk=os.read(stream.fileno(),4096)
            except OSError: return
            if not chunk: return
            with self.lock:
                if len(self.buffers[key])+len(chunk)>16384:
                    self.overflow=True
                    try: self._kill_group()
                    except (OSError,RuntimeError): pass  # stop() reports the recorded denial.
                    return
                self.buffers[key].extend(chunk)
    def _kill_group(self):
        # The overflow reader and the owner can race here. Exactly one signal
        # attempt is made; a denied signal is remembered and never hidden.
        with self.kill_lock:
            if self.group_signal_failure: raise RuntimeError('probe group signal denied')
            if self.group_terminated: return
            try:
                os.killpg(self.child.pid,signal.SIGKILL)
            except ProcessLookupError:
                self.group_absent=True
            except PermissionError:
                # A group may disappear between operations. Only a precise
                # ESRCH observation accepts absence; a live/denied group fails.
                try: os.killpg(self.child.pid,0)
                except ProcessLookupError: self.group_absent=True
                except OSError:
                    self.group_signal_failure=True
                    raise
                else:
                    self.group_signal_failure=True
                    raise
            except OSError:
                self.group_signal_failure=True
                raise
            self.group_terminated=True

    def _require_group_absent(self):
        if self.group_absent: return
        deadline=time.monotonic()+5
        while True:
            try: os.killpg(self.child.pid,0)
            except ProcessLookupError:
                self.group_absent=True
                return
            except PermissionError:
                raise RuntimeError('probe group status denied') from None
            if time.monotonic()>=deadline: raise RuntimeError('probe group still exists')
            time.sleep(.025)

    def ready(self):
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            with self.lock: output=bytes(self.buffers['out']); overflow=self.overflow
            if overflow: raise RuntimeError('probe output limit')
            if b'\n' in output:
                line=output.split(b'\n',1)[0]
                match=re.fullmatch(rb'READY ([0-9]{1,5}) ([0-9]{1,20})',line)
                if not match: raise RuntimeError('probe readiness invalid')
                port,epoch=map(int,match.groups())
                if not 1<=port<=65535 or not 1<=epoch<=18446744073709551615: raise RuntimeError('probe readiness invalid')
                return port,epoch
            if self.child.poll() is not None: raise RuntimeError('probe exited before readiness')
            time.sleep(.02)
        raise TimeoutError('probe readiness deadline')
    def stop(self,graceful):
        timed_out=False
        if self.child.poll() is None and graceful:
            try: self.child.stdin.write(b'\n'); self.child.stdin.flush(); self.child.stdin.close()
            except (BrokenPipeError,OSError): pass
            try: self.child.wait(timeout=10)
            except subprocess.TimeoutExpired: timed_out=True
        # Kill the owned process group even if its leader exited, so children
        # cannot retain output pipes or survive a failed/complete fixture.
        signal_error=False
        try: self._kill_group()
        except (OSError,RuntimeError):
            signal_error=True
            # A denied signal must remain a failure. Close stdin once to allow
            # cooperative exit; do not retry the denied group signal or fall
            # back to killing only the leader.
            if not self.child.stdin.closed:
                try: self.child.stdin.close()
                except OSError: pass
        wait_error=False
        if self.child.poll() is None:
            try: self.child.wait(timeout=5)
            except subprocess.TimeoutExpired: wait_error=True
        for thread in self.threads: thread.join(timeout=5)
        join_error=any(thread.is_alive() for thread in self.threads)
        for stream in (self.child.stdin,self.child.stdout,self.child.stderr):
            if not stream.closed: stream.close()
        if signal_error: raise RuntimeError('probe group signal denied')
        if wait_error: raise RuntimeError('probe cleanup timeout')
        if join_error: raise RuntimeError('probe output thread not joined')
        self._require_group_absent()
        if timed_out: raise RuntimeError('probe shutdown timeout')
        if graceful:
            with self.lock: out=bytes(self.buffers['out']); err=bytes(self.buffers['err']); overflow=self.overflow
            if self.child.returncode!=0 or overflow or err or not re.fullmatch(rb'READY [0-9]+ [0-9]+\nSTOPPED\n',out):
                raise RuntimeError('probe shutdown failed')


def client_context(work, client='client', ca='ca.crt'):
    context=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=str(work/ca))
    if client is not None: context.load_cert_chain(str(work/(client+'.crt')),str(work/(client+'.key')))
    context.set_alpn_protocols(['http/1.1'])
    return context


def http_call(work,port,body,*,client='client',method='POST',path='/v1/causal-events',headers=None,chunked=False):
    connection=http.client.HTTPSConnection('localhost',port,context=client_context(work,client),timeout=8)
    try:
        connection.request(method,path,body=body,headers=headers or {'content-type':'application/json'},encode_chunked=chunked)
        response=connection.getresponse(); data=response.read(8193)
        if len(data)>8192 or response.getheader('content-type')!='application/json': raise AssertionError('response framing invalid')
        try: result=json.loads(data,object_pairs_hook=unique_pairs)
        except (ValueError,UnicodeDecodeError): raise AssertionError('response JSON invalid') from None
        return response.status,result
    finally: connection.close()


def unique_pairs(items):
    value={}
    for k,v in items:
        if k in value: raise ValueError('duplicate JSON key')
        value[k]=v
    return value


def expect_error(result,status,code):
    actual,body=result
    if actual!=status or not isinstance(body,dict) or set(body)!={'code','message','request_id','retryable'} or body['code']!=code or body['message']!='Request could not be completed' or body['retryable'] is not False:
        raise AssertionError('unexpected redacted HTTP error')
    try: request_id=uuid.UUID(body['request_id'])
    except (ValueError,TypeError,AttributeError): raise AssertionError('invalid request id') from None
    if str(request_id)!=body['request_id']: raise AssertionError('invalid request id')


def raw_call(work,port,wire):
    with socket.create_connection(('localhost',port),timeout=8) as raw:
        with client_context(work).wrap_socket(raw,server_hostname='localhost') as peer:
            peer.settimeout(8); peer.sendall(wire)
            response=http.client.HTTPResponse(peer); response.begin(); data=response.read(8193)
            if len(data)>8192 or response.getheader('content-type')!='application/json': raise AssertionError('response framing invalid')
            try: body=json.loads(data,object_pairs_hook=unique_pairs)
            except (ValueError,UnicodeDecodeError): raise AssertionError('response JSON invalid') from None
            return response.status,body


def streamed_limit_call(work,port):
    with socket.create_connection(('localhost',port),timeout=8) as raw:
        with client_context(work).wrap_socket(raw,server_hostname='localhost') as peer:
            peer.settimeout(8)
            peer.sendall(b'POST /v1/causal-events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n')
            chunk=b'10000\r\n'+b' '*65536+b'\r\n'
            for _ in range(16): peer.sendall(chunk)
            peer.sendall(b'1\r\n \r\n0\r\n\r\n')
            response=http.client.HTTPResponse(peer); response.begin(); data=response.read(8193)
            if len(data)>8192 or response.getheader('content-type')!='application/json': raise AssertionError('response framing invalid')
            try: body=json.loads(data,object_pairs_hook=unique_pairs)
            except (ValueError,UnicodeDecodeError): raise AssertionError('response JSON invalid') from None
            return response.status,body




EXPECTED_STAGES=('probe_ready','missing_client_certificate','unknown_client_certificate','untrusted_server_ca','wrong_server_name',
    'wrong_method','query_string','wrong_media','content_encoding','declared_trailer','actual_trailer',
    'declared_global_bound','streamed_global_bound','declared_event_bound','declared_byte_bound','noncanonical','unknown_body_field',
    'wrong_tenant','wrong_runtime','wrong_epoch','accepted_and_duplicate','incomplete_client_eof','unread_committed_response',
    'inflight_shutdown_cancellation','collector_revocation','revoked_exact_replay','revoked_new_batch','bounded_shutdown')


def negative_case(label,call,status,code,baseline,counts,state):
    state['current_case']=label
    expect_error(call(),status,code)
    if counts()!=baseline: raise AssertionError('negative request wrote data')
    state['stages'].append(label)


def require_scenarios(stages):
    if tuple(stages)!=EXPECTED_STAGES:
        raise RuntimeError('incomplete HTTPS qualification')


def run_https_cases(base,work,env,_counts,state):
    """Exercise all real endpoint cases; each failure prevents PASS."""
    peer=state.pop('_https_peer')
    args=base[:11]+[peer]+base[13:]+[str(work)]
    if len(args)!=24: raise RuntimeError('probe argument count invalid')
    cid=state['container_id']
    sql=['docker','exec','-i',cid,'psql','-XqAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-U','postgres','-d','contour_fixture']
    def execute(statement): return command(sql,data=statement.encode(),timeout=120).decode().strip()
    def stage(name): state['stages'].append(name)
    stage_start=len(state['stages'])
    monitor=ProbeProcess(args,env)
    try:
        state['current_case']='https_probe_start'
        https_port,epoch=monitor.ready()
        if epoch!=1: raise AssertionError('unexpected epoch')
        state['stages'].append('probe_ready')
        batch={'wire_version':1,'batch_id':str(uuid.uuid4()),'tenant_id':IDS[0],'runtime_id':IDS[1],
               'session_epoch':epoch,'first_seq':1,'last_seq':1,
               'events':[{'kind':'root','event_id':'1'*32,'seq':1,'root':'a'*32}]}
        canonical=lambda obj:json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
        raw=canonical(batch)
        def counts():
            return execute("SELECT (SELECT count(*) FROM contour.causal_sessions)::text||'|'||(SELECT count(*) FROM contour.causal_inbox_batches)::text||'|'||(SELECT count(*) FROM contour.causal_inbox_events)::text||'|'||coalesce((SELECT used_bytes::text FROM contour.origin_logical_usage WHERE tenant_id='"+IDS[0]+"'),'0');")
        def no_write(label,call,status,code,baseline):
            negative_case(label,call,status,code,baseline,counts,state)
        if counts()!='1|0|0|0': raise AssertionError('initial causal state is not empty')
        baseline=counts()
        # A missing client certificate must fail TLS; a valid unregistered
        # certificate must complete TLS but fail registry authorization.
        state['current_case']='missing_client_certificate'
        try: http_call(work,https_port,raw,client=None)
        except (ssl.SSLError,ConnectionResetError,BrokenPipeError,http.client.RemoteDisconnected): pass
        else: raise AssertionError('missing client certificate accepted')
        if counts()!=baseline: raise AssertionError('negative request wrote data')
        stage('missing_client_certificate')
        no_write('unknown_client_certificate',lambda:http_call(work,https_port,raw,client='unknown',headers={'content-type':'application/json','x-tenant-id':IDS[0],'x-runtime-id':IDS[1],'x-forwarded-client-cert':peer}),403,'not_authorized',baseline)
        for label,ca_name,server_name in (('untrusted_server_ca','untrusted.crt','localhost'),('wrong_server_name','ca.crt','not-localhost.invalid')):
            state['current_case']=label
            try:
                with socket.create_connection(('localhost',https_port),timeout=8) as plain:
                    with client_context(work,ca=ca_name).wrap_socket(plain,server_hostname=server_name): pass
            except ssl.SSLCertVerificationError: pass
            else: raise AssertionError('untrusted server accepted')
            if counts()!=baseline: raise AssertionError('negative request wrote data')
            stage(label)
        no_write('wrong_method',lambda:http_call(work,https_port,raw,method='GET'),405,'method_not_allowed',baseline)
        no_write('query_string',lambda:http_call(work,https_port,raw,path='/v1/causal-events?x=1'),404,'not_found',baseline)
        no_write('wrong_media',lambda:http_call(work,https_port,raw,headers={'content-type':'text/plain'}),415,'unsupported_media_type',baseline)
        no_write('content_encoding',lambda:http_call(work,https_port,raw,headers={'content-type':'application/json','content-encoding':'gzip'}),415,'unsupported_encoding',baseline)
        no_write('declared_trailer',lambda:http_call(work,https_port,raw,headers={'content-type':'application/json','trailer':'x-test'}),415,'unsupported_encoding',baseline)
        no_write('actual_trailer',lambda:raw_call(work,https_port,b'POST /v1/causal-events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\n{}\r\n0\r\nx-test: x\r\n\r\n'),400,'unsupported_trailers',baseline)
        no_write('declared_global_bound',lambda:raw_call(work,https_port,b'POST /v1/causal-events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n'),413,'batch_too_large',baseline)
        no_write('streamed_global_bound',lambda:streamed_limit_call(work,https_port),413,'batch_too_large',baseline)
        roots=[{'kind':'root','event_id':str(i)*32,'seq':i,'root':chr(96+i)*32} for i in (1,2,3)]
        too_many=canonical(dict(batch,first_seq=1,last_seq=3,events=roots))
        if len(too_many)>700: raise AssertionError('event bound fixture exceeds byte bound')
        no_write('declared_event_bound',lambda:http_call(work,https_port,too_many),422,'invalid_batch',baseline)
        attempts=[{'kind':'attempt','event_id':str(i)*32,'seq':i,'root':'a'*32,'activity':chr(96+i)*32,'attempt':chr(98+i)*32,'marker_digest':'f'*64} for i in (1,2)]
        too_large=canonical(dict(batch,first_seq=1,last_seq=2,events=attempts))
        if not 700<len(too_large)<1048576: raise AssertionError('byte bound fixture size invalid')
        no_write('declared_byte_bound',lambda:http_call(work,https_port,too_large),422,'invalid_batch',baseline)
        no_write('noncanonical',lambda:http_call(work,https_port,raw+b' '),422,'invalid_batch',baseline)
        no_write('unknown_body_field',lambda:http_call(work,https_port,canonical(dict(batch,unexpected='forged'))),422,'invalid_batch',baseline)
        for name,field,value in (('wrong_tenant','tenant_id','f0000000-0000-4000-8000-000000000002'),('wrong_runtime','runtime_id','fc000000-0000-4000-8000-000000000002'),('wrong_epoch','session_epoch',epoch+1)):
            no_write(name,lambda field=field,value=value:http_call(work,https_port,canonical(dict(batch,**{field:value}))),403,'not_authorized',baseline)
        state['current_case']='accepted_and_duplicate'
        status,first=http_call(work,https_port,raw)
        expected_keys={'batch_id','runtime_id','session_epoch','batch_digest','receipt_id','accepted_at','status'}
        digest=hashlib.sha256(b'apicontour/causal-events/1\n'+raw).hexdigest()
        if status!=200 or not isinstance(first,dict) or set(first)!=expected_keys or first['status']!='accepted' or first['batch_id']!=batch['batch_id'] or first['runtime_id']!=IDS[1] or first['session_epoch']!=epoch or first['batch_digest']!=digest:
            raise AssertionError('accepted receipt invalid')
        if str(uuid.UUID(first['receipt_id']))!=first['receipt_id']: raise AssertionError('receipt UUID invalid')
        accepted=datetime.datetime.fromisoformat(first['accepted_at'].replace('Z','+00:00'))
        if accepted.tzinfo is None: raise AssertionError('receipt time invalid')
        utc=accepted.astimezone(datetime.timezone.utc)-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
        micros=(utc.days*86400+utc.seconds)*1000000+utc.microseconds
        stored=execute("SELECT receipt_id::text||'|'||floor(extract(epoch FROM accepted_at)*1000000)::bigint::text||'|'||encode(batch_digest,'hex')||'|'||encode(canonical_batch,'hex') FROM contour.causal_inbox_batches WHERE batch_id='"+batch['batch_id']+"';")
        if stored!='|'.join((first['receipt_id'],str(micros),digest,raw.hex())) or counts()!='1|1|1|'+str(len(raw)):
            raise AssertionError('receipt or quota mismatch')
        status,again=http_call(work,https_port,raw,headers={'content-type':'application/json','x-tenant-id':'f0000000-0000-4000-8000-000000000002','x-runtime-id':'fc000000-0000-4000-8000-000000000002'})
        if status!=200 or again!=dict(first,status='duplicate') or counts()!='1|1|1|'+str(len(raw)):
            raise AssertionError('duplicate receipt mismatch')
        stage('accepted_and_duplicate')
        # Incomplete request EOF must not create an event; a later exact
        # retry remains usable. This is not an in-flight DB cancellation test.
        state['current_case']='incomplete_client_eof'
        with socket.create_connection(('localhost',https_port),timeout=8) as plain:
            with client_context(work).wrap_socket(plain,server_hostname='localhost') as tls:
                tls.sendall(b'POST /v1/causal-events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{')
        time.sleep(.2)
        if counts()!='1|1|1|'+str(len(raw)): raise AssertionError('incomplete EOF wrote data')
        if http_call(work,https_port,raw)!=(200,dict(first,status='duplicate')): raise AssertionError('retry after EOF failed')
        stage('incomplete_client_eof')
        # A full second request is sent without the application reading a
        # response. Independent SQL must observe commit before socket close.
        state['current_case']='unread_committed_response'
        batch2=dict(batch,batch_id=str(uuid.uuid4()),first_seq=2,last_seq=2,events=[{'kind':'root','event_id':'2'*32,'seq':2,'root':'b'*32}])
        raw2=canonical(batch2); total=len(raw)+len(raw2)
        with socket.create_connection(('localhost',https_port),timeout=8) as plain:
            with client_context(work).wrap_socket(plain,server_hostname='localhost') as tls:
                tls.sendall(b'POST /v1/causal-events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(raw2)).encode()+b'\r\n\r\n'+raw2)
                wait=time.monotonic()+10
                while counts()!='1|2|2|'+str(total):
                    if time.monotonic()>=wait: raise TimeoutError('unread response commit deadline')
                    time.sleep(.05)
        status,replay=http_call(work,https_port,raw2)
        if status!=200 or not isinstance(replay,dict) or set(replay)!=expected_keys or replay.get('status')!='duplicate' or replay.get('batch_id')!=batch2['batch_id'] or replay.get('runtime_id')!=IDS[1] or replay.get('session_epoch')!=epoch or replay.get('batch_digest')!=hashlib.sha256(b'apicontour/causal-events/1\n'+raw2).hexdigest():
            raise AssertionError('unread response retry mismatch')
        accepted2=datetime.datetime.fromisoformat(replay['accepted_at'].replace('Z','+00:00'))
        if accepted2.tzinfo is None: raise AssertionError('receipt time invalid')
        utc2=accepted2.astimezone(datetime.timezone.utc)-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
        micros2=(utc2.days*86400+utc2.seconds)*1000000+utc2.microseconds
        row=execute("SELECT receipt_id::text||'|'||floor(extract(epoch FROM accepted_at)*1000000)::bigint::text FROM contour.causal_inbox_batches WHERE batch_id='"+batch2['batch_id']+"';")
        if row!='|'.join((replay['receipt_id'],str(micros2))) or counts()!='1|2|2|'+str(total): raise AssertionError('unread receipt or quota mismatch')
        stage('unread_committed_response')
        # Disposable trigger holds the active INSERT behind an advisory
        # barrier. Verify it is waiting while Q is held, then shut down the
        # server and require both rollback and Q release before retrying.
        state['current_case']='inflight_shutdown_cancellation'
        barrier_key=secrets.randbelow(1900000000)+1
        execute("CREATE FUNCTION contour.fixture_https_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(19890,"+str(barrier_key)+"); RETURN NEW; END $$; CREATE TRIGGER fixture_https_barrier BEFORE INSERT ON contour.causal_inbox_batches FOR EACH ROW EXECUTE FUNCTION contour.fixture_https_barrier();")
        blocker=ProbeProcess(sql,env=None)
        try:
            blocker.child.stdin.write(("BEGIN; DO $$ BEGIN PERFORM pg_advisory_xact_lock(19890,"+str(barrier_key)+"); END $$;\n\\echo READY 1 1\n").encode()); blocker.child.stdin.flush()
            if blocker.ready()!=(1,1): raise AssertionError('barrier not held')
            pending=dict(batch,batch_id=str(uuid.uuid4()),first_seq=3,last_seq=3,events=[{'kind':'root','event_id':'3'*32,'seq':3,'root':'c'*32}])
            pending_raw=canonical(pending)
            with socket.create_connection(('localhost',https_port),timeout=8) as plain:
                with client_context(work).wrap_socket(plain,server_hostname='localhost') as tls:
                    tls.sendall(b'POST /v1/causal-events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(pending_raw)).encode()+b'\r\n\r\n'+pending_raw)
                    def waiter():
                        return execute("SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype='advisory' AND classid=19890 AND objid="+str(barrier_key)+" AND objsubid=2 AND NOT granted;")
                    until=time.monotonic()+4
                    while waiter()!='1':
                        if time.monotonic()>=until: raise TimeoutError('database barrier wait deadline')
                        time.sleep(.025)
                    qtest="SELECT pg_try_advisory_xact_lock(1330792270,pg_catalog.hashtext('"+IDS[0]+"'))::text;"
                    if execute(qtest)!='false': raise AssertionError('inflight Q lock missing')
                    monitor.stop(True); monitor=None
                    until=time.monotonic()+12
                    while waiter()!='0' or execute(qtest)!='true':
                        if time.monotonic()>=until: raise TimeoutError('database cancellation deadline')
                        time.sleep(.05)
            if counts()!='1|2|2|'+str(total): raise AssertionError('cancelled insert wrote data')
            blocker.child.stdin.write(b'ROLLBACK;\n\\q\n'); blocker.child.stdin.flush(); blocker.child.stdin.close()
            blocker.child.wait(timeout=8)
            if blocker.child.returncode!=0: raise RuntimeError('barrier release failed')
        finally:
            blocker.stop(False)
        execute('DROP TRIGGER fixture_https_barrier ON contour.causal_inbox_batches; DROP FUNCTION contour.fixture_https_barrier();')
        monitor=ProbeProcess(args,env)
        https_port,recovered_epoch=monitor.ready()
        if recovered_epoch!=epoch: raise AssertionError('retry session changed')
        status,pending_receipt=http_call(work,https_port,pending_raw)
        if status!=200 or pending_receipt.get('status')!='accepted' or pending_receipt.get('batch_id')!=pending['batch_id'] or pending_receipt.get('batch_digest')!=hashlib.sha256(b'apicontour/causal-events/1\n'+pending_raw).hexdigest(): raise AssertionError('cancelled insert retry failed')
        total+=len(pending_raw)
        if counts()!='1|3|3|'+str(total): raise AssertionError('cancelled insert retry quota mismatch')
        stage('inflight_shutdown_cancellation')
        # A stopped-server database clone permits independent irreversible
        # collector revocation without weakening or restoring the original.
        state['current_case']='collector_revocation'
        monitor.stop(True); monitor=None
        admin_sql=list(sql); admin_sql[-1]='postgres'
        command(admin_sql,data=b'CREATE DATABASE contour_clone TEMPLATE contour_fixture;',timeout=120)
        clone_sql=list(sql); clone_sql[-1]='contour_clone'
        def execute_clone(statement): return command(clone_sql,data=statement.encode(),timeout=120).decode().strip()
        clone_args=list(args); clone_args[3]='contour_clone'
        monitor=ProbeProcess(clone_args,env)
        clone_port,clone_epoch=monitor.ready()
        if clone_epoch!=epoch: raise AssertionError('clone session changed')
        execute_clone("BEGIN; SELECT set_config('apicontour.tenant_id','"+IDS[0]+"',true); SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('"+IDS[0]+"','"+IDS[2]+"'); UPDATE contour.collector_authorization SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id='"+IDS[0]+"' AND collector_id='"+IDS[2]+"'; COMMIT;")
        expected_clone='1|3|3|'+str(total)
        def clone_counts():
            return execute_clone("SELECT (SELECT count(*) FROM contour.causal_sessions)::text||'|'||(SELECT count(*) FROM contour.causal_inbox_batches)::text||'|'||(SELECT count(*) FROM contour.causal_inbox_events)::text||'|'||coalesce((SELECT used_bytes::text FROM contour.origin_logical_usage WHERE tenant_id='"+IDS[0]+"'),'0');")
        expect_error(http_call(work,clone_port,raw),403,'not_authorized')
        clone_new=dict(batch,batch_id=str(uuid.uuid4()),first_seq=4,last_seq=4,events=[{'kind':'root','event_id':'4'*32,'seq':4,'root':'d'*32}])
        expect_error(http_call(work,clone_port,canonical(clone_new)),403,'not_authorized')
        if clone_counts()!=expected_clone: raise AssertionError('collector revocation wrote data')
        monitor.stop(True); monitor=None
        command(admin_sql,data=b'DROP DATABASE contour_clone;',timeout=120)
        stage('collector_revocation')
        monitor=ProbeProcess(args,env)
        https_port,recovered_epoch=monitor.ready()
        if recovered_epoch!=epoch: raise AssertionError('retry session changed')
        state['current_case']='runtime_revocation'
        execute("SELECT set_config('apicontour.tenant_id','"+IDS[0]+"',false); SET ROLE contour_causal_provisioner; SELECT contour.end_causal_runtime('"+IDS[0]+"','"+IDS[1]+"','export_revoked'); RESET ROLE;")
        baseline=counts()
        no_write('revoked_exact_replay',lambda:http_call(work,https_port,raw),403,'not_authorized',baseline)
        batch3=dict(batch,batch_id=str(uuid.uuid4()),first_seq=4,last_seq=4,events=[{'kind':'root','event_id':'4'*32,'seq':4,'root':'d'*32}])
        no_write('revoked_new_batch',lambda:http_call(work,https_port,canonical(batch3)),403,'not_authorized',baseline)
        state['current_case']='bounded_shutdown'
        monitor.stop(True); monitor=None
        stage('bounded_shutdown')
        state['limitations']=['No ambiguous COMMIT fault injection was performed; shutdown cancellation uses a fixture-only pre-insert barrier.',
                              'Unread response case proves the application did not read; it does not prove zero response bytes reached the socket.',
                              'No producer attestation, retention or production ingress activation is established.']
        require_scenarios(state['stages'][stage_start:])
        state.pop('current_case',None)
        state['status']='passed'
    finally:
        if monitor is not None:
            monitor.stop(False)



def install_helpers(bridge,inbox,loaded_hashes=None):
    """Adapt only fixture inputs; ownership and cleanup stay in bridge driver."""
    global command, IDS
    bg=bridge['main'].__globals__
    original_command=bridge['command']; original_checked=bridge['checked']
    original_snapshot=bridge['snapshot']; original_build=bridge['build_probe']
    original_sign=bridge['signed_payload']
    IDS=bridge['IDS']
    context={}
    def setup_tls(work):
        if context.get('tls_ready'): return
        if not work.is_absolute() or not (work/'ca.crt').is_file() or not (work/'ca.key').is_file() or not (work/'server.crt').is_file() or not (work/'server.key').is_file():
            raise ValueError('fixture TLS input unavailable')
        (work/'client.ext').write_text('basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n')
        for client in ('client','unknown'):
            original_command(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+client,'-keyout',str(work/(client+'.key')),'-out',str(work/(client+'.csr'))],timeout=30)
            original_command(['openssl','x509','-req','-in',str(work/(client+'.csr')),'-CA',str(work/'ca.crt'),'-CAkey',str(work/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(work/'client.ext'),'-out',str(work/(client+'.crt'))],timeout=30)
        for src,dst in (('ca.crt','ca.crt.der'),('server.crt','server.crt.der'),('client.crt','client.crt.der')):
            (work/dst).write_bytes(original_command(['openssl','x509','-in',str(work/src),'-outform','DER'],timeout=15))
        (work/'server.key.der').write_bytes(original_command(['openssl','pkcs8','-topk8','-nocrypt','-in',str(work/'server.key'),'-outform','DER'],timeout=15))
        context['peer']=hashlib.sha256((work/'client.crt.der').read_bytes()).hexdigest()
        context['tls_ready']=True
    def command_proxy(args,**kwargs):
        if args[:2]==['openssl','req'] and '-keyout' in args:
            key=Path(args[args.index('-keyout')+1])
            if key.name=='server.key': context['work']=key.parent
        if len(args)>=6 and args[:3]==['docker','exec','-i'] and args[-1]=='cat > /var/lib/postgresql/data/pg_hba.conf':
            data=kwargs.get('data'); old=b'hostssl contour_fixture causal_issuer_login,causal_inbox_login,causal_mixed_login all scram-sha-256'
            if not isinstance(data,bytes) or data.count(old)!=1: raise RuntimeError('fixture HBA marker mismatch')
            kwargs['data']=data.replace(old,old.replace(b'contour_fixture ',b'contour_fixture,contour_clone '),1)
        return original_command(args,**kwargs)
    command=command_proxy
    def checked_proxy(path):
        raw=original_checked(path)
        if path==ROOT/'db/tests/causal_session_setup.sql':
            work=context.get('work')
            if work is None: raise RuntimeError('fixture TLS work directory unavailable')
            setup_tls(work)
            marker=b"decode(repeat('33',32),'hex')"
            if raw.count(marker)!=1: raise RuntimeError('export leaf marker mismatch')
            raw=raw.replace(marker,("decode('"+context['peer']+"','hex')").encode(),1)
        return raw
    def sign_proxy(template,domain,key,directory,name):
        if domain==b'apicontour/causal-grant/1\n':
            template=dict(template,max_batch_events=2,max_batch_bytes=700)
        return original_sign(template,domain,key,directory,name)
    def snapshot():
        if loaded_hashes is not None:
            for name,expected in loaded_hashes.items():
                if hashlib.sha256(safe_source(name).read_bytes()).hexdigest()!=expected:
                    raise RuntimeError('qualification helper changed after loading')
        result={'inbox:'+key:value for key,value in inbox['source_snapshot']().items()}
        result.update({'bridge:'+key:value for key,value in original_snapshot().items()})
        for path in ('scripts/test-postgres-causal-https.py','tests/fixtures/causal-https/test_https_driver.py',
                     'scripts/test-postgres-causal-bridge.py','tests/fixtures/causal-bridge/test_bridge_driver.py',
                     'crates/contour-ingress/examples/causal_https_probe.rs','crates/contour-ingress/CAUSAL-HTTPS.md',
                     'crates/contour-ingress/src/causal_service.rs','crates/contour-ingress/src/pool.rs',
                     'crates/contour-postgres/tests/fixtures/causal_bridge.json'):
            result['https:'+path]=bridge['digest_file'](safe_source(path))
        return result
    def scenario(base,work,env,counts,state,execute):
        if context.get('work')!=work or not context.get('tls_ready'): raise RuntimeError('fixture TLS state unavailable')
        state['_https_peer']=context['peer']
        state['boundary']='synthetic HTTPS mTLS and PostgreSQL TLS; no producer attestation or production activation'
        run_https_cases(base,work,env,counts,state)
    bg.update({'command':command_proxy,'checked':checked_proxy,'signed_payload':sign_proxy,
               'snapshot':snapshot,'build_probe':lambda target:original_build(target,'contour-ingress','causal_https_probe'),
               'run_scenario':scenario})
    return context


def main():
    if len(sys.argv)!=1: raise ValueError('qualification accepts no arguments')
    bridge,inbox,loaded_hashes=load_helpers()
    install_helpers(bridge,inbox,loaded_hashes)
    bridge['main']()


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('FAIL:',type(error).__name__,file=sys.stderr)
        raise SystemExit(1) from None
