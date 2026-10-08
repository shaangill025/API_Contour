"""Caller-driven retries over actual mTLS; scripted statuses are not DB receipts."""
import base64
import contextlib
import hashlib
import json
import queue
import socket
import subprocess
import threading


@contextlib.contextmanager
def sentinel():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(0.2)
        yield listener
def untouched(listener):
    try: contact,_=listener.accept()
    except socket.timeout: return
    contact.close()
    raise AssertionError('terminal/expired/revoked state contacted owned endpoint sentinel')
def disable(body,policy_path,directory,execute):
    envelope=json.loads(policy_path.read_bytes())
    raw=envelope['payload_base64url'];policy=json.loads(base64.urlsafe_b64decode(raw+'='*((4-len(raw)%4)%4)))
    policy.update(revision=2,enabled=False)
    payload=json.dumps(policy,separators=(',',':')).encode()
    message=directory/'retry-message';signature=directory/'retry-signature'
    message.write_bytes(b'apicontour/policy/1\n'+payload)
    subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(directory/'signer.key'),'-in',str(message),'-out',str(signature)],capture_output=True,check=True,timeout=5)
    encode=lambda data:base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    envelope.update(payload_base64url=encode(payload),signature_base64url=encode(signature.read_bytes()))
    signed=json.dumps(envelope,separators=(',',':')).encode()
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); INSERT INTO contour.policy_revisions VALUES('%s','%s',2,decode('%s','hex')); UPDATE contour.collector_authorization SET active_revision=2,enabled=false WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (body['tenant_id'],body['tenant_id'],body['collector_id'],body['tenant_id'],body['collector_id'],signed.hex(),body['tenant_id'],body['collector_id']))
    policy_path.write_bytes(signed)


def run_cases(execute,setup,server,relay,directory,environment,probe):
    modes=['seconds','date','lost','malformed','duplicate','cap','ttl','revoke','cancel','binding','400','422','401','403','409','413']
    for mode in modes:
        print('Controller case: '+mode,flush=True)
        short=mode in ['ttl','401']
        body,collector,_=setup('retry_'+mode,current=1,history=(1,),change=(lambda p:p.update(queue_ttl_seconds=2)) if short else None)
        identity="tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (body['tenant_id'],collector,body['batch_id'])
        path=directory/'retry-input.json';path.write_text(json.dumps(body))
        policy_path=directory/'retry-policy.json'
        policy_path.write_bytes(bytes.fromhex(execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE tenant_id='%s' AND collector_id='%s' AND revision=1;" % (body['tenant_id'],collector))))
        signals={name:threading.Event() for name in ['phase','eof','release','sent']};evidence={}
        terminal=mode in ['ttl','revoke','400','422','401','403','409','413','binding']
        with sentinel() as backend, sentinel() as next_https:
            with server(body,backend=backend.getsockname()[1] if terminal else None,deadline=5000) as upstream:
                with contextlib.ExitStack() as owned:
                    fault=owned.enter_context(relay(upstream,'retry-'+mode,evidence,signals))
                    arguments=[probe,str(directory),str(path),str(policy_path),'retry-%s:%d,good:%d' % (mode,fault,next_https.getsockname()[1] if terminal else upstream)]
                    if mode in ['cap','revoke','cancel']:
                        listener=owned.enter_context(socket.socket());listener.settimeout(10)
                        listener.bind(('127.0.0.1',0));listener.listen(1)
                        arguments.append(str(listener.getsockname()[1]))
                    process=subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
                    lines=queue.Queue()
                    def read_lines():
                        for line in process.stdout:lines.put(line)
                        lines.put(None)
                    reader=threading.Thread(target=read_lines,daemon=True);reader.start()
                    def marker():
                        try:line=lines.get(timeout=12)
                        except queue.Empty:raise AssertionError('controller marker timed out')
                        if line is None:
                            process.wait(timeout=2)
                            raise AssertionError('controller probe exited: '+process.stderr.read().strip())
                        return json.loads(line)
                    try:
                        decision=marker();assert decision['charge']>0
                        if mode=='seconds':assert decision['retry_after_ms']==1000
                        elif mode=='date':assert 0<=decision['retry_after_ms']<=2000
                        elif mode in ['cap','revoke','cancel']:assert decision['retry_after_ms']==300000
                        elif mode=='ttl':assert decision['retry_after_ms']==10000
                        else:assert decision['retry_after_ms'] is None
                        if mode!='lost':assert signals['eof'].wait(2) and process.poll() is None, 'error body/driver retained during backoff'
                        committed=mode in ['seconds','date','lost']
                        assert execute('SELECT count(*) FROM contour.ingestion_batches WHERE '+identity+';')==('1' if committed else '0')
                        process.stdin.write('\n');process.stdin.flush()
                        if mode in ['cap','revoke','cancel']:
                            control,_=listener.accept();control.settimeout(2);owned.enter_context(control)
                            assert control.recv(1)==b'A', 'retry wait was not explicitly pending'
                            if mode=='revoke':disable(body,policy_path,directory,execute)
                            control.sendall(b'C')
                        result=marker();_,error=process.communicate(timeout=3)
                        assert process.returncode==0 and not error,'controller probe failed: '+error
                        if terminal:
                            expected={'ttl':'expired','revoke':'revoked','400':'discard','422':'discard','401':'pause-expired','403':'paused','409':'stopped','413':'stopped','binding':'binding'}[mode]
                            assert result['terminal']==expected
                            assert result['charge']==(decision['charge'] if mode in ['403','409','413','binding'] else 0)
                            untouched(backend);untouched(next_https)
                        else:
                            assert result['status']==('duplicate' if committed else 'accepted')
                            if committed:assert result['receipt_id']==evidence['receipt_id'] and result['accepted_at']==evidence['accepted_at']
                            wire=(directory/'delivery-wire.json').read_bytes()
                            row=execute("SELECT encode(b.request_digest,'hex')||'|'||encode(p.checked_batch,'hex') FROM contour.ingestion_batches b JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE b."+identity.replace(' AND ',' AND b.')+';')
                            digest,payload=row.split('|')
                            canonical=json.dumps(json.loads(wire),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
                            assert digest==(directory/'delivery-digest.txt').read_text()==hashlib.sha256(b'apicontour/batch/1\n'+canonical).hexdigest() and bytes.fromhex(payload)==wire
                    finally:
                        if process.poll() is None:process.kill();process.wait(timeout=3)
                        reader.join(2)
                        for pipe in [process.stdin,process.stdout,process.stderr]:pipe.close()
    print('Actual TLS header-only classification, bounded Retry-After, timed exact retry, pause/TTL/revocation and wait cancellation passed')
