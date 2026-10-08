"""Pre-send children and uncertain committed-parent/413 exclusion over real TLS/PG."""
import base64
import contextlib
from datetime import datetime
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import queue
import runpy
import subprocess
import threading
import time


def instant(value):
    # Rust emits 1–9 fraction digits; Python 3.9 fromisoformat accepts only 3/6.
    # Keep the full fraction for exact TTL checks; wall-clock waiting rounds up.
    assert value.endswith('Z')
    whole, separator, fraction = value[:-1].partition('.')
    assert not separator or (fraction.isascii() and fraction.isdigit() and 1 <= len(fraction) <= 9)
    seconds = int(datetime.fromisoformat(whole+'+00:00').timestamp())
    return Decimal(seconds) + (Decimal('0.'+fraction) if separator else Decimal(0))


def run_cases(execute,setup,server,relay,directory,environment,probe):
    print('Bounded FIFO delivery: children and committed lost reply → 413 guard',flush=True)
    body,collector,_=setup('bounded_delivery',current=1,history=(1,))
    path=directory/'bounded-input.json';path.write_text(json.dumps(body))
    policy_path=directory/'bounded-policy.json'
    policy_path.write_bytes(bytes.fromhex(execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE tenant_id='%s' AND collector_id='%s' AND revision=1;" % (body['tenant_id'],collector))))
    evidence={};signals={name:threading.Event() for name in ['phase','eof','release','sent']}
    with server(body,deadline=5000) as upstream:
        with contextlib.ExitStack() as owned:
            lost=owned.enter_context(relay(upstream,'lost',evidence,signals))
            refused=owned.enter_context(relay(upstream,'retry-413',{},signals))
            result=subprocess.run([probe,str(directory),str(path),str(policy_path),'bounded:%d:%d:%d' % (upstream,lost,refused)],capture_output=True,text=True,env=environment,timeout=20)
            assert result.returncode==0 and not result.stderr, 'bounded probe failed: '+result.stderr
            outcome=json.loads(result.stdout)
            assert outcome['charge']==0 and len(outcome['bounded'])==3
            assert evidence['status']=='accepted' and signals['eof'].is_set()
            assert outcome['bounded'][0]['receipt_id']==evidence['receipt_id']
            assert outcome['bounded'][0]['accepted_at']==evidence['accepted_at']
    envelope=json.loads(policy_path.read_bytes());encoded=envelope['payload_base64url']
    policy=json.loads(base64.urlsafe_b64decode(encoded+'='*((4-len(encoded)%4)%4)))
    records=[]
    for i,receipt in enumerate(outcome['bounded'],1):
        wire=(directory/('bounded-wire-%d.json'%i)).read_bytes();value=json.loads(wire)
        assert len(wire)<=outcome['wire_limit'] and len(value['records'])==1
        record=value['records'][0];records.append(record['record_id'])
        assert value['tenant_id']==body['tenant_id'] and value['collector_id']==collector
        original=json.loads((directory/'bounded-original.json').read_bytes())[i-1]
        assert record['record_id']==original['record_id'] and record['queued_at']==original['queued_at'] and record['expires_at']==original['expires_at']
        assert record['structure']==body['records'][0]['structure']
        assert record['first_seen']==body['records'][0]['first_seen'] and record['last_seen']==body['records'][0]['last_seen']
        assert instant(record['expires_at'])-instant(record['queued_at'])==policy['queue_ttl_seconds']
        row=execute("SELECT encode(b.request_digest,'hex') || '|' || encode(p.checked_batch,'hex') FROM contour.ingestion_batches b JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE b.tenant_id='%s' AND b.collector_id='%s' AND b.batch_id='%s';" % (body['tenant_id'],collector,receipt['batch_id']))
        digest,payload=row.split('|')
        canonical=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        assert digest==hashlib.sha256(b'apicontour/batch/1\n'+canonical).hexdigest() and bytes.fromhex(payload)==wire
    assert records==['00000000-0000-4000-8000-%012x'%i for i in range(1,4)]
    assert execute("SELECT count(*) FROM contour.ingestion_batches WHERE tenant_id='%s' AND collector_id='%s';" % (body['tenant_id'],collector))=='3'
    print('Actual bounded FIFO children retain identity/content/TTL; known committed lost reply → 413 cannot thaw parent; exact duplicate receipt and zero charge passed',flush=True)

    helpers=runpy.run_path(str(Path(__file__).with_name('test-collector-retry.py')))
    for mode in ['expire','disable']:
        print('Bounded pending-child case: '+mode,flush=True)
        body,collector,_=setup('bounded_'+mode,current=1,history=(1,),change=(lambda p:p.update(queue_ttl_seconds=2)) if mode=='expire' else None)
        path.write_text(json.dumps(body))
        policy_path.write_bytes(bytes.fromhex(execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE tenant_id='%s' AND collector_id='%s' AND revision=1;" % (body['tenant_id'],collector))))
        process=None;reader=None
        try:
            with server(body,deadline=5000) as upstream:
                process=subprocess.Popen([probe,str(directory),str(path),str(policy_path),'bounded-%s:%d:0:0'%(mode,upstream)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
                lines=queue.Queue()
                def read_lines():
                    for line in process.stdout:lines.put(line)
                    lines.put(None)
                reader=threading.Thread(target=read_lines,daemon=True);reader.start()
                def marker():
                    try:line=lines.get(timeout=12)
                    except queue.Empty:raise AssertionError('bounded pending marker timeout')
                    if line is None:
                        process.wait(timeout=2)
                        raise AssertionError('bounded pending probe exited: '+process.stderr.read().strip())
                    return json.loads(line)
                phase=marker();assert phase['phase']=='pending' and phase['charge']>0
            # Initial real DB server is stopped before next backend sentinel setup.
            if mode=='expire':
                original=json.loads((directory/'bounded-original.json').read_bytes())
                expiry=max(instant(v['expires_at']) for v in original)
                time.sleep(max(0,float(expiry+Decimal('0.000001'))-time.time()))
            else:
                helpers['disable'](body,policy_path,directory,execute)
                reenrolled,new_collector,_=setup('bounded_reenrolled',current=1,history=(1,))
                (directory/'bounded-reenroll.json').write_text(json.dumps(reenrolled))
                (directory/'bounded-reenroll-policy.json').write_bytes(bytes.fromhex(execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE tenant_id='%s' AND collector_id='%s' AND revision=1;"%(reenrolled['tenant_id'],new_collector))))
            with helpers['sentinel']() as backend,helpers['sentinel']() as next_https:
                with server(body,backend=backend.getsockname()[1],deadline=5000) as blocked_database:
                    process.stdin.write(json.dumps([next_https.getsockname()[1],blocked_database])+'\n');process.stdin.flush()
                    outcome=marker();assert outcome=={'terminal':'bounded-'+mode,'charge':0}
                    _,error=process.communicate(timeout=3)
                    assert process.returncode==0 and not error,'bounded pending probe failed: '+error
                    helpers['untouched'](next_https);helpers['untouched'](backend)
            assert execute("SELECT count(*) FROM contour.ingestion_batches WHERE tenant_id='%s' AND collector_id='%s';"%(body['tenant_id'],collector))=='1'
        finally:
            if process is not None:
                if process.poll() is None:process.kill();process.wait(timeout=3)
                if reader is not None:reader.join(2)
                for pipe in [process.stdin,process.stdout,process.stderr]:pipe.close()
    print('Actual pending-child expiry and signed policy disablement purge before next HTTPS/DB TCP contact; reenrolled identity cannot inherit records passed',flush=True)
