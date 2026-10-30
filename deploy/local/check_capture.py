"""Exercise only the owned synthetic capture profile; retains all records and state."""
import copy
import datetime
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/'.local-mvp'
COMPOSE=['docker','compose','-f',str(ROOT/'deploy/local/compose.yaml')]
TENANT='00000000-0000-4000-8000-000000000001'
PROJECT='00000000-0000-4000-8000-000000000002'
SERVICE='00000000-0000-4000-8000-000000000003'
ENVIRONMENT='00000000-0000-4000-8000-000000000004'
COLLECTOR='00000000-0000-4000-8000-000000000201'
SOURCE='00000000-0000-4000-8000-000000000202'
DEPLOYMENT='00000000-0000-4000-8000-000000000203'


def run(args, *, input=None, timeout=60):
    result=subprocess.run(args,cwd=ROOT,input=input,capture_output=True,text=True,timeout=timeout)
    if result.returncode: raise RuntimeError('synthetic capture fixture command failed')
    return result.stdout.strip()


def sql(text):
    return run(COMPOSE+['exec','-T','-u','postgres','postgres','psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_local'],input=text)


def main():
    os.environ['LOCAL_UID']=str(os.getuid()); os.environ['LOCAL_GID']=str(os.getgid())
    context=ssl.create_default_context(cafile=str(STATE/'ca.crt'))
    context.load_cert_chain(STATE/'capture/private/collector.crt',STATE/'capture/private/collector.key')
    def post(path,value,ctx=context,host='localhost'):
        connection=http.client.HTTPSConnection(host,9445,context=ctx,timeout=8)
        try:
            connection.request('POST',path,body=json.dumps(value,separators=(',',':')).encode(),headers={'Content-Type':'application/json'})
            response=connection.getresponse(); body=response.read(1_048_577)
            if len(body)>1_048_576: raise RuntimeError('fixture response too large')
            return response.status,json.loads(body)
        finally: connection.close()
    challenge=secrets.token_hex(32)
    status,authority=post('/v1/collector-authority',dict(wire_version=1,challenge=challenge,source_ids=[SOURCE]))
    assert status==200 and authority['challenge']==challenge and authority['tenant_id']==TENANT and authority['collector_id']==COLLECTOR
    assert len(authority['sources'])==1 and authority['sources'][0]['source_id']==SOURCE
    no_client=ssl.create_default_context(cafile=str(STATE/'ca.crt'))
    try: post('/v1/collector-authority',dict(wire_version=1,challenge=challenge,source_ids=[SOURCE]),no_client)
    except (ssl.SSLError,ConnectionError,OSError): pass
    else: raise AssertionError('missing collector certificate accepted')
    now=datetime.datetime.now(datetime.timezone.utc)
    iso=lambda value:value.isoformat(timespec='microseconds').replace('+00:00','Z')
    batch=copy.deepcopy(next(x['body'] for x in json.loads((ROOT/'docs/specification/fixtures/batches.json').read_text()) if x['id']=='valid_structure'))
    batch.update(batch_id=str(uuid.uuid4()),tenant_id=TENANT,collector_id=COLLECTOR,created_at=iso(now))
    record=batch['records'][0]
    record.update(record_id=str(uuid.uuid4()),project_id=PROJECT,service_id=SERVICE,environment_id=ENVIRONMENT,deployment_id=DEPLOYMENT,source_id=SOURCE,first_seen=iso(now),last_seen=iso(now),queued_at=iso(now),expires_at=iso(now+datetime.timedelta(minutes=5)),structure={'kind':'object','fields':{'id':{'kind':'string'}},'additional':None})
    wrong_identity=copy.deepcopy(batch)
    wrong_identity['collector_id']='00000000-0000-4000-8000-000000000299'
    assert post('/v1/batches',wrong_identity)[0]==403
    try:
        with socket.create_connection(('127.0.0.1',9445),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname='wrong.invalid'): pass
    except ssl.SSLCertVerificationError: pass
    else: raise AssertionError('wrong ingress TLS name accepted')
    # Hold projection to demonstrate pending durable data, not receipt-only scheduling.
    run(COMPOSE+['stop','capture-worker'])
    try:
        status,receipt=post('/v1/batches',batch)
        assert status==200 and receipt['batch_id']==batch['batch_id'] and receipt['status']=='accepted'
        status,duplicate=post('/v1/batches',batch)
        assert status==200 and duplicate['batch_id']==batch['batch_id'] and duplicate['status']=='duplicate' and duplicate['receipt_id']==receipt['receipt_id']
        batch_id=batch['batch_id']
        assert sql("SELECT count(*) FROM contour.ingestion_payloads WHERE tenant_id='"+TENANT+"' AND collector_id='"+COLLECTOR+"' AND batch_id='"+batch_id+"';")=='1'
        assert sql("SELECT count(*) FROM contour.catalog_processed_batches WHERE tenant_id='"+TENANT+"' AND collector_id='"+COLLECTOR+"' AND batch_id='"+batch_id+"';")=='0'
        run(COMPOSE+['restart','postgres','capture-ingress'],timeout=90)
    finally:
        run(COMPOSE+['start','capture-worker'],timeout=60)
    until=time.monotonic()+40
    while True:
        count=sql("SELECT count(*) FROM contour.observation_windows WHERE tenant_id='"+TENANT+"' AND collector_id='"+COLLECTOR+"' AND batch_id='"+batch_id+"' AND record_id='"+record['record_id']+"';")
        if count=='1': break
        if time.monotonic()>=until: raise RuntimeError('pending capture was not projected')
        time.sleep(.25)
    assert sql("SELECT count(*) FROM contour.catalog_processed_batches WHERE tenant_id='"+TENANT+"' AND collector_id='"+COLLECTOR+"' AND batch_id='"+batch_id+"';")=='1'
    print('Synthetic mTLS receipt, duplicate, durable pending restart and exactly-once projection passed; API/UI visibility remains separate.')

if __name__=='__main__': main()
