"""Fixed synthetic SQL28 issuer scenario; peer and deployment proof are excluded."""
import base64
import datetime
import json
import hashlib
import re
import secrets
import uuid
from pathlib import Path

TENANT='f0000000-0000-4000-8000-000000000001'
IDS=(TENANT,'fc000000-0000-4000-8000-000000000010','f6000000-0000-4000-8000-000000000003',
     'f7000000-0000-4000-8000-000000000010','f1000000-0000-4000-8000-000000000001',
     'f2000000-0000-4000-8000-000000000001','f3000000-0000-4000-8000-000000000001',
     'f4000000-0000-4000-8000-000000000001','f5000000-0000-4000-8000-000000000010',
     'f9000000-0000-4000-8000-000000000010')
MANIFEST='af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d'
CHECKS=('receiver-issuer-positive','receiver-issuer-generic-refusal','receiver-issuer-cross-profiles','receiver-issuer-negatives','receiver-events-positive-retry','receiver-events-denials')


def _canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def _payload(item):
    text=item['payload_base64url']; return json.loads(base64.urlsafe_b64decode(text+'='*((-len(text))%4)))
def _encoded(raw): return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def run(*,execute,openssl,write_private,private_dir,probe_call,ca_pem,port,passwords,fixture_bytes,export_leaf=None):
    """Execute fixed public-role calls and inspect exact SQL scope, no raw output."""
    if set(passwords)!={'issuer','wrong'} or any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}',v) for v in passwords.values()): raise ValueError('issuer fixture password')
    if not isinstance(ca_pem,bytes) or not re.fullmatch('[0-9]{1,5}',str(port)): raise ValueError('issuer fixture TLS')
    if export_leaf is None: export_leaf='ed'*32
    if type(export_leaf) is not str or not re.fullmatch('[0-9a-f]{64}',export_leaf): raise ValueError('issuer fixture export leaf')
    template=json.loads(fixture_bytes); now=datetime.datetime.now(datetime.timezone.utc)
    stamp=lambda t:t.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    issued=stamp(now-datetime.timedelta(minutes=1)); expires=stamp(now+datetime.timedelta(minutes=8))
    grant=_payload(template['grant']);grant.update(tenant_id=IDS[0],runtime_id=IDS[1],collector_id=IDS[2],source_id=IDS[3],instance_id=IDS[8],lifecycle_id=IDS[9],revision=2,issued_at=issued,expires_at=expires,causal_profile='nodered_5_0_9_receiver_v1',profile_sha256=MANIFEST)
    policy=_payload(template['policy']);policy.update(tenant_id=IDS[0],collector_id=IDS[2],service_ids=[IDS[5]],revision=2,issued_at=issued,expires_at=expires)
    public={}
    for name in ('grant','policy'):
        private=openssl(['genpkey','-algorithm','ED25519'])
        if not private.startswith(b'-----BEGIN PRIVATE KEY-----\n') or len(private)>4096: raise ValueError('issuer fixture key')
        write_private('issuer-'+name+'.key',private)
        der=openssl(['pkey','-in',str(Path(private_dir)/('issuer-'+name+'.key')),'-pubout','-outform','DER'])
        if len(der)!=44 or der[:12]!=bytes.fromhex('302a300506032b6570032100'): raise ValueError('issuer fixture public key')
        public[name]=der[-32:].hex()
    def signed(name,payload,key,domain):
        body=_canonical(payload); message=domain+body
        write_private('issuer-message-'+name,message)
        sig=openssl(['pkeyutl','-sign','-rawin','-inkey',str(Path(private_dir)/('issuer-'+key+'.key')),'-in',str(Path(private_dir)/('issuer-message-'+name))])
        if len(sig)!=64: raise ValueError('issuer fixture signature')
        return {'key_id':'fixture','signature_profile':'ed25519-v1','payload_base64url':_encoded(body),'signature_base64url':_encoded(sig)}
    p=signed('policy',policy,'policy',b'apicontour/policy/1\n')
    profiles={'valid':grant,'legacy':dict(grant,causal_profile='nodered_5_0_9_v1',profile_sha256='b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510'),
              'wire':dict(grant,causal_profile='nodered_5_0_9_wire_v1',profile_sha256='a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e'),
              'wrong-scope':dict(grant,tenant_id='f0000000-0000-4000-8000-000000000002'),
              'expired':dict(grant,issued_at=stamp(now-datetime.timedelta(minutes=3)),expires_at=stamp(now-datetime.timedelta(minutes=1)))}
    grants={name:signed(name,value,'grant',b'apicontour/causal-grant/1\n') for name,value in profiles.items()}
    writer_password=secrets.token_hex(32)
    batch={'wire_version':1,'batch_id':str(uuid.uuid4()),'tenant_id':IDS[0],'runtime_id':IDS[1],'session_epoch':1,'first_seq':1,'last_seq':1,'events':[{'kind':'root','event_id':'1'*32,'seq':1,'root':'a'*32}]}
    raw_batch=_canonical(batch); wrong_batch=_canonical(dict(batch,tenant_id='f0000000-0000-4000-8000-000000000002'))
    execute("BEGIN; CREATE ROLE causal_event_writer_login LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '%s'; GRANT contour_causal_inbox_writer TO causal_event_writer_login; GRANT CONNECT ON DATABASE contour_local TO causal_event_writer_login; COMMIT;"%writer_password)
    execute("BEGIN; CREATE ROLE causal_issuer_login LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '%s'; GRANT contour_causal_issuer TO causal_issuer_login; GRANT CONNECT ON DATABASE contour_local TO causal_issuer_login; CREATE ROLE causal_provisioner_login LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '%s'; GRANT contour_causal_provisioner TO causal_provisioner_login; GRANT CONNECT ON DATABASE contour_local TO causal_provisioner_login; COMMIT;"%(passwords['issuer'],passwords['wrong']))
    # Create a separate source/lifecycle/runtime; append policy revision 2 under
    # the existing collector guard. Existing reader rows remain immutable.
    i=IDS
    execute("INSERT INTO contour.workload_instances VALUES ('%s','%s','%s','%s','%s','%s');"%(i[0],i[4],i[5],i[6],i[7],i[8]))
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('%s','%s'); SELECT contour.register_instance_source('%s','%s','%s','%s','%s','%s','%s','f8000000-0000-4000-8000-000000000010','%s'); INSERT INTO contour.source_authorization VALUES ('%s','%s','%s','runtime',ARRAY['http_json_v1']); INSERT INTO contour.policy_revisions VALUES ('%s','%s',2,decode('%s','hex')); UPDATE contour.collector_authorization SET active_revision=2,enabled=true WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;"%(i[0],i[0],i[2],i[0],i[3],i[2],i[4],i[5],i[6],i[7],i[8],i[0],i[3],i[2],i[0],i[2],_canonical(p).hex(),i[0],i[2]))
    prefix="BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SET LOCAL ROLE " % i[0]
    execute(prefix+"contour_admin; SELECT contour.enroll_origin('%s','%s','%s','%s','%s','%s','%s','trusted_platform_v1',decode(repeat('e8',32),'hex')); COMMIT;"%(i[0],i[9],i[4],i[5],i[6],i[7],i[8]))
    execute(prefix+"contour_admin; SELECT contour.enroll_origin_credential('%s','fa000000-0000-4000-8000-000000000010','%s',decode(repeat('e9',32),'hex')); COMMIT;"%(i[0],i[9]))
    execute(prefix+"contour_causal_provisioner; SELECT contour.enroll_causal_runtime('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','00000000-0000-4000-8000-000000000504',decode('%s','hex'),decode('%s','hex')); COMMIT;"%(*i,MANIFEST,export_leaf))
    def case(mode,grant_name='valid',*,damaged=False,wrong_role=False):
        nonce=str(uuid.uuid4());g=dict(grants[grant_name])
        if damaged:
            signature=g['signature_base64url'];g['signature_base64url']=('B' if signature[0]=='A' else 'A')+signature[1:]
        payload={'batch':raw_batch.decode(),'wrong_batch':wrong_batch.decode(),'writer_password':writer_password,'ca_pem':ca_pem.decode('ascii'),'epoch':'1','grant':g,'grant_public':public['grant'],'ids':list(i),'mode':mode,'nonce':nonce,'password':passwords['wrong' if wrong_role else 'issuer'],'peer':export_leaf,'policy':p,'policy_public':public['policy'],'port':str(port),'user':'causal_provisioner_login' if wrong_role else 'causal_issuer_login'}
        probe_call(_canonical(payload))
        row=execute("SELECT count(*)::text FROM contour.causal_sessions WHERE tenant_id='%s' AND runtime_id='%s' AND nonce='%s';"%(i[0],i[1],nonce))
        if row!=('1' if mode=='positive' else '0'): raise RuntimeError('issuer fixture nonce evidence')
        return nonce
    case('generic');case('wrong-profile','legacy');case('wrong-profile','wire')
    for mode in ('wrong-peer','wrong-scope','expired','wrong-role','deadline','wrong-signature'):
        case(mode,mode if mode in ('wrong-scope','expired') else 'valid',damaged=mode=='wrong-signature',wrong_role=mode=='wrong-role')
    baseline=execute("SELECT coalesce((SELECT used_bytes::text FROM contour.origin_logical_usage WHERE tenant_id='%s'),'0');"%i[0])
    if not baseline.isdigit(): raise RuntimeError('issuer fixture quota baseline')
    nonce=case('positive')
    digest=hashlib.sha256(b'apicontour/causal-events/1\n'+raw_batch).hexdigest()
    evidence=execute("SELECT (count(*)=1 AND bool_and(canonical_batch=decode('%s','hex') AND batch_digest=decode('%s','hex') AND event_count=1 AND receipt_id IS NOT NULL AND isfinite(accepted_at) AND receipt_digest=contour.causal_receipt_digest(tenant_id,runtime_id,session_epoch,batch_id,receipt_id,accepted_at,batch_digest,event_count)))::text FROM contour.causal_inbox_batches WHERE tenant_id='%s' AND runtime_id='%s' AND session_epoch=1 AND batch_id='%s';"%(raw_batch.hex(),digest,i[0],i[1],batch['batch_id']))
    if evidence!='true': raise RuntimeError('receiver event batch receipt evidence')
    events=execute("SELECT count(*)::text FROM contour.causal_inbox_events WHERE tenant_id='%s' AND runtime_id='%s' AND session_epoch=1 AND batch_id='%s' AND seq=1 AND event_id='%s' AND kind='root' AND root='%s';"%(i[0],i[1],batch['batch_id'],'1'*32,'a'*32))
    used=execute("SELECT coalesce((SELECT used_bytes::text FROM contour.origin_logical_usage WHERE tenant_id='%s'),'0');"%i[0])
    if events!='1' or not used.isdigit() or int(used)!=int(baseline)+len(raw_batch): raise RuntimeError('receiver event quota evidence')
    grant_digest=hashlib.sha256(_canonical(grant)).hexdigest()
    query=("SELECT (count(*)=1 AND bool_and(epoch=1 AND (claim).profile_name='nodered_5_0_9_receiver_v1' AND (claim).profile_hash=decode('%s','hex') AND (claim).collector_id='%s'::uuid AND (claim).source_id='%s'::uuid AND (claim).project_id='%s'::uuid AND (claim).service_id='%s'::uuid AND (claim).environment_id='%s'::uuid AND (claim).deployment_id='%s'::uuid AND (claim).instance_id='%s'::uuid AND (claim).lifecycle_id='%s'::uuid AND (claim).export_leaf=decode('%s','hex') AND (claim).grant_digest=decode('%s','hex') AND (claim).policy_revision=2 AND (claim).policy_envelope=decode('%s','hex')))::text FROM contour.causal_sessions WHERE tenant_id='%s' AND runtime_id='%s' AND nonce='%s';"%(MANIFEST,*i[2:10],export_leaf,grant_digest,_canonical(p).hex(),i[0],i[1],nonce))
    if execute(query)!='true': raise RuntimeError('issuer fixture committed scope')
    return CHECKS
