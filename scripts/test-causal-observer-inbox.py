"""Owned SQL-only observer qualification using trusted synthetic issuer claims.

Neither mTLS nor marker signatures are verified here. The capture proof is
produced by the existing origin ingress and catalog worker, not fabricated.
"""
import base64
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import runpy

ROOT = Path(__file__).resolve().parents[1]
U = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
GATE_SOURCE='00000000-0000-4000-8000-00000000ce01'
GATE_INSTANCE='00000000-0000-4000-8000-00000000ce02'
GATE_GRANT='00000000-0000-4000-8000-00000000ce03'
GATE_ID='00000000-0000-4000-8000-00000000ce04'
RUNTIME_COLLECTOR='00000000-0000-4000-8000-00000000ce05'
RUNTIME_SOURCE='00000000-0000-4000-8000-00000000ce06'
RUNTIME_ID='00000000-0000-4000-8000-00000000ce07'
NONCE='00000000-0000-4000-8000-00000000ce08'
BATCH='00000000-0000-4000-8000-00000000ce09'
RECORD='00000000-0000-4000-8000-00000000ce0a'
PROFILE='00000000-0000-4000-8000-000000000503'
ARTIFACT='a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e'


def _uuid(value):
    if type(value) is not str or re.fullmatch(U,value) is None: raise ValueError('invalid fixture UUID')
    return value


def _sign(policy, directory, name):
    payload=json.dumps(policy,separators=(',',':')).encode()
    message=directory/(name+'-message'); signature=directory/(name+'-signature')
    message.write_bytes(b'apicontour/policy/1\n'+payload)
    subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(directory/'signer.key'),'-in',str(message),'-out',str(signature)],check=True,timeout=10,capture_output=True)
    enc=lambda value: base64.urlsafe_b64encode(value).rstrip(b'=').decode()
    return json.dumps(dict(key_id='fixture',signature_profile='ed25519-v1',payload_base64url=enc(payload),signature_base64url=enc(signature.read_bytes())),separators=(',',':')).encode()


def run_cases(execute, submit, body, port, directory, environment, target_dir, *, receiver_scenario=None, receiver_after=None):
    tenant=_uuid(body['tenant_id']); collector=_uuid(body['collector_id'])
    r=body['records'][1]['record']; scope=[_uuid(r[k]) for k in ('project_id','service_id','environment_id','deployment_id')]
    p,s,e,d=scope
    # Fetch the exact current signed envelope and keep its original time bounds.
    policy_row=json.loads(execute("SELECT row_to_json(x) FROM (SELECT pr.revision::text,encode(pr.signed_envelope,'hex') AS envelope FROM contour.collector_authorization ca JOIN contour.policy_revisions pr ON (pr.tenant_id,pr.collector_id,pr.revision)=(ca.tenant_id,ca.collector_id,ca.active_revision) WHERE ca.tenant_id='%s' AND ca.collector_id='%s') x;" % (tenant,collector)))
    old=json.loads(bytes.fromhex(policy_row['envelope'])); encoded=old['payload_base64url']; policy=json.loads(base64.urlsafe_b64decode(encoded+'='*((-len(encoded))%4)))
    revision=int(policy_row['revision'])+1
    policy.update(revision=revision,techniques=['runtime','gateway'])
    gateway_envelope=_sign(policy,directory,'observer-gateway-policy')
    runtime_policy=dict(policy,collector_id=RUNTIME_COLLECTOR,revision=1,service_ids=[],techniques=['runtime'])
    # Active proof is read only from the already accepted original batch.
    original_batch=_uuid(body['batch_id']); original_record=_uuid(r['record_id'])
    proof=json.loads(execute("SELECT row_to_json(x) FROM (SELECT lifecycle_id,credential_id,origin_project_id,origin_service_id,origin_environment_id,origin_deployment_id,instance_id,encode(leaf_sha256,'hex') AS leaf FROM contour.origin_proofs WHERE tenant_id='%s' AND collector_id='%s' AND batch_id='%s' AND record_id='%s') x;" % (tenant,collector,original_batch,original_record)))
    op,osvc,oe,od,oi,lifecycle,credential=[_uuid(proof[k]) for k in ('origin_project_id','origin_service_id','origin_environment_id','origin_deployment_id','instance_id','lifecycle_id','credential_id')]
    if not re.fullmatch('[0-9a-f]{64}',proof['leaf']): raise ValueError('invalid proof leaf')
    runtime_policy['service_ids']=[osvc]
    runtime_envelope=_sign(runtime_policy,directory,'observer-runtime-policy')
    # New source, new signed policy, and origin grant; prior source/proof untouched.
    execute("""BEGIN; SELECT set_config('apicontour.tenant_id','%(t)s',true); SET LOCAL ROLE contour_admin;
    SELECT contour.lock_collector('%(t)s','%(c)s');
    INSERT INTO contour.workload_instances VALUES ('%(t)s','%(p)s','%(s)s','%(e)s','%(d)s','%(i)s');
    SELECT contour.register_instance_source('%(t)s','%(src)s','%(c)s','%(p)s','%(s)s','%(e)s','%(d)s','%(src)s','%(i)s');
    INSERT INTO contour.source_authorization VALUES ('%(t)s','%(src)s','%(c)s','gateway',ARRAY['http_json_v1']);
    INSERT INTO contour.policy_revisions VALUES ('%(t)s','%(c)s',%(rev)d,decode('%(env)s','hex'));
    UPDATE contour.collector_authorization SET active_revision=%(rev)d WHERE tenant_id='%(t)s' AND collector_id='%(c)s'; COMMIT;
    SELECT set_config('apicontour.tenant_id','%(t)s',false); SET ROLE contour_admin;
    SELECT contour.grant_origin_observer('%(t)s','%(grant)s','%(life)s','%(src)s','%(c)s','%(p)s','%(s)s','%(e)s','%(d)s'); RESET ROLE;""" % dict(t=tenant,c=collector,p=p,s=s,e=e,d=d,i=GATE_INSTANCE,src=GATE_SOURCE,rev=revision,env=gateway_envelope.hex(),grant=GATE_GRANT,life=lifecycle))
    candidate=copy.deepcopy(body); candidate['batch_id']=BATCH; candidate['records']=[copy.deepcopy(body['records'][1])]
    record=candidate['records'][0]['record']; record.update(record_id=RECORD,source_id=GATE_SOURCE,policy_revision=revision,direction='request')
    submit(candidate,status='accepted')
    probe=Path(target_dir)/'debug/examples/catalog_probe'
    result=subprocess.run([str(probe),str(port),str(directory/'ca.crt'),BATCH,'Processed',tenant,collector,'5000'],input='\n',capture_output=True,text=True,env=environment,timeout=15,check=True)
    if result.stdout.strip()!='Processed' or result.stderr: raise RuntimeError('observer catalog materialization failed')
    # Exact 1..25 comes from the historical lane; apply the trusted migrations separately.
    if execute("SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;")!='{'+','.join(map(str,range(1,26)))+'}': raise RuntimeError('observer input ledger mismatch')
    for name in ('0026_causal_evidence_enrollment.sql','0027_causal_observer_inbox.sql'):
        execute((ROOT/'db/opt-in-migrations'/name).read_text())
    if execute("SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;")!='{'+','.join(map(str,range(1,28)))+'}': raise RuntimeError('observer output ledger mismatch')
    params=dict(t=tenant,c=collector,p=p,s=s,e=e,d=d,gi=GATE_INSTANCE,gs=GATE_SOURCE,gid=GATE_ID,rc=RUNTIME_COLLECTOR,rs=RUNTIME_SOURCE,rid=RUNTIME_ID,n=NONCE,b=BATCH,rec=RECORD,op=op,os=osvc,oe=oe,od=od,oi=oi,life=lifecycle,cred=credential,leaf=proof['leaf'],profile=PROFILE,artifact=ARTIFACT,gr=revision,genv=gateway_envelope.hex(),renv=runtime_envelope.hex(),issued=policy['issued_at'],expires=policy['expires_at'])
    # All values are controlled UUIDs/hex or validated timestamps from the signed fixture policy.
    for key in ('issued','expires'):
        if not re.fullmatch(r'[0-9T:Z.+-]+',params[key]): raise ValueError('invalid policy time')
    seed=SEED_SQL % params
    if (receiver_scenario is None)!=(receiver_after is None) or (receiver_after is not None and not callable(receiver_after)): raise ValueError('incomplete receiver scenario')
    observer_fixture=(ROOT/'db/tests/causal_observer_inbox.sql').read_text()
    if receiver_scenario is not None:
        if not callable(receiver_scenario): raise ValueError('invalid receiver scenario')
        parts=receiver_scenario(observer_fixture)
        if type(parts) is not tuple or len(parts)!=3 or any(type(x) is not str or not x for x in parts) or sum(len(x.encode('utf-8')) for x in parts)>6000000: raise ValueError('invalid receiver scenario')
        prefix,observer_fixture,suffix=parts
        observer_fixture=prefix+'\n'+observer_fixture+'\n'+suffix
    combined=_diagnostic_sql(seed,observer_fixture)
    edge = None
    if sys.argv[1:] in (['--causal-edge-reconciliation'], ['--causal-human-connections']):
        if receiver_after is None: raise ValueError('edge requires receiver scenario')
        edge = runpy.run_path(str(ROOT / 'scripts/test-postgres-tls.py'))['checked_edge_loader']()
        combined += '\n' + edge['continuation_sql']()
        if sys.argv[1:] == ['--causal-human-connections']:
            human = runpy.run_path(str(ROOT / 'scripts/test-postgres-tls.py'))['checked_human_causal_loader']()
            combined += '\n' + human['continuation_sql']()
    _run_combined(execute,combined,receiver_after,edge,directory)
    if receiver_scenario is not None:
        path=directory/'causal-receiver.done';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:
            out.write(b'causal-receiver-complete\n');out.flush();os.fsync(out.fileno())
    path=directory/'causal-observer.done'; fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(b'causal-observer-complete\n'); out.flush(); os.fsync(out.fileno())

def _run_combined(execute, combined, receiver_after, edge, directory):
    execute(combined, timeout=300)
    if receiver_after is not None: receiver_after(execute)
    if edge is not None: edge['write_receipt'](directory)


def _diagnostic_sql(seed, fixture):
    """Mark audited seed boundaries; preserve the fixture's exact bytes."""
    markers=(('SET ROLE contour_causal_provisioner;\nSELECT contour.register_causal_profile(', 'profile'),
             ('SELECT contour.enroll_causal_runtime(', 'runtime-enroll'),
             ('CREATE TEMP TABLE observer_claim ', 'session'),
             ('SELECT contour.claim_causal_generation(', 'generation'),
             ('SELECT contour.bind_causal_marker_key(', 'marker'),
             ('CREATE TEMP TABLE observer_gateway(', 'gateway'),
             ('DO $$ BEGIN\n IF NOT EXISTS(SELECT 1 FROM contour.origin_proofs', 'proof'),
             ('CREATE TEMP TABLE observer_seed(', 'canonical'))
    for token, label in markers:
        if seed.count(token)!=1: raise ValueError('observer diagnostic boundary changed')
        seed=seed.replace(token, '\\echo observer-step='+label+'\n'+token,1)
    anchors=(('-- Disposable PostgreSQL only.', 'parser'),
             ('-- First fact may precede producer-attempt and receiver facts,', 'first-accept'),
             ('CREATE TEMP TABLE observer_usage AS SELECT', 'replay'),
             ('DO $$ DECLARE r bytea; p contour.verified_observer_claim; x contour.causal_session_claim; BEGIN', 'negativeclaims'),
             ('-- New, correctly linked backend delivery cannot consume quota', 'quota'),
             ('-- Materialize canonical adversarial delivery graphs under owner;', 'graph'),
             ('-- Build two detached 31-delivery fragments.', 'chains'))
    for token,label in anchors:
        if fixture.count(token)!=1: raise ValueError('observer case diagnostic boundary changed')
        fixture=fixture.replace(token, '\\echo observer-step='+label+'\n'+token,1)
    return '\\set VERBOSITY verbose\n\\echo observer-step=runtime-source\n'+seed+'\n\\echo observer-step=cases\n'+fixture


# One psql backend is essential: all claim rows and observer_seed are temporary.
# Only the issuer assertions below are synthetic. The marker wire is a bounded
# placeholder; neither a signature nor mTLS verification is claimed.
SEED_SQL = r"""
SELECT set_config('apicontour.tenant_id','%(t)s',false);
BEGIN; SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector('%(t)s','%(rc)s');
INSERT INTO contour.collectors VALUES ('%(t)s','%(rc)s');
INSERT INTO contour.workload_assignments VALUES ('%(t)s','%(rc)s','%(op)s','%(os)s','%(oe)s','%(od)s');
SELECT contour.register_instance_source('%(t)s','%(rs)s','%(rc)s','%(op)s','%(os)s','%(oe)s','%(od)s','%(rs)s','%(oi)s');
INSERT INTO contour.source_authorization VALUES ('%(t)s','%(rs)s','%(rc)s','runtime',ARRAY['http_json_v1']);
INSERT INTO contour.policy_revisions VALUES ('%(t)s','%(rc)s',1,decode('%(renv)s','hex'));
UPDATE contour.collector_authorization SET active_revision=1,enabled=true WHERE tenant_id='%(t)s' AND collector_id='%(rc)s'; COMMIT;
SET ROLE contour_causal_provisioner;
SELECT contour.register_causal_profile('%(t)s','%(profile)s',decode('%(artifact)s','hex'));
SELECT contour.enroll_causal_runtime('%(t)s','%(rid)s','%(rc)s','%(rs)s','%(op)s','%(os)s','%(oe)s','%(od)s','%(oi)s','%(life)s','%(profile)s',decode('%(artifact)s','hex'),decode(repeat('ce',32),'hex'));
RESET ROLE;
CREATE TEMP TABLE observer_claim (claim contour.causal_session_claim NOT NULL, epoch numeric);
INSERT INTO observer_claim(claim) VALUES (ROW('%(t)s'::uuid,'%(rid)s'::uuid,'%(rc)s'::uuid,'%(rs)s'::uuid,'%(op)s'::uuid,'%(os)s'::uuid,'%(oe)s'::uuid,'%(od)s'::uuid,'%(oi)s'::uuid,'%(life)s'::uuid,decode(repeat('ce',32),'hex'),'nodered_5_0_9_wire_v1',decode('%(artifact)s','hex'),'%(n)s'::uuid,1,decode(repeat('ab',32),'hex'),'%(issued)s'::timestamptz,'%(expires)s'::timestamptz,1,decode('%(renv)s','hex'),'%(issued)s'::timestamptz,'%(expires)s'::timestamptz,900000000,10,1024,1024,60)::contour.causal_session_claim);
GRANT SELECT,UPDATE ON observer_claim TO contour_causal_issuer;
SET ROLE contour_causal_issuer;
UPDATE observer_claim SET epoch=(SELECT epoch FROM contour.issue_causal_session(claim));
SELECT contour.claim_causal_generation('%(t)s','%(rid)s',(SELECT epoch FROM observer_claim),'%(n)s',decode(repeat('a1',32),'hex'));
RESET ROLE;
GRANT SELECT ON observer_claim TO contour_causal_provisioner;
SET ROLE contour_causal_provisioner;
SELECT contour.bind_causal_marker_key('%(t)s','%(rid)s',(SELECT epoch FROM observer_claim),'%(n)s',decode(repeat('a1',32),'hex'),'%(cred)s',decode('%(leaf)s','hex'),decode(repeat('42',32),'hex'));
RESET ROLE;
CREATE TEMP TABLE observer_gateway(generation text);
GRANT SELECT,INSERT ON observer_gateway TO contour_causal_evidence_provisioner;
SET ROLE contour_causal_evidence_provisioner;
INSERT INTO observer_gateway SELECT generation FROM contour.enroll_causal_gateway(ROW('%(t)s'::uuid,'%(gid)s'::uuid,'%(c)s'::uuid,'%(gs)s'::uuid,'%(p)s'::uuid,'%(s)s'::uuid,'%(e)s'::uuid,'%(d)s'::uuid,'%(gi)s'::uuid,decode(repeat('b1',32),'hex'),decode(repeat('b2',32),'hex'),decode(repeat('b3',32),'hex'),%(gr)d,decode('%(genv)s','hex'),'%(issued)s'::timestamptz,'%(expires)s'::timestamptz,900000000)::contour.gateway_enrollment_claim);
RESET ROLE;
-- Fail closed unless the exact newly submitted request has its own committed
-- immutable origin proof and complete catalog observation before seed creation.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM contour.origin_proofs p JOIN contour.observation_windows w USING(tenant_id,collector_id,batch_id,record_id)
 WHERE (p.tenant_id,p.collector_id,p.batch_id,p.record_id,p.source_id,p.lifecycle_id,p.credential_id,p.leaf_sha256)=('%(t)s'::uuid,'%(c)s'::uuid,'%(b)s'::uuid,'%(rec)s'::uuid,'%(gs)s'::uuid,'%(life)s'::uuid,'%(cred)s'::uuid,decode('%(leaf)s','hex')))
 THEN RAISE EXCEPTION 'observer committed request proof unavailable'; END IF;
END $$;
CREATE TEMP TABLE observer_seed(raw bytea NOT NULL, proof contour.verified_observer_claim NOT NULL);
GRANT SELECT ON observer_claim,observer_gateway TO contour_owner;
GRANT INSERT ON observer_seed TO contour_owner;
SET ROLE contour_owner;
INSERT INTO observer_seed
 SELECT convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'batch_id','%(b)s','signed_marker','ac1.fixture.signature','binding',jsonb_build_object(
 'wire_version',1,'tenant_id','%(t)s','gateway_id','%(gid)s','gateway_generation',g.generation,'collector_id','%(c)s','record_id','%(rec)s',
 'producer_runtime_id','%(rid)s','producer_session_epoch',c.epoch::text,'producer_attempt_id',repeat('22',16),
 'marker_digest',encode(sha256(convert_to(E'apicontour/causal-marker-wire/1\nac1.fixture.signature','UTF8')),'hex'),
 'receiver_runtime_id','%(rid)s','receiver_session_epoch','1','delivery_handle',repeat('44',16),'retry_of',NULL))),'UTF8'),
 ROW(decode(repeat('b2',32),'hex'),c.claim,c.epoch,decode(repeat('42',32),'hex'),decode(repeat('a1',32),'hex'),repeat('11',16),repeat('33',16),repeat('22',16),sha256(convert_to(E'apicontour/causal-marker-wire/1\nac1.fixture.signature','UTF8')))::contour.verified_observer_claim
 FROM observer_claim c CROSS JOIN observer_gateway g;
RESET ROLE;
"""
