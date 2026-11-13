#!/usr/bin/env python3
"""Owned PostgreSQL TLS SQL24 candidate qualification; synthetic and dormant only."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import signal
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).absolute().parent.parent
OPT=('0015_origin_lifecycle','0016_v2_unattributed','0017_origin_proofs','0018_causal_runtime_registry','0019_causal_sessions','0020_causal_inbox','0021_origin_admission','0022_causal_generation','0023_causal_marker_bindings','0024_causal_live_profile')
SOURCE_ONLY_MIGRATIONS=('0025_historical_origin','0026_causal_evidence_enrollment','0027_causal_observer_inbox','0028_causal_receiver_enrollment','0029_causal_receiver_inbox','0030_causal_gateway_reader','0031_causal_edge_reconciliation','0032_human_causal_reader',)
EXAMPLE=ROOT/'crates/contour-postgres/examples/causal_live_profile_probe.rs'
REQUIRED_STAGES=('profile_pre','legacy_pre','profile_post','legacy_post','negative_grants',
                 'issue_unknown','clock_guard','quota_guard','weak','wrong_role','positive',
                 'expired','cancel','marker_unknown','issue_context_unknown','revoked','artifact_unchanged')

def qualification_pass(primary,failures,stages,probe_hash):
    return primary is None and not failures and tuple(stages)==REQUIRED_STAGES and bool(probe_hash)


def safe(path):
    if not path.is_absolute(): raise ValueError('absolute source required')
    for p in (path,*path.parents):
        if p.is_symlink(): raise ValueError('source symlink')
    if not path.is_file(): raise ValueError('source unavailable')
    return path

def helpers():
    paths=[safe(ROOT/'scripts/test-postgres-causal-bridge.py'),safe(ROOT/'scripts/test-postgres-causal-https.py')]
    hashes=[hashlib.sha256(p.read_bytes()).digest() for p in paths]
    result=[runpy.run_path(str(p)) for p in paths]
    if any(hashlib.sha256(p.read_bytes()).digest()!=h for p,h in zip(paths,hashes)): raise RuntimeError('helper changed')
    return result

def snapshot(bridge):
    paths=set(bridge['source_paths']())
    paths.update([EXAMPLE, ROOT/'scripts/test-postgres-causal-live-profile.py',ROOT/'tests/fixtures/causal-live-profile/test_driver.py',ROOT/'scripts/test-postgres-causal-https.py',ROOT/'tests/fixtures/causal-https/test_https_driver.py'])
    paths.update(ROOT/'db/opt-in-migrations'/(n+'.sql') for n in OPT + SOURCE_ONLY_MIGRATIONS)
    if set((ROOT/'db/opt-in-migrations').glob('*.sql'))!={ROOT/'db/opt-in-migrations'/(n+'.sql') for n in OPT + SOURCE_ONLY_MIGRATIONS}: raise ValueError('migration list changed')
    return {str(path):bridge['digest_file'](safe(path)) for path in sorted(paths)}

def artifact(lines,target,bridge):
    found=[]
    for line in lines:
        obj=json.loads(line); t=obj.get('target') or {}
        if obj.get('reason')=='compiler-artifact' and t.get('name')=='causal_live_profile_probe' and t.get('kind')==['example'] and t.get('src_path')==str(EXAMPLE) and not (obj.get('profile') or {}).get('test',False):
            path=Path(obj.get('executable') or '')
            if not path.is_absolute() or '..' in path.parts: raise RuntimeError('invalid cargo executable')
            safe(path); path.resolve(strict=True).relative_to(target.resolve(strict=True))
            if not os.access(path,os.X_OK): raise RuntimeError('cargo executable unavailable')
            bridge['digest_file'](path); found.append(path)
    if len(found)!=1: raise RuntimeError('ambiguous cargo executable')
    return found[0]

def main():
    if len(sys.argv)!=1: raise ValueError('no arguments accepted')
    bridge,https=helpers(); before=snapshot(bridge); os.umask(0o077)
    result_dir=Path(tempfile.mkdtemp(prefix='contour-live-profile-result-')).resolve()
    os.chmod(result_dir,0o700)
    started=time.monotonic(); probe_hash=None; stages=[]; passed=False
    print('private result:',result_dir/'result.json',flush=True)
    run=bridge['command']; rid=uuid.uuid4().hex; network='contour-live-profile-net-'+rid; container='contour-live-profile-'+rid; nid=cid=None; network_attempted=container_attempted=False
    previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('overall deadline'))); signal.setitimer(signal.ITIMER_REAL,600)
    try:
      with tempfile.TemporaryDirectory(prefix='contour-live-profile-') as temp:
        work=Path(temp).resolve(); os.chmod(work,0o700); target=work/'target'; target.mkdir()
        env=os.environ.copy(); env['CARGO_TARGET_DIR']=str(target)
        lines=bridge['bounded_process_output'](['cargo','build','-p','contour-postgres','--example','causal_live_profile_probe','--locked','--offline','--message-format=json'],cwd=ROOT,env=env)
        probe=artifact(lines,target,bridge); probe_hash=bridge['digest_file'](probe)
        ca=work/'ca.crt'; ca_key=work/'ca.key'; key=work/'server.key'; cert=work/'server.crt'; request=work/'request.cnf'
        request.write_text('[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256','-config',str(request),'-extensions','ca','-subj','/CN=synthetic permit CA','-keyout',str(ca_key),'-out',str(ca)],timeout=30)
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-sha256','-config',str(request),'-keyout',str(key),'-out',str(work/'server.csr')],timeout=30)
        (work/'extensions').write_text('subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
        run(['openssl','x509','-req','-in',str(work/'server.csr'),'-CA',str(ca),'-CAkey',str(ca_key),'-CAcreateserial','-days','1','-extfile',str(work/'extensions'),'-out',str(cert)],timeout=30)
        for name in ('grant','policy'):
            run(['openssl','genpkey','-algorithm','ED25519','-out',str(work/(name+'.key'))],timeout=15)
            public=run(['openssl','pkey','-in',str(work/(name+'.key')),'-pubout','-outform','DER'],timeout=15)
            if len(public)!=44 or not public.startswith(bytes.fromhex('302a300506032b6570032100')): raise RuntimeError('invalid public key')
            (work/(name+'.pub')).write_bytes(public[-32:])
        sample=json.loads(safe(ROOT/'crates/contour-postgres/tests/fixtures/causal_bridge.json').read_bytes()); ids=bridge['IDS']
        def payload(name):
            x=sample[name]['payload_base64url']; return json.loads(base64.urlsafe_b64decode(x+'='*((-len(x))%4)))
        now=datetime.datetime.now(datetime.timezone.utc); stamp=lambda x:x.strftime('%Y-%m-%dT%H:%M:%SZ'); issued=stamp(now-datetime.timedelta(seconds=10)); expires=stamp(now+datetime.timedelta(minutes=8))
        grant=payload('grant'); grant.update(tenant_id=ids[0],runtime_id=ids[1],collector_id=ids[2],source_id=ids[3],instance_id=ids[8],lifecycle_id=ids[9],revision=1,issued_at=issued,expires_at=expires)
        policy=payload('policy'); policy.update(tenant_id=ids[0],collector_id=ids[2],service_ids=[ids[5]],revision=1,issued_at=issued,expires_at=expires)
        candidate_ids=list(ids); candidate_ids[1]='fc000000-0000-4000-8000-000000000003'; candidate_ids[2]='f6000000-0000-4000-8000-000000000003'; candidate_ids[3]='f7000000-0000-4000-8000-000000000003'; candidate_ids[8]='f5000000-0000-4000-8000-000000000003'; candidate_ids[9]='f9000000-0000-4000-8000-000000000003'
        candidate_grant=dict(grant, runtime_id=candidate_ids[1],collector_id=candidate_ids[2],source_id=candidate_ids[3],instance_id=candidate_ids[8],lifecycle_id=candidate_ids[9],causal_profile='nodered_5_0_9_wire_v1',profile_sha256='a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e')
        candidate_policy=dict(policy,collector_id=candidate_ids[2])
        negative_scope=dict(candidate_grant,tenant_id='f0000000-0000-4000-8000-000000000002')
        negative_hash=dict(candidate_grant,profile_sha256='b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510')
        negative_time=dict(candidate_grant,expires_at=stamp(now-datetime.timedelta(seconds=1)))
        for name,data,domain,key in [('grant',grant,b'apicontour/causal-grant/1\n','grant'),('policy',policy,b'apicontour/policy/1\n','policy'),('candidate_grant',candidate_grant,b'apicontour/causal-grant/1\n','grant'),('candidate_policy',candidate_policy,b'apicontour/policy/1\n','policy'),('negative_scope',negative_scope,b'apicontour/causal-grant/1\n','grant'),('negative_hash',negative_hash,b'apicontour/causal-grant/1\n','grant'),('negative_time',negative_time,b'apicontour/causal-grant/1\n','grant')]: (work/(name+'.json')).write_bytes(bridge['signed_payload'](data,domain,work/(key+'.key'),work,name))
        (work/'batch.json').write_text('{}')
        run(['docker','image','inspect',bridge['IMAGE']],timeout=20); network_attempted=True
        net=run(['docker','network','create','--label',bridge['LABEL']+'='+rid,'--driver','bridge','--opt','com.docker.network.bridge.enable_ip_masquerade=false',network],timeout=30).decode().strip()
        net_info=bridge['inspect_owned']('network',network,rid); nid=net_info['Id']
        if net!=nid or not bridge['network_valid'](net_info,net,()): raise RuntimeError('network mismatch')
        password=secrets.token_hex(24); container_attempted=True
        raw=run(['docker','create','--pull=never','--name',container,'--label',bridge['LABEL']+'='+rid,'--network',net,'--publish','127.0.0.1::5432','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m','-e','POSTGRES_DB=contour_fixture','-e','POSTGRES_PASSWORD='+password,'-e','POSTGRES_HOST_AUTH_METHOD=scram-sha-256',bridge['IMAGE'],'sh','-c','chown postgres:postgres /tmp/server.key /tmp/server.crt && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c listen_addresses=* -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key -c log_line_prefix="%m [%p] %u " -c log_error_verbosity=verbose'],timeout=30).decode().strip()
        info=bridge['inspect_owned']('container',container,rid); cid=info['Id']
        if raw!=cid: raise RuntimeError('container identity mismatch')
        for f in ('server.key','server.crt'): run(['docker','cp',str(work/f),cid+':/tmp/'+f],timeout=20)
        run(['docker','start',cid],timeout=30); deadline=time.monotonic()+60
        while True:
            result=bridge['run_process'](['docker','exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -U postgres -d contour_fixture'],timeout=5)
            if result.returncode==0: break
            if time.monotonic()>=deadline: raise TimeoutError('readiness deadline')
            time.sleep(.2)
        info=bridge['inspect_owned']('container',container,rid); net_info=bridge['inspect_owned']('network',network,rid)
        networks=info['NetworkSettings']['Networks']; ports=info['NetworkSettings']['Ports']
        if not bridge['network_valid'](net_info,net,(cid,)) or len(networks)!=1 or next(iter(networks.values())).get('NetworkID')!=net or set(ports)!={'5432/tcp'}: raise RuntimeError('network mismatch')
        bindings=ports['5432/tcp']
        if not isinstance(bindings,list) or len(bindings)!=1 or bindings[0].get('HostIp')!='127.0.0.1' or not str(bindings[0].get('HostPort','')).isdigit() or not 1<=int(bindings[0]['HostPort'])<=65535: raise RuntimeError('port mismatch')
        port=str(bindings[0]['HostPort']); sql=['docker','exec','-i',cid,'psql','-XqAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-U','postgres','-d','contour_fixture']
        def execute(text): return run(sql,data=text.encode(),timeout=120).decode().strip()
        execute(safe(ROOT/'db/bootstrap.sql').read_text())
        for n in bridge['PROVISIONS']: execute(safe(ROOT/('db/provision_'+n+'.sql')).read_text())
        for n in bridge['MIGRATIONS']: execute(safe(ROOT/('db/migrations/'+n+'.sql')).read_text())
        for n in OPT[:3]: execute(safe(ROOT/('db/opt-in-migrations/'+n+'.sql')).read_text())
        pre=safe(ROOT/'db/tests/causal_runtime_registry_pre.sql').read_text(); marker="INSERT INTO contour.policy_revisions VALUES ('"+ids[0]+"','"+ids[2]+"',1,decode('01','hex'));"
        if pre.count(marker)!=1: raise RuntimeError('pre-fixture mismatch')
        pre=pre.replace(marker,"INSERT INTO contour.policy_revisions VALUES ('"+ids[0]+"','"+ids[2]+"',1,decode('"+(work/'policy.json').read_bytes().hex()+"','hex'));",1)
        candidate_marker="INSERT INTO contour.policy_revisions VALUES ('"+candidate_ids[0]+"','"+candidate_ids[2]+"',1,decode('01','hex'));"
        if pre.count(candidate_marker)!=1: raise RuntimeError('candidate pre-fixture mismatch')
        pre=pre.replace(candidate_marker,"INSERT INTO contour.policy_revisions VALUES ('"+candidate_ids[0]+"','"+candidate_ids[2]+"',1,decode('"+(work/'candidate_policy.json').read_bytes().hex()+"','hex'));",1)
        execute(pre)
        execute(safe(ROOT/('db/opt-in-migrations/'+OPT[3]+'.sql')).read_text()); execute(safe(ROOT/'db/tests/causal_session_setup.sql').read_text())
        for n in OPT[4:-1]: execute(safe(ROOT/('db/opt-in-migrations/'+n+'.sql')).read_text())
        if execute('SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;')!='{'+','.join(map(str,range(1,24)))+'}': raise RuntimeError('ledger mismatch')
        execute("CREATE ROLE causal_issuer_login LOGIN PASSWORD '"+password+"'; CREATE ROLE causal_provisioner_login LOGIN PASSWORD '"+password+"'; GRANT contour_causal_issuer TO causal_issuer_login; GRANT contour_causal_provisioner TO causal_provisioner_login;")
        hba='local all all trust\nhostnossl all all all reject\nhostssl contour_fixture causal_issuer_login,causal_provisioner_login all scram-sha-256\nhostssl all all all reject\n'
        before_reload=execute('SELECT floor(extract(epoch FROM pg_conf_load_time())*1000000)::bigint;')
        run(['docker','exec','-i',cid,'sh','-c','cat > /var/lib/postgresql/data/pg_hba.conf'],data=hba.encode(),timeout=20)
        if execute('SELECT pg_reload_conf();')!='t': raise RuntimeError('HBA reload failed')
        deadline=time.monotonic()+10
        while int(execute('SELECT floor(extract(epoch FROM pg_conf_load_time())*1000000)::bigint;'))<=int(before_reload):
            if time.monotonic()>=deadline: raise TimeoutError('HBA reload deadline')
            time.sleep(.05)
        if execute('SELECT count(*) FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL;')!='0': raise RuntimeError('HBA invalid')
        proof=execute("SELECT (count(*)=4 AND count(*) FILTER (WHERE type='local' AND auth_method='trust')=1 AND count(*) FILTER (WHERE type='hostnossl' AND auth_method='reject')=1 AND count(*) FILTER (WHERE type='hostssl' AND auth_method='scram-sha-256')=1 AND count(*) FILTER (WHERE type='hostssl' AND auth_method='reject')=1)::text FROM pg_catalog.pg_hba_file_rules;")
        if proof!='true': raise RuntimeError('HBA proof failed')
        environment={'PATH':os.environ.get('PATH',os.defpath),'CONTOUR_CAUSAL_ISSUER_PASSWORD':password}
        base=[str(probe),'localhost',port,'contour_fixture',str(ca),'causal_issuer_login','causal_provisioner_login',str(work/'grant.pub'),str(work/'policy.pub'),str(work/'grant.json'),str(work/'policy.json'),str(work/'batch.json'),'33'*32,*ids,'placeholder']
        def legacy():
            args=list(base); args[-1]=str(uuid.uuid4())
            result=bridge['run_process'](args+['legacy'],timeout=40,env=environment,limit=4096)
            if result.returncode or result.stderr or result.stdout!=b'LEGACY\n': raise AssertionError('legacy protocol mismatch')
        profile_checks(execute,candidate_ids,False); stages.append('profile_pre')
        legacy(); stages.append('legacy_pre')
        execute(safe(ROOT/('db/opt-in-migrations/'+OPT[-1]+'.sql')).read_text())
        if execute('SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;')!='{'+','.join(map(str,range(1,25)))+'}': raise RuntimeError('ledger mismatch')
        profile_checks(execute,candidate_ids,True); stages.append('profile_post')
        legacy(); stages.append('legacy_post')
        candidate_base=candidate_arguments(base,work,candidate_ids)
        candidate_bridge=dict(bridge,IDS=candidate_ids)
        negative_grants(candidate_base,work,environment,execute,candidate_bridge); stages.append('negative_grants')
        issue_unknown(candidate_base,environment,execute,candidate_bridge); stages.append('issue_unknown')
        clock_guard(execute,candidate_ids); stages.append('clock_guard')
        quota_guard(candidate_base,environment,execute,candidate_bridge); stages.append('quota_guard')
        exercise(candidate_base,environment,execute,candidate_bridge,https,stages)
        if bridge['digest_file'](probe)!=probe_hash: raise RuntimeError('probe changed')
        stages.append('artifact_unchanged')
    finally:
        primary=sys.exc_info()[1]; failures=[]
        def checked_cleanup(phase,action):
            try: action()
            except BaseException as error:
                print('fixture cleanup failed phase='+phase,file=sys.stderr); failures.append(error)
        checked_cleanup('timer',lambda:(signal.setitimer(signal.ITIMER_REAL,0),signal.signal(signal.SIGALRM,previous)))
        checked_cleanup('container',lambda:bridge['cleanup']('container',container,rid,known_id=cid) if container_attempted else bridge['require_empty_label_inventory']('container',rid))
        checked_cleanup('network',lambda:bridge['cleanup']('network',network,rid,known_id=nid) if network_attempted else bridge['require_empty_label_inventory']('network',rid))
        def check_source():
            if snapshot(bridge)!=before: raise RuntimeError('qualification source changed')
        checked_cleanup('source',check_source)
        passed=qualification_pass(primary,failures,stages,probe_hash)
        def write_receipt():
            receipt={'status':'passed' if passed else 'failed',
                     'boundary':'PostgreSQL TLS; synthetic peer pin; no exporter TLS or launch proof',
                     'source_hashes':before,'probe_sha256':probe_hash,'completed_stages':stages,
                     'elapsed_seconds':round(time.monotonic()-started,3),
                     'cleanup_failures':len(failures),
                     'failure_type':type(primary).__name__ if primary else None}
            path=result_dir/'result.json'; pending=result_dir/'result.pending'
            with pending.open('x',encoding='utf-8') as output:
                os.chmod(pending,0o600)
                json.dump(receipt,output,sort_keys=True,indent=2); output.write('\n')
                output.flush(); os.fsync(output.fileno())
            os.replace(pending,path)
        checked_cleanup('receipt',write_receipt)
        if failures:
            groups=([BaseExceptionGroup('primary',[primary])] if primary is not None else [])+[BaseExceptionGroup('cleanup',failures)]
            raise BaseExceptionGroup('qualification',groups) from None
    if not passed: raise RuntimeError('qualification incomplete')
    print('PASS: synthetic SQL24 and database TLS component; no exporter TLS or launch proof')


def candidate_arguments(base,work,ids):
    if len(base)!=24 or len(ids)!=10: raise ValueError('invalid probe arguments')
    candidate=list(base)
    candidate[9]=str(work/'candidate_grant.json')
    candidate[10]=str(work/'candidate_policy.json')
    candidate[12]='55'*32
    candidate[13:23]=ids
    return candidate


def profile_checks(execute,ids,after):
    """Exact registry transitions, with each denial caught by SQLSTATE."""
    t,r,c,src,p,service,e,d,i,lifecycle=ids
    old='00000000-0000-4000-8000-000000000501'
    candidate='00000000-0000-4000-8000-000000000503'
    unknown='00000000-0000-4000-8000-000000000502'
    old_hash='b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510'
    candidate_hash='a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e'
    def reg(profile,digest): return f"contour.register_causal_profile('{t}','{profile}',decode('{digest}','hex'))"
    def enrollment(profile,digest):
        return f"contour.enroll_causal_runtime('{t}','{r}','{c}','{src}','{p}','{service}','{e}','{d}','{i}','{lifecycle}','{profile}',decode('{digest}','hex'),decode(repeat('55',32),'hex'))"
    def reject(call):
        return f"DO $$ BEGIN PERFORM {call}; RAISE EXCEPTION 'unexpected acceptance'; EXCEPTION WHEN check_violation THEN NULL; END $$;"
    prefix=f"BEGIN; SELECT set_config('apicontour.tenant_id','{t}',true); SET LOCAL ROLE contour_causal_provisioner; "
    execute(prefix+'SELECT '+reg(old,old_hash)+'; COMMIT;')
    if not after:
        for call in (reg(candidate,candidate_hash),enrollment(candidate,candidate_hash)):
            execute(prefix+reject(call)+' COMMIT;')
        return
    # Each function begins its own Q/leaf/C operation and must have a fresh transaction.
    for call in (reg(candidate,candidate_hash),reg(candidate,candidate_hash),
                 enrollment(candidate,candidate_hash),enrollment(candidate,candidate_hash)):
        execute(prefix+'SELECT '+call+'; COMMIT;')
    for profile,digest in ((candidate,old_hash),(old,candidate_hash),(unknown,candidate_hash),(candidate,'00'*32)):
        for call in (reg(profile,digest),enrollment(profile,digest)):
            execute(prefix+reject(call)+' COMMIT;')
    # Owner-only tables must remain inaccessible to both application roles.
    for role in ('contour_causal_provisioner','contour_causal_issuer'):
        execute(f"BEGIN; SET LOCAL ROLE {role}; DO $$ BEGIN PERFORM count(*) FROM contour.causal_runtime_profiles; RAISE EXCEPTION 'unexpected read'; EXCEPTION WHEN insufficient_privilege THEN NULL; END $$; COMMIT;")
    actual=execute(f"SELECT count(*) FROM contour.causal_runtime_bindings WHERE tenant_id='{t}' AND runtime_id='{r}' AND profile_id='{candidate}' AND artifact_sha256=decode('{candidate_hash}','hex');")
    if actual!='1': raise AssertionError('candidate registry row mismatch')


def strict_drain(monitor,key,stream):
    # A read failure is not EOF, even if an expected protocol prefix arrived.
    while True:
        try: chunk=os.read(stream.fileno(),4096)
        except OSError:
            with monitor.lock: monitor.read_failed=True
            return
        if not chunk: return
        with monitor.lock:
            if len(monitor.buffers[key])+len(chunk)>16384:
                monitor.overflow=True
                try: monitor._kill_group()
                except (OSError,RuntimeError): pass  # stop() must report signal failure.
                return
            monitor.buffers[key].extend(chunk)


def strict_monitor(base,args,env):
    class Monitor(base):
        def __init__(self,*values):
            self.read_failed=False
            super().__init__(*values)
        def _drain(self,key,stream): strict_drain(self,key,stream)
    return Monitor(args,env)


def monitor_output(monitor,expected):
    with monitor.lock:
        out=bytes(monitor.buffers['out']); err=bytes(monitor.buffers['err'])
        bad=monitor.overflow or monitor.read_failed
    if bad or err or out!=expected: raise RuntimeError('probe output invalid')


def negative_grants(base,work,env,execute,bridge):
    cases=(('negative_identity','negative_scope.json'),('negative_scope','negative_hash.json'),('negative_expired','negative_time.json'),('negative_signature',None))
    for mode,filename in cases:
        args=list(base); args[-1]=str(uuid.uuid4())
        if filename is not None: args[9]=str(work/filename)
        else: args[7]=args[8]  # A different synthetic public key, never a private key.
        result=bridge['run_process'](args+[mode],timeout=20,env=env,limit=4096)
        if result.returncode or result.stderr or result.stdout!=b'REFUSED\n': raise AssertionError('negative grant protocol mismatch')
    tenant,runtime=bridge['IDS'][:2]
    if execute(f"SELECT count(*) FROM contour.causal_sessions WHERE tenant_id='{tenant}' AND runtime_id='{runtime}';")!='0': raise AssertionError('negative grant created session')


def issue_unknown(base,env,execute,bridge):
    """Delay COMMIT after issue, then reconcile only the identical original request."""
    execute("CREATE SEQUENCE contour.fixture_issue_entered; GRANT USAGE,SELECT ON SEQUENCE contour.fixture_issue_entered TO contour_owner; GRANT USAGE ON SEQUENCE contour.fixture_issue_entered TO causal_issuer_login; CREATE FUNCTION contour.fixture_issue_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('contour.fixture_issue_entered'); PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER fixture_issue_delay AFTER INSERT ON contour.causal_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.fixture_issue_delay();")
    if execute("SELECT has_sequence_privilege('causal_issuer_login','contour.fixture_issue_entered','USAGE');")!='t': raise AssertionError('issue sequence privilege unavailable')
    args=list(base); args[-1]=str(uuid.uuid4())
    result=bridge['run_process'](args+['issue_unknown'],timeout=20,env=env,limit=4096)
    if result.returncode or result.stderr or result.stdout!=b'OUTCOME_UNKNOWN\n': raise AssertionError('unknown issue protocol mismatch')
    if execute("SELECT is_called::text||'|'||last_value::text FROM contour.fixture_issue_entered;")!='true|1': raise AssertionError('issue commit never entered')
    until=time.monotonic()+10
    while execute("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename='causal_issuer_login';")!='0':
        if time.monotonic()>=until: raise TimeoutError('unknown issue backend not absent')
        time.sleep(.05)
    execute('DROP TRIGGER fixture_issue_delay ON contour.causal_sessions; DROP FUNCTION contour.fixture_issue_delay(); DROP SEQUENCE contour.fixture_issue_entered;')
    result=bridge['run_process'](args+['issue_retry'],timeout=20,env=env,limit=4096)
    if result.returncode or result.stderr or result.stdout!=b'RETRIED\n': raise AssertionError('issue retry protocol mismatch')
    tenant,runtime=bridge['IDS'][:2]
    if execute(f"SELECT count(*) FROM contour.causal_sessions WHERE tenant_id='{tenant}' AND runtime_id='{runtime}' AND nonce='{args[-1]}';")!='1': raise AssertionError('issue retry row mismatch')


def clock_guard(execute,ids):
    tenant,runtime,collector=ids[:3]
    sql=(f"BEGIN; SELECT set_config('apicontour.tenant_id','{tenant}',true); SET LOCAL ROLE contour_owner; "
         f"SELECT contour.begin_origin_operation('{tenant}'); SELECT contour.lock_origin_credential(decode(repeat('55',32),'hex')); SELECT contour.lock_origin_collector('{tenant}','{collector}'); "
         "SELECT contour.causal_runtime_authority_locked(s.claim,clock_timestamp())::text||'|'||contour.causal_runtime_authority_locked(s.claim,NULL)::text||'|'||contour.causal_runtime_authority_locked(s.claim,clock_timestamp()+interval '1 hour')::text "
         f"FROM contour.causal_sessions s WHERE s.tenant_id='{tenant}' AND s.runtime_id='{runtime}' AND s.epoch=1; COMMIT;")
    if execute(sql).splitlines()[-1]!='true|false|false': raise AssertionError('current clock guard mismatch')


def quota_guard(base,env,execute,bridge):
    tenant,runtime=bridge['IDS'][:2]
    def usage(value):
        execute(f"BEGIN; SELECT set_config('apicontour.tenant_id','{tenant}',true); SET LOCAL ROLE contour_owner; SELECT contour.begin_origin_operation('{tenant}'); INSERT INTO contour.origin_logical_usage VALUES ('{tenant}',{value}) ON CONFLICT(tenant_id) DO UPDATE SET used_bytes=excluded.used_bytes; COMMIT;")
    usage(1073741824)
    args=list(base); args[-1]=str(uuid.uuid4())
    result=bridge['run_process'](args+['quota'],timeout=20,env=env,limit=4096)
    if result.returncode or result.stderr or result.stdout!=b'QUOTA\n': raise AssertionError('quota protocol mismatch')
    state=execute(f"SELECT (SELECT count(*) FROM contour.causal_generation_claims WHERE tenant_id='{tenant}' AND runtime_id='{runtime}')||'|'||(SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='{tenant}');")
    if state!='0|1073741824': raise AssertionError('quota state mismatch')
    usage(0)


def marker_unknown(base,env,execute,bridge):
    tenant,runtime=bridge['IDS'][:2]
    execute("CREATE SEQUENCE contour.fixture_marker_commit_entered; GRANT USAGE,SELECT ON SEQUENCE contour.fixture_marker_commit_entered TO contour_owner; GRANT USAGE ON SEQUENCE contour.fixture_marker_commit_entered TO causal_provisioner_login; CREATE FUNCTION contour.fixture_marker_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('contour.fixture_marker_commit_entered'); PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER fixture_marker_commit_delay AFTER INSERT ON contour.causal_marker_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.fixture_marker_commit_delay();")
    if execute("SELECT has_sequence_privilege('causal_provisioner_login','contour.fixture_marker_commit_entered','USAGE');")!='t': raise AssertionError('marker sequence privilege unavailable')
    args=list(base); args[-1]=str(uuid.uuid4())
    result=bridge['run_process'](args+['marker_unknown'],timeout=20,env=env,limit=4096)
    if result.returncode or result.stderr or result.stdout!=b'MARKER_OUTCOME_UNKNOWN\n': raise AssertionError('unknown marker protocol mismatch')
    if execute("SELECT is_called::text||'|'||last_value::text FROM contour.fixture_marker_commit_entered;")!='true|1': raise AssertionError('marker commit never entered')
    until=time.monotonic()+10
    while execute("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename='causal_provisioner_login';")!='0':
        if time.monotonic()>=until: raise TimeoutError('unknown marker backend not absent')
        time.sleep(.05)
    execute('DROP TRIGGER fixture_marker_commit_delay ON contour.causal_marker_bindings; DROP FUNCTION contour.fixture_marker_commit_delay(); DROP SEQUENCE contour.fixture_marker_commit_entered;')
    # Read-only evidence only: never automatically retry an ambiguous marker bind.
    count=execute(f"SELECT count(*) FROM contour.causal_marker_bindings WHERE tenant_id='{tenant}' AND runtime_id='{runtime}' AND nonce='{args[-1]}';")
    if count not in ('0','1'): raise AssertionError('unknown marker row mismatch')
    return int(count)


def issue_context_unknown(base,env,execute,bridge):
    """Prove a deferred fixture trigger caused a real post-commit context leak."""
    args=list(base); args[-1]=str(uuid.uuid4())
    tenant,runtime=bridge['IDS'][:2]
    if any(not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',x) for x in (tenant,runtime,args[-1])): raise ValueError('context fixture identity invalid')
    query=f"SELECT count(*) FROM contour.causal_sessions WHERE tenant_id='{tenant}' AND runtime_id='{runtime}' AND nonce='{args[-1]}';"
    if execute(query)!='0': raise AssertionError('context fixture nonce exists')
    # The security-definer issue call sets a transaction-local tenant. The deferred
    # trigger replaces it with a session setting at COMMIT, after all precommit checks.
    setup=("BEGIN; CREATE FUNCTION contour.fixture_issue_context_leak() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
           "PERFORM set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000002',false); RETURN NEW; END $$; "
           "CREATE CONSTRAINT TRIGGER fixture_issue_context_leak AFTER INSERT ON contour.causal_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
           f"WHEN (NEW.tenant_id='{tenant}'::uuid AND NEW.runtime_id='{runtime}'::uuid AND NEW.nonce='{args[-1]}'::uuid) "
           "EXECUTE FUNCTION contour.fixture_issue_context_leak(); COMMIT;")
    execute(setup)
    try:
        result=None; probe_error=None
        try: result=bridge['run_process'](args+['issue_context_unknown'],timeout=20,env=env,limit=4096)
        except Exception as error: probe_error=error
        committed=execute(query)
        if committed!='1': raise AssertionError('context failure did not commit exact nonce')
        outcomes={b'CONTEXT_OUTCOME_UNKNOWN\n':'unknown',b'CONTEXT_UNEXPECTED_SUCCESS\n':'unexpected-success',b'CONTEXT_WRONG_OUTCOME\n':'wrong'}
        outcome=outcomes.get(result.stdout,'wrong') if result is not None and result.returncode==0 and not result.stderr else 'wrong'
        print('issue-context committed=1 outcome='+outcome,flush=True)
        if probe_error is not None: raise probe_error
        if outcome!='unknown': raise AssertionError('context failure protocol mismatch')
    finally:
        execute('DROP TRIGGER fixture_issue_context_leak ON contour.causal_sessions; DROP FUNCTION contour.fixture_issue_context_leak();')


def exercise(base,env,execute,bridge,https,stages):
    tenant=bridge['IDS'][0]; runtime=bridge['IDS'][1]; extra=0
    def state(sessions,rows,used):
        query=f"SELECT (SELECT count(*) FROM contour.causal_sessions WHERE tenant_id='{tenant}' AND runtime_id='{runtime}')||'|'||(SELECT count(*) FROM contour.causal_generation_claims WHERE tenant_id='{tenant}' AND runtime_id='{runtime}')||'|'||(SELECT count(*) FROM contour.causal_marker_bindings WHERE tenant_id='{tenant}' AND runtime_id='{runtime}')||'|'||coalesce((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='{tenant}'),0);"
        if execute(query)!=f'{sessions+2+extra}|{sessions}|{rows}|{used}': raise AssertionError('durable marker state mismatch')
    def arguments(mode,user=None):
        a=list(base); a[-1]=str(uuid.uuid4())
        if user: a[6]=user
        return a+[mode]
    def simple(mode,expected,user=None):
        result=bridge['run_process'](arguments(mode,user),timeout=40,env=env,limit=4096)
        if result.returncode!=0 or result.stderr or result.stdout!=expected: raise AssertionError('probe protocol mismatch: '+mode)
    def interactive(mode,action):
        monitor=strict_monitor(https['ProbeProcess'],arguments(mode),env)
        stopped=False
        try:
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                with monitor.lock: out=bytes(monitor.buffers['out']); err=bytes(monitor.buffers['err']); overflow=monitor.overflow or monitor.read_failed
                if overflow or err or out not in (b'',b'READY\n'): raise RuntimeError('probe readiness invalid')
                if out==b'READY\n': break
                if monitor.child.poll() is not None: raise RuntimeError('probe exited before barrier')
                time.sleep(.02)
            else: raise TimeoutError('probe barrier deadline')
            action(); monitor.child.stdin.write(b'GO\n'); monitor.child.stdin.flush(); monitor.child.wait(timeout=15)
            monitor.stop(False); stopped=True
            monitor_output(monitor,b'READY\nREFUSED\n')
            if monitor.child.returncode: raise AssertionError('interactive protocol mismatch')
        finally:
            primary=sys.exc_info()[1]
            if not stopped:
                try: monitor.stop(False)
                except BaseException as cleanup:
                    if primary is not None: raise BaseExceptionGroup('probe and cleanup',[primary,cleanup]) from None
                    raise
    state(0,0,0)
    simple('weak',b'REFUSED\n','causal_issuer_login'); state(1,0,92); stages.append('weak')
    simple('wrong_role',b'REFUSED\n','causal_issuer_login'); state(2,0,184); stages.append('wrong_role')
    result=bridge['run_process'](arguments('positive'),timeout=40,env=env,limit=4096)
    if result.returncode or result.stderr: raise AssertionError('positive bridge failed')
    match=re.fullmatch(rb'BOUND ([0-9]{1,20})\nCONFLICT_INVALIDATED\n',result.stdout)
    if not match: raise AssertionError('positive bridge output invalid')
    stored=execute(f"SELECT floor(extract(epoch FROM bound_at)*1000000)::bigint::text||'|'||encode(marker_public_key,'hex') FROM contour.causal_marker_bindings WHERE tenant_id='{tenant}' AND runtime_id='{runtime}';")
    if stored!=match.group(1).decode()+'|'+Path(base[7]).read_bytes().hex(): raise AssertionError('binding receipt differs from committed row')
    state(3,1,548); stages.append('positive')
    interactive('expired',lambda:time.sleep(3.5)); state(4,1,640); stages.append('expired')
    # A sequence proves the delayed INSERT was reached even though cancellation
    # rolls its transaction back; a separate client waits for its backend exit.
    execute("CREATE SEQUENCE contour.fixture_marker_entered; GRANT USAGE,SELECT ON SEQUENCE contour.fixture_marker_entered TO contour_owner; CREATE FUNCTION contour.fixture_marker_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('contour.fixture_marker_entered'); PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE TRIGGER fixture_marker_delay BEFORE INSERT ON contour.causal_marker_bindings FOR EACH ROW EXECUTE FUNCTION contour.fixture_marker_delay();")
    simple('cancel',b'CANCELLED\n')
    if execute("SELECT is_called::text||'|'||last_value::text FROM contour.fixture_marker_entered;")!='true|1': raise AssertionError('cancellation never reached insert')
    until=time.monotonic()+10
    while execute("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename='causal_provisioner_login';")!='0':
        if time.monotonic()>=until: raise TimeoutError('cancelled backend not absent')
        time.sleep(.05)
    state(5,1,732); stages.append('cancel')
    execute('DROP TRIGGER fixture_marker_delay ON contour.causal_marker_bindings; DROP FUNCTION contour.fixture_marker_delay(); DROP SEQUENCE contour.fixture_marker_entered;')
    committed=marker_unknown(base,env,execute,bridge)
    state(6,1+committed,824+272*committed); stages.append('marker_unknown')
    issue_context_unknown(base,env,execute,bridge); extra=1; state(6,1+committed,824+272*committed); stages.append('issue_context_unknown')
    execute(f"BEGIN; SELECT set_config('apicontour.tenant_id','{tenant}',true); SET LOCAL ROLE contour_admin; SELECT contour.enroll_origin_credential('{tenant}','fa000000-0000-4000-8000-000000000011','{bridge['IDS'][9]}',decode(repeat('44',32),'hex')); COMMIT;")
    def revoke():
        execute(f"BEGIN; SELECT set_config('apicontour.tenant_id','{tenant}',true); SET LOCAL ROLE contour_admin; SELECT contour.end_origin('{tenant}','credential_revoked','fa000000-0000-4000-8000-000000000003'); COMMIT;")
        check=execute(f"BEGIN; SELECT set_config('apicontour.tenant_id','{tenant}',true); SET LOCAL ROLE contour_causal_issuer; SELECT contour.check_causal_session('{tenant}','{runtime}',10); COMMIT;")
        if check.splitlines()[-1]!='t': raise AssertionError('other credential did not keep session current')
    interactive('revoked',revoke); state(7,1+committed,916+272*committed); stages.append('revoked')


if __name__=='__main__':
    try: main()
    except BaseException as error:
        print('FAIL:',type(error).__name__,file=sys.stderr)
        sys.exit(1)
