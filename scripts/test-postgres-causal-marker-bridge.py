#!/usr/bin/env python3
"""Owned PostgreSQL TLS SQL23 checked bridge; synthetic and dormant only."""
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
OPT=('0015_origin_lifecycle','0016_v2_unattributed','0017_origin_proofs','0018_causal_runtime_registry','0019_causal_sessions','0020_causal_inbox','0021_origin_admission','0022_causal_generation','0023_causal_marker_bindings')
EXTRA_SOURCE_MIGRATIONS=('0024_causal_live_profile','0025_historical_origin','0026_causal_evidence_enrollment','0027_causal_observer_inbox','0028_causal_receiver_enrollment','0029_causal_receiver_inbox','0030_causal_gateway_reader',)
EXAMPLE=ROOT/'crates/contour-postgres/examples/causal_marker_binding_probe.rs'

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
    paths.update([EXAMPLE, ROOT/'scripts/test-postgres-causal-marker-bridge.py',ROOT/'tests/fixtures/causal-marker-bridge/test_driver.py',ROOT/'scripts/test-postgres-causal-https.py',ROOT/'tests/fixtures/causal-https/test_https_driver.py'])
    paths.update(ROOT/'db/opt-in-migrations'/(n+'.sql') for n in OPT + EXTRA_SOURCE_MIGRATIONS)
    if set((ROOT/'db/opt-in-migrations').glob('*.sql'))!={ROOT/'db/opt-in-migrations'/(n+'.sql') for n in OPT + EXTRA_SOURCE_MIGRATIONS}: raise ValueError('migration list changed')
    return {str(path):bridge['digest_file'](safe(path)) for path in sorted(paths)}

def artifact(lines,target,bridge):
    found=[]
    for line in lines:
        obj=json.loads(line); t=obj.get('target') or {}
        if obj.get('reason')=='compiler-artifact' and t.get('name')=='causal_marker_binding_probe' and t.get('kind')==['example'] and t.get('src_path')==str(EXAMPLE) and not (obj.get('profile') or {}).get('test',False):
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
    run=bridge['command']; rid=uuid.uuid4().hex; network='contour-marker-bridge-net-'+rid; container='contour-marker-bridge-'+rid; nid=cid=None; network_attempted=container_attempted=False
    previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('overall deadline'))); signal.setitimer(signal.ITIMER_REAL,600)
    try:
      with tempfile.TemporaryDirectory(prefix='contour-marker-bridge-') as temp:
        work=Path(temp).resolve(); os.chmod(work,0o700); target=work/'target'; target.mkdir()
        env=os.environ.copy(); env['CARGO_TARGET_DIR']=str(target)
        lines=bridge['bounded_process_output'](['cargo','build','-p','contour-postgres','--example','causal_marker_binding_probe','--locked','--offline','--message-format=json'],cwd=ROOT,env=env)
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
        for name,data,domain in [('grant',grant,b'apicontour/causal-grant/1\n'),('policy',policy,b'apicontour/policy/1\n')]: (work/(name+'.json')).write_bytes(bridge['signed_payload'](data,domain,work/(name+'.key'),work,name))
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
        execute(pre.replace(marker,"INSERT INTO contour.policy_revisions VALUES ('"+ids[0]+"','"+ids[2]+"',1,decode('"+(work/'policy.json').read_bytes().hex()+"','hex'));",1))
        execute(safe(ROOT/('db/opt-in-migrations/'+OPT[3]+'.sql')).read_text()); execute(safe(ROOT/'db/tests/causal_session_setup.sql').read_text())
        for n in OPT[4:]: execute(safe(ROOT/('db/opt-in-migrations/'+n+'.sql')).read_text())
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
        exercise(base,environment,execute,bridge,https)
        if bridge['digest_file'](probe)!=probe_hash: raise RuntimeError('probe changed')
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
        if failures:
            groups=([BaseExceptionGroup('primary',[primary])] if primary is not None else [])+[BaseExceptionGroup('cleanup',failures)]
            raise BaseExceptionGroup('qualification',groups) from None
    print('PASS: synthetic checked marker bridge; no key possession or launch proof')


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


def exercise(base,env,execute,bridge,https):
    tenant=bridge['IDS'][0]; runtime=bridge['IDS'][1]
    def state(sessions,rows,used):
        query=f"SELECT (SELECT count(*) FROM contour.causal_sessions WHERE tenant_id='{tenant}')||'|'||(SELECT count(*) FROM contour.causal_generation_claims WHERE tenant_id='{tenant}')||'|'||(SELECT count(*) FROM contour.causal_marker_bindings WHERE tenant_id='{tenant}')||'|'||coalesce((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='{tenant}'),0);"
        if execute(query)!=f'{sessions}|{sessions}|{rows}|{used}': raise AssertionError('durable marker state mismatch')
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
    simple('weak',b'REFUSED\n','causal_issuer_login'); state(1,0,92)
    simple('wrong_role',b'REFUSED\n','causal_issuer_login'); state(2,0,184)
    result=bridge['run_process'](arguments('positive'),timeout=40,env=env,limit=4096)
    if result.returncode or result.stderr: raise AssertionError('positive bridge failed')
    match=re.fullmatch(rb'BOUND ([0-9]{1,20})\nCONFLICT_INVALIDATED\n',result.stdout)
    if not match: raise AssertionError('positive bridge output invalid')
    stored=execute(f"SELECT floor(extract(epoch FROM bound_at)*1000000)::bigint::text||'|'||encode(marker_public_key,'hex') FROM contour.causal_marker_bindings WHERE tenant_id='{tenant}';")
    if stored!=match.group(1).decode()+'|'+Path(base[7]).read_bytes().hex(): raise AssertionError('binding receipt differs from committed row')
    state(3,1,548)
    interactive('expired',lambda:time.sleep(3.5)); state(4,1,640)
    # A sequence proves the delayed INSERT was reached even though cancellation
    # rolls its transaction back; a separate client waits for its backend exit.
    execute("CREATE SEQUENCE contour.fixture_marker_entered; GRANT USAGE,SELECT ON SEQUENCE contour.fixture_marker_entered TO contour_owner; CREATE FUNCTION contour.fixture_marker_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('contour.fixture_marker_entered'); PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE TRIGGER fixture_marker_delay BEFORE INSERT ON contour.causal_marker_bindings FOR EACH ROW EXECUTE FUNCTION contour.fixture_marker_delay();")
    simple('cancel',b'CANCELLED\n')
    if execute("SELECT is_called::text||'|'||last_value::text FROM contour.fixture_marker_entered;")!='true|1': raise AssertionError('cancellation never reached insert')
    until=time.monotonic()+10
    while execute("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename='causal_provisioner_login';")!='0':
        if time.monotonic()>=until: raise TimeoutError('cancelled backend not absent')
        time.sleep(.05)
    state(5,1,732)
    execute('DROP TRIGGER fixture_marker_delay ON contour.causal_marker_bindings; DROP FUNCTION contour.fixture_marker_delay(); DROP SEQUENCE contour.fixture_marker_entered;')
    execute(f"BEGIN; SELECT set_config('apicontour.tenant_id','{tenant}',true); SET LOCAL ROLE contour_admin; SELECT contour.enroll_origin_credential('{tenant}','fa000000-0000-4000-8000-000000000011','{bridge['IDS'][9]}',decode(repeat('44',32),'hex')); COMMIT;")
    def revoke():
        execute(f"BEGIN; SELECT set_config('apicontour.tenant_id','{tenant}',true); SET LOCAL ROLE contour_admin; SELECT contour.end_origin('{tenant}','credential_revoked','fa000000-0000-4000-8000-000000000001'); COMMIT;")
        check=execute(f"BEGIN; SELECT set_config('apicontour.tenant_id','{tenant}',true); SET LOCAL ROLE contour_causal_issuer; SELECT contour.check_causal_session('{tenant}','{runtime}',6); COMMIT;")
        if check.splitlines()[-1]!='t': raise AssertionError('other credential did not keep session current')
    interactive('revoked',revoke); state(6,1,824)


if __name__=='__main__':
    try: main()
    except BaseException as error:
        print('FAIL:',type(error).__name__,file=sys.stderr)
        sys.exit(1)
