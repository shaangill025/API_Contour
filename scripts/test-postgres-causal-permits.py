#!/usr/bin/env python3
"""Owned PostgreSQL TLS -> checked owner -> inherited Node signer control fixture.

Synthetic only: no application wire, graph, source attestation or key erasure claim.
"""
import base64
from contextlib import ExitStack, contextmanager
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).absolute().parent.parent
OPT=('0015_origin_lifecycle','0016_v2_unattributed','0017_origin_proofs','0018_causal_runtime_registry','0019_causal_sessions','0020_causal_inbox','0021_origin_admission','0022_causal_generation')
EXAMPLE=ROOT/'crates/contour-ingress/examples/causal_permit_probe.rs'
NODE=ROOT/'collectors/nodered/error-integration/private-owner-permit.js'
MARKER=ROOT/'collectors/nodered/error-integration/causal-marker.js'


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
    paths.update([EXAMPLE,NODE,MARKER,ROOT/'scripts/test-postgres-causal-permits.py',ROOT/'tests/fixtures/causal-permits/test_driver.py',ROOT/'scripts/test-postgres-causal-https.py',ROOT/'tests/fixtures/causal-https/test_https_driver.py',ROOT/'db/opt-in-migrations/0022_causal_generation.sql',ROOT/'crates/contour-ingress/Cargo.toml'])
    for crate in ('contour-ingress','contour-delivery','contour-platform','contour-abi','contour-wasm'):
        source=ROOT/'crates'/crate/'src'
        if source.is_symlink() or not source.is_dir(): raise ValueError('source directory unavailable')
        for parent,dirs,files in os.walk(source,followlinks=False,onerror=lambda e:(_ for _ in ()).throw(e)):
            if any((Path(parent)/n).is_symlink() for n in dirs+files): raise ValueError('source symlink')
        paths.update(source.rglob('*.rs'))
        build=ROOT/'crates'/crate/'build.rs'
        if build.exists() or build.is_symlink(): paths.add(build)
    expected={ROOT/'db/opt-in-migrations'/(n+'.sql') for n in OPT}
    if set((ROOT/'db/opt-in-migrations').glob('*.sql'))!=expected: raise ValueError('migration list changed')
    return {str(path):bridge['digest_file'](safe(path)) for path in sorted(paths)}


def artifact(lines,target,bridge):
    found=[]
    for line in lines:
        obj=json.loads(line); t=obj.get('target') or {}
        if obj.get('reason')=='compiler-artifact' and t.get('name')=='causal_permit_probe' and t.get('kind')==['example'] and t.get('src_path')==str(EXAMPLE) and not (obj.get('profile') or {}).get('test',False):
            path=Path(obj.get('executable') or '')
            if not path.is_absolute() or '..' in path.parts: raise RuntimeError('invalid cargo executable')
            safe(path); path.resolve(strict=True).relative_to(target.resolve(strict=True))
            if not os.access(path,os.X_OK): raise RuntimeError('cargo executable unavailable')
            bridge['digest_file'](path); found.append(path)
    if len(found)!=1: raise RuntimeError('ambiguous cargo executable')
    return found[0]


def line(monitor,index,expected,timeout=15):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        with monitor.lock: out=bytes(monitor.buffers['out']); err=bytes(monitor.buffers['err']); overflow=monitor.overflow
        if overflow or err: raise RuntimeError('probe output invalid')
        lines=out.splitlines(keepends=True)
        if len(lines)>index and lines[index].endswith(b'\n'):
            if lines[index]!=expected+b'\n': raise RuntimeError('probe stage invalid')
            return
        if monitor.child.poll() is not None: raise RuntimeError('probe exited before stage')
        time.sleep(.01)
    raise TimeoutError('probe stage deadline')


def authority_rejection_observed(log):
    rows=log.splitlines()
    return (any(b'causal_revocation_login' in row and b'contour.issue_causal_session' in row for row in rows)
            and any(b'causal_revocation_login' in row and b'23514' in row and b'session unavailable' in row for row in rows))


def assert_active(monitor):
    # A previously buffered STOPPED cannot be attributed to a later mutation.
    with monitor.lock: out=bytes(monitor.buffers['out']); err=bytes(monitor.buffers['err']); overflow=monitor.overflow
    if overflow or err or out!=b'ACTIVE\n' or monitor.child.poll() is not None:
        raise AssertionError('probe was not active at control boundary')


@contextmanager
def owned_probe(monitor,phase):
    if phase not in ('finish','eof','expiry','epoch-old','epoch-new','competition','revocation'):
        raise ValueError('invalid probe phase')
    def report():
        pid=getattr(monitor.child,'pid',None)
        print('probe cleanup failed phase='+phase+' pid='+(str(pid) if type(pid) is int and pid>0 else 'unknown'),file=sys.stderr)
    try:
        yield monitor
    except BaseException as primary:
        try: monitor.stop(False)
        except BaseException as cleanup:
            report()
            raise BaseExceptionGroup('probe failure and cleanup failure',[primary,cleanup]) from None
        raise
    else:
        try: monitor.stop(False)
        except BaseException:
            report()
            raise


def finish(monitor,expected):
    with owned_probe(monitor,'finish'):
        monitor.child.wait(timeout=5)
    with monitor.lock: out=bytes(monitor.buffers['out']); err=bytes(monitor.buffers['err']); overflow=monitor.overflow
    if monitor.child.returncode!=0 or overflow or err or out!=expected: raise RuntimeError('probe final output invalid')


def exercise(base,work,env,execute,bridge,https,container):
    tenant=bridge['IDS'][0]; runtime=bridge['IDS'][1]; leaf='33'*32
    def journal(name):
        path=work/name; path.mkdir(mode=0o700); return str(path.resolve(strict=True))
    def args(name,mode,nonce): return base[:-1]+[nonce,journal(name),mode,str(NODE),str(MARKER)]
    def start(argv): return https['ProbeProcess'](argv,env)
    def counts(expected):
        sql=f"SELECT (SELECT count(*) FROM contour.causal_sessions WHERE tenant_id='{tenant}' AND runtime_id='{runtime}')||'|'||(SELECT count(*) FROM contour.causal_generation_claims WHERE tenant_id='{tenant}' AND runtime_id='{runtime}')||'|'||coalesce((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='{tenant}'),0);"
        if execute(sql)!=expected: raise AssertionError('generation accounting mismatch')
    one=args('eof','eof',str(uuid.uuid4())); monitor=start(one)
    with owned_probe(monitor,'eof'):
        line(monitor,0,b'ACTIVE'); line(monitor,1,b'STOPPED',3); finish(monitor,b'ACTIVE\nSTOPPED\n')
    counts('1|1|92')
    live=f"BEGIN; SET LOCAL apicontour.tenant_id='{tenant}'; SET LOCAL ROLE contour_causal_issuer; SELECT contour.check_causal_session('{tenant}','{runtime}',1)::text; COMMIT;"
    if execute(live)!='true': raise AssertionError('original session not live for restart control')
    restarted=bridge['run_process'](one,env=env,timeout=20,limit=1024)
    if restarted.returncode!=0 or restarted.stdout!=b'CLAIM_REJECTED\n' or restarted.stderr: raise AssertionError('consumed journal relaunched')
    if execute(live)!='true': raise AssertionError('original session expired during restart control')
    counts('1|1|92')
    # A short real session expires; no external clock modification.
    two=args('expiry','expiry',str(uuid.uuid4())); monitor=start(two)
    with owned_probe(monitor,'expiry'):
        line(monitor,0,b'ACTIVE'); line(monitor,1,b'STOPPED',6); finish(monitor,b'ACTIVE\nSTOPPED\n')
    counts('2|2|184')
    # A new checked issue supersedes a still-live old child.
    three=args('epoch-old','normal',str(uuid.uuid4())); monitor=start(three); successor=None
    with ExitStack() as stack:
        stack.enter_context(owned_probe(monitor,'epoch-old'))
        line(monitor,0,b'ACTIVE'); successor=start(args('epoch-new','claim-only',str(uuid.uuid4())))
        stack.enter_context(owned_probe(successor,'epoch-new'))
        line(successor,0,b'CLAIMED'); line(monitor,1,b'STOPPED',2)
        successor.child.stdin.write(b'GO\n'); successor.child.stdin.flush(); finish(successor,b'CLAIMED\n'); finish(monitor,b'ACTIVE\nSTOPPED\n')
    counts('4|4|368')
    # Competition has its own live owner; contention can legitimately close it.
    nonce=str(uuid.uuid4()); four=args('competition','normal',nonce); monitor=start(four)
    with owned_probe(monitor,'competition'):
        line(monitor,0,b'ACTIVE'); assert_active(monitor)
        rival=args('rival','normal',nonce); rival[5]='causal_rival_login'
        result=bridge['run_process'](rival,env=env,timeout=20,limit=1024)
        if result.returncode!=0 or result.stdout!=b'CLAIM_REJECTED\n' or result.stderr: raise AssertionError('competing journal accepted')
        logs=bridge['run_process'](['docker','logs','--tail','200',container],timeout=10,limit=1048576)
        if logs.returncode: raise RuntimeError('fixture logs unavailable')
        log=logs.stdout+logs.stderr
        if not any(b'causal_rival_login' in row and b'SELECT contour.claim_causal_generation' in row for row in log.splitlines()) or not any(b'causal_rival_login' in row and b'generation conflict' in row for row in log.splitlines()): raise AssertionError('rival database conflict not observed')
        counts('5|5|460')
        monitor.child.stdin.write(b'STOP\n'); monitor.child.stdin.flush()
        line(monitor,1,b'STOPPED',3); finish(monitor,b'ACTIVE\nSTOPPED\n')
    # A fresh owner and dedicated role make an authority rejection observable
    # independently of the earlier competition and its Q-lock contention.
    five=args('revocation','normal',str(uuid.uuid4())); five[5]='causal_revocation_login'; monitor=start(five)
    with owned_probe(monitor,'revocation'):
        line(monitor,0,b'ACTIVE'); counts('6|6|552')
        live_sql=f"SELECT (expires_at>clock_timestamp()+interval '30 seconds' AND (claim).grant_expires>clock_timestamp()+interval '30 seconds' AND (claim).policy_expires>clock_timestamp()+interval '30 seconds')::text FROM contour.causal_sessions WHERE tenant_id='{tenant}' AND runtime_id='{runtime}' AND epoch=6;"
        if execute(live_sql)!='true': raise AssertionError('revocation session lacks live lease')
        logs=bridge['run_process'](['docker','logs','--tail','200',container],timeout=10,limit=1048576)
        if logs.returncode: raise RuntimeError('fixture logs unavailable')
        if any(b'causal_revocation_login' in row and b'23514' in row for row in (logs.stdout+logs.stderr).splitlines()): raise AssertionError('authority rejection preceded trigger')
        assert_active(monitor)
        started=time.monotonic()
        execute("BEGIN; SELECT set_config('apicontour.tenant_id','"+tenant+"',true); SET LOCAL ROLE contour_causal_provisioner; SELECT contour.end_causal_runtime('"+tenant+"','"+runtime+"','export_revoked'); COMMIT;")
        line(monitor,1,b'STOPPED',1)
        if time.monotonic()-started>=1: raise AssertionError('revocation response exceeded permit bound')
        finish(monitor,b'ACTIVE\nSTOPPED\n')
        logs=bridge['run_process'](['docker','logs','--tail','200',container],timeout=10,limit=1048576)
        if logs.returncode: raise RuntimeError('fixture logs unavailable')
        log=logs.stdout+logs.stderr
        if not authority_rejection_observed(log): raise AssertionError('post-commit authority rejection not observed')
    # No claim is made that the earlier epoch case isolated epoch rejection from contention.
    print('LIMITATION: epoch closure may include lock contention',flush=True)
    counts('6|6|552')



def node_version(bridge):
    result=bridge['run_process'](['node','--version'],env={'PATH':os.environ.get('PATH',os.defpath)},timeout=10,limit=64)
    if result.returncode or result.stderr or not re.fullmatch(rb'v[0-9]+\.[0-9]+\.[0-9]+\n',result.stdout): raise RuntimeError('Node version unavailable')
    return result.stdout.decode('ascii').strip()


def main():
    if len(sys.argv)!=1: raise ValueError('no arguments accepted')
    bridge,https=helpers(); before=snapshot(bridge); version=node_version(bridge); os.umask(0o077)
    print('Host Node '+version+'; no qualified Node-RED or pinned image claim',flush=True)
    run=bridge['command']; rid=uuid.uuid4().hex; network='contour-permit-net-'+rid; container='contour-permit-'+rid; nid=cid=None; network_attempted=container_attempted=False
    previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('overall deadline'))); signal.setitimer(signal.ITIMER_REAL,600)
    try:
      with tempfile.TemporaryDirectory(prefix='contour-permits-') as temp:
        work=Path(temp).resolve(); os.chmod(work,0o700); target=work/'target'; target.mkdir()
        env=os.environ.copy(); env['CARGO_TARGET_DIR']=str(target)
        lines=bridge['bounded_process_output'](['cargo','build','-p','contour-ingress','--example','causal_permit_probe','--locked','--offline','--message-format=json'],cwd=ROOT,env=env)
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
        if execute('SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;')!='{'+','.join(map(str,range(1,23)))+'}': raise RuntimeError('ledger mismatch')
        execute("CREATE ROLE causal_issuer_login LOGIN PASSWORD '"+password+"'; CREATE ROLE causal_rival_login LOGIN PASSWORD '"+password+"'; CREATE ROLE causal_revocation_login LOGIN PASSWORD '"+password+"'; GRANT contour_causal_issuer TO causal_issuer_login,causal_rival_login,causal_revocation_login; ALTER ROLE causal_rival_login SET log_statement='all'; ALTER ROLE causal_revocation_login SET log_statement='all';")
        hba='local all all trust\nhostnossl all all all reject\nhostssl contour_fixture causal_issuer_login,causal_rival_login,causal_revocation_login all scram-sha-256\nhostssl all all all reject\n'
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
        environment={'PATH':os.environ.get('PATH',os.defpath),'CONTOUR_CAUSAL_ISSUER_PASSWORD':password}; base=[str(probe),'localhost',port,'contour_fixture',str(ca),'causal_issuer_login','unused',str(work/'grant.pub'),str(work/'policy.pub'),str(work/'grant.json'),str(work/'policy.json'),str(work/'batch.json'),'33'*32,*ids,'placeholder']
        exercise(base,work,environment,execute,bridge,https,container)
        if bridge['digest_file'](probe)!=probe_hash: raise RuntimeError('probe changed')
        if node_version(bridge)!=version: raise RuntimeError('Node version changed')
    finally:
        primary=sys.exc_info()[1]; failures=[]
        def checked_cleanup(phase,action):
            try: action()
            except BaseException as error:
                print('fixture cleanup failed phase='+phase,file=sys.stderr)
                failures.append(error)
        checked_cleanup('timer',lambda:(signal.setitimer(signal.ITIMER_REAL,0),signal.signal(signal.SIGALRM,previous)))
        checked_cleanup('container',lambda:bridge['cleanup']('container',container,rid,known_id=cid) if container_attempted else bridge['require_empty_label_inventory']('container',rid))
        checked_cleanup('network',lambda:bridge['cleanup']('network',network,rid,known_id=nid) if network_attempted else bridge['require_empty_label_inventory']('network',rid))
        def check_source():
            if snapshot(bridge)!=before: raise RuntimeError('qualification source changed')
        checked_cleanup('source',check_source)
        if failures:
            raise BaseExceptionGroup('qualification failure and cleanup failures',([primary] if primary is not None else [])+failures) from None
    print('PASS: checked issuer, private Node signer and generation controls; no wire or source attestation')

if __name__=='__main__':
    try: main()
    except Exception as error:
        print('FAIL:',type(error).__name__,file=sys.stderr); sys.exit(1)
