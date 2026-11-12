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
EXTRA_SOURCE_MIGRATIONS=('0023_causal_marker_bindings','0024_causal_live_profile','0025_historical_origin','0026_causal_evidence_enrollment','0027_causal_observer_inbox')
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
    paths.update([EXAMPLE,NODE,MARKER,ROOT/'scripts/test-postgres-causal-permits.py',ROOT/'tests/fixtures/causal-permits/test_driver.py',ROOT/'scripts/test-postgres-causal-https.py',ROOT/'tests/fixtures/causal-https/test_https_driver.py',ROOT/'db/opt-in-migrations/0022_causal_generation.sql',ROOT/'db/opt-in-migrations/0023_causal_marker_bindings.sql',ROOT/'crates/contour-ingress/Cargo.toml'])
    for crate in ('contour-ingress','contour-delivery','contour-platform','contour-abi','contour-wasm'):
        source=ROOT/'crates'/crate/'src'
        if source.is_symlink() or not source.is_dir(): raise ValueError('source directory unavailable')
        for parent,dirs,files in os.walk(source,followlinks=False,onerror=lambda e:(_ for _ in ()).throw(e)):
            if any((Path(parent)/n).is_symlink() for n in dirs+files): raise ValueError('source symlink')
        paths.update(source.rglob('*.rs'))
        build=ROOT/'crates'/crate/'build.rs'
        if build.exists() or build.is_symlink(): paths.add(build)
    paths.add(ROOT/'db/opt-in-migrations/0025_historical_origin.sql')
    paths.add(ROOT/'db/opt-in-migrations/0026_causal_evidence_enrollment.sql')
    paths.add(ROOT/'db/opt-in-migrations/0027_causal_observer_inbox.sql')
    expected={ROOT/'db/opt-in-migrations'/(n+'.sql') for n in OPT + EXTRA_SOURCE_MIGRATIONS}
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


def contention_diagnostics(log, code, message):
    if (code,message) not in ((b'40001',b'origin gate busy'),(b'23514',b'session unavailable')): raise ValueError('unsupported contention diagnostic')
    return sum(b'causal_contention_login' in row and code in row and row.rstrip().endswith(message) for row in log.splitlines())


def revoke_until(attempt,deadline):
    """Retry only an explicitly rolled-back Busy within the original deadline."""
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('revocation deadline')
        result=attempt(remaining)
        if time.monotonic()>=deadline: raise TimeoutError('revocation deadline')
        if result=='committed': return
        if result!='busy': raise RuntimeError('revocation outcome unknown')
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('revocation deadline')
        time.sleep(min(.01,remaining))


def revocation_attempt(bridge,container,tenant,runtime,remaining):
    """Return Busy only after exact gate error, explicit rollback and psql exit."""
    if any(not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value) for value in (tenant,runtime)):
        raise ValueError('invalid fixture identity')
    script=("BEGIN;\nDO $$ BEGIN PERFORM set_config('apicontour.tenant_id','"+tenant+"',true); END $$;\n"
      "SET LOCAL ROLE contour_causal_provisioner;\n"
      "DO $$ DECLARE state text; detail text; BEGIN BEGIN "
      "PERFORM contour.end_causal_runtime('"+tenant+"','"+runtime+"','export_revoked'); "
      "PERFORM set_config('apicontour.fixture_busy','false',true); "
      "EXCEPTION WHEN SQLSTATE '40001' THEN GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE, detail=MESSAGE_TEXT; "
      "IF state <> '40001' OR detail NOT IN ('origin gate busy','credential gate busy','collector gate busy') THEN RAISE; END IF; "
      "PERFORM set_config('apicontour.fixture_busy','true',true); END; END $$;\n"
      "SELECT current_setting('apicontour.fixture_busy') AS retry \\gset\n"
      "\\if :retry\nROLLBACK;\n\\echo REVOCATION_ROLLED_BACK\n\\else\nCOMMIT;\n\\echo REVOCATION_COMMITTED\n\\endif\n")
    args=['docker','exec','-i',container,'psql','-XqAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-U','postgres','-d','contour_fixture']
    result=bridge['run_process'](args,data=script.encode(),timeout=remaining,limit=8192)
    if result.returncode or result.stderr: raise RuntimeError('revocation outcome unknown')
    if result.stdout==b'REVOCATION_ROLLED_BACK\n': return 'busy'
    if result.stdout==b'REVOCATION_COMMITTED\n': return 'committed'
    raise RuntimeError('revocation outcome unknown')


def require_revocation_proof(execute,tenant,runtime):
    if execute("SELECT count(*)::text FROM contour.causal_runtime_terminal_events WHERE tenant_id='"+tenant+"' AND runtime_id='"+runtime+"' AND event_kind='export_revoked';")!='1':
        raise AssertionError('committed revocation unproven')


def assert_active(monitor):
    # A previously buffered STOPPED cannot be attributed to a later mutation.
    with monitor.lock: out=bytes(monitor.buffers['out']); err=bytes(monitor.buffers['err']); overflow=monitor.overflow
    if overflow or err or out!=b'ACTIVE\n' or monitor.child.poll() is not None:
        raise AssertionError('probe was not active at control boundary')


def confirm_post_contention(monitor):
    # The previous permit is at most one second. Staying active beyond that
    # window proves the signer obtained a fresh response after Q released.
    until=time.monotonic()+1.2
    while time.monotonic()<until:
        assert_active(monitor)
        time.sleep(.01)
    assert_active(monitor)


def cooperative_stop(monitor,phase):
    if monitor.child.poll() is not None: return
    stream=monitor.child.stdin; errors=[]
    try:
        if phase=='gate': stream.write(b'ROLLBACK;\n\\q\n'); stream.flush()
        elif phase not in ('epoch-new','claim-busy','finish'):
            stream.write(b'STOP\n'); stream.flush()
    except BaseException as exc: errors.append(exc)
    try:
        if not stream.closed: stream.close()
    except BaseException as exc: errors.append(exc)
    try: monitor.child.wait(timeout=5)
    except BaseException as exc: errors.append(exc)
    if errors: raise BaseExceptionGroup('cooperative cleanup',errors)


@contextmanager
def owned_probe(monitor,phase):
    if phase not in ('finish','eof','expiry','epoch-old','epoch-new','competition','revocation','gate','contention','claim-busy'):
        raise ValueError('invalid probe phase')
    try:
        yield monitor
    except BaseException as primary:
        errors=[]
        try: cooperative_stop(monitor,phase)
        except BaseException as cleanup: errors.append(cleanup)
        try: monitor.stop(False)
        except BaseException as cleanup: errors.append(cleanup)
        if errors: raise BaseExceptionGroup('probe failure and cleanup failure',[primary,*errors]) from None
        raise
    else:
        monitor.stop(False)


def finish(monitor,expected):
    monitor.child.wait(timeout=5)
    monitor.stop(False)
    with monitor.lock: out=bytes(monitor.buffers['out']); err=bytes(monitor.buffers['err']); overflow=monitor.overflow
    if monitor.child.returncode!=0 or overflow or err or out!=expected: raise RuntimeError('probe final output invalid')


def exercise(base,work,env,execute,bridge,https,container,revoker=None):
    tenant=bridge['IDS'][0]; runtime=bridge['IDS'][1]; leaf='33'*32
    def journal(name):
        path=work/name; path.mkdir(mode=0o700); return str(path.resolve(strict=True))
    def args(name,mode,nonce): return base[:-1]+[nonce,journal(name),mode,str(NODE),str(MARKER)]
    def start(argv): return https['ProbeProcess'](argv,env)
    def counts(expected):
        sql=f"SELECT (SELECT count(*) FROM contour.causal_sessions WHERE tenant_id='{tenant}' AND runtime_id='{runtime}')||'|'||(SELECT count(*) FROM contour.causal_generation_claims WHERE tenant_id='{tenant}' AND runtime_id='{runtime}')||'|'||coalesce((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='{tenant}'),0);"
        if execute(sql)!=expected: raise AssertionError('generation accounting mismatch')
    def gate(disable=False):
        monitor=https['ProbeProcess'](['docker','exec','-i','-u','postgres',container,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_fixture'],{'PATH':env['PATH']})
        try:
            body="BEGIN; DO $$ BEGIN PERFORM pg_catalog.set_config('apicontour.tenant_id','"+tenant+"',true); PERFORM pg_catalog.pg_advisory_xact_lock(1330792270,pg_catalog.hashtext('"+tenant+"'));"
            if disable: body+=" PERFORM contour.lock_origin_collector('"+tenant+"','"+bridge['IDS'][2]+"');"
            body+=" END $$; "
            if disable: body+="SET LOCAL ROLE contour_admin; UPDATE contour.collector_authorization SET enabled=false WHERE tenant_id='"+tenant+"' AND collector_id='"+bridge['IDS'][2]+"'; "
            monitor.child.stdin.write((body+"SELECT 'LOCKED';\n").encode()); monitor.child.stdin.flush()
        except BaseException as primary:
            failures=[]
            try: cooperative_stop(monitor,'gate')
            except BaseException as cleanup: failures.append(cleanup)
            try: monitor.stop(False)
            except BaseException as cleanup: failures.append(cleanup)
            if failures: raise BaseExceptionGroup('gate start and cleanup failure',[primary,*failures]) from None
            raise
        return monitor
    def unlock(monitor):
        monitor.child.stdin.write(b'COMMIT;\n\\q\n'); monitor.child.stdin.flush()
        finish(monitor,b'LOCKED\n')
    def busy_count():
        result=bridge['run_process'](['docker','logs','--tail','400',container],timeout=10,limit=1048576)
        if result.returncode: raise RuntimeError('fixture logs unavailable')
        return contention_diagnostics(result.stdout+result.stderr,b'40001',b'origin gate busy')
    def wait_busy(previous):
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            if busy_count()>previous: return
            time.sleep(.01)
        raise TimeoutError('gate contention was not observed')
    def authority_denials():
        result=bridge['run_process'](['docker','logs','--tail','400',container],timeout=10,limit=1048576)
        if result.returncode: raise RuntimeError('fixture logs unavailable')
        return contention_diagnostics(result.stdout+result.stderr,b'23514',b'session unavailable')
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
    # Observe a real Q-gate denial, release it, and require the existing
    # generation to remain active; then sustained contention must close it.
    six=args('contention','normal',str(uuid.uuid4())); six[5]='causal_contention_login'; monitor=start(six)
    with owned_probe(monitor,'contention'):
        line(monitor,0,b'ACTIVE'); counts('6|6|552'); previous=busy_count()
        holder=gate()
        with owned_probe(holder,'gate'):
            line(holder,0,b'LOCKED'); wait_busy(previous); unlock(holder)
        confirm_post_contention(monitor)
        counts('6|6|552'); previous=busy_count(); holder=gate()
        with owned_probe(holder,'gate'):
            line(holder,0,b'LOCKED'); wait_busy(previous); line(monitor,1,b'STOPPED',2); unlock(holder)
        finish(monitor,b'ACTIVE\nSTOPPED\n'); counts('6|6|552')
    # Commit a checked collector disable while the gate is held after a Busy;
    # the next full retry must observe it instead of issuing a permit.
    authority=args('authority-backoff','normal',str(uuid.uuid4())); authority[5]='causal_contention_login'; monitor=start(authority)
    with owned_probe(monitor,'contention'):
        line(monitor,0,b'ACTIVE'); counts('7|7|644'); previous=busy_count(); old_denials=authority_denials(); holder=gate(disable=True)
        with owned_probe(holder,'gate'):
            line(holder,0,b'LOCKED'); wait_busy(previous); assert_active(monitor); unlock(holder)
            stop_deadline=time.monotonic()+2
        committed=execute("SELECT count(*) FILTER (WHERE enabled=false)::text||'|'||count(*) FILTER (WHERE enabled IS DISTINCT FROM false)::text FROM contour.collector_authorization WHERE tenant_id='"+tenant+"' AND collector_id='"+bridge['IDS'][2]+"';")
        if committed!='1|0': raise AssertionError('collector disable was not committed')
        remaining=stop_deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('authority response deadline')
        line(monitor,1,b'STOPPED',remaining); finish(monitor,b'ACTIVE\nSTOPPED\n')
        if authority_denials()<=old_denials: raise AssertionError('authority change was not observed after contention')
        counts('7|7|644')
    collector=bridge['IDS'][2]
    execute("BEGIN; DO $$ BEGIN PERFORM pg_catalog.set_config('apicontour.tenant_id','"+tenant+"',true); PERFORM contour.begin_origin_operation('"+tenant+"'); PERFORM contour.lock_origin_collector('"+tenant+"','"+collector+"'); END $$; SET LOCAL ROLE contour_admin; UPDATE contour.collector_authorization SET enabled=true WHERE tenant_id='"+tenant+"' AND collector_id='"+collector+"'; COMMIT;")
    # Component proof only: an already-issued session gets a real claim Busy;
    # after releasing Q the original issue and fixed generation succeed once.
    seven=args('claim-busy','claim-busy',str(uuid.uuid4())); monitor=start(seven)
    with owned_probe(monitor,'claim-busy'):
        line(monitor,0,b'ISSUED'); counts('8|7|644'); holder=gate()
        with owned_probe(holder,'gate'):
            line(holder,0,b'LOCKED'); monitor.child.stdin.write(b'GO\n'); monitor.child.stdin.flush()
            line(monitor,1,b'CLAIM_BUSY'); unlock(holder)
        monitor.child.stdin.write(b'GO\n'); monitor.child.stdin.flush()
        line(monitor,2,b'CLAIM_OK'); finish(monitor,b'ISSUED\nCLAIM_BUSY\nCLAIM_OK\n'); counts('8|8|736')
    # A fresh owner and dedicated role make an authority rejection observable
    # independently of the earlier competition and its Q-lock contention.
    five=args('revocation','normal',str(uuid.uuid4())); five[5]='causal_revocation_login'; monitor=start(five)
    with owned_probe(monitor,'revocation'):
        line(monitor,0,b'ACTIVE'); counts('9|9|828')
        live_sql=f"SELECT (expires_at>clock_timestamp()+interval '30 seconds' AND (claim).grant_expires>clock_timestamp()+interval '30 seconds' AND (claim).policy_expires>clock_timestamp()+interval '30 seconds')::text FROM contour.causal_sessions WHERE tenant_id='{tenant}' AND runtime_id='{runtime}' AND epoch=9;"
        if execute(live_sql)!='true': raise AssertionError('revocation session lacks live lease')
        logs=bridge['run_process'](['docker','logs','--tail','200',container],timeout=10,limit=1048576)
        if logs.returncode: raise RuntimeError('fixture logs unavailable')
        if any(b'causal_revocation_login' in row and b'23514' in row for row in (logs.stdout+logs.stderr).splitlines()): raise AssertionError('authority rejection preceded trigger')
        assert_active(monitor)
        deadline=time.monotonic()+1
        revoke_until(revoker if revoker is not None else lambda remaining:revocation_attempt(bridge,container,tenant,runtime,remaining),deadline)
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('revocation deadline')
        line(monitor,1,b'STOPPED',remaining)
        if time.monotonic()>=deadline: raise AssertionError('revocation response exceeded permit bound')
        finish(monitor,b'ACTIVE\nSTOPPED\n')
        require_revocation_proof(execute,tenant,runtime)
        logs=bridge['run_process'](['docker','logs','--tail','200',container],timeout=10,limit=1048576)
        if logs.returncode: raise RuntimeError('fixture logs unavailable')
        log=logs.stdout+logs.stderr
        if not authority_rejection_observed(log): raise AssertionError('post-commit authority rejection not observed')
    # No claim is made that the earlier epoch case isolated epoch rejection from contention.
    print('LIMITATION: epoch closure may include lock contention',flush=True)
    counts('9|9|828')



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
        execute("CREATE ROLE causal_issuer_login LOGIN PASSWORD '"+password+"'; CREATE ROLE causal_rival_login LOGIN PASSWORD '"+password+"'; CREATE ROLE causal_revocation_login LOGIN PASSWORD '"+password+"'; CREATE ROLE causal_contention_login LOGIN PASSWORD '"+password+"'; GRANT contour_causal_issuer TO causal_issuer_login,causal_rival_login,causal_revocation_login,causal_contention_login; ALTER ROLE causal_rival_login SET log_statement='all'; ALTER ROLE causal_revocation_login SET log_statement='all'; ALTER ROLE causal_contention_login SET log_statement='all';")
        hba='local all all trust\nhostnossl all all all reject\nhostssl contour_fixture causal_issuer_login,causal_rival_login,causal_revocation_login,causal_contention_login all scram-sha-256\nhostssl all all all reject\n'
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
            groups=([BaseExceptionGroup('primary',[primary])] if primary is not None else [])+[BaseExceptionGroup('cleanup',failures)]
            raise BaseExceptionGroup('qualification',groups) from None
    print('PASS: checked issuer, private Node signer and generation controls; no wire or source attestation')

def failure_lines(error,phase='primary'):
    if isinstance(error,BaseExceptionGroup):
        if error.message in ('primary','cleanup'): phase=error.message
        result=[]
        for index,child in enumerate(error.exceptions):
            child_phase=phase
            if error.message in ('probe failure and cleanup failure','gate start and cleanup failure','qualification failure and cleanup failures') and index>0: child_phase='cleanup'
            if error.message=='cooperative cleanup': child_phase='cleanup'
            result.extend(failure_lines(child,child_phase))
        return result
    kind=type(error).__name__
    if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,79}',kind): kind='Exception'
    locations=[]; tb=error.__traceback__
    while tb is not None:
        name=Path(tb.tb_frame.f_code.co_filename).name
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',name): name='unknown'
        locations.append(f'{name}:{tb.tb_lineno}'); tb=tb.tb_next
    state=re.fullmatch(r'fixture command failed SQLSTATE ([0-9A-Z]{5})',str(error)) if type(error) is RuntimeError else None
    detail=(' SQLSTATE '+state.group(1)) if state else ''
    return [f'FAIL {phase} {kind} {loc}{detail}' for loc in (locations or ['unknown:0'])]


if __name__=='__main__':
    try: main()
    except BaseException as error:
        for line in failure_lines(error): print(line,file=sys.stderr)
        sys.exit(1)
