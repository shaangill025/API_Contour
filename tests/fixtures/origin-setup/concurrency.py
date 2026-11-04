"""One owned uncommitted observer transaction; no external database access."""
import selectors
import os
import subprocess
import time
import uuid


def probe(name, execute, observer_rollback_sql):
    from deploy.local import capture_profiles, provision
    profile = capture_profiles.ORIGIN_PILOT
    t,p,s,e,c,src,d = map(provision.sql_quote, (*provision.IDS, profile.capture.collector,
                                              profile.capture.source, profile.capture.deployment))
    target,instance,lifecycle,grant = map(provision.sql_quote, (
        '00000000-0000-4000-8000-000000000991', '00000000-0000-4000-8000-000000000992',
        '00000000-0000-4000-8000-000000000993', '00000000-0000-4000-8000-000000000994'))
    execute(f"BEGIN; INSERT INTO contour.deployments VALUES ({t},{target},{p},{s},{e}); INSERT INTO contour.workload_instances VALUES ({t},{p},{s},{e},{target},{instance}); COMMIT;")
    execute(f"BEGIN; SELECT set_config('apicontour.tenant_id',{t},true); SET LOCAL ROLE contour_admin; SELECT contour.enroll_origin({t},{lifecycle},{p},{s},{e},{target},{instance},'trusted_platform_v1',decode('{'cc'*32}','hex')); COMMIT;")
    if not observer_rollback_sql.rstrip().endswith('ROLLBACK;'):
        raise RuntimeError('expected owned observer rollback transaction')
    marker = 'origin_observer_held_' + uuid.uuid4().hex
    args = ['docker','exec','-i',name,'psql','-X','-qAt','-v','ON_ERROR_STOP=1',
            '-h','/var/run/postgresql','-U','postgres','-d','contour_local']
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, bufsize=0)
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        process.stdin.write((observer_rollback_sql.rstrip()[:-len('ROLLBACK;')] + '\n\\echo ' + marker + '\n').encode())
        process.stdin.flush()
        deadline = time.monotonic() + 15
        ready = False
        buffered = b''
        while time.monotonic() < deadline:
            events = selector.select(max(0, deadline-time.monotonic()))
            if not events:
                break
            chunk = os.read(process.stdout.fileno(),65536)
            if not chunk:
                break
            buffered += chunk
            if len(buffered)>65536:
                raise RuntimeError('owned observer barrier output exceeded bound')
            if marker.encode() in buffered.splitlines():
                ready = True
                break
        if not ready:
            raise RuntimeError('owned observer transaction did not reach barrier')
        invisible = execute(f'SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND source_id={src};') == '0'
        competing = subprocess.run(args, input=f"BEGIN; SELECT set_config('apicontour.tenant_id',{t},true); SET LOCAL ROLE contour_admin; SET LOCAL lock_timeout='200ms'; SELECT contour.lock_collector({t},{c}); COMMIT;",
                                   text=True,capture_output=True,timeout=10)
        serialized = competing.returncode != 0 and 'lock timeout' in competing.stderr
        attempted = subprocess.run(args, input=f"BEGIN; SELECT set_config('apicontour.tenant_id',{t},true); SET LOCAL ROLE contour_admin; SELECT contour.grant_origin_observer({t},{grant},{lifecycle},{src},{c},{p},{s},{e},{d}); COMMIT;",
                                   text=True,capture_output=True,timeout=10)
        denied = attempted.returncode != 0 and 'collector gate busy' in attempted.stderr
        output, errors = process.communicate(b'ROLLBACK;\n',timeout=10)
        if process.returncode:
            raise RuntimeError('owned observer rollback failed')
        unchanged = execute(f'SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND source_id={src};') == '0'
        no_grant = execute(f'SELECT count(*) FROM contour.origin_observer_grants WHERE tenant_id={t} AND grant_id={grant};') == '0'
        if not all((invisible, serialized, denied, unchanged, no_grant)):
            raise RuntimeError('owned observer concurrency assertion failed')
        return dict(uncommitted_source_invisible=invisible, competing_collector_serialized=serialized,
                    concurrent_grant_denied=denied, rollback_source_absent=unchanged, no_probe_grant=no_grant)
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill();process.wait(timeout=5)
        for stream in (process.stdin,process.stdout,process.stderr):
            if stream is not None:stream.close()
