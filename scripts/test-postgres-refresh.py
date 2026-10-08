"""Required restricted-login TLS read cases using the existing owned fixture."""
import base64
import contextlib
import datetime
import json
import queue
import subprocess
import threading
import time


def run_cases(container, execute, setup, probe, port, directory, environment):
    counter = 0
    def observe(sql, until):
        remaining = until-time.monotonic()
        if remaining <= 0:
            raise AssertionError('refresh observation deadline')
        value = execute(sql, timeout=min(3,remaining))
        if time.monotonic() > until:
            raise AssertionError('refresh observation deadline')
        return value

    def scoped(body, sql):
        execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); %s COMMIT;" % (body['tenant_id'],body['tenant_id'],body['collector_id'],sql))

    def where(body, qualifier=''):
        prefix = qualifier+'.' if qualifier else ''
        return "%stenant_id='%s' AND %scollector_id='%s'" % (prefix,body['tenant_id'],prefix,body['collector_id'])

    def check(body, wanted='Ok', source_ids=None, identity=None, configured=5000, budget=None, preflight=False, abort=None):
        nonlocal counter
        counter += 1
        path = directory/('refresh-%d.ids' % counter)
        ids = source_ids if source_ids is not None else [body['records'][0]['source_id']]
        path.write_text(''.join(source+'\n' for source in ids))
        expected = identity or [body['tenant_id'],body['collector_id']]
        child_environment = dict(environment)
        if preflight:
            child_environment.pop('CONTOUR_FIXTURE_PASSWORD',None)
        arguments = [probe,'0' if preflight else str(port),str(directory/('missing-ca' if preflight else 'ca.crt')),
            str(directory/('missing-key' if preflight else 'signer.raw')),str(path),wanted,*expected,
            str(configured),str(budget if budget is not None else configured)]
        process = subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=child_environment)
        markers = queue.Queue()
        reader = threading.Thread(target=lambda: markers.put(process.stdout.readline()),daemon=True)
        reader.start()
        try:
            until = time.monotonic()+configured/1000+4
            while True:
                if abort is not None and abort.is_set():
                    raise AssertionError('owned refresh check cancelled')
                remaining = until-time.monotonic()
                if remaining <= 0:
                    raise AssertionError('refresh probe marker deadline')
                try:
                    actual = markers.get(timeout=min(0.1,remaining)).strip()
                    break
                except queue.Empty:
                    continue
            marker = 'Invalidated' if wanted == 'Cancel' else wanted
            if actual != marker:
                _, errors = process.communicate(input='\n',timeout=3)
                raise AssertionError('refresh marker mismatch: expected %s, got %s; %s' % (marker,actual or 'EOF',errors.strip()))
            if not preflight:
                until = time.monotonic()+configured/1000+2
                while observe("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls';",until) != '0':
                    if abort is not None and abort.is_set():
                        raise AssertionError('owned refresh cleanup cancelled')
                    time.sleep(min(0.02,max(0,until-time.monotonic())))
                if process.poll() is not None:
                    raise AssertionError('refresh runtime exited before backend cleanup proof')
            output, errors = process.communicate(input=None if preflight else '\n',timeout=3)
            if process.returncode or output or errors:
                raise AssertionError('refresh probe failed or leaked nonstatic diagnostics')
            if wanted == 'Ok':
                lines = path.with_suffix('.result').read_text().splitlines()
                revision, checked, tenant, collector = lines[0].split('|')
                row = execute("SELECT a.active_revision::numeric(20,0)::text,encode(p.signed_envelope,'hex') FROM contour.collector_authorization a JOIN contour.policy_revisions p ON p.tenant_id=a.tenant_id AND p.collector_id=a.collector_id AND p.revision=a.active_revision WHERE %s;" % where(body,'a'))
                stored_revision, stored_envelope = row.split('|')
                if revision != stored_revision or [tenant,collector] != expected or path.with_suffix('.envelope').read_bytes().hex() != stored_envelope:
                    raise AssertionError('refresh changed signed envelope or current scoped revision')
                now = int(execute('SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;'))
                if not 0 <= now-int(checked) <= 5_000_000:
                    raise AssertionError('refresh DB checked time was not a fresh unchanged snapshot')
                expected_rows = execute("SELECT s.source_id::text,s.tenant_id::text,s.collector_id::text,s.project_id::text,s.service_id::text,s.environment_id::text,s.deployment_id::text,a.technique,array_to_string(a.parser_profiles,',') FROM contour.sources s JOIN contour.source_authorization a USING(tenant_id,source_id,collector_id) WHERE s.tenant_id='%s' AND s.collector_id='%s' AND s.source_id IN (%s) ORDER BY s.source_id;" % (*expected,','.join("'%s'" % source for source in ids))).splitlines()
                if lines[1:] != expected_rows or len(lines)-1 != len(ids):
                    raise AssertionError('refresh trusted caller workloads or returned incomplete bindings')
            elif path.with_suffix('.result').exists() or path.with_suffix('.envelope').exists():
                raise AssertionError('failed refresh exported partial authority')
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            reader.join(2)
            for pipe in [process.stdin,process.stdout,process.stderr]:
                pipe.close()

    body, _, _ = setup('refresh_current',current=3)
    check(body)
    for ids in [[],[body['collector_id']]*2,[body['collector_id']]*501,['AAAAAAAA-0000-0000-0000-000000000000']]:
        check(body,'Source',source_ids=ids,preflight=True)
    check(body,'Identity',identity=['SYNTHETIC_SECRET',body['collector_id']],preflight=True)
    unknown = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    check(body,'Missing',identity=[body['tenant_id'],unknown])
    check(body,'Source',source_ids=[unknown])
    check(body,'Source',source_ids=[body['collector_id'],unknown])
    other, _, _ = setup('refresh_other_collector')
    foreign, _, _ = setup('refresh_foreign_tenant',tenant='bbbbbbbb-0000-0000-0000-000000000000')
    for candidate in [other,foreign]:
        check(body,'Source',source_ids=[candidate['collector_id']])
    for state, assignment, wanted in [('disabled','enabled=false','Disabled'),('revoked','enabled=false,revoked_at=clock_timestamp()','Revoked')]:
        candidate, _, _ = setup('refresh_'+state)
        scoped(candidate,'UPDATE contour.collector_authorization SET %s WHERE %s;' % (assignment,where(candidate)))
        check(candidate,wanted)
    signed_disabled, _, _ = setup('refresh_signed_disabled',lambda policy: policy.update(enabled=False))
    check(signed_disabled,'Admission')
    expired, _, _ = setup('refresh_expired',lambda policy: policy.update(expires_at=(datetime.datetime.fromisoformat(policy['issued_at'].replace('Z','+00:00'))+datetime.timedelta(seconds=29)).isoformat().replace('+00:00','Z')))
    check(expired,'Policy')
    wrong, _, _ = setup('wrong_signer')
    check(wrong,'Policy')
    maximum, _, _ = setup('refresh_max_revision',current=18446744073709551615,history=(18446744073709551615,))
    check(maximum)
    profiles, _, _ = setup('refresh_profiles128')
    scoped(profiles,"UPDATE contour.source_authorization SET parser_profiles=ARRAY[%s] WHERE %s;" % (','.join("'profile_%03d'" % number for number in range(128)),where(profiles)))
    check(profiles)
    print('Restricted TLS refresh current/envelope/binding/scope/state/signature/profile bounds and preconnect rejection passed',flush=True)

    @contextlib.contextmanager
    def holder(body, table=False, update=''):
        process = subprocess.Popen(['docker','exec','-i',container,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_fixture','-At'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        markers = queue.Queue()
        reader = threading.Thread(target=lambda: [markers.put(line.strip()) for line in process.stdout],daemon=True)
        reader.start()
        try:
            statement = 'LOCK TABLE contour.source_authorization IN ACCESS EXCLUSIVE MODE;' if table else "SELECT contour.lock_collector('%s','%s');" % (body['tenant_id'],body['collector_id'])
            process.stdin.write("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); %s %s\n\\echo HELD\n" % (body['tenant_id'],statement,update))
            process.stdin.flush()
            until = time.monotonic()+5
            while markers.get(timeout=max(0.01,until-time.monotonic())) != 'HELD':
                pass
            yield process
        finally:
            if process.poll() is None:
                try:
                    process.communicate(input='ROLLBACK;\n',timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            reader.join(2)
            for pipe in [process.stdin,process.stdout,process.stderr]:
                pipe.close()

    def blocked(body, wanted, table=False, update='', expiry=None, budget=700):
        outcomes = queue.Queue()
        worker = None
        abort = threading.Event()
        configured = 25000 if expiry else 5000
        try:
            with holder(body,table,update) as held:
                def run():
                    try:
                        check(body,wanted,configured=configured,budget=configured if expiry or update else budget,abort=abort)
                        outcomes.put(None)
                    except Exception as error:
                        outcomes.put(error)
                worker = threading.Thread(target=run,daemon=True)
                worker.start()
                until = time.monotonic()+5
                wait = 'relation' if table else 'advisory'
                while observe("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls' AND wait_event='%s';" % wait,until) != '1':
                    if not outcomes.empty():
                        raise AssertionError('refresh did not reach intended DB lock phase')
                    time.sleep(0.01)
                if expiry:
                    until = time.monotonic()+20
                    while int(observe('SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;',until)) < expiry:
                        time.sleep(min(0.05,max(0,until-time.monotonic())))
                if update or expiry:
                    held.stdin.write('COMMIT;\n')
                    held.stdin.flush()
                result = outcomes.get(timeout=configured/1000+5)
                if result is not None:
                    raise result
        finally:
            abort.set()
            if worker is not None:
                worker.join(12)
                if worker.is_alive():
                    raise AssertionError('owned refresh worker did not finish')

    for mode in ['Deadline','Cancel']:
        candidate, _, _ = setup('refresh_lock_'+mode)
        blocked(candidate,mode,budget=2500 if mode=='Cancel' else 700)
    changed, _, _ = setup('refresh_serialized_update',current=2,history=(1,3))
    update = "UPDATE contour.collector_authorization SET active_revision=3 WHERE %s; UPDATE contour.source_authorization SET parser_profiles=ARRAY['http_json_v1','updated_profile'] WHERE %s;" % (where(changed),where(changed))
    blocked(changed,'Ok',update=update)
    slow, _, _ = setup('refresh_expiry_after_sources',lambda policy: policy.update(expires_at=(datetime.datetime.fromisoformat(policy['issued_at'].replace('Z','+00:00'))+datetime.timedelta(seconds=45)).isoformat().replace('+00:00','Z')))
    encoded = execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE %s AND revision=2;" % where(slow))
    envelope = json.loads(bytes.fromhex(encoded))
    payload = envelope['payload_base64url']
    policy = json.loads(base64.urlsafe_b64decode(payload+'='*((-len(payload))%4)))
    instant = datetime.datetime.fromisoformat(policy['expires_at'].replace('Z','+00:00'))
    delta = instant-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
    expiry = (delta.days*86400+delta.seconds)*1000000+delta.microseconds
    blocked(slow,'Admission',table=True,expiry=expiry)
    print('Refresh original-deadline/cancel invalidation, runtime-held cleanup, serialized revision/profile update and final fresh-lease rejection passed',flush=True)
