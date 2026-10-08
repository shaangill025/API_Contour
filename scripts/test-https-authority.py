"""Actual enrolled mTLS authority snapshots and shared database capacity."""
import contextlib
import datetime
from decimal import Decimal
import http.client
import json
import queue
import secrets
import socket
import subprocess
import threading
import time


def run_cases(container, execute, setup, server, request, context, directory):
    target = '/v1/collector-authority'
    item = '00000000-0000-0000-0000-000000000001'

    def payload(source):
        return dict(wire_version=1, challenge=secrets.token_hex(32), source_ids=[source])

    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, 'duplicate authority response field'
            result[key] = value
        return result

    def call(port, body, wanted=200, client='http-client', method='POST', headers=None, path=target, chunked=False):
        raw = json.dumps(body).encode() if isinstance(body, dict) else body
        expected_challenge = json.loads(raw)['challenge'] if wanted == 200 else None
        connection = http.client.HTTPSConnection('localhost', port, context=context(client), timeout=8)
        try:
            outgoing = (raw[index:index+4096] for index in range(0,len(raw),4096)) if chunked else raw
            connection.request(method, path, outgoing, headers or {'Content-Type':'application/json'}, encode_chunked=chunked)
            response = connection.getresponse()
            raw = response.read(8 * 1048576 + 1)
            assert len(raw) <= 8 * 1048576, 'authority response wire bound exceeded'
            assert response.status == wanted, 'authority HTTP status mismatch'
            result = json.loads(raw, object_pairs_hook=unique)
            if wanted == 200:
                assert response.getheader('Cache-Control') == 'no-store'
                assert set(result) == {'wire_version','challenge','tenant_id','collector_id','checked_at','signed_policy','sources'}
                assert result['wire_version'] == 1 and result['challenge'] == expected_challenge
            else:
                assert set(result) == {'code','message','request_id','retryable'}
                assert b'SYNTHETIC_SECRET' not in raw, 'authority error exposed request metadata'
            return result
        finally:
            connection.close()

    def scope(body):
        return "tenant_id='%s' AND collector_id='%s'" % (body['tenant_id'], body['collector_id'])

    def change(body, statement):
        execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); %s; COMMIT;" % (body['tenant_id'],body['tenant_id'],body['collector_id'],statement))

    first, _, source = setup('online_http', current=1, history=(1,2))
    second, _, second_source = setup('online_http_other', current=1, history=(1,), tenant='bbbbbbbb-0000-0000-0000-000000000000')
    with server(first, additional_identity=second) as port:
        before = Decimal(execute('SELECT extract(epoch FROM clock_timestamp());'))
        result = call(port, payload(source))
        after = Decimal(execute('SELECT extract(epoch FROM clock_timestamp());'))
        # Preserve variable-width fractions on Python 3.9 without rounding.
        assert result['checked_at'].endswith('Z')
        whole, separator, fraction = result['checked_at'][:-1].partition('.')
        seconds = int(datetime.datetime.fromisoformat(whole+'+00:00').timestamp())
        instant = Decimal(seconds) + (Decimal('0.'+fraction) if separator else Decimal(0))
        assert before <= instant <= after
        assert (result['tenant_id'], result['collector_id']) == (first['tenant_id'], first['collector_id'])
        signed = json.loads(bytes.fromhex(execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE %s AND revision=1;" % scope(first))))
        assert result['signed_policy'] == signed, 'signed policy fields changed in transport'
        assert result['sources'] == [dict(source_id=source, project_id=item, service_id=item,
            environment_id=item, deployment_id=item, technique='runtime', parser_profiles=['http_json_v1'])]
        pid = execute("SELECT pid FROM pg_stat_activity WHERE usename='contour_tls';")
        request(port, first)
        other = call(port, payload(second_source), client='http-other')
        assert other['tenant_id'] == second['tenant_id'] and other['collector_id'] == second['collector_id']
        assert execute("SELECT pid FROM pg_stat_activity WHERE usename='contour_tls';") == pid, 'mixed cross-tenant clean session not reused'
        call(port, payload(second_source), 403)
        unknown = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        call(port, payload(unknown), 403)
        call(port, dict(payload(source), source_ids=[source,unknown]), 403)
        call(port, payload(second_source), client='http-other')
        assert execute("SELECT pid FROM pg_stat_activity WHERE usename='contour_tls';") == pid, 'rejected refresh leaked context or lost clean reuse'
        change(first, "UPDATE contour.collector_authorization SET active_revision=2 WHERE %s" % scope(first))
        updated = call(port, payload(source))
        signed = json.loads(bytes.fromhex(execute("SELECT encode(signed_envelope,'hex') FROM contour.policy_revisions WHERE %s AND revision=2;" % scope(first))))
        assert updated['signed_policy'] == signed and updated['signed_policy'] != result['signed_policy']
        encoded = json.dumps(payload(source)).encode()
        call(port, encoded + b' ' * (32768 - len(encoded)))
        encoded = json.dumps(payload(source)).encode()
        call(port, encoded + b' ' * (32768 - len(encoded)), chunked=True)
        call(port, payload(source), 405, method='GET')
        call(port, payload(source), 404, path=target+'?scope=ignored')
        call(port, payload(source), 415, headers={'Content-Type':'application/json','Content-Encoding':'gzip'})
    with server(first) as port:
        call(port, payload(source), 403, client='http-other')
        for client in [None, 'http-untrusted']:
            try:
                call(port, payload(source), client=client)
            except (OSError, http.client.HTTPException):
                pass
            else:
                raise AssertionError('authority endpoint accepted untrusted TLS client')

    # An owned TCP sentinel proves malformed requests cannot consume a DB slot.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); listener.listen(8); listener.settimeout(0.15)
        with server(first, backend=listener.getsockname()[1]) as port:
            invalid = [dict(payload(source), tenant_id=first['tenant_id']),
                dict(payload(source), challenge='SYNTHETIC_SECRET'), dict(payload(source), wire_version=2),
                dict(payload(source), source_ids=[]), dict(payload(source), source_ids=[source,source]),
                dict(payload(source), source_ids=[source.upper()]),
                dict(payload(source), source_ids=['00000000-0000-0000-0001-%012x' % i for i in range(501)])]
            # Use a UUID that actually contains letters for uppercase rejection.
            invalid[-2]['source_ids'] = ['AAAAAAAA-0000-0000-0000-000000000001']
            raw = json.dumps(payload(source)).encode()
            invalid.extend([raw[:-1]+b',"challenge":"'+b'0'*64+b'"}', b'{'])
            for value in invalid:
                call(port, value, 400)
            call(port, raw+b' '*(32769-len(raw)), 413)
            call(port, raw+b' '*(32769-len(raw)), 413, chunked=True)
            try:
                accepted, _ = listener.accept()
            except socket.timeout:
                pass
            else:
                accepted.close()
                raise AssertionError('invalid authority request contacted database')

    for state in ['disabled','revoked','signed_disabled','expired','wrong_signer']:
        mutate = (lambda policy: policy.update(enabled=False)) if state=='signed_disabled' else None
        if state=='expired':
            mutate = lambda policy: policy.update(expires_at=(datetime.datetime.fromisoformat(policy['issued_at'].replace('Z','+00:00'))+datetime.timedelta(seconds=1)).isoformat().replace('+00:00','Z'))
        body, _, src = setup('wrong_signer' if state=='wrong_signer' else 'online_'+state, change=mutate, current=1, history=(1,))
        if state in ['disabled','revoked']:
            assignment = "enabled=false" + (",revoked_at=clock_timestamp()" if state=='revoked' else '')
            change(body, 'UPDATE contour.collector_authorization SET '+assignment+' WHERE '+scope(body))
            if state == 'revoked':
                assert execute('SELECT revoked_at IS NOT NULL FROM contour.collector_authorization WHERE '+scope(body)+';') == 't'
        with server(body) as port:
            call(port, payload(src), 403)

    # Exercise the maximum requested source/profile counts through real TLS.
    large, _, _ = setup('online_maximum', current=1, history=(1,))
    profiles = ['p%03d_' % i + 'x'*59 for i in range(128)]
    array = 'ARRAY['+','.join("'%s'" % value for value in profiles)+']'
    source_sql = "('00000000-0000-0000-0001-'||lpad(to_hex(n),12,'0'))::uuid"
    change(large, "INSERT INTO contour.sources SELECT '%s',%s,'%s','%s','%s','%s','%s',%s FROM generate_series(1,500) n; INSERT INTO contour.source_authorization SELECT '%s',%s,'%s','runtime',%s FROM generate_series(1,500) n" % (large['tenant_id'],source_sql,large['collector_id'],item,item,item,item,source_sql,large['tenant_id'],source_sql,large['collector_id'],array))
    wanted_sources = ['00000000-0000-0000-0001-%012x' % i for i in range(1,501)]
    with server(large) as port:
        maximum = call(port, dict(payload(wanted_sources[0]), source_ids=wanted_sources))
        assert {row['source_id'] for row in maximum['sources']} == set(wanted_sources)
        assert len(maximum['sources']) == 500 and all(row['parser_profiles'] == profiles for row in maximum['sources'])

    @contextlib.contextmanager
    def locked(body):
        holder = subprocess.Popen(['docker','exec','-i',container,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_fixture','-At'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        markers = queue.Queue()
        reader = threading.Thread(target=lambda: [markers.put(line.strip()) for line in holder.stdout],daemon=True)
        reader.start()
        try:
            holder.stdin.write("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s');\n\\echo HELD\n" % (body['tenant_id'],body['tenant_id'],body['collector_id']))
            holder.stdin.flush()
            until = time.monotonic()+5
            while markers.get(timeout=max(0.01,until-time.monotonic())) != 'HELD':
                pass
            yield
        finally:
            if holder.poll() is None:
                try:
                    holder.communicate(input='ROLLBACK;\n',timeout=3)
                except subprocess.TimeoutExpired:
                    holder.kill(); holder.wait(timeout=3)
            reader.join(2)
            for pipe in [holder.stdin,holder.stdout,holder.stderr]: pipe.close()

    def observe(sql, until):
        remaining = until-time.monotonic()
        assert remaining > 0, 'authority shared-capacity observation deadline'
        value = execute(sql, timeout=min(3,remaining))
        assert time.monotonic() <= until, 'authority shared-capacity observation deadline'
        return value

    body, _, src = setup('online_shared_capacity', current=1, history=(1,))
    sessions = "SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls';"
    waits = "SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls' AND wait_event='advisory';"
    streams = []
    with locked(body):
        with server(body,deadline=10000,database_deadline=25000,budget_check=True) as port:
            try:
                started = time.monotonic()
                tails = []
                for path, value in [('/v1/batches',body),(target,payload(src))]:
                    stream = context().wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=3),server_hostname='localhost')
                    streams.append(stream)
                    raw = json.dumps(value).encode()
                    stream.sendall(('POST '+path+' HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: '+str(len(raw))+'\r\n\r\n').encode()+raw[:-1])
                    tails.append(raw[-1:])
                assert time.monotonic()-started < 1, 'slow-body setup exceeded timing window'
                time.sleep(max(0,started+7-time.monotonic()))
                assert time.monotonic()-started < 8, 'slow-body release exceeded timing window'
                for stream, tail in zip(streams,tails): stream.sendall(tail)
                until = started+9
                while observe(waits,until) != '2': time.sleep(0.02)
                for stream in streams: stream.close()
                for result in [call(port,payload(src),503),request(port,body,503)]:
                    assert result['code']=='database_capacity_unavailable', 'refresh bypassed shared slots'
                assert int(observe(sessions,until)) <= 2
                until = time.monotonic()+28
                while observe(sessions,until) != '0': time.sleep(0.02)
                assert (directory/'budget-state').read_text() == '0|2', 'refresh extended original job deadline'
                assert call(port,payload(src),503)['code']=='database_capacity_unavailable'
                for table in ['ingestion_batches','ingestion_payloads']:
                    assert execute('SELECT count(*) FROM contour.'+table+' WHERE '+scope(body)+';') == '0'
            finally:
                for stream in streams: stream.close()
    print('Actual authority HTTPS scope/current-policy/500-source bounds, no-contact rejection and shared pool cancellation/quarantine passed',flush=True)
