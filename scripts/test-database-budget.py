"""Real restricted PostgreSQL sessions remain charged after HTTP cancellation."""
import contextlib
import http.client
import json
import queue
import socket
import subprocess
import threading
import time


def run_cases(container, execute, setup, server, request, context, scope, environment, directory):
    def observe(sql, until):
        remaining = until-time.monotonic()
        if remaining <= 0:
            raise AssertionError('database capacity observation deadline')
        value = execute(sql, timeout=min(3, remaining))
        if time.monotonic() > until:
            raise AssertionError('database capacity observation deadline')
        return value

    sessions = "SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls';"
    waits = "SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls' AND wait_event='advisory';"

    @contextlib.contextmanager
    def locked(body):
        holder = subprocess.Popen(['docker','exec','-i',container,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_fixture','-At'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        markers = queue.Queue()
        reader = threading.Thread(target=lambda: [markers.put(line.strip()) for line in holder.stdout], daemon=True)
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
                    holder.kill()
                    holder.wait(timeout=3)
            reader.join(2)
            for pipe in [holder.stdin,holder.stdout,holder.stderr]:
                pipe.close()

    def send(port, body):
        stream = context().wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=3),server_hostname='localhost')
        stream.settimeout(5)
        raw = json.dumps(body).encode()
        stream.sendall(b'POST /v1/batches HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: '+str(len(raw)).encode()+b'\r\n\r\n'+raw)
        return stream

    body, _, _ = setup('budget_cancellation')
    baseline = environment.get('CONTOUR_BUDGET_BASELINE_PROBE')
    streams = []
    with locked(body):
        with server(body,database_deadline=10000,executable=baseline,budget_check=not baseline) as port:
            try:
                streams = [send(port,body) for _ in range(2)]
                until = time.monotonic()+3
                while observe(waits,until) != '2':
                    time.sleep(0.02)
                for stream in streams:
                    if baseline and stream.recv(1) != b'':
                        raise AssertionError('original absolute HTTP deadline extended by pool')
                    stream.close()
                streams = [send(port,body) for _ in range(2)]
                until = time.monotonic()+3
                if baseline:
                    while int(observe(sessions,until)) <= 2:
                        time.sleep(0.02)
                    print('Historical two-slot HTTP service observed remote session count: '+observe(sessions,until),flush=True)
                    raise AssertionError('RED: historical HTTP cancellation exceeded two potentially live database sessions')
                for stream in streams:
                    response = http.client.HTTPResponse(stream)
                    response.begin()
                    error = json.loads(response.read(4096))
                    if response.status != 503 or error['code'] != 'database_capacity_unavailable':
                        raise AssertionError('quarantined slot admitted replacement database work')
                if int(observe(sessions,until)) > 2:
                    raise AssertionError('fixed database budget exceeded two sessions')
                until = time.monotonic()+12
                while observe(sessions,until) != '0':
                    time.sleep(0.02)
                if (directory/'budget-state').read_text() != '0|2':
                    raise AssertionError('receiver drop did not retain jobs only within original HTTP budget')
                error = request(port,body,503)
                if error['code'] != 'database_capacity_unavailable' or observe(sessions,until) != '0':
                    raise AssertionError('timer or eventual remote cleanup recycled uncertain slot')
                pairs = execute('SELECT (SELECT count(*) FROM contour.ingestion_batches WHERE %s),(SELECT count(*) FROM contour.ingestion_payloads WHERE %s);' % (scope(body),scope(body)))
                if pairs != '0|0':
                    raise AssertionError('precommit cancelled admission retained inbox pair')
            finally:
                for stream in streams:
                    stream.close()
    print('Database N=2 two-wave cancellation, permanent quarantine and zero inbox pairs passed',flush=True)

    first, _, _ = setup('budget_healthy_first')
    second, _, _ = setup('budget_healthy_second',tenant='bbbbbbbb-0000-0000-0000-000000000000')
    with server(first,additional_identity=second) as port:
        accepted = request(port,first)
        pid = execute("SELECT pid FROM pg_stat_activity WHERE usename='contour_tls';")
        repeated = request(port,first)
        if accepted['status'] != 'accepted' or repeated['status'] != 'duplicate':
            raise AssertionError('healthy pooled submission changed receipt outcomes')
        if execute("SELECT pid FROM pg_stat_activity WHERE usename='contour_tls';") != pid:
            raise AssertionError('clean transaction did not reuse owned database session')
        request(port,second,client='http-other')
        if execute("SELECT pid FROM pg_stat_activity WHERE usename='contour_tls';") != pid:
            raise AssertionError('cross-tenant submission did not reuse clean owned session')
    for drop_serving in [False,True]:
        with server(second,drop_serving=drop_serving,database_deadline=3000) as port:
            request(port,second)
    print('Healthy reuse and explicit/future-drop sealed shutdown passed with runtime alive',flush=True)

    # TLS refusal after one TCP connection is uncertain, not a fallback signal.
    listener = socket.socket()
    listener.bind(('127.0.0.1',0))
    listener.listen(4)
    listener.settimeout(0.2)
    failed_port = listener.getsockname()[1]
    stop = threading.Event()
    attempts = []
    def refuse():
        while not stop.is_set():
            try:
                stream, _ = listener.accept()
            except socket.timeout:
                continue
            with stream:
                stream.settimeout(2)
                with stream.makefile('rb') as incoming:
                    attempts.append(incoming.read(8))
                stream.sendall(b'N')
    reader = threading.Thread(target=refuse,daemon=True)
    reader.start()
    try:
        with server(second,backend=failed_port) as port:
            request(port,second,503)
            request(port,second,503)
            error = request(port,second,503)
            if error['code'] != 'database_capacity_unavailable' or len(attempts) != 2:
                raise AssertionError('failed connect replaced uncertain capacity or retried an address')
            if any(packet != b'\x00\x00\x00\x08\x04\xd2\x16/' for packet in attempts):
                raise AssertionError('single-address probe sent credentials before TLS')
    finally:
        stop.set()
        reader.join(3)
        listener.close()
        if reader.is_alive():
            raise AssertionError('owned TLS refusal listener did not stop')
    print('Exactly one TCP/TLS attempt per charged slot; no credentials or fallback',flush=True)
