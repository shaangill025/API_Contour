"""Verify owned local container startup failure and durable restart; never reset data."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
COMPOSE = ['docker', 'compose', '-f', str(ROOT / 'deploy/local/compose.yaml')]


def main():
    os.environ['LOCAL_UID'] = str(os.getuid())
    os.environ['LOCAL_GID'] = str(os.getgid())
    provision = runpy.run_path(str(ROOT / 'deploy/local/provision.py'))
    sql = provision['psql']
    context = ssl.create_default_context(cafile=str(STATE / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.ProxyHandler({}))

    def run(command, timeout=120):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout)
        assert result.returncode == 0, 'owned container command failed'
        return result.stdout

    def ready():
        with opener.open('https://localhost:9443/readyz', timeout=3) as response:
            return response.status == 200 and response.read(1025) == b'{"ready":true}'

    def wait_ready():
        until = time.monotonic() + 20
        while True:
            try:
                if ready(): return
            except (urllib.error.URLError, OSError, TimeoutError): pass
            assert time.monotonic() < until, 'application did not recover readiness'
            time.sleep(.1)

    def snapshot():
        return sql("SELECT json_build_array((SELECT count(*) FROM contour.public_declared_contracts),"
                   "(SELECT count(*) FROM contour.comparisons),(SELECT count(*) FROM contour.review_requests),"
                   "(SELECT count(*) FROM contour.review_decisions),"
                   "(SELECT coalesce(json_agg(current_event_id ORDER BY tenant_id,operation_id)::text,'[]') FROM contour.approval_heads));")

    def identities():
        return [hashlib.sha256((STATE / name).read_bytes()).digest() for name in
                ['accounts.json', 'subjects.json', 'approved-jwks.json', 'ca.crt', 'tls/server.key', 'database-password']]

    assert ready(), 'start the local stack before verifying it'
    before, identity = snapshot(), identities()
    assert json.loads(before)[0] > 0 and json.loads(before)[3] > 0, 'run the business workflow before testing durability'
    # Detached Compose success must never be treated as a ready application.
    with tempfile.TemporaryDirectory(prefix='contour-exit-check-') as folder:
        override = Path(folder) / 'exit.json'
        override.write_text(json.dumps({'services': {'app': {'entrypoint': ['/bin/false']}}}))
        up = runpy.run_path(str(ROOT / 'deploy/local/up.py'))
        original = up['main'].__globals__['run']

        def exiting_start(command, timeout=180):
            if command == COMPOSE + ['up', '-d', '--no-build', 'app']:
                command = COMPOSE + ['-f', str(override), 'up', '-d', '--no-build', 'app']
            return original(command, timeout)

        up['main'].__globals__['run'] = exiting_start
        try:
            try:
                up['main']()
            except RuntimeError as error:
                assert str(error) == 'application exited during startup', 'startup failed for an unrelated reason'
            else:
                raise AssertionError('startup reported readiness for an exited application')
        finally:
            run(COMPOSE + ['up', '-d', '--no-build', 'app'])
            wait_ready()
    assert snapshot() == before and identities() == identity, 'failed application start changed durable state'
    run(COMPOSE + ['restart', 'app', 'postgres', 'keycloak'])
    run([sys.executable, str(ROOT / 'deploy/local/up.py')], timeout=600)
    assert ready(), 'restarted application is not ready'
    assert snapshot() == before, 'restart changed immutable records or approval heads'
    assert identities() == identity, 'restart replaced local identity or credential material'
    print('Exited application rejected; container restart preserved imports, comparisons, decisions, approval heads and identities.')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Local stack check failed; data and credentials retained.', file=sys.stderr)
        if isinstance(error, AssertionError): print(str(error), file=sys.stderr)
        raise SystemExit(1)
