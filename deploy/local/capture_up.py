"""Start the optional, synthetic capture profile against the existing local database."""
import base64
import datetime
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import ssl
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
CAPTURE = STATE / 'capture'
COMPOSE = ['docker','compose','-f',str(ROOT/'deploy/local/compose.yaml')]
TENANT = '00000000-0000-4000-8000-000000000001'
COLLECTOR = '00000000-0000-4000-8000-000000000201'
SOURCE = '00000000-0000-4000-8000-000000000202'
EXPECTED_SOURCE = dict(source_id=SOURCE,project_id='00000000-0000-4000-8000-000000000002',
    service_id='00000000-0000-4000-8000-000000000003',environment_id='00000000-0000-4000-8000-000000000004',
    deployment_id='00000000-0000-4000-8000-000000000203',technique='gateway',parser_profiles=['http_json_v1'])


def run(command, timeout):
    result = subprocess.run(command,cwd=ROOT,capture_output=True,timeout=timeout)
    if result.returncode: raise RuntimeError('capture startup command failed')


def lease():
    envelope=json.loads((CAPTURE/'private/policy.json').read_text())
    payload=envelope['payload_base64url']
    policy=json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))
    expires=datetime.datetime.fromisoformat(policy['expires_at'].replace('Z','+00:00'))
    if expires <= datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=30):
        raise RuntimeError('synthetic policy expired or near expiry; renewal is not yet implemented')
    return envelope


class AuthorityDeadline(Exception):
    pass


def authority_ready(expected, deadline):
    # ITIMER_REAL bounds DNS, connect, TLS, HTTP headers and body together.
    # Startup owns the main thread; refuse an existing timer rather than alter it.
    previous=signal.getsignal(signal.SIGALRM)
    if signal.getitimer(signal.ITIMER_REAL) != (0.0,0.0):
        raise RuntimeError('authority deadline timer already in use')
    remaining=deadline-time.monotonic()
    if remaining <= 0: raise RuntimeError('authenticated capture authority not ready')
    def expired(_signum, _frame):
        raise AuthorityDeadline()
    signal.signal(signal.SIGALRM,expired)
    try:
        signal.setitimer(signal.ITIMER_REAL,remaining)
        return authority_exchange(expected,deadline)
    except AuthorityDeadline:
        raise RuntimeError('authenticated capture authority not ready') from None
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous)


def authority_exchange(expected, deadline):
    context=ssl.create_default_context(cafile=str(STATE/'ca.crt'))
    context.load_cert_chain(CAPTURE/'private/collector.crt',CAPTURE/'private/collector.key')
    while time.monotonic() < deadline:
        remaining=deadline-time.monotonic()
        challenge=secrets.token_hex(32)
        body=json.dumps(dict(wire_version=1,challenge=challenge,source_ids=[SOURCE]),separators=(',',':')).encode()
        connection=http.client.HTTPSConnection('localhost',9445,context=context,timeout=min(3,remaining))
        try:
            connection.request('POST','/v1/collector-authority',body=body,headers={'Content-Type':'application/json'})
            response=connection.getresponse(); data=bytearray()
            while True:
                if time.monotonic() >= deadline: raise RuntimeError('authority readiness deadline')
                chunk=response.read1(min(16384,8*1_048_576+1-len(data)))
                if not chunk: break
                data.extend(chunk)
                if len(data)>8*1_048_576: raise RuntimeError('authority response limit')
            value=json.loads(data)
            if (response.status==200 and value.get('wire_version')==1 and value.get('challenge')==challenge
                    and value.get('tenant_id')==TENANT and value.get('collector_id')==COLLECTOR
                    and value.get('signed_policy')==expected and value.get('sources')==[EXPECTED_SOURCE]):
                return
        except (OSError,ssl.SSLError,http.client.HTTPException,ValueError,TypeError):
            pass
        finally:
            connection.close()
        if time.monotonic() < deadline: time.sleep(min(.25,deadline-time.monotonic()))
    raise RuntimeError('authenticated capture authority not ready')


def running(service):
    result=subprocess.run(COMPOSE+['ps','--status','running','--quiet',service],cwd=ROOT,capture_output=True,timeout=5)
    return result.returncode==0 and bool(result.stdout.strip())


def main():
    os.umask(0o077)
    if os.getuid() == 0: raise RuntimeError('capture runtime must be non-root')
    os.environ['LOCAL_UID'] = str(os.getuid()); os.environ['LOCAL_GID'] = str(os.getgid())
    if not (STATE/'business.json').is_file(): raise RuntimeError('start local business stack first')
    # Existing state must pass its lease check and is never regenerated. On a
    # fresh profile, create short-lived authority only after the lengthy build.
    existing=CAPTURE.exists()
    if existing: lease()
    run(COMPOSE+['build','app'],1800)
    if not existing: run([sys.executable,str(ROOT/'deploy/local/capture_init.py')],60)
    expected=lease()
    run([sys.executable,str(ROOT/'deploy/local/capture_provision.py')],60)
    if lease() != expected: raise RuntimeError('synthetic policy changed during provisioning')
    run(COMPOSE+['--profile','capture','up','-d','--no-build','capture-ingress','capture-worker'],90)
    authority_ready(expected,time.monotonic()+20)
    # The same restricted worker config must connect and execute a scoped pending-ID query.
    run(COMPOSE+['--profile','capture','run','--rm','--no-deps','--entrypoint','/usr/local/bin/local_capture','capture-worker','check','/run/capture/worker.json'],15)
    if not all(running(service) for service in ['capture-ingress','capture-worker']):
        raise RuntimeError('capture service exited during readiness')
    if lease() != expected: raise RuntimeError('synthetic policy changed during readiness')
    print('Synthetic capture profile ready; policy has a short fixed lease.')

if __name__ == '__main__':
    try: main()
    except Exception:
        print('Capture startup failed; state retained. Synthetic policy renewal is not yet implemented.',file=sys.stderr)
        raise SystemExit(1)
