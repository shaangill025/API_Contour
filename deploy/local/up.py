"""Start owned local infrastructure; retain all volumes and credentials."""
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
COMPOSE = ['docker','compose','-f',str(ROOT / 'deploy/local/compose.yaml')]
ISSUER = 'https://localhost:8444/realms/apicontour-local'

def run(command, timeout=180):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout)
    if result.returncode: raise RuntimeError('local startup command failed')

def main():
    os.umask(0o077)
    os.environ['LOCAL_UID'] = str(os.getuid())
    os.environ['LOCAL_GID'] = str(os.getgid())
    if os.getuid() == 0: raise RuntimeError('local application must run as a non-root user')
    if not STATE.exists(): run([sys.executable, str(ROOT / 'deploy/local/init.py')], 60)
    # Missing initialization files may indicate lost credentials; never regenerate them.
    for file in ['accounts.json','ca.crt','tls/server.crt','tls/server.key',
                 'postgres/admin-password','postgres/pg_hba.conf','postgres/pgpass','database-password']:
        if not (STATE / file).is_file(): raise RuntimeError('local state incomplete')
    run(COMPOSE + ['up','-d','--pull','never','keycloak','postgres'], 90)
    context = ssl.create_default_context(cafile=str(STATE / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.ProxyHandler({}))
    until = time.monotonic() + 90
    while True:
        try:
            with opener.open(ISSUER + '/.well-known/openid-configuration', timeout=3) as response:
                if response.status == 200: break
        except (urllib.error.URLError, TimeoutError, OSError): pass
        if time.monotonic() >= until: raise RuntimeError('identity provider readiness deadline')
        time.sleep(.5)
    run([sys.executable, str(ROOT / 'deploy/local/check_oidc.py')])
    until = time.monotonic() + 60
    while True:
        ready = subprocess.run(COMPOSE + ['exec','-T','-u','postgres','postgres','pg_isready','-U','postgres','-d','contour_local'], capture_output=True, timeout=5)
        if ready.returncode == 0: break
        if time.monotonic() >= until: raise RuntimeError('database readiness deadline')
        time.sleep(.5)
    run([sys.executable, str(ROOT / 'deploy/local/provision.py')])
    config = {'issuer': ISSUER, 'authorization_endpoint': ISSUER + '/protocol/openid-connect/auth',
              'token_endpoint': ISSUER + '/protocol/openid-connect/token', 'client_id': 'apicontour-local',
              'callback': 'https://localhost:9443/auth/callback', 'tls_certificate': str(STATE / 'tls/server.crt'),
              'tls_private_key': str(STATE / 'tls/server.key'), 'provider_ca': str(STATE / 'ca.crt'),
              'jwks': str(STATE / 'approved-jwks.json')}
    path = STATE / 'platform.json'
    if path.exists() and json.loads(path.read_text()) != config: raise RuntimeError('platform configuration drift')
    if not path.exists(): path.write_text(json.dumps(config, indent=2) + '\n')
    container_config = dict(config, transport='docker', tls_certificate='/run/config/server.crt',
                            tls_private_key='/run/config/server.key', provider_ca='/run/config/ca.crt',
                            jwks='/run/config/jwks.json')
    business = json.loads((STATE / 'business.json').read_text())
    container_business = dict(business, database_host='postgres', database_port=5432,
                              database_password_file='/run/config/database-password',
                              database_ca_file='/run/config/ca.crt')
    for name, value in [('container-platform.json', container_config), ('container-business.json', container_business)]:
        target = STATE / name
        if target.exists() and json.loads(target.read_text()) != value: raise RuntimeError('container configuration drift')
        if not target.exists(): target.write_text(json.dumps(value, indent=2) + '\n')
    run(COMPOSE + ['build', 'app'], 1800)
    run(COMPOSE + ['up', '-d', '--no-build', 'app'], 90)
    # A detached start can succeed even when the application immediately exits.
    # Check its state before and after the verified HTTPS response.
    def app_running():
        result = subprocess.run(COMPOSE + ['ps', '--status', 'running', '--quiet', 'app'],
                                cwd=ROOT, capture_output=True, timeout=5)
        if result.returncode: raise RuntimeError('application status unavailable')
        return bool(result.stdout.strip())
    until = time.monotonic() + 60
    while True:
        if not app_running(): raise RuntimeError('application exited during startup')
        try:
            with opener.open('https://localhost:9443/readyz', timeout=3) as response:
                if (response.url == 'https://localhost:9443/readyz' and response.status == 200
                        and response.read(1025) == b'{"ready":true}'):
                    if not app_running(): raise RuntimeError('application exited during startup')
                    break
        except (urllib.error.URLError, TimeoutError, OSError): pass
        if time.monotonic() >= until: raise RuntimeError('application readiness deadline')
        time.sleep(.5)
    print('Local application ready at https://localhost:9443; existing state was retained.')

if __name__ == '__main__':
    try: main()
    except Exception:
        print('Local startup failed; existing state was retained. Check local services and configuration.', file=sys.stderr)
        raise SystemExit(1)
