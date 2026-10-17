"""Initialize only a fresh, ignored local MVP directory; never overwrite credentials."""
import json
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'


def main():
    os.umask(0o077)
    STATE.mkdir(mode=0o700)  # Existing state is an error, never an implicit reset.
    tls = STATE / 'tls'
    realm = STATE / 'realm'
    tls.mkdir(); realm.mkdir()
    request = STATE / 'request.cnf'
    request.write_text('[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
    def openssl(*args):
        result = subprocess.run(['openssl', *map(str, args)], capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('local certificate generation failed; partial state retained')
    openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '30', '-sha256',
            '-config', request, '-extensions', 'ca', '-subj', '/CN=APIContour local development CA',
            '-keyout', STATE / 'ca.key', '-out', STATE / 'ca.crt')
    openssl('req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-config', request,
            '-subj', '/CN=localhost', '-keyout', tls / 'server.key', '-out', STATE / 'server.csr')
    extensions = STATE / 'extensions.cnf'
    extensions.write_text('subjectAltName=DNS:localhost,DNS:keycloak,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
    openssl('x509', '-req', '-in', STATE / 'server.csr', '-CA', STATE / 'ca.crt',
            '-CAkey', STATE / 'ca.key', '-CAcreateserial', '-days', '30', '-sha256',
            '-extfile', extensions, '-out', tls / 'server.crt')
    accounts = {name: secrets.token_urlsafe(24) for name in ['owner', 'viewer']}
    # This realm is local-only. Roles here never grant application database authority.
    data = {'realm': 'apicontour-local', 'enabled': True, 'sslRequired': 'all',
            'registrationAllowed': False, 'resetPasswordAllowed': False,
            'accessTokenLifespan': 300, 'ssoSessionIdleTimeout': 1800,
            'clients': [{'clientId': 'apicontour-local', 'enabled': True,
                         'protocol': 'openid-connect', 'publicClient': True,
                         'standardFlowEnabled': True, 'implicitFlowEnabled': False,
                         'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
                         'redirectUris': ['https://localhost:9443/auth/callback'],
                         'webOrigins': ['https://localhost:9443'],
                         'attributes': {'pkce.code.challenge.method': 'S256'}}],
            'users': [{'username': name, 'enabled': True, 'emailVerified': True,
                       'firstName': 'Local', 'lastName': name.title(),
                       'email': name + '@example.invalid', 'requiredActions': [],
                       'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
                      for name, password in accounts.items()]}
    (realm / 'apicontour-local-realm.json').write_text(json.dumps(data, indent=2) + '\n')
    (STATE / 'accounts.json').write_text(json.dumps(accounts, indent=2) + '\n')
    # Keycloak runs as an unprivileged container user. Only its read-only mounted
    # subdirectories are traversable/readable; the host state parent stays 0700.
    for folder in [tls, realm]:
        folder.chmod(0o755)
        for path in folder.iterdir(): path.chmod(0o644)
    print('Local HTTPS certificates and synthetic accounts initialized in .local-mvp; no system trust changed.')


if __name__ == '__main__':
    main()
