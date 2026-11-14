"""Fixed human realm definition; identity creation is owned by the pilot."""
import re


def _realm(accounts):
    if (type(accounts) is not dict or set(accounts) != {'owner', 'viewer'}
            or any(type(value) is not str or not re.fullmatch('[A-Za-z0-9_-]{32,128}', value)
                   for value in accounts.values()) or accounts['owner'] == accounts['viewer']):
        raise ValueError('invalid human accounts')
    return {'realm': 'apicontour-mvp', 'enabled': True, 'sslRequired': 'all',
            'registrationAllowed': False, 'resetPasswordAllowed': False,
            'accessTokenLifespan': 300, 'ssoSessionIdleTimeout': 1800,
            'clients': [{'clientId': 'apicontour-mvp', 'enabled': True,
                         'protocol': 'openid-connect', 'publicClient': True,
                         'standardFlowEnabled': True, 'implicitFlowEnabled': False,
                         'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
                         'redirectUris': ['https://mvp.localhost:19443/auth/callback'],
                         'webOrigins': ['https://mvp.localhost:19443'],
                         'attributes': {'pkce.code.challenge.method': 'S256'}}],
            'users': [{'username': name, 'enabled': True, 'emailVerified': True,
                       'firstName': 'Local', 'lastName': name.title(),
                       'email': name + '@example.invalid', 'requiredActions': [],
                       'credentials': [{'type': 'password', 'value': accounts[name], 'temporary': False}]}
                      for name in ('owner', 'viewer')]}


def initialize():
    """Generate only fresh, private human identities using the owned pilot CA."""
    import json
    import os
    import secrets
    from deploy.local import origin21_managed_init, origin21_profile
    from deploy.pilot import origin_credentials

    origin21_profile.require_context(origin21_profile.HUMAN)
    base = origin21_profile.HUMAN.profile.state.parent
    origin_credentials._dir(base)
    human = base/'human'
    os.mkdir(human, 0o700)
    for name in ('idp', 'realm'):
        os.mkdir(human/name, 0o700)
    request = human/'request.cnf'
    origin_credentials._write(request, b'[req]\ndistinguished_name=dn\n[dn]\n')
    for name, hostname, folder in (('app', 'mvp.localhost', human),
                                    ('idp', 'idp.mvp.localhost', human/'idp')):
        key, cert = folder/(name+'.key'), folder/(name+'.crt')
        csr, extensions = human/(name+'.csr'), human/(name+'.ext')
        origin_credentials._write(extensions, ('basicConstraints=critical,CA:FALSE\n'
            'keyUsage=critical,digitalSignature,keyEncipherment\n'
            'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+hostname+'\n').encode('ascii'))
        run = origin21_managed_init._run_openssl
        run('req','-new','-newkey','rsa:2048','-nodes','-sha256','-config',request,
            '-subj','/CN='+hostname,'-keyout',key,'-out',csr)
        run('x509','-req','-in',csr,'-CA',base/'ca.crt','-CAkey',base/'ca.key',
            '-set_serial',str(secrets.randbits(127)+1),'-days','7','-sha256','-extfile',extensions,'-out',cert)
        for path in (key,cert):
            os.chmod(path,0o600)
            origin_credentials._file(path)
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
        if run('x509','-in',cert,'-pubkey','-noout') != run('pkey','-in',key,'-pubout'):
            raise ValueError('human certificate key mismatch')
        run('verify','-CAfile',base/'ca.crt','-purpose','sslserver',cert)
        extension=run('x509','-in',cert,'-noout','-ext','subjectAltName').decode('ascii').splitlines()
        if len(extension)!=2 or extension[1].strip()!='DNS:'+hostname: raise ValueError('human certificate SAN drift')
    accounts = {name: secrets.token_urlsafe(32) for name in ('owner','viewer')}
    origin_credentials._write(base/'accounts.json', (json.dumps(accounts,sort_keys=True)+'\n').encode())
    origin_credentials._write(human/'realm'/'apicontour-mvp-realm.json',
                              (json.dumps(_realm(accounts),sort_keys=True)+'\n').encode())
    # The host root remains 0700; the nonroot provider must read its bind mounts.
    for folder in (human/'idp', human/'realm'):
        for path in folder.iterdir(): os.chmod(path,0o644)
        os.chmod(folder,0o755)
    for folder in (human/'idp', human/'realm', human, base):
        fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
