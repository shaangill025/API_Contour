"""Exercise the local provider only. Never follow a redirect or print credentials."""
import base64
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
ORIGIN = 'https://localhost:8444'
ISSUER = ORIGIN + '/realms/apicontour-local'
CLIENT = 'apicontour-local'
CALLBACK = 'https://localhost:9443/auth/callback'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.actions = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form' and attrs.get('id') == 'kc-form-login':
            self.actions.append(attrs.get('action', ''))


def _settings(selected):
    if selected is None:
        return STATE, ORIGIN, ISSUER, CLIENT, CALLBACK
    from deploy.local import origin21_profile
    if selected is not origin21_profile.HUMAN: raise ValueError('unsupported OIDC profile')
    origin = 'https://idp.mvp.localhost:18444'
    return (selected.profile.state.parent, origin, origin + '/realms/apicontour-mvp',
            'apicontour-mvp', 'https://mvp.localhost:19443/auth/callback')



def _private_approved(path, value):
    from deploy.pilot import origin_credentials
    if os.path.lexists(path):
        if json.loads(origin_credentials._file(path, 65536)) != value:
            raise ValueError('provider identity material changed')
        return
    origin_credentials._write(path, (json.dumps(value, indent=2) + '\n').encode())


def _artifact_snapshot(path):
    import stat
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or
            not before.st_mode & 0o111 or not 0<before.st_size<=256*1024*1024):
            raise ValueError('unsafe verifier artifact')
        digest=hashlib.sha256()
        while True:
            chunk=os.read(fd,1024*1024)
            if not chunk: break
            digest.update(chunk)
        after=os.fstat(fd)
        identity=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        if identity(before)!=identity(after): raise ValueError('verifier artifact changed while reading')
        return identity(before),digest.hexdigest()
    finally:
        os.close(fd)


def _check_human_verifier(record):
    path,target,source,identity,digest,source_digest=record
    if (not path.is_absolute() or not target.is_absolute() or path.resolve(strict=True)!=path or
        target.resolve(strict=True)!=target or target not in path.parents or
        source.resolve(strict=True)!=source or hashlib.sha256(source.read_bytes()).hexdigest()!=source_digest or
        _artifact_snapshot(path)!=(identity,digest)):
        raise ValueError('human verifier artifact changed')
    return path


def _build_human_verifier(target):
    target=Path(target)
    if not target.is_absolute() or target.resolve(strict=True)!=target: raise ValueError('invalid private verifier target')
    source=ROOT/'crates/contour-auth/examples/verify_local.rs'
    manifest=ROOT/'crates/contour-auth/Cargo.toml'
    if source.resolve(strict=True)!=source or manifest.resolve(strict=True)!=manifest: raise ValueError('invalid verifier source')
    source_digest=hashlib.sha256(source.read_bytes()).hexdigest()
    env={key:value for key,value in os.environ.items() if not (key.startswith('CARGO_BUILD_') or key.startswith('CARGO_TARGET_') or key in ('CARGO_ENCODED_RUSTFLAGS','RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER'))}
    env.update(CARGO_TARGET_DIR=str(target),AWS_LC_SYS_USE_SYSTEM='0')
    metadata=subprocess.run(['cargo','metadata','--format-version','1','--no-deps','--offline','--locked'],cwd=ROOT,env=env,capture_output=True,text=True,timeout=30)
    if metadata.returncode or len(metadata.stdout)>16*1024*1024: raise ValueError('verifier metadata unavailable')
    packages=json.loads(metadata.stdout).get('packages')
    if type(packages) is not list: raise ValueError('invalid verifier metadata')
    matches=[item for item in packages if type(item) is dict and item.get('name')=='contour-auth' and item.get('manifest_path')==str(manifest)]
    if len(matches)!=1 or not isinstance(matches[0].get('id'),str): raise ValueError('verifier package mismatch')
    package=matches[0]
    targets=package.get('targets')
    if type(targets) is not list or len([item for item in targets if type(item) is dict and item.get('name')=='verify_local' and item.get('kind')==['example'] and item.get('src_path')==str(source)])!=1:
        raise ValueError('verifier example mismatch')
    result=subprocess.run(['cargo','build','-p','contour-auth','--example','verify_local','--locked','--offline',
                           '--target-dir',str(target),'--message-format=json'],cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
    if result.returncode or len(result.stdout)>32*1024*1024: raise ValueError('human verifier build failed')
    found=[]
    for line in result.stdout.splitlines():
        try: value=json.loads(line)
        except ValueError: raise ValueError('invalid verifier build output') from None
        if type(value) is not dict or value.get('reason')!='compiler-artifact': continue
        item=value.get('target') or {}
        if value.get('package_id')==package['id'] and item.get('name')=='verify_local':
            if (item.get('kind')!=['example'] or item.get('src_path')!=str(source) or value.get('fresh') is not False or
                type(value.get('executable')) is not str): raise ValueError('verifier artifact mismatch')
            found.append(Path(value['executable']))
    if len(found)!=1: raise ValueError('verifier artifact missing or ambiguous')
    path=found[0]
    if not path.is_absolute() or target not in path.parents or path.resolve(strict=True)!=path: raise ValueError('verifier artifact outside private target')
    identity,digest=_artifact_snapshot(path)
    return (path,target,source,identity,digest,source_digest)

def main(*, selected=None):
    if selected is not None and not __debug__: raise RuntimeError('human OIDC requires Python assertions')
    if selected is None: return _run(selected,None)
    from deploy.local import origin21_profile
    from deploy.pilot import origin_credentials
    origin21_profile.require_context(selected)
    state, _, _, _, _ = _settings(selected)
    origin_credentials._dir(state)
    with tempfile.TemporaryDirectory(prefix='oidc-target-',dir=state) as folder:
        return _run(selected,Path(folder).resolve())


def _run(selected, target):
    STATE, ORIGIN, ISSUER, CLIENT, CALLBACK = _settings(selected)
    os.umask(0o077)
    if selected is None:
        build_env = dict(os.environ, AWS_LC_SYS_USE_SYSTEM='0')
        build = subprocess.run(['cargo', 'build', '-p', 'contour-auth', '--example', 'verify_local',
                                '--locked', '--offline'], cwd=ROOT, env=build_env,
                               capture_output=True, timeout=180)
        assert build.returncode == 0, 'current-source local verifier build failed'
        verifier_record=None
    else:
        verifier_record=_build_human_verifier(target)
    context = ssl.create_default_context(cafile=STATE / 'ca.crt')
    if selected is None:
        accounts = json.loads((STATE / 'accounts.json').read_text())
    else:
        from deploy.pilot import origin_credentials
        accounts = json.loads(origin_credentials._file(STATE / 'accounts.json', 16384))
    def client():
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirect(),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.ProxyHandler({}))

    def request(opener, url, form=None):
        parsed = urllib.parse.urlsplit(url)
        assert (parsed.scheme, parsed.netloc) == ('https', urllib.parse.urlsplit(ORIGIN).netloc), 'nonlocal destination refused'
        req = urllib.request.Request(url, data=None if form is None else urllib.parse.urlencode(form).encode())
        try: response = opener.open(req, timeout=5)
        except urllib.error.HTTPError as error: response = error
        with response:
            body = response.read(1_048_577)
            assert len(body) <= 1_048_576, 'provider response exceeded bound'
            return response.status, response.headers, body

    browser = client()
    until = time.monotonic() + 120
    while True:
        try:
            status, _, body = request(browser, ISSUER + '/.well-known/openid-configuration')
            if status == 200: break
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        assert time.monotonic() < until, 'local provider readiness timed out'
        time.sleep(.25)
    metadata = json.loads(body)
    assert metadata['issuer'] == ISSUER
    auth = ISSUER + '/protocol/openid-connect/auth'
    token_endpoint = ISSUER + '/protocol/openid-connect/token'
    certs = ISSUER + '/protocol/openid-connect/certs'
    assert metadata['authorization_endpoint'] == auth and metadata['token_endpoint'] == token_endpoint
    assert metadata['jwks_uri'] == certs
    status, _, body = request(browser, certs)
    assert status == 200
    # Operator setup explicitly approves only signing RS256 keys from this exact
    # configured HTTPS endpoint. Keep the application's strict verifier unchanged.
    keys = [key for key in json.loads(body)['keys']
            if key.get('kty') == 'RSA' and key.get('alg') == 'RS256' and key.get('use') == 'sig']
    assert 1 <= len(keys) <= 32, 'no bounded RS256 signing key set'
    approved = json.dumps({'keys': keys})
    assert len(approved.encode()) <= 65536
    if selected is None:
        if (STATE / 'approved-jwks.json').exists():
            assert json.loads((STATE / 'approved-jwks.json').read_text()) == json.loads(approved), 'provider signing keys changed; explicit reapproval required'
        (STATE / 'approved-jwks.json').write_text(approved + '\n')
    else:
        _private_approved(STATE / 'approved-jwks.json', json.loads(approved))
    if selected is None:
        target = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'], cwd=ROOT, text=True, timeout=15))['target_directory']
        verifier = Path(target) / 'debug/examples/verify_local'
    else:
        verifier = _check_human_verifier(verifier_record)

    def authorize(name):
        browser = client()  # New browser session proves both accounts independently.
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        proof = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(proof.encode()).digest()).rstrip(b'=').decode()
        query = {'client_id': CLIENT, 'redirect_uri': CALLBACK, 'response_type': 'code',
                 'scope': 'openid', 'state': state, 'nonce': nonce,
                 'code_challenge': challenge, 'code_challenge_method': 'S256'}
        status, _, body = request(browser, auth + '?' + urllib.parse.urlencode(query))
        assert status == 200, 'authorization page unavailable'
        parser = LoginForm(); parser.feed(body.decode())
        assert len(parser.actions) == 1, 'expected one local login form'
        status, headers, _ = request(browser, parser.actions[0], {'username': name, 'password': accounts[name], 'credentialId': ''})
        assert status == 302, 'local account login did not complete'
        redirect = urllib.parse.urlsplit(headers['Location'])
        assert urllib.parse.urlunsplit(redirect._replace(query='', fragment='')) == CALLBACK
        result = urllib.parse.parse_qs(redirect.query, strict_parsing=True)
        assert result.get('state') == [state] and len(result.get('code', [])) == 1
        assert len(result['code'][0]) <= 8192
        return result['code'][0], proof, nonce

    def redeem(code, proof):
        return request(client(), token_endpoint, {'grant_type': 'authorization_code',
                       'client_id': CLIENT, 'redirect_uri': CALLBACK, 'code': code, 'code_verifier': proof})

    subjects = {}
    for name in ['owner', 'viewer']:
        code, proof, nonce = authorize(name)
        status, _, body = redeem(code, proof)
        assert status == 200, 'code exchange failed'
        token = json.loads(body)['id_token']
        with tempfile.TemporaryDirectory(prefix='oidc-', dir=STATE) as folder:
            folder = Path(folder)
            (folder / 'token').write_text(token)
            (folder / 'nonce').write_text(nonce)
            argv = [str(verifier), ISSUER, CLIENT, str(STATE / 'approved-jwks.json'), str(folder / 'token'), str(folder / 'nonce')]
            if verifier_record is not None: _check_human_verifier(verifier_record)
            result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
            if verifier_record is not None: _check_human_verifier(verifier_record)
            assert result.returncode == 0 and result.stdout.strip() == 'verified', 'actual verifier rejected provider token'
            (folder / 'nonce').write_text('wrong-nonce')
            if verifier_record is not None: _check_human_verifier(verifier_record)
            assert subprocess.run(argv, capture_output=True, timeout=5).returncode != 0, 'nonce mismatch accepted'
            if verifier_record is not None: _check_human_verifier(verifier_record)
        # Signature/issuer/audience/nonce/expiry were checked above before using sub.
        encoded = token.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        subjects[name] = claims['sub']
        assert redeem(code, proof)[0] == 400, 'authorization code replay accepted'
    assert subjects['owner'] != subjects['viewer'], 'account identities collided'
    if selected is None:
        if (STATE / 'subjects.json').exists():
            assert json.loads((STATE / 'subjects.json').read_text()) == subjects, 'provider account subjects changed'
        (STATE / 'subjects.json').write_text(json.dumps(subjects, indent=2) + '\n')
    code, _, _ = authorize('owner')
    assert redeem(code, secrets.token_urlsafe(48))[0] == 400, 'wrong PKCE verifier accepted'
    status, _, _ = request(client(), token_endpoint, {'grant_type': 'password', 'client_id': CLIENT,
                          'username': 'owner', 'password': accounts['owner']})
    assert status == 400, 'direct password grant unexpectedly enabled'
    if selected is not None:
        _private_approved(STATE / 'subjects.json', subjects)
    print('Local owner/viewer HTTPS code login, actual RS256 verification, nonce rejection, PKCE rejection, code replay denial and disabled password grant passed.')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        # Exception objects from HTTP clients can contain credentials/codes/URLs.
        print('Local OIDC check failed; credentials and response bodies withheld.', file=sys.stderr)
        print(type(error).__name__, file=sys.stderr)
        if isinstance(error, AssertionError): print(str(error), file=sys.stderr)
        for frame in traceback.extract_tb(error.__traceback__):
            print(Path(frame.filename).name + ':' + str(frame.lineno) + ' ' + frame.name, file=sys.stderr)
        raise SystemExit(1)
