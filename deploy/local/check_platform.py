"""Real local provider -> application callback -> opaque session integration.

Starts and terminates only its own platform process. No browser certificate trust
is changed, and no token/cookie/password/credential-bearing URL is printed.
"""
import http.cookiejar
import json
import os
from pathlib import Path
import runpy
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
APP = 'https://localhost:9443'
PROVIDER = 'https://localhost:8444'
ISSUER = PROVIDER + '/realms/apicontour-local'


def main():
    os.umask(0o077)
    helpers = runpy.run_path(str(ROOT / 'deploy/local/check_oidc.py'))
    context = ssl.create_default_context(cafile=STATE / 'ca.crt')
    accounts = json.loads((STATE / 'accounts.json').read_text())
    config = {'issuer': ISSUER, 'authorization_endpoint': ISSUER + '/protocol/openid-connect/auth',
              'token_endpoint': ISSUER + '/protocol/openid-connect/token', 'client_id': 'apicontour-local',
              'callback': APP + '/auth/callback', 'tls_certificate': str(STATE / 'tls/server.crt'),
              'tls_private_key': str(STATE / 'tls/server.key'), 'provider_ca': str(STATE / 'ca.crt'),
              'jwks': str(STATE / 'approved-jwks.json')}
    config_path = STATE / 'platform.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    build = subprocess.run(['cargo', 'build', '-p', 'contour-platform', '--locked', '--offline'], cwd=ROOT,
                           env=dict(os.environ, AWS_LC_SYS_USE_SYSTEM='0'), capture_output=True, timeout=180)
    assert build.returncode == 0, 'current platform build failed'
    target = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'], cwd=ROOT, text=True, timeout=15))['target_directory']
    def browser():
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                             helpers['NoRedirect'](), urllib.request.HTTPCookieProcessor(jar),
                                             urllib.request.ProxyHandler({}))
        return opener, jar

    def request(opener, url, data=None, headers=None):
        parsed = urllib.parse.urlsplit(url)
        assert (parsed.scheme, parsed.netloc) in [('https','localhost:9443'), ('https','localhost:8444')], 'unapproved destination'
        try: response = opener.open(urllib.request.Request(url, data=data, headers=headers or {}), timeout=5)
        except urllib.error.HTTPError as error: response = error
        with response:
            body = response.read(1_048_577)
            assert len(body) <= 1_048_576
            return response.status, response.headers, body

    def authorize(opener, name):
        status, headers, _ = request(opener, APP + '/auth/login')
        assert status == 303, 'application login did not redirect'
        cookies = headers.get_all('Set-Cookie') or []
        assert len(cookies) == 1 and cookies[0].startswith('__Host-contour-login=')
        assert all(flag in cookies[0] for flag in ['Secure','HttpOnly','SameSite=Lax','Path=/'])
        status, _, body = request(opener, headers['Location'])
        assert status == 200
        form = helpers['LoginForm'](); form.feed(body.decode())
        assert len(form.actions) == 1
        status, headers, _ = request(opener, form.actions[0], urllib.parse.urlencode({'username': name, 'password': accounts[name], 'credentialId': ''}).encode())
        assert status == 302, 'provider login failed'
        callback = headers['Location']
        assert callback.startswith(APP + '/auth/callback?')
        return callback

    process = subprocess.Popen([str(Path(target) / 'debug/contour-platform'), str(config_path)],
                               cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        opener, _ = browser()
        until = time.monotonic() + 10
        while True:
            assert process.poll() is None, 'owned platform failed to start (port may be occupied)'
            try:
                if request(opener, APP + '/livez')[0] == 200: break
            except (urllib.error.URLError, ConnectionError, TimeoutError): pass
            assert time.monotonic() < until, 'platform readiness deadline'
            time.sleep(.05)
        assert request(opener, APP + '/readyz')[0] == 503
        assert request(opener, APP + '/auth/session')[0] == 401
        assert request(opener, APP + '/v1/operations')[0] == 401
        for name in ['owner', 'viewer']:
            opener, jar = browser()
            callback = authorize(opener, name)
            stranger, _ = browser()
            assert request(stranger, callback)[0] == 401, 'callback accepted without browser binding'
            status, headers, _ = request(opener, callback)
            assert status == 303 and headers.get('Location') == '/', 'application callback failed'
            cookies = headers.get_all('Set-Cookie') or []
            session = [value for value in cookies if value.startswith('__Host-contour-session=')]
            assert len(session) == 1 and all(flag in session[0] for flag in ['Secure','HttpOnly','SameSite=Lax','Path=/'])
            assert 'Domain=' not in session[0] and 'id_token' not in session[0]
            assert json.loads(request(opener, APP + '/auth/session')[2]) == {'authenticated': True}
            assert request(opener, callback)[0] == 401, 'callback replay accepted'
            assert request(opener, APP + '/v1/operations')[0] == 503, 'unfinished business host misreported availability'
            cookie_value = session[0].split(';',1)[0]
            # Wrong-origin requests must leave the existing session intact.
            for origin in ['https://evil.example', 'null', 'https://localhost:9443.evil.example']:
                assert request(opener, APP + '/auth/logout', b'{}', {'Origin': origin, 'Content-Type':'application/json'})[0] == 400
                assert request(opener, APP + '/auth/session')[0] == 200
            assert request(opener, APP + '/auth/logout', b'{}', {'Origin': APP, 'Content-Type':'text/plain'})[0] == 400
            assert request(opener, APP + '/auth/logout', b'{}', {'Origin': APP, 'Content-Type':'application/json'})[0] == 200
            assert request(opener, APP + '/auth/session')[0] == 401
            replay, _ = browser()
            assert request(replay, APP + '/auth/session', headers={'Cookie': cookie_value})[0] == 401, 'logout left session reusable'
        # A callback from the wrong browser with a supplied wrong binding consumes
        # that login attempt and cannot be rescued by replaying the original cookie.
        opener, _ = browser()
        callback = authorize(opener, 'owner')
        stranger, _ = browser()
        assert request(stranger, callback, headers={'Cookie':'__Host-contour-login=' + 'A' * 43})[0] == 401
        assert request(opener, callback)[0] == 401
        # Exact issuer binding is checked independently of token verification.
        opener, _ = browser()
        callback = authorize(opener, 'owner')
        parts = urllib.parse.urlsplit(callback)
        query = urllib.parse.parse_qs(parts.query)
        query['iss'] = ['https://other.example']
        wrong_issuer = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query, doseq=True)))
        assert request(opener, wrong_issuer)[0] == 401
        assert request(opener, callback)[0] == 401
        print('Real owner/viewer application callback, browser binding, opaque cookies, session use, replay/issuer rejection, origin protection and logout invalidation passed.')
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        process.stdout.close(); process.stderr.close()


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Local platform check failed; sensitive response data withheld.', file=sys.stderr)
        print(type(error).__name__, file=sys.stderr)
        if isinstance(error, AssertionError): print(str(error), file=sys.stderr)
        for frame in traceback.extract_tb(error.__traceback__):
            print(Path(frame.filename).name + ':' + str(frame.lineno) + ' ' + frame.name, file=sys.stderr)
        raise SystemExit(1)
