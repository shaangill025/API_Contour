"""Exercise the real local business API without exposing credentials or response bodies.

Requires the provisioned local stack, platform.json, business.json, approved JWKS,
accounts, CA, and built web/dist. Starts and stops only this check's platform host.
The test creates synthetic imports, comparisons and reviews; it never resets data.
"""
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import runpy
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
APP = 'https://localhost:9443'
PROVIDER = 'https://localhost:8444'


def main():
    os.umask(0o077)
    helpers = runpy.run_path(str(ROOT / 'deploy/local/check_oidc.py'))
    context = ssl.create_default_context(cafile=STATE / 'ca.crt')
    accounts = json.loads((STATE / 'accounts.json').read_text())
    config = json.loads((STATE / 'business.json').read_text())
    build = subprocess.run(['cargo', 'build', '-p', 'contour-platform', '--locked', '--offline'], cwd=ROOT,
                           env=dict(os.environ, AWS_LC_SYS_USE_SYSTEM='0'), capture_output=True, timeout=180)
    assert build.returncode == 0, 'current platform build failed'
    target = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'], cwd=ROOT, text=True, timeout=15))['target_directory']

    def browser():
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), helpers['NoRedirect'](),
                                             urllib.request.HTTPCookieProcessor(jar), urllib.request.ProxyHandler({}))
        opener.fixture_jar = jar
        return opener

    def request(opener, url, value=None, headers=None):
        parsed = urllib.parse.urlsplit(url)
        assert (parsed.scheme, parsed.netloc) in [('https', 'localhost:9443'), ('https', 'localhost:8444')], 'unapproved destination'
        data = None if value is None else json.dumps(value, separators=(',', ':')).encode()
        try:
            response = opener.open(urllib.request.Request(url, data=data, headers=headers or {}), timeout=25)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(1_048_577)
            assert len(body) <= 1_048_576, 'response exceeds bound'
            return response.status, response.headers, body

    def login(name):
        opener = browser()
        status, headers, _ = request(opener, APP + '/auth/login')
        assert status == 303, 'login redirect failed'
        status, _, body = request(opener, headers['Location'])
        assert status == 200, 'provider login page failed'
        form = helpers['LoginForm'](); form.feed(body.decode())
        assert len(form.actions) == 1, 'provider login form unavailable'
        form_body = urllib.parse.urlencode({'username': name, 'password': accounts[name], 'credentialId': ''}).encode()
        parsed = urllib.parse.urlsplit(form.actions[0])
        assert (parsed.scheme, parsed.netloc) == ('https', 'localhost:8444'), 'provider form destination invalid'
        try:
            response = opener.open(urllib.request.Request(form.actions[0], data=form_body), timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == 302, 'provider authentication failed'
            callback = response.headers['Location']
        assert callback.startswith(APP + '/auth/callback?'), 'callback destination invalid'
        status, headers, _ = request(opener, callback)
        assert status == 303 and headers.get('Location') == '/', 'callback failed'
        cookies = headers.get_all('Set-Cookie') or []
        sessions = [c for c in cookies if c.startswith('__Host-contour-session=')]
        assert len(sessions) == 1 and all(flag in sessions[0] for flag in ['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/']), 'opaque session cookie missing'
        assert request(opener, APP + '/auth/session')[0] == 200, 'session unavailable'
        return opener

    def get(opener, path, wanted=200):
        status, _, body = request(opener, APP + path)
        assert status == wanted, 'GET %s expected %d got %d' % (path.split('?')[0].split('/')[2], wanted, status)
        return json.loads(body) if status == 200 else None

    def post(opener, path, value, wanted=200, key=None, origin=APP):
        headers = {'Origin': origin, 'Content-Type': 'application/json'}
        if key is not None: headers['Idempotency-Key'] = key
        status, _, body = request(opener, APP + path, value, headers)
        assert status == wanted, 'POST %s expected %d got %d' % (path.split('/')[2], wanted, status)
        return json.loads(body) if status == 200 else None

    process = subprocess.Popen([str(Path(target) / 'debug/contour-platform'), str(STATE / 'platform.json'),
                                str(STATE / 'business.json'), str(ROOT / 'web/dist')], cwd=ROOT,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        anonymous = browser()
        until = time.monotonic() + 15
        while True:
            assert process.poll() is None, 'owned platform failed to start (port may be occupied)'
            try:
                if request(anonymous, APP + '/readyz')[0] == 200: break
            except (urllib.error.URLError, ConnectionError, TimeoutError): pass
            assert time.monotonic() < until, 'business readiness deadline'
            time.sleep(.1)
        get(anonymous, '/v1/operations', 401)
        owner, viewer = login('owner'), login('viewer')
        project, service = config['project_id'], config['service_id']
        documents = [(ROOT / 'deploy/local/sample-baseline.json').read_text(), (ROOT / 'deploy/local/sample-candidate.json').read_text()]
        imports = [{'project_id': project, 'service_id': service, 'format': 'openapi_json', 'content': document} for document in documents]
        keys = [str(uuid.uuid4()), str(uuid.uuid4())]
        baseline = post(owner, '/v1/contracts/import', imports[0], key=keys[0])
        assert baseline['id'] == keys[0] and baseline['kind'] == 'declared' and baseline['revision'] > 0, 'baseline identity invalid'
        assert post(owner, '/v1/contracts/import', imports[0], key=keys[0]) == baseline, 'import retry changed record'
        post(owner, '/v1/contracts/import', imports[1], 409, keys[0])
        candidate = post(owner, '/v1/contracts/import', imports[1], key=keys[1])
        assert candidate['id'] == keys[1], 'candidate identity invalid'
        # The server has committed before sending response headers. Drop the body,
        # then recover the same durable import using the original request key.
        recovery_key = str(uuid.uuid4())
        session = [cookie for cookie in owner.fixture_jar if cookie.name == '__Host-contour-session']
        assert len(session) == 1, 'session unavailable for response-loss check'
        lost = http.client.HTTPSConnection('localhost', 9443, context=context, timeout=25)
        try:
            encoded = json.dumps(imports[0], separators=(',', ':')).encode()
            lost.request('POST', '/v1/contracts/import', encoded,
                         {'Origin': APP, 'Content-Type': 'application/json', 'Idempotency-Key': recovery_key,
                          'Cookie': session[0].name + '=' + session[0].value})
            response = lost.getresponse()
            assert response.status == 200, 'response-loss import did not commit'
            response.close()
        finally:
            lost.close()
        recovered = post(owner, '/v1/contracts/import', imports[0], key=recovery_key)
        assert recovered['id'] == recovery_key and recovered['revision'] > 0, 'response-loss recovery changed identity'
        assert post(owner, '/v1/contracts/import', imports[0], key=recovery_key) == recovered, 'response-loss recovery created duplicate'
        bad = dict(imports[0], format='openapi_yaml')
        post(owner, '/v1/contracts/import', bad, 422, str(uuid.uuid4()))
        post(owner, '/v1/contracts/import', imports[0], 400, str(uuid.uuid4()), 'https://evil.example')
        post(viewer, '/v1/contracts/import', imports[0], 403, str(uuid.uuid4()))
        operations = []
        cursor = None
        for _ in range(100):
            page = get(owner, '/v1/operations' + ('?limit=200&cursor=' + urllib.parse.quote(cursor, safe='') if cursor else '?limit=200'))
            operations.extend(page['items']); cursor = page['next_cursor']
            if cursor is None: break
        assert cursor is None, 'catalog pagination exceeded bound'
        matches = [op for op in operations if op['route_template'] == '/orders' and op['operation'] == 'POST']
        assert len(matches) == 1, 'imported operation unavailable or ambiguous'
        operation = matches[0]; opid = operation['id']; prior = operation['approved_contract_id']
        assert operation['last_seen'] is None and operation['visibility'] is None and operation['completeness'] is None, 'import-only observation fields changed'
        assert get(viewer, '/v1/operations/' + opid) == operation, 'viewer operation differs'
        comparison_body = {'operation_id': opid, 'left_id': prior or baseline['id'], 'left_kind': 'approved' if prior else 'declared', 'right_id': candidate['id'], 'right_kind': 'declared'}
        comparison_key = str(uuid.uuid4())
        compared = post(owner, '/v1/comparisons', comparison_body, key=comparison_key)
        assert compared['id'] == comparison_key and compared['right_id'] == candidate['id'], 'comparison identity invalid'
        assert get(owner, '/v1/comparisons/' + comparison_key) == compared
        assert get(viewer, '/v1/comparisons/' + comparison_key) == compared
        post(viewer, '/v1/comparisons', comparison_body, 403, str(uuid.uuid4()))
        review_body = {'operation_id': opid, 'comparison_id': comparison_key, 'candidate_contract_id': candidate['id'], 'expected_baseline_id': prior}
        review_key, stale_key = str(uuid.uuid4()), str(uuid.uuid4())
        review = post(owner, '/v1/reviews', review_body, key=review_key)
        stale = post(owner, '/v1/reviews', review_body, key=stale_key)
        assert review['id'] == review_key and review['candidate_contract_id'] == candidate['id'] and review['revision'] == 1 and review['status'] == 'pending'
        assert get(owner, '/v1/reviews/' + review_key) == review
        assert get(viewer, '/v1/reviews/' + review_key) == review
        post(viewer, '/v1/reviews', review_body, 403, str(uuid.uuid4()))
        decision = {'decision': 'approve', 'expected_revision': 1}
        post(viewer, '/v1/reviews/' + review_key + '/decision', decision, 403)
        approved = post(owner, '/v1/reviews/' + review_key + '/decision', decision)
        assert approved['status'] == 'approved' and approved['revision'] == 2 and approved['id'] == review_key
        assert post(owner, '/v1/reviews/' + review_key + '/decision', decision) == approved, 'decision retry changed record'
        post(owner, '/v1/reviews/' + review_key + '/decision', {'decision': 'approve', 'expected_revision': 2}, 409)
        post(owner, '/v1/reviews/' + stale['id'] + '/decision', decision, 409)
        new = get(owner, '/v1/operations/' + opid)['approved_contract_id']
        assert new and new != prior, 'approval did not update catalog head'
        assert get(viewer, '/v1/operations/' + opid)['approved_contract_id'] == new
        for opener in [owner, viewer]:
            post(opener, '/auth/logout', {})
            get(opener, '/v1/operations', 401)
        print('Local HTTPS owner/viewer business workflow, import retry, comparison, review, approval CAS, access denial and logout passed.')
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        process.stdout.close(); process.stderr.close()


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Local business check failed; credentials and response bodies withheld.', file=sys.stderr)
        print(type(error).__name__, file=sys.stderr)
        if isinstance(error, AssertionError): print(str(error), file=sys.stderr)
        raise SystemExit(1)
