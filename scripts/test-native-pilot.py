#!/usr/bin/env python3
"""Run the owned synthetic Node-RED/native capture qualification.

This is an operator command, not a production deployment or an origin/causal,
retry, sentinel, HTTP/2, or performance proof. It never prints application bodies,
credentials, policy contents, peer identities, or SQL output.
"""
import base64
import datetime
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local-mvp'
EVIDENCE = ROOT / '.agentic' / 'tasks' / 'black-box-pilot-20261030' / 'evidence'
MAX_LOG = 1024 * 1024
IMAGES = (
    'docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963',
    'envoyproxy/envoy:v1.37.11@sha256:7765ad61185fca9c9a770c9e2cad640d085d708ae9c22f3741345e88331472a4',
    'node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3',
    'rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0',
    'debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8',
)
COMPOSE = ['docker','compose','-f','deploy/pilot/compose.yaml','-f','deploy/pilot/native-overlay.yaml','--profile','native-capture']
SCOPE = "w.tenant_id='00000000-0000-4000-8000-000000000001' AND w.collector_id='00000000-0000-4000-8000-000000000301'"
REQUEST = '{"kind":"object","fields":{"probe":{"kind":"boolean"}},"additional":null}'
RESPONSE = '{"kind":"object","fields":{"result":{"kind":"string"}},"additional":null}'
TENANT = '00000000-0000-4000-8000-000000000001'
PROJECT = '00000000-0000-4000-8000-000000000002'
SERVICE = '00000000-0000-4000-8000-000000000003'
ENVIRONMENT = '00000000-0000-4000-8000-000000000004'
SOURCE = '00000000-0000-4000-8000-000000000302'
DEPLOYMENT = '00000000-0000-4000-8000-000000000303'
# contour-core OperationKey::canonical_bytes is a compact JSON array of these
# eight ordered string components (operation.rs, codec version 1).
def operation_key(direction):
    return json.dumps([TENANT,PROJECT,SERVICE,ENVIRONMENT,'http',direction,'POST','/pilot'],separators=(',',':'))

TLS_EVENTS = {
    'wrong-upstream-name': 'upstream_certificate_rejected',
    'wrong-upstream-ca': 'upstream_certificate_rejected',
    'missing-forwarder': 'forwarder_certificate_missing',
    'wrong-forwarder': 'forwarder_leaf_rejected',
}


class Failure(RuntimeError):
    pass


def private_write(path, data):
    with path.open('xb') as out:
        os.fchmod(out.fileno(), 0o600)
        out.write(data)


def kill_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # The process group has already exited.


def run_bounded(args, *, cwd, env, log, seconds):
    """Capture at most MAX_LOG bytes, kill the whole command group on overrun."""
    deadline = time.monotonic() + seconds
    with log.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        proc = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        total = 0
        failed = None
        try:
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    failed = 'deadline'
                    break
                for key, _ in selector.select(min(left, 0.25)):
                    data = os.read(key.fileobj.fileno(), min(65536, MAX_LOG + 1 - total))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(data)
                    if total > MAX_LOG:
                        failed = 'output limit'
                        break
                    output.write(data)
                if failed:
                    break
            if failed:
                kill_group(proc.pid)
            try:
                code = proc.wait(timeout=max(0.1, deadline-time.monotonic()) if not failed else 5)
            except subprocess.TimeoutExpired:
                kill_group(proc.pid)
                proc.wait(timeout=5)
                failed = 'deadline'
                code = -1
        finally:
            selector.close()
            if proc.poll() is None:
                kill_group(proc.pid)
                proc.wait(timeout=5)
            proc.stdout.close()
    if failed or code:
        raise Failure('command failed: '+(failed or str(code)))
    return log.read_bytes()


def is_expired_or_pending(capture, now):
    if os.path.lexists(capture/'private'/'renew.pending'):
        return True
    envelope = json.loads((capture/'private'/'policy.json').read_bytes())
    value = envelope['payload_base64url']
    policy = json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))
    expiry = datetime.datetime.fromisoformat(policy['expires_at'].replace('Z', '+00:00'))
    if expiry.tzinfo is None:
        raise Failure('invalid policy expiry')
    return expiry <= now


def altered_gateway(original, mode):
    result = dict(original)
    if mode == 'wrong-name':
        result['upstream_name'] = 'wrong-name.invalid'
    elif mode == 'wrong-ca':
        result['upstream_ca_der'] = '/run/native-negative/wrong-ca.der'
    else:
        raise Failure('unknown gateway test')
    return result


def altered_envoy(original, mode):
    result = json.loads(json.dumps(original))
    common = result['static_resources']['clusters'][0]['transport_socket']['typed_config']['common_tls_context']
    if mode == 'missing-client':
        common.pop('tls_certificates')
    elif mode == 'wrong-client':
        common['tls_certificates'] = [{'certificate_chain': {'filename':'/run/native-negative/client.pem'},
                                      'private_key': {'filename':'/run/native-negative/client.key'}}]
    else:
        raise Failure('unknown forwarder test')
    return result


def override(service, config_target, config_file, extra=()):
    # These absolute bind sources exist only under the unique operator evidence
    # directory. Original configuration and credentials are never rewritten.
    mounts = [str(config_file)+':'+config_target+':ro']
    mounts.extend(str(source)+':'+target+':ro' for source,target in extra)
    return {'services': {service: {'volumes': mounts}}}


def with_restoration(work, restore):
    failure = None
    try:
        work()
    except BaseException as exc:
        failure = exc
    try:
        restore()
    except BaseException as exc:
        if failure is not None:
            raise BaseExceptionGroup('test and restoration failed', [failure, exc])
        raise
    if failure is not None:
        raise failure


class Driver:
    def __init__(self):
        os.umask(0o077)
        EVIDENCE.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.folder = EVIDENCE/('native-qualification-'+str(uuid.uuid4()))
        self.folder.mkdir(mode=0o700)
        self.env = dict(os.environ, LOCAL_UID=str(os.getuid()), LOCAL_GID=str(os.getgid()),
                        PYTHONDONTWRITEBYTECODE='1', PILOT_TARGET='https://pilot-gateway:9443/pilot',
                        PILOT_TLS_TEST='normal', PILOT_DESTINATION_MODE='normal')
        self.sequence = 0
        self.started = False
        spec = importlib.util.spec_from_file_location('owned_local_provision', ROOT/'deploy/local/provision.py')
        self.base = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.base)

    def run(self, name, args, seconds):
        self.sequence += 1
        print(name+': starting', flush=True)
        try:
            result = run_bounded(args, cwd=ROOT, env=self.env,
                                 log=self.folder/(f'{self.sequence:03d}-{name}.private.log'), seconds=seconds)
        except Exception as exc:
            print(name+': failed; private diagnostics retained', flush=True)
            raise Failure(name+' failed') from exc
        print(name+': passed', flush=True)
        return result

    def compose(self, name, args, seconds=90, extra_config=None):
        command = COMPOSE.copy()
        if extra_config:
            # Docker accepts extra -f only before --profile.
            command = COMPOSE[:-2] + ['-f',str(extra_config)] + COMPOSE[-2:]
        return self.run(name, command+args, seconds)

    def proof(self):
        # Database returns only counts/booleans, never a raw observed shape or value.
        common = ("w.source_id='"+SOURCE+"' AND w.project_id='"+PROJECT+"' AND w.service_id='"+SERVICE+"' AND "
                  "w.environment_id='"+ENVIRONMENT+"' AND w.deployment_id='"+DEPLOYMENT+"' AND o.identity_version=1 AND "
                  "v.parser_profile='http_json_v1' AND w.visibility='structure' AND NOT w.route_uncertain")
        request = "("+common+" AND o.canonical_key=convert_to('"+operation_key('request')+"','UTF8') AND w.status_code IS NULL AND convert_from(v.structure_wire,'UTF8')::jsonb = '"+REQUEST+"'::jsonb)"
        response = "("+common+" AND o.canonical_key=convert_to('"+operation_key('response')+"','UTF8') AND w.status_code=200 AND convert_from(v.structure_wire,'UTF8')::jsonb = '"+RESPONSE+"'::jsonb)"
        query = ("SELECT count(*)::text || ',' || count(*) FILTER (WHERE "
          "w.completeness IS DISTINCT FROM 'complete' OR NOT COALESCE(("+request+" OR "+response+"),false))::text || ',' || "
          "count(*) FILTER (WHERE "+request+")::text || ',' || count(*) FILTER (WHERE "+response+")::text "
          "FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id) "
          "JOIN contour.operations o ON o.tenant_id=w.tenant_id AND o.operation_id=w.operation_id WHERE "+SCOPE)
        try:
            values = tuple(map(int, self.base.psql(query).split(',')))
        except (ValueError, TypeError) as exc:
            raise Failure('invalid projection check') from exc
        if len(values) != 4 or values[1] != 0:
            raise Failure('projection shape or completeness mismatch')
        return values

    def product(self, name, expect='normal'):
        # check.py only emits status and closed booleans; wrong-name selects its
        # fixed 502 expectation, not a change to Node-RED TLS configuration.
        self.run(name, [sys.executable,'deploy/pilot/check.py','--expect',expect], 150)

    def product_closed(self, name):
        for replica in ('replica1','replica2'):
            raw = self.compose(name+'-'+replica, ['exec','-T',replica,'node','/pilot/probe.js','gateway-denied'], 15)
            if len(raw) > 1024:
                raise Failure('closed probe result limit')
            try:
                result = json.loads(raw)
            except ValueError as exc:
                raise Failure('invalid closed probe result') from exc
            if result.get('status') not in (502,503) or result.get('expected_body') is not True or result.get('exception') != 'none':
                raise Failure('negative control did not fail closed')

    def wait_growth(self, before, minimum, label):
        deadline = time.monotonic()+35
        for attempt in range(40):
            now = self.proof()
            if now[0] >= before[0]+minimum and now[2] >= before[2]+minimum//2 and now[3] >= before[3]+minimum//2:
                return now
            if time.monotonic() >= deadline:
                break
            self.product(label+'-probe-'+str(attempt))
            time.sleep(0.5)
        raise Failure('expected request and response projections missing')

    def stable(self):
        # Do not start a negative control while a previous accepted batch is
        # still making its way through asynchronous owned delivery.
        previous = self.proof()
        stable_since = time.monotonic()
        deadline = stable_since+20
        while time.monotonic() < deadline:
            time.sleep(0.5)
            current = self.proof()
            if current != previous:
                previous, stable_since = current, time.monotonic()
            if time.monotonic()-stable_since >= 3:
                return current
        raise Failure('projection did not quiesce')

    def write_override(self, name, service, target, config, mounts=()):
        config_file = self.folder/(name+'-config.json')
        private_write(config_file, json.dumps(config,separators=(',',':')).encode())
        overlay = self.folder/(name+'-overlay.json')
        private_write(overlay, json.dumps(override(service,target,config_file,mounts),separators=(',',':')).encode())
        return overlay

    def diagnose_failure(self, work):
        # Preserve the failing configuration's diagnostics before its service is
        # recreated; main also collects the final project state before cleanup.
        try:
            work()
        except Exception as original:
            try:
                self.diagnostics()
            except BaseException as diagnostic:
                raise BaseExceptionGroup('operation and diagnostics failed', [original, diagnostic])
            raise

    def event_snapshot(self, event):
        container = self.compose('event-container', ['ps','-q','native-gateway'], 20).strip()
        if not container or b'\n' in container:
            raise Failure('native gateway container unavailable')
        logs = self.compose('event-log', ['logs','--no-color','--no-log-prefix','native-gateway'], 20)
        marker = ('apicontour_native_gateway: '+event).encode()
        return container, sum(line.strip() == marker for line in logs.splitlines())

    def negative(self, name, service, target, config, mounts=()):
        before = self.stable()
        self.product(name+'-before')
        self.wait_growth(before, 4, name+'-before')
        initial = self.stable()
        overlay = self.write_override(name, service, target, config, mounts)
        def work():
            self.compose(name+'-start', ['up','-d','--pull','never','--no-deps','--force-recreate',service], extra_config=overlay)
            time.sleep(3)
            running = self.compose(name+'-running', ['ps','--status','running','--services',service], 20)
            if running.strip() != service.encode():
                raise Failure('negative-control service is not running')
            event = TLS_EVENTS[name]
            identity, prior = self.event_snapshot(event)
            if prior != 0:
                raise Failure('negative-control event is not fresh')
            self.product_closed(name+'-closed')
            current, after = self.event_snapshot(event)
            if current != identity or after <= prior:
                raise Failure('required typed TLS rejection not observed')
            time.sleep(2)
            if self.proof() != initial:
                raise Failure('negative control changed capture projections')
        def restore():
            self.compose(name+'-restore', ['up','-d','--pull','never','--no-deps','--force-recreate',service])
        # Recreate from the untampered project definition even after a failed
        # negative check; no normal preflight is asserted during the override.
        with_restoration(lambda: self.diagnose_failure(work), restore)
        self.run(name+'-preflight', [sys.executable,'deploy/pilot/native_prepare.py','--check'], 30)
        self.product(name+'-recovered')
        self.wait_growth(initial, 4, name+'-recovered')

    def make_negative_credentials(self):
        bad_key=self.folder/'wrong-ca.key'; bad_pem=self.folder/'wrong-ca.pem'; bad_der=self.folder/'wrong-ca.der'
        self.run('wrong-ca-create',['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(bad_key),'-out',str(bad_pem),'-days','1','-subj','/CN=synthetic-untrusted-ca'],30)
        self.run('wrong-ca-der',['openssl','x509','-in',str(bad_pem),'-outform','DER','-out',str(bad_der)],10)
        key=self.folder/'client.key'; csr=self.folder/'client.csr'; cert=self.folder/'client.pem'; ext=self.folder/'client.cnf'
        private_write(ext,b'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:synthetic-wrong-forwarder\n')
        self.run('wrong-client-key',['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(csr),'-subj','/CN=synthetic-wrong-forwarder'],30)
        self.run('wrong-client-sign',['openssl','x509','-req','-in',str(csr),'-CA',str(STATE/'ca.crt'),'-CAkey',str(STATE/'ca.key'),'-set_serial',str(uuid.uuid4().int),'-days','1','-extfile',str(ext),'-out',str(cert)],30)
        self.run('wrong-client-chain',['openssl','verify','-CAfile',str(STATE/'ca.crt'),'-purpose','sslclient',str(cert)],15)
        wrong_der=self.folder/'client.der'
        self.run('wrong-client-der',['openssl','x509','-in',str(cert),'-outform','DER','-out',str(wrong_der)],10)
        if wrong_der.read_bytes() == (STATE/'pilot/native/gateway/forwarder.der').read_bytes():
            raise Failure('negative client matches authorized leaf')
        if bad_der.read_bytes() == (STATE/'pilot/capture/runtime/ca.der').read_bytes():
            raise Failure('negative CA matches authorized CA')
        for path in (bad_key,bad_pem,bad_der,key,csr,cert): os.chmod(path,0o600)
        return bad_der,cert,key

    def provision(self):
        for index,image in enumerate(IMAGES):
            self.run('cached-image-'+str(index),['docker','image','inspect',image],15)
        existing = self.compose('existing-pilot-containers',['ps','--all','-q'],30)
        if existing.strip(): raise Failure('existing pilot containers must be preserved')
        # A checked local build precedes any short policy lease or renewal.
        self.run('build',['docker','compose','-f','deploy/local/compose.yaml','build','--pull=false','app'],1800)
        if not (STATE/'pilot').exists():
            self.run('pilot-init',[sys.executable,'deploy/pilot/prepare.py'],150)
        capture=STATE/'pilot'/'capture'
        if not capture.exists():
            self.run('pilot-capture-init',[sys.executable,'deploy/local/capture_init.py','--profile','pilot'],90)
        if is_expired_or_pending(capture, datetime.datetime.now(datetime.timezone.utc)):
            self.run('pilot-explicit-renew',[sys.executable,'deploy/local/capture_renew.py','--profile','pilot'],90)
        self.run('pilot-enrollment',[sys.executable,'deploy/local/capture_provision.py','--profile','pilot'],90)
        if not (STATE/'pilot'/'native').exists():
            self.run('native-init',[sys.executable,'deploy/pilot/native_prepare.py'],150)
        self.run('native-preflight',[sys.executable,'deploy/pilot/native_prepare.py','--check'],30)

    def run_all(self):
        self.provision()
        initial=self.proof()
        self.started=True
        self.compose('native-start',['up','-d','--pull','never','--force-recreate'],90)
        self.product('initial-product')
        self.wait_growth(initial, 4, 'initial')
        self.run('native-ready-preflight',[sys.executable,'deploy/pilot/native_prepare.py','--check'],30)
        gateway=json.loads((STATE/'pilot/native/gateway/gateway.json').read_bytes())
        envoy=json.loads((STATE/'pilot/native/forwarder/envoy.json').read_bytes())
        bad_ca,client_cert,client_key=self.make_negative_credentials()
        self.negative('wrong-upstream-name','native-gateway','/run/native/gateway.json',altered_gateway(gateway,'wrong-name'))
        self.negative('wrong-upstream-ca','native-gateway','/run/native/gateway.json',altered_gateway(gateway,'wrong-ca'),[(bad_ca,'/run/native-negative/wrong-ca.der')])
        self.negative('missing-forwarder','native-envoy','/run/forwarder/envoy.json',altered_envoy(envoy,'missing-client'))
        self.negative('wrong-forwarder','native-envoy','/run/forwarder/envoy.json',altered_envoy(envoy,'wrong-client'),[(client_cert,'/run/native-negative/client.pem'),(client_key,'/run/native-negative/client.key')])
        baseline=self.stable()
        def outage():
            self.compose('ingress-stop',['stop','--timeout','10','pilot-capture-ingress'],40)
            # Capture refresh runs every 10 seconds with a 5-second I/O deadline.
            time.sleep(17)
            self.product('outage-forwarding')
            time.sleep(2)
            if self.proof() != baseline: raise Failure('outage changed persisted captures')
        def restart():
            self.compose('ingress-restart',['up','-d','--pull','never','--no-deps','--force-recreate','pilot-capture-ingress'])
        with_restoration(lambda: self.diagnose_failure(outage), restart)
        self.product('outage-recovered')
        self.wait_growth(baseline, 4, 'outage-recovered')
        self.run('native-final-preflight',[sys.executable,'deploy/pilot/native_prepare.py','--check'],30)

    def diagnostics(self):
        """Collect bounded private diagnostics before destroying owned services."""
        failures=[]
        checks=[('failure-service-status',['ps','--all','--format','json'])]
        checks.extend(('failure-'+service+'-logs', ['logs','--no-color','--no-log-prefix','--tail','500',service])
                      for service in ('native-gateway','native-envoy','pilot-capture-ingress'))
        for name, args in checks:
            try:
                self.compose(name, args, 20)
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise ExceptionGroup('private diagnostics failed', failures)

    def cleanup(self):
        def containers():
            if self.started:
                self.compose('native-cleanup',['down','--timeout','10'],60)
        def generated_keys():
            # Only keys created under this run's exclusive directory are removed.
            for name in ('wrong-ca.key','client.key'):
                (self.folder/name).unlink(missing_ok=True)
        with_restoration(containers, generated_keys)


def main():
    driver=Driver()
    failed=None
    try:
        driver.run_all()
    except BaseException as exc:
        failed=exc
        if isinstance(exc, Exception) and driver.started:
            try:
                driver.diagnostics()
            except BaseException as diagnostic:
                failed=BaseExceptionGroup('qualification and diagnostics failed', [failed, diagnostic])
    try:
        driver.cleanup()
    except BaseException as exc:
        print('Native cleanup failed; inspect private diagnostics.',file=sys.stderr)
        failed = BaseExceptionGroup('qualification and cleanup failed', [failed, exc]) if failed else exc
    if failed:
        print('Native pilot qualification failed; private diagnostics retained.',file=sys.stderr)
        if isinstance(failed, Exception): raise SystemExit(1) from failed
        raise failed
    print('PASS owned HTTP/1 product path, TLS negative controls, and capture-ingress outage recovery.', flush=True)
    print('Outage evidence covers forwarding availability and later delivery recovery; it does not prove capture paused before copying.', flush=True)
    print('Not proved: origin, causal attribution, retry identity, sentinel scans, HTTP/2, or performance.', flush=True)


class DriverUnitTests(unittest.TestCase):
    def test_overrides_preserve_original_and_fix_destinations(self):
        gateway={'upstream_name':'pilot-destination','upstream_ca_der':'/run/native/upstream-ca.der'}
        changed=altered_gateway(gateway,'wrong-name')
        self.assertEqual(changed['upstream_name'],'wrong-name.invalid')
        self.assertEqual(gateway['upstream_name'],'pilot-destination')
        self.assertEqual(altered_gateway(gateway,'wrong-ca')['upstream_ca_der'],'/run/native-negative/wrong-ca.der')
        with self.assertRaises(Failure): altered_gateway(gateway,'other')
        envoy={'static_resources':{'clusters':[{'transport_socket':{'typed_config':{'common_tls_context':{'tls_certificates':[{'key':'original'}]}}}}]}}
        removed=altered_envoy(envoy,'missing-client')
        path=lambda d:d['static_resources']['clusters'][0]['transport_socket']['typed_config']['common_tls_context']
        self.assertNotIn('tls_certificates',path(removed)); self.assertIn('tls_certificates',path(envoy))
        self.assertEqual(path(altered_envoy(envoy,'wrong-client'))['tls_certificates'][0]['private_key']['filename'],'/run/native-negative/client.key')

    def test_policy_renewal_is_only_expired_or_pending(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cap=Path(tmp); private=cap/'private'; private.mkdir()
            now=datetime.datetime.now(datetime.timezone.utc)
            def put(expiry):
                raw=json.dumps({'expires_at':expiry.isoformat()}).encode()
                (private/'policy.json').write_text(json.dumps({'payload_base64url':base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}))
            put(now+datetime.timedelta(seconds=1)); self.assertFalse(is_expired_or_pending(cap,now))
            put(now-datetime.timedelta(seconds=1)); self.assertTrue(is_expired_or_pending(cap,now))
            put(now+datetime.timedelta(days=1)); (private/'renew.pending').write_text('synthetic')
            self.assertTrue(is_expired_or_pending(cap,now))

    def test_failure_always_invokes_cleanup(self):
        fake=mock.Mock()
        fake.run_all.side_effect=Failure('synthetic')
        fake.started=True
        with mock.patch(__name__+'.Driver',return_value=fake), mock.patch('builtins.print'):
            with self.assertRaises(SystemExit): main()
        fake.cleanup.assert_called_once_with()
        fake.diagnostics.assert_called_once_with()
        self.assertLess(fake.method_calls.index(mock.call.diagnostics()),fake.method_calls.index(mock.call.cleanup()))

    def test_diagnostic_and_cleanup_failures_preserve_original(self):
        fake=mock.Mock(); fake.started=True
        fake.run_all.side_effect=Failure('original')
        fake.diagnostics.side_effect=Failure('diagnostic')
        fake.cleanup.side_effect=Failure('cleanup')
        with mock.patch(__name__+'.Driver',return_value=fake), mock.patch('builtins.print'):
            with self.assertRaises(SystemExit) as stopped: main()
        error=stopped.exception.__cause__
        self.assertIsInstance(error, ExceptionGroup)
        self.assertEqual(str(error.exceptions[0].exceptions[0]), 'original')
        self.assertEqual(str(error.exceptions[0].exceptions[1]), 'diagnostic')
        self.assertEqual(str(error.exceptions[1]), 'cleanup')

    def test_diagnostics_attempt_all_bounded_service_checks_after_one_failure(self):
        driver=Driver.__new__(Driver); checks=[]
        def compose(name,args,seconds=90,extra_config=None):
            checks.append((name,args,seconds))
            if name=='failure-service-status': raise Failure('status')
        driver.compose=compose
        with self.assertRaises(ExceptionGroup): driver.diagnostics()
        self.assertEqual([name for name,_,_ in checks], ['failure-service-status','failure-native-gateway-logs','failure-native-envoy-logs','failure-pilot-capture-ingress-logs'])
        self.assertTrue(all(seconds==20 for _,_,seconds in checks))
        self.assertTrue(all('--tail' in args and '500' in args for _,args,_ in checks[1:]))

    def test_override_failure_diagnosed_before_restore_and_original_retained(self):
        driver=Driver.__new__(Driver); events=[]
        driver.stable=lambda: (4,0,2,2)
        driver.product=lambda name: None
        driver.wait_growth=lambda before,minimum,label: None
        driver.write_override=lambda *args: Path('/synthetic/override')
        driver.event_snapshot=lambda event: (b'gateway',0)
        driver.proof=lambda: (4,0,2,2)
        def compose(name,args,seconds=90,extra_config=None):
            events.append(name)
            return b'native-envoy\n' if name.endswith('-running') else b''
        driver.compose=compose
        driver.product_closed=lambda name: (_ for _ in ()).throw(Failure('closed failure'))
        driver.diagnostics=lambda: events.append('diagnostics')
        with mock.patch(__name__+'.time.sleep'):
            with self.assertRaisesRegex(Failure,'closed failure'):
                driver.negative('missing-forwarder','native-envoy','/run/config',{})
        self.assertLess(events.index('diagnostics'),events.index('missing-forwarder-restore'))
        driver.diagnostics=lambda: (_ for _ in ()).throw(Failure('diagnostic failure'))
        with mock.patch(__name__+'.time.sleep'):
            with self.assertRaises(ExceptionGroup) as failure:
                driver.negative('missing-forwarder','native-envoy','/run/config',{})
        self.assertEqual([str(item) for item in failure.exception.exceptions],['closed failure','diagnostic failure'])

    def test_restoration_runs_and_preserves_both_failures(self):
        def fail(): raise Failure('test')
        def restore(): raise Failure('restore')
        with self.assertRaises(ExceptionGroup) as failure:
            with_restoration(fail, restore)
        self.assertEqual([str(e) for e in failure.exception.exceptions], ['test','restore'])

    def test_keyboard_interrupt_still_restores_and_cleans(self):
        restored=mock.Mock()
        def interrupted(): raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): with_restoration(interrupted, restored)
        restored.assert_called_once_with()
        fake=mock.Mock(); fake.run_all.side_effect=KeyboardInterrupt()
        with mock.patch(__name__+'.Driver',return_value=fake), mock.patch('builtins.print'):
            with self.assertRaises(KeyboardInterrupt): main()
        fake.cleanup.assert_called_once_with()
        fake.cleanup.side_effect=Failure('cleanup')
        with mock.patch(__name__+'.Driver',return_value=fake), mock.patch('builtins.print'):
            with self.assertRaises(BaseExceptionGroup) as failure: main()
        self.assertIsInstance(failure.exception.exceptions[0], KeyboardInterrupt)
        self.assertEqual(str(failure.exception.exceptions[1]), 'cleanup')

    def test_projection_query_requires_scope_and_canonical_direction(self):
        driver=Driver.__new__(Driver); driver.base=mock.Mock()
        driver.base.psql.return_value='0,0,0,0'
        driver.proof()
        query=driver.base.psql.call_args.args[0]
        for marker in ['w.source_id', 'w.project_id', 'w.service_id', 'w.environment_id', 'w.deployment_id', 'o.canonical_key', 'request', 'response', 'POST', '/pilot']:
            self.assertIn(marker,query)
        self.assertEqual(operation_key('request'), '["00000000-0000-4000-8000-000000000001","00000000-0000-4000-8000-000000000002","00000000-0000-4000-8000-000000000003","00000000-0000-4000-8000-000000000004","http","request","POST","/pilot"]')
        driver.base.psql.return_value='4,1,2,1'
        with self.assertRaises(Failure): driver.proof()

    def test_typed_event_parser_counts_only_exact_marker_in_current_container(self):
        driver=Driver.__new__(Driver)
        def compose(name,args,seconds=90,extra_config=None):
            if name == 'event-container': return b'container-1\n'
            return b'apicontour_native_gateway: forwarder_certificate_missing\nother text\n'
        driver.compose=compose
        self.assertEqual(driver.event_snapshot('forwarder_certificate_missing'), (b'container-1',1))
        self.assertEqual(driver.event_snapshot('forwarder_leaf_rejected'), (b'container-1',0))

    def test_generic_failure_without_new_typed_tls_event_fails(self):
        driver=Driver.__new__(Driver)
        driver.stable=lambda: (4,0,2,2)
        driver.write_override=lambda *args: Path('/synthetic/override')
        driver.compose=lambda name,args,seconds=90,extra_config=None: b'native-envoy\n' if name.endswith('-running') else b''
        driver.product_closed=lambda name: None
        driver.product=lambda name: None
        driver.wait_growth=lambda before,minimum,label: None
        driver.proof=lambda: (4,0,2,2)
        driver.run=lambda name,args,seconds: None
        for snapshots in [[(b'unchanged',0),(b'unchanged',0)], [(b'unchanged',1)], [(b'first',0),(b'second',1)]]:
            values=iter(snapshots)
            driver.event_snapshot=lambda name: next(values)
            with mock.patch(__name__+'.time.sleep'):
                with self.assertRaises(Failure): driver.negative('missing-forwarder','native-envoy','/run/config',{})

    def test_provision_builds_before_explicit_expired_renewal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            driver=Driver.__new__(Driver)
            calls=[]
            driver.run=lambda name, args, seconds: calls.append((name,args)) or b''
            driver.compose=lambda name,args,seconds=90,extra_config=None: b''
            with mock.patch(__name__+'.STATE',Path(directory)), mock.patch(__name__+'.is_expired_or_pending',return_value=True):
                driver.provision()
            names=[name for name,_ in calls]
            self.assertLess(names.index('build'), names.index('pilot-capture-init'))
            self.assertLess(names.index('build'), names.index('pilot-explicit-renew'))
            command=next(args for name,args in calls if name=='pilot-explicit-renew')
            self.assertEqual(command[-2:], ['--profile','pilot'])
            calls.clear()
            with mock.patch(__name__+'.STATE',Path(directory)), mock.patch(__name__+'.is_expired_or_pending',return_value=False):
                driver.provision()
            self.assertNotIn('pilot-explicit-renew',[name for name,_ in calls])

    def test_private_log_has_a_hard_size_limit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory, mock.patch(__name__+'.MAX_LOG',1024):
            path=Path(directory)/'bounded.log'
            with self.assertRaises(Failure):
                run_bounded([sys.executable,'-c','import sys;sys.stdout.write("x"*4096);sys.stdout.flush()'],cwd=Path(directory),env=dict(os.environ),log=path,seconds=5)
            self.assertLessEqual(path.stat().st_size,1024)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_negative_restores_before_normal_preflight_and_checks_counts(self):
        driver=Driver.__new__(Driver)
        events=[]
        driver.stable=lambda: (4,0,2,2)
        driver.write_override=lambda *args: Path('/synthetic/override')
        def compose(name,args,seconds=90,extra_config=None):
            events.append(name)
            return b'native-envoy\n' if name.endswith('-running') else b''
        driver.compose=compose
        driver.product_closed=lambda name: events.append(name)
        driver.proof=lambda: (4,0,2,2)
        driver.run=lambda name,args,seconds: events.append(name)
        driver.product=lambda name: events.append(name)
        driver.wait_growth=lambda before,minimum,label: events.append(label)
        snapshots=iter([(b'gateway',0),(b'gateway',1)])
        driver.event_snapshot=lambda event: next(snapshots)
        with mock.patch(__name__+'.time.sleep'):
            driver.negative('missing-forwarder','native-envoy','/run/config',{})
        self.assertLess(events.index('missing-forwarder-closed'),events.index('missing-forwarder-restore'))
        self.assertLess(events.index('missing-forwarder-restore'),events.index('missing-forwarder-preflight'))
        self.assertEqual(events.count('missing-forwarder-preflight'),1)
        driver.proof=lambda: (5,0,3,2)
        snapshots=iter([(b'gateway',0),(b'gateway',1)])
        events.clear()
        with mock.patch(__name__+'.time.sleep'):
            with self.assertRaises(Failure): driver.negative('missing-forwarder','native-envoy','/run/config',{})
        self.assertIn('missing-forwarder-restore',events)
        self.assertNotIn('missing-forwarder-preflight',events)


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]])
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit('expected no arguments or --self-test')
