#!/usr/bin/env python3
"""Exercise local certificate rotation through the pinned Envoy image."""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
fixture = load('gateway_fixture', 'scripts/test-managed-gateway.py')
certificates = load('certificates', 'deploy/gateway/certificates.py')


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('exchange deadline exceeded')
    return remaining


def _response(tls, deadline):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        tls.settimeout(_remaining(deadline))
        chunk = tls.recv(min(1024, 8193 - len(data)))
        if not chunk:
            raise ValueError('incomplete response headers')
        data.extend(chunk)
        if len(data) > 8192:
            raise ValueError('response headers too large')
    head, body = bytes(data).split(b'\r\n\r\n', 1)
    lines = head.split(b'\r\n')
    if not lines or lines[0] not in (b'HTTP/1.1 201 Created', b'HTTP/1.0 201 Created'):
        raise ValueError('unexpected response status')
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b':')
        name = name.strip().lower()
        if not separator or not name or name in headers:
            raise ValueError('invalid response headers')
        headers[name] = value.strip()
    length = headers.get(b'content-length', b'')
    if not length.isdigit() or len(length) > 5:
        raise ValueError('invalid response length')
    size = int(length)
    if size > 4096 or b'transfer-encoding' in headers or len(body) > size:
        raise ValueError('response body too large')
    while len(body) < size:
        tls.settimeout(_remaining(deadline))
        chunk = tls.recv(min(1024, size - len(body)))
        if not chunk:
            raise ValueError('incomplete response body')
        body += chunk
    if headers.get(b'x-reply') != b'synthetic' or body != fixture.SENTINEL:
        raise ValueError('unexpected application response')


def exchange(port, ca, deadline):
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    with socket.create_connection(('127.0.0.1', port), timeout=_remaining(deadline)) as sock:
        sock.settimeout(_remaining(deadline))
        with ctx.wrap_socket(sock, server_hostname='gateway.test') as tls:
            fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            tls.settimeout(_remaining(deadline))
            tls.sendall(b'POST /probe?q=1 HTTP/1.1\r\nHost: gateway.test\r\nX-Test: synthetic\r\nConnection: close\r\nContent-Length: ' + str(len(fixture.SENTINEL)).encode() + b'\r\n\r\n' + fixture.SENTINEL)
            _response(tls, deadline)
            return fingerprint


def cleanup_container(name):
    def matching():
        output = fixture.cmd('docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}').stdout.decode('utf-8').splitlines()
        if any(item != name for item in output):
            raise RuntimeError('unexpected cleanup listing')
        return bool(output)
    if matching():
        fixture.cmd('docker', 'rm', '-f', name)
    if matching():
        raise RuntimeError('container cleanup failed')


def cleanup_owned(names, server, original):
    failures = []
    for name in names:
        try:
            cleanup_container(name)
        except Exception as error:
            failures.append((name, error))
    try:
        fixture.stop(server)
    except Exception as error:
        failures.append(('server', error))
    if failures:
        message = 'cleanup failed for ' + ', '.join(name for name, _ in failures)
        if original is not None:
            original.add_note(message)
        else:
            raise RuntimeError(message) from failures[0][1]


def publish_sds(name, manager):
    # Fixed command and fixed paths; the document contains references, never keys.
    document = manager.sds_document()
    fixture.cmd('docker', 'exec', '-i', name, '/bin/sh', '-c',
                'cat > /run/watch/sds.pending && mv -f /run/watch/sds.pending /run/watch/sds.json',
                input=document)


def main():
    if os.getuid() == 0:
        raise RuntimeError('run as nonroot')
    fixture.cmd('docker', 'image', 'inspect', fixture.gateway.IMAGE)
    name = 'contour-cert-fixture-' + uuid.uuid4().hex[:12]
    validation_name = name + '-validate'
    with tempfile.TemporaryDirectory(prefix='contour-cert-') as temp:
        root = Path(temp)
        fixture.certs(root)
        # Keep negative cases orthogonal: both have gateway.test and its matching key.
        (root / 'index.txt').write_text('')
        (root / 'serial').write_text('33\n')
        (root / 'ca.cnf').write_text((root / 'ca.cnf').read_text().replace('DNS:upstream.test', 'DNS:gateway.test'))
        fixture.cmd('openssl', 'ca', '-batch', '-config', 'ca.cnf', '-in', 'down.csr', '-out', 'expired-gateway.pem', '-startdate', '20200101000000Z', '-enddate', '20210101000000Z', cwd=root)
        fixture.cmd('openssl', 'x509', '-req', '-in', 'down.csr', '-CA', 'other.pem', '-CAkey', 'other.key', '-set_serial', '456', '-out', 'untrusted-gateway.pem', '-days', '1', '-extfile', 'down.ext', cwd=root)
        # The ca tool emits descriptive text before PEM; canonicalize for the manager.
        (root / 'expired-gateway.pem').write_bytes(fixture.cmd('openssl', 'x509', '-in', 'expired-gateway.pem', cwd=root).stdout)
        fixture.cmd('openssl', 'verify', '-x509_strict', '-purpose', 'sslserver', '-verify_hostname', 'gateway.test', '-no_check_time', '-CAfile', 'ca.pem', 'expired-gateway.pem', cwd=root)
        fixture.cmd('openssl', 'verify', '-x509_strict', '-purpose', 'sslserver', '-verify_hostname', 'gateway.test', '-CAfile', 'other.pem', 'untrusted-gateway.pem', cwd=root)
        fixture.cmd('openssl', 'verify', '-x509_strict', '-purpose', 'sslserver', '-verify_hostname', 'wrong.test', '-CAfile', 'ca.pem', 'wrong.pem', cwd=root)
        published = root / 'published'
        manager = certificates.Certificates(published, root / 'ca.pem', root / 'ca.key', 'gateway.test')
        manager.activate(root / 'down.pem', root / 'down.key')
        (root / 'sds.json').write_bytes(manager.sds_document())
        server = fixture.serve(root, 'up', ssl.TLSVersion.TLSv1_3)
        try:
            host, address, listen_port, network = fixture.network_profile(sys.platform)
            config = fixture.gateway.config(host, server.server_port, listen_address=address, listen_port=listen_port, sds=True)
            (root / 'envoy.json').write_text(json.dumps(config))
            mounts = []
            for source, target in ((root / 'envoy.json', '/fixture/envoy.json'), (root / 'sds.json', '/fixture/sds.json'), (root / 'ca.pem', '/fixture/ca.pem'), (published, '/certs')):
                mounts += ['-v', str(source) + ':' + target + ':ro']
            tmpfs = ['--tmpfs', f'/run/watch:rw,noexec,nosuid,size=1m,mode=0700,uid={os.getuid()},gid={os.getgid()}']
            bootstrap = ['/bin/sh', '-c', 'cp /fixture/sds.json /run/watch/sds.json && exec "$@"', 'fixture-bootstrap']
            try:
                fixture.cmd('docker', 'run', '--pull', 'never', '--rm', '--name', validation_name, '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '256m', '--cpus', '1', '--pids-limit', '128', '--log-driver', 'none', *tmpfs, *mounts, fixture.gateway.IMAGE, *bootstrap, 'envoy', '--mode', 'validate', '-c', '/fixture/envoy.json')
            except subprocess.CalledProcessError as error:
                raise RuntimeError('Envoy validation failed: ' + error.stderr.decode('utf-8', errors='replace')[:4096]) from error
            fixture.cmd('docker', 'run', '--pull', 'never', '-d', '--name', name, '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '256m', '--cpus', '1', '--pids-limit', '128', '--log-driver', 'none', *network, *tmpfs, *mounts, fixture.gateway.IMAGE, *bootstrap, 'envoy', '-c', '/fixture/envoy.json', '--log-level', 'off', '--concurrency', '1')
            port = int(fixture.cmd('docker', 'port', name, '8443/tcp').stdout.decode().strip().rsplit(':', 1)[1]) if sys.platform == 'darwin' else listen_port
            def wait_for(old=None):
                deadline = time.monotonic() + 15
                unchanged = errors = 0
                while time.monotonic() < deadline:
                    try:
                        value = exchange(port, root / 'ca.pem', deadline)
                        if value != old:
                            return value
                        unchanged += 1
                    except (OSError, ssl.SSLError, http.client.HTTPException):
                        errors += 1
                    time.sleep(.1)
                raise AssertionError(f'certificate exchange did not converge (unchanged={unchanged}, transport_errors={errors})')
            first = wait_for()
            for cert, key in (('wrong.pem', 'wrong.key'), ('down.pem', 'wrong.key'),
                              ('expired-gateway.pem', 'down.key'), ('untrusted-gateway.pem', 'down.key')):
                before = os.readlink(published / 'current')
                try:
                    manager.activate(root / cert, root / key)
                except ValueError:
                    pass
                else:
                    raise AssertionError('invalid certificate activation succeeded')
                assert os.readlink(published / 'current') == before
                assert exchange(port, root / 'ca.pem', time.monotonic() + 15) == first
            assert manager.renewal_due(2 * 86400)
            manager.issue()
            publish_sds(name, manager)
            second = wait_for(first)
            assert second != first
            manager.rollback()
            publish_sds(name, manager)
            assert wait_for(second) == first
            assert fixture.cmd('docker', 'inspect', '--format', '{{.HostConfig.LogConfig.Type}}', name).stdout.strip() == b'none'
            assert not (published / 'ca.key').exists()
        finally:
            cleanup_owned((validation_name, name), server, sys.exception())
    print('PASS certificate rotation, new-peer fingerprints, rollback and application exchange')

if __name__ == '__main__':
    main()
