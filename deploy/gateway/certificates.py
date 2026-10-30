"""Bounded local certificate publication for the synthetic gateway fixture.

Single writer only. The CA and its private key must be outside the publication tree.
"""
import os
import json
from pathlib import Path
import re
import stat
import shutil
import subprocess
import tempfile
import uuid


def _run(*args):
    try:
        return subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=30).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValueError('certificate operation failed') from exc


class Certificates:
    def __init__(self, directory, ca, ca_key, hostname):
        self.directory = Path(directory).resolve()
        self.ca = Path(ca).resolve()
        self.ca_key = Path(ca_key).resolve()
        if self.directory in self.ca.parents or self.directory in self.ca_key.parents:
            raise ValueError('CA material must be outside publication directory')
        if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', hostname):
            raise ValueError('invalid hostname')
        self.hostname = hostname
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.stat().st_mode & 0o077:
            raise ValueError('publication directory must be private')

    def _target(self, link, required=True):
        p = self.directory / link
        if not p.is_symlink():
            if not p.exists() and not required:
                return None
            raise ValueError('missing or corrupt certificate state')
        target = os.readlink(p)
        if not re.fullmatch(r'v-[0-9a-f]{32}', target) or (self.directory / target).is_symlink() or not (self.directory / target).is_dir():
            raise ValueError('missing or corrupt certificate state')
        return target

    def _read(self, path, limit=65536):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                    raise ValueError('invalid certificate input')
                data = stream.read(limit + 1)
                if len(data) > limit:
                    raise ValueError('invalid certificate input')
                return data
        except OSError as exc:
            raise ValueError('invalid certificate input') from exc

    def _validate(self, cert, key, *, allow_expired=False):
        options = ['-no_check_time'] if allow_expired else []
        _run('verify', '-x509_strict', '-purpose', 'sslserver', '-verify_hostname', self.hostname,
             *options, '-CAfile', self.ca, cert)
        sans = _run('x509', '-in', cert, '-noout', '-ext', 'subjectAltName').decode('ascii')
        if self.hostname not in re.findall(r'DNS:([^,\s]+)', sans):
            raise ValueError('certificate lacks exact DNS name')
        pubcert = _run('x509', '-in', cert, '-pubkey', '-noout')
        pubkey = _run('pkey', '-in', key, '-pubout')
        if pubcert != pubkey:
            raise ValueError('certificate key mismatch')
        if pubkey == _run('pkey', '-in', self.ca_key, '-pubout'):
            raise ValueError('issuer key cannot be published')

    def _previous(self, current):
        path = self.directory / current / 'previous'
        try:
            value = self._read(path, 64).decode('ascii')
        except (UnicodeError, ValueError) as exc:
            raise ValueError('missing or corrupt certificate state') from exc
        if value == '':
            return None
        if not re.fullmatch(r'v-[0-9a-f]{32}', value) or not (self.directory / value).is_dir():
            raise ValueError('missing or corrupt certificate state')
        return value

    def _swap(self, name, target):
        tmp = self.directory / ('.link-' + uuid.uuid4().hex)
        try:
            os.symlink(target, tmp)
            os.replace(tmp, self.directory / name)
        finally:
            if tmp.is_symlink():
                tmp.unlink()

    def _prune(self):
        current = self._target('current')
        keep = {current, self._previous(current)}
        for p in self.directory.iterdir():
            if re.fullmatch(r'v-[0-9a-f]{32}', p.name) and p.name not in keep and p.is_dir() and not p.is_symlink():
                shutil.rmtree(p)

    def activate(self, cert, key):
        current = self._target('current', False)
        if current:
            self._previous(current)
            self._validate(self.directory / current / 'cert.pem', self.directory / current / 'key.pem', allow_expired=True)
        # Read and validate outside the mount. Accept exactly one PEM object of each
        # type, so an otherwise valid first object cannot smuggle trailing secrets.
        cert_data, key_data = self._read(cert), self._read(key)
        patterns = (rb'\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*',
                    rb'\s*-----BEGIN (?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\s+[A-Za-z0-9+/=\s]+-----END (?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\s*')
        if not re.fullmatch(patterns[0], cert_data) or not re.fullmatch(patterns[1], key_data):
            raise ValueError('invalid certificate input')
        with tempfile.TemporaryDirectory(prefix='stage-', dir=self.directory.parent) as temp:
            stage = Path(temp)
            (stage / 'cert.pem').write_bytes(cert_data)
            (stage / 'key.pem').write_bytes(key_data)
            os.chmod(stage / 'key.pem', 0o600)
            self._validate(stage / 'cert.pem', stage / 'key.pem')
            # OpenSSL output is canonical single-object PEM, never the input bytes.
            cert_data = _run('x509', '-in', stage / 'cert.pem')
            key_data = _run('pkey', '-in', stage / 'key.pem')
        self._publish(cert_data, key_data, current)

    def _publish(self, cert_data, key_data, previous):
        name = 'v-' + uuid.uuid4().hex
        version = self.directory / name
        version.mkdir(mode=0o700)
        try:
            for dest, data in (('cert.pem', cert_data), ('key.pem', key_data), ('previous', (previous or '').encode('ascii'))):
                with os.fdopen(os.open(version / dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as dst:
                    dst.write(data)
            self._swap('current', name)
        except BaseException:
            if self._target('current', False) != name:
                shutil.rmtree(version)
            raise
        self._prune()

    def rollback(self):
        current = self._target('current')
        previous = self._previous(current)
        if previous is None:
            raise ValueError('missing or corrupt certificate state')
        cert, key = self.directory / previous / 'cert.pem', self.directory / previous / 'key.pem'
        self._validate(cert, key)
        self._publish(self._read(cert), self._read(key), current)

    def sds_document(self):
        """Describe the validated committed leaf; publication is a separate step."""
        current = self._target('current')
        self._previous(current)
        cert = self.directory / current / 'cert.pem'
        key = self.directory / current / 'key.pem'
        self._read(cert)
        self._read(key)
        self._validate(cert, key)
        return json.dumps({'version_info': current, 'resources': [{
            '@type': 'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret',
            'name': 'gateway', 'tls_certificate': {
                'certificate_chain': {'filename': '/certs/' + current + '/cert.pem'},
                'private_key': {'filename': '/certs/' + current + '/key.pem'},
            }}]}, separators=(',', ':')).encode('ascii')

    def renewal_due(self, seconds):
        if type(seconds) is not int or seconds < 0:
            raise ValueError('invalid renewal threshold')
        current = self._target('current')
        self._previous(current)
        cert = self.directory / current / 'cert.pem'
        self._validate(cert, self.directory / current / 'key.pem', allow_expired=True)
        result = subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', str(seconds)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode not in (0, 1):
            raise ValueError('certificate expiry check failed')
        return result.returncode == 1

    def issue(self, days=1):
        if type(days) is not int or not 1 <= days <= 365:
            raise ValueError('invalid certificate lifetime')
        with tempfile.TemporaryDirectory(prefix='issue-', dir=self.directory.parent) as temp:
            p = Path(temp)
            key, csr, cert, ext = (p / n for n in ('key', 'csr', 'cert', 'ext'))
            ext.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:' + self.hostname + '\nextendedKeyUsage=serverAuth\n')
            _run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', '/CN=' + self.hostname)
            _run('x509', '-req', '-in', csr, '-CA', self.ca, '-CAkey', self.ca_key, '-set_serial', str(int.from_bytes(os.urandom(20), 'big')), '-out', cert, '-days', str(days), '-extfile', ext)
            self.activate(cert, key)
