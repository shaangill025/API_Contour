"""Local OpenSSL 3.6.3 CA snapshot prototype; not deployment authority.

Point observations only: the trusted host, its dynamic libraries, and its clock
remain prerequisites. The future factory/control-plane handoff is not implemented.
"""
import datetime
import hashlib
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import tempfile
import time

_TOOL_HASH = '103fc7706cf6646f226d96f29242d81890363499afc730e7ef1fadd64b3a123c'
_TOKEN = object()
_MAX = 65536


def _identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size,
            s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)


def _tool(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('invalid tool path')
    for parent in reversed(path.parents):
        s = os.lstat(parent)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0, os.getuid()) or s.st_mode & 0o022:
            raise ValueError('unsafe tool path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid()
                or stat.S_IMODE(s.st_mode) != 0o500 or s.st_nlink != 1 or s.st_size > 16 * 1024 * 1024):
            raise ValueError('unsafe tool')
        h = hashlib.sha256()
        while chunk := os.read(fd, 65536):
            h.update(chunk)
        if h.hexdigest() != _TOOL_HASH or _identity(os.fstat(fd)) != _identity(s) or _identity(os.lstat(path)) != _identity(s):
            raise ValueError('tool drift')
        return _identity(s)
    finally:
        os.close(fd)


def _open_parent(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.name:
        raise ValueError('unsafe CA path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    chain = []
    try:
        parts = path.parts[1:-1]
        for index in range(len(parts) + 1):
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or info.st_mode & 0o022):
                raise ValueError('unsafe CA parent')
            if index == len(parts) and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError('unsafe CA parent')
            chain.append((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid))
            if index < len(parts):
                child = os.open(parts[index], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
        return fd, tuple(chain)
    except Exception:
        os.close(fd)
        raise


def _snapshot(path):
    parent_fd = None
    fd = None
    try:
        parent_fd, chain = _open_parent(path)
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or
                stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1 or not 0 < s.st_size <= _MAX):
            raise ValueError('unsafe CA snapshot')
        data = b''
        while len(data) <= _MAX:
            part = os.read(fd, _MAX + 1 - len(data))
            if not part:
                break
            data += part
        again, final_chain = _open_parent(path)
        try:
            final = os.stat(Path(path).name, dir_fd=again, follow_symlinks=False)
            if (len(data) != s.st_size or _identity(os.fstat(fd)) != _identity(s)
                    or _identity(final) != _identity(s) or final_chain != chain):
                raise ValueError('CA snapshot drift')
        finally:
            os.close(again)
        if not re.fullmatch(rb'-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END CERTIFICATE-----\n', data):
            raise ValueError('invalid CA PEM')
        return data, (_identity(s), chain)
    except OSError:
        raise ValueError('unsafe CA path') from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _run(tool, args, input_file):
    # Fixed arguments and private file stdin; bound both elapsed time and stdout.
    with open(input_file, 'rb') as source:
        p = subprocess.Popen([str(tool), *args], stdin=source, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
        result = bytearray()
        deadline = time.monotonic() + 10
        sel = selectors.DefaultSelector()
        try:
            sel.register(p.stdout, selectors.EVENT_READ)
            while sel.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise ValueError('certificate inspection timeout')
                if not sel.select(left):
                    raise ValueError('certificate inspection timeout')
                part = os.read(p.stdout.fileno(), 4096)
                if not part:
                    sel.unregister(p.stdout)
                    break
                result.extend(part)
                if len(result) > _MAX:
                    raise ValueError('certificate inspection output too large')
            if p.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                raise ValueError('certificate inspection failed')
            return bytes(result)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError('certificate inspection failed') from None
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            sel.close()
            p.stdout.close()


class _LocalCaReceipt:
    __slots__ = ('_path', '_data', '_file_id', '_tool', '_tool_id', '_before', '_after')

    def __init__(self, token, path, data, file_id, tool, tool_id, before, after):
        if token is not _TOKEN:
            raise ValueError('private receipt')
        self._path, self._data, self._file_id = path, data, file_id
        self._tool, self._tool_id = tool, tool_id
        self._before, self._after = before, after

    def revalidate(self):
        data, identity = _snapshot(self._path)
        if (data != self._data or identity != self._file_id or _tool(self._tool) != self._tool_id
                or not self._before <= datetime.datetime.now(datetime.timezone.utc) < self._after):
            raise ValueError('CA receipt drift')
        return hashlib.sha256(data).digest()


def inspect_local_ca(path, openssl):
    """Inspect one private CA file and return local snapshot evidence, not authority."""
    path, openssl = Path(path), Path(openssl)
    tool_id = _tool(openssl)
    data, file_id = _snapshot(path)
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / 'ca.pem'
        fd = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
        local_id = _identity(os.lstat(local))
        version = _run(openssl, ['version'], local)
        if not re.fullmatch(rb'OpenSSL 3\.6\.3 9 Jun 2026(?: \(Library: OpenSSL 3\.6\.3 9 Jun 2026\))?\n', version):
            raise ValueError('unqualified OpenSSL version')
        dates = _run(openssl, ['x509', '-noout', '-dates', '-dateopt', 'iso_8601'], local)
        match = re.fullmatch(rb'notBefore=(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)Z\nnotAfter=(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)Z\n', dates)
        if not match:
            raise ValueError('invalid CA dates')
        before, after = (datetime.datetime.strptime(v.decode('ascii'), '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc) for v in match.groups())
        if not before <= datetime.datetime.now(datetime.timezone.utc) < after:
            raise ValueError('CA outside validity')
        constraints = _run(openssl, ['x509', '-noout', '-ext', 'basicConstraints'], local)
        if not re.fullmatch(rb'X509v3 Basic Constraints:(?: critical)?\n    CA:TRUE(?:, pathlen:\d+)?\n', constraints):
            raise ValueError('invalid CA constraints')
        usage = _run(openssl, ['x509', '-noout', '-ext', 'keyUsage'], local)
        if not re.fullmatch(rb'X509v3 Key Usage:(?: critical)?\n    Certificate Sign(?:, CRL Sign)?\n', usage):
            raise ValueError('invalid CA key usage')
        if _run(openssl, ['verify', '-x509_strict', '-check_ss_sig', '-CAfile', str(local), str(local)], local) != (str(local) + ': OK\n').encode():
            raise ValueError('CA verification failed')
        if _identity(os.lstat(local)) != local_id or local.read_bytes() != data:
            raise ValueError('temporary CA drift')
    receipt = _LocalCaReceipt(_TOKEN, path, data, file_id, openssl, tool_id, before, after)
    receipt.revalidate()
    return receipt


class _LocalLeafUsageReceipt:
    """Local point observation; not a certificate or deployment authority."""
    __slots__ = ('_path', '_data', '_file_id', '_tool', '_tool_id')

    def __init__(self, token, path, data, file_id, tool, tool_id):
        if token is not _TOKEN:
            raise ValueError('private receipt')
        self._path, self._data, self._file_id = path, data, file_id
        self._tool, self._tool_id = tool, tool_id

    def revalidate(self):
        data, identity = _snapshot(self._path)
        if data != self._data or identity != self._file_id or _tool(self._tool) != self._tool_id:
            raise ValueError('leaf receipt drift')
        return hashlib.sha256(data).digest()


def inspect_local_leaf_usage(path, openssl):
    """Check explicit digitalSignature KU on one captured PEM, without granting authority.

    This does not check a leaf's chain, key, EKU, name, or validity. A future
    factory must bind those independent checks to these exact captured bytes.
    """
    path, openssl = Path(path), Path(openssl)
    tool_id = _tool(openssl)
    data, file_id = _snapshot(path)
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / 'leaf.pem'
        fd = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
        local_id = _identity(os.lstat(local))
        version = _run(openssl, ['version'], local)
        if not re.fullmatch(rb'OpenSSL 3\.6\.3 9 Jun 2026(?: \(Library: OpenSSL 3\.6\.3 9 Jun 2026\))?\n', version):
            raise ValueError('unqualified OpenSSL version')
        usage = _run(openssl, ['x509', '-noout', '-ext', 'keyUsage'], local)
        match = re.fullmatch(rb'X509v3 Key Usage:(?: critical)?\n    ([A-Za-z ,]+)\n', usage)
        allowed = {b'Digital Signature', b'Non Repudiation', b'Key Encipherment',
                   b'Data Encipherment', b'Key Agreement', b'Certificate Sign',
                   b'CRL Sign', b'Encipher Only', b'Decipher Only'}
        values = match.group(1).split(b', ') if match else []
        if not values or len(values) != len(set(values)) or any(v not in allowed for v in values) or b'Digital Signature' not in values:
            raise ValueError('invalid leaf key usage')
        if _identity(os.lstat(local)) != local_id or local.read_bytes() != data:
            raise ValueError('temporary leaf drift')
    receipt = _LocalLeafUsageReceipt(_TOKEN, path, data, file_id, openssl, tool_id)
    receipt.revalidate()
    return receipt
