"""Closed synthetic origin identity bundle; no policy or runtime startup.

Partial generation is retained and classified DRIFT: it is never repaired or
reissued implicitly. The caller supplies the operator-owned synthetic CA paths.
"""
import hashlib
import base64
import binascii
import os
from pathlib import Path
import secrets
import stat
import subprocess
import tempfile

from deploy.local import capture_profiles, capture_renew
from deploy.pilot import origin_setup_state as state

# name, key destination, certificate destination, purpose, exact SANs, DER cert
# destinations, DER key destinations. Paths are relative to the closed state.
CERTS = (
 ('capture-server','capture/private/server.key','capture/private/server.crt','serverAuth','DNS:localhost,DNS:ingress,IP:127.0.0.1',('capture/runtime/server.crt.der',),('capture/private/server.key.der','capture/runtime/server.key.der')),
 ('collector','capture/private/collector.key','capture/private/collector.crt','clientAuth','DNS:localhost,DNS:ingress,IP:127.0.0.1',('capture/runtime/collector.crt.der',),('capture/private/collector.key.der',)),
 ('replica1-client','replica1/client.key','replica1/client.crt','clientAuth','DNS:replica1',('replica1/client.crt.der',),()),
 ('replica1-server','replica1/server.key','replica1/server.crt','serverAuth','DNS:localhost,DNS:replica1,IP:127.0.0.1',(),()),
 ('replica2-client','replica2/client.key','replica2/client.crt','clientAuth','DNS:replica2',('replica2/client.crt.der',),()),
 ('replica2-server','replica2/server.key','replica2/server.crt','serverAuth','DNS:localhost,DNS:replica2,IP:127.0.0.1',(),()),
 ('destination','destination/server.key','destination/server.crt','serverAuth','DNS:pilot-destination',(),()),
 ('edge','native/forwarder/edge.key','native/forwarder/edge.pem','serverAuth','DNS:pilot-gateway,DNS:pilot-destination',(),()),
 ('gateway','native/gateway/server-key.pem','native/gateway/server.pem','serverAuth','DNS:native-gateway.test',('native/gateway/server.der',),('native/gateway/server-key.der',)),
 ('forwarder','native/forwarder/forwarder.key','native/forwarder/forwarder.pem','clientAuth','DNS:envoy-forwarder',('native/gateway/forwarder.der',),()),
 ('upstream-client','native/gateway/upstream-client-key.pem','native/gateway/upstream-client.pem','clientAuth','DNS:native-observer-upstream',('native/gateway/upstream-client.der',),('native/gateway/upstream-client-key.der',)),
)
COPIES = {
 'native/gateway/collector.der':'capture/runtime/collector.crt.der',
 'native/gateway/collector-key.der':'capture/private/collector.key.der',
 'native/gateway/policy-public-key.bin':'capture/runtime/policy.raw',
}
CA_DER = ('capture/runtime/ca.der','native/gateway/forwarder-ca.der','native/gateway/upstream-ca.der','native/gateway/delivery-ca.der')
CA_PEM = ('native/forwarder/pilot-ca.pem','native/forwarder/observer-ca.pem')
OTHER = ('capture/private/policy.key','capture/runtime/policy.raw','capture/runtime/ingress.password','capture/runtime/worker.password')
FILES = frozenset([part for _,key,cert,_,_,ders,keys in CERTS for part in (key,cert,*ders,*keys)] + list(COPIES) + list(CA_DER) + list(CA_PEM) + list(OTHER))
DIRS = frozenset(str(parent) for path in FILES for parent in Path(path).parents if str(parent) != '.')


def _run(*args):
    result = subprocess.run(['openssl', *map(str,args)], capture_output=True, timeout=30)
    if result.returncode: raise ValueError('credential cryptographic validation failed')
    return result.stdout


def _parse_leaf_inspection(raw, purpose, sans):
    """Parse only the fixed public key, two extensions and checkend result."""
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= 65536 or not raw.endswith(b'\n')
            or any(byte != 10 and not 32 <= byte <= 126 for byte in raw)):
        raise ValueError('invalid certificate inspection output')
    try:
        lines=raw.decode('ascii').splitlines()
        end=lines.index('-----END PUBLIC KEY-----')
        if lines[0]!='-----BEGIN PUBLIC KEY-----' or end<2:
            raise ValueError('invalid certificate public key')
        body=lines[1:end]
        if any(not line or len(line)>64 for line in body): raise ValueError('invalid public key encoding')
        if not base64.b64decode(''.join(body),validate=True): raise ValueError('empty public key')
        tail=lines[end+1:]
        if len(tail)!=5 or tail[-1]!='Certificate will not expire': raise ValueError('invalid certificate inspection sections')
        sections={}
        for index in (0,2):
            header=tail[index].strip()
            if header.endswith(' critical'): header=header[:-9]
            if header not in ('X509v3 Extended Key Usage:', 'X509v3 Subject Alternative Name:') or header in sections:
                raise ValueError('invalid certificate extension')
            sections[header]=tail[index+1].strip()
        if sections.get('X509v3 Extended Key Usage:') != ('TLS Web Client Authentication' if purpose=='clientAuth' else 'TLS Web Server Authentication'):
            raise ValueError('leaf purpose drift')
        if sections.get('X509v3 Subject Alternative Name:') != sans.replace('IP:','IP Address:').replace(',',', '):
            raise ValueError('leaf SAN drift')
        return ('\n'.join(lines[:end+1])+'\n').encode('ascii')
    except (UnicodeError, IndexError, binascii.Error) as error:
        raise ValueError('invalid certificate inspection output') from error


def _write(path, data):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    dfd = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(dfd)
    finally: os.close(dfd)


def _file(path, limit=65536):
    info = os.lstat(path)
    if stat.S_IMODE(info.st_mode)!=0o600: raise ValueError('credential mode')
    return capture_renew.read_file(path,limit)


def _dir(path):
    info=os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('credential directory')


def _walk(root, allow_renewal=False):
    result=set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        base=Path(directory)
        for name in dirs:
            path=base/name; _dir(path); result.add(str(path.relative_to(root))+'/')
        for name in files:
            path=base/name
            if base == root and name in ('setup.lock','setup.json'):
                result.add(name); continue
            relative=str(path.relative_to(root))
            if allow_renewal and relative=='capture/private/origin-renew.lock':
                info=os.lstat(path)
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: raise ValueError('renewal lock drift')
            elif allow_renewal and relative=='capture/private/origin-renew.pending':
                _file(path,9*((capture_renew.MAX_ENVELOPE+2)//3)*4+4096)
            else: _file(path)
            result.add(relative)
    return result


def _expected(): return set(FILES) | {directory+'/' for directory in DIRS}


class Credentials:
    def __init__(self, profile, ca_cert, ca_key):
        if profile is not capture_profiles.ORIGIN_PILOT: raise ValueError('unsupported origin profile')
        self.profile, self.ca_cert, self.ca_key = profile, Path(ca_cert), Path(ca_key)
        self.allow_observer_policy = False
        self.allow_renewal_artifacts = frozenset()

    def inspect(self):
        root=self.profile.state
        try:
            _dir(root)
            entries = _walk(root, bool(self.allow_renewal_artifacts)) - {'setup.lock','setup.json'}
            entries -= self.allow_renewal_artifacts
            if self.allow_observer_policy: entries.discard('capture/private/observer-policy.json')
            if not entries: return state.ABSENT
            if entries != _expected(): return state.DRIFT
            self._verify()
            return state.EXACT
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError): return state.DRIFT

    def commitment(self):
        if self.inspect() != state.EXACT: raise ValueError('credential bundle drift')
        digest=hashlib.sha256()
        for name in sorted(FILES):
            digest.update(name.encode() + b'\0' + hashlib.sha256(_file(self.profile.state/name)).digest())
        return digest.hexdigest()

    def _verify(self):
        root=self.profile.state
        ca=_file(self.ca_cert); ca_key=_file(self.ca_key,16384)
        # Use private temporary files, not process arguments, for sensitive bytes.
        with tempfile.TemporaryDirectory(prefix='.origin-check-') as tmp:
            tmp=Path(tmp); caf=tmp/'ca'; cak=tmp/'ca.key'; caf.write_bytes(ca); cak.write_bytes(ca_key)
            ca_pub=_run('x509','-in',caf,'-pubkey','-noout')
            key_pub=_run('pkey','-in',cak,'-pubout')
            if ca_pub != key_pub: raise ValueError('CA key mismatch')
            ca_der=_run('x509','-in',caf,'-outform','DER')
            if any(_file(root/p)!=ca_der for p in CA_DER) or any(_file(root/p)!=ca for p in CA_PEM): raise ValueError('CA copy drift')
            fingerprints=[]; public_keys=[]
            for name,key,cert,purpose,sans,ders,keys in CERTS:
                key_data=_file(root/key,16384); cert_data=_file(root/cert)
                keyf=tmp/'key'; certf=tmp/'cert'; keyf.write_bytes(key_data); certf.write_bytes(cert_data)
                inspected=_run('x509','-in',certf,'-pubkey','-ext','extendedKeyUsage,subjectAltName','-checkend','0','-noout')
                if _parse_leaf_inspection(inspected,purpose,sans) != _run('pkey','-in',keyf,'-pubout'): raise ValueError('leaf key mismatch')
                public_keys.append(_run('pkey','-in',keyf,'-pubout','-outform','DER'))
                _run('verify','-CAfile',caf,'-purpose','sslclient' if purpose=='clientAuth' else 'sslserver',certf)
                der=_run('x509','-in',certf,'-outform','DER')
                keyder=_run('pkcs8','-topk8','-nocrypt','-in',keyf,'-outform','DER')
                if any(_file(root/p)!=der for p in ders) or any(_file(root/p)!=keyder for p in keys): raise ValueError('DER copy drift')
                fingerprints.append(hashlib.sha256(der).digest())
            if len(set(fingerprints))!=len(fingerprints) or len(set(public_keys))!=len(public_keys): raise ValueError('duplicate identity')
            signer=tmp/'signer'; signer.write_bytes(_file(root/'capture/private/policy.key',16384))
            public=_run('pkey','-in',signer,'-pubout','-outform','DER')
            if len(public)!=44 or public[:12]!=bytes.fromhex('302a300506032b6570032100') or _file(root/'capture/runtime/policy.raw',32)!=public[-32:]: raise ValueError('signer drift')
            passwords=[_file(root/('capture/runtime/'+n+'.password'),4096) for n in ('ingress','worker')]
            if passwords[0]==passwords[1] or any(len(p)<32 for p in passwords): raise ValueError('role secret drift')
            if any(_file(root/dest)!=_file(root/src) for dest,src in COPIES.items()): raise ValueError('credential copy drift')

    def apply(self):
        root=self.profile.state
        ca=_file(self.ca_cert); ca_key=_file(self.ca_key,16384)
        # Freeze the validated issuer inputs before any bundle directory exists.
        with tempfile.TemporaryDirectory(prefix='.origin-issue-') as tmp:
            tmp=Path(tmp); ca_file=tmp/'ca.crt'; ca_key_file=tmp/'ca.key'
            _write(ca_file,ca); _write(ca_key_file,ca_key)
            if _run('x509','-in',ca_file,'-pubkey','-noout') != _run('pkey','-in',ca_key_file,'-pubout'):
                raise ValueError('CA key mismatch')
            # Creation is exclusive; interruptions leave partial state as DRIFT.
            for directory in sorted(DIRS,key=lambda p:(p.count('/'),p)):
                target = root/directory
                target.mkdir(mode=0o700)
                parent = os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try: os.fsync(parent)
                finally: os.close(parent)
            for name,key,cert,purpose,sans,ders,keys in CERTS:
                config=tmp/'req.cnf'; config.write_text('[req]\ndistinguished_name=dn\n[dn]\n')
                ext=tmp/'ext.cnf'; ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+purpose+'\nsubjectAltName='+sans+'\n')
                k=tmp/'key.pem'; csr=tmp/'req.csr'; c=tmp/'cert.pem'
                _run('req','-new','-newkey','rsa:3072','-nodes','-sha256','-config',config,'-subj','/CN=local-origin-fixture','-keyout',k,'-out',csr)
                _run('x509','-req','-in',csr,'-CA',ca_file,'-CAkey',ca_key_file,'-set_serial',str(secrets.randbits(127)+1),'-days','7','-sha256','-extfile',ext,'-out',c)
                _write(root/key,k.read_bytes()); _write(root/cert,c.read_bytes())
                der=_run('x509','-in',c,'-outform','DER'); kd=_run('pkcs8','-topk8','-nocrypt','-in',k,'-outform','DER')
                for path in ders: _write(root/path,der)
                for path in keys: _write(root/path,kd)
            policy=tmp/'policy.key'; _run('genpkey','-algorithm','ED25519','-out',policy)
            pub=_run('pkey','-in',policy,'-pubout','-outform','DER')
            if len(pub)!=44 or pub[:12]!=bytes.fromhex('302a300506032b6570032100'): raise ValueError('signer format')
            _write(root/'capture/private/policy.key',policy.read_bytes()); _write(root/'capture/runtime/policy.raw',pub[-32:])
            for name in ('ingress','worker'): _write(root/('capture/runtime/'+name+'.password'),secrets.token_urlsafe(32).encode())
            ca_der=_run('x509','-in',ca_file,'-outform','DER')
            for path in CA_DER: _write(root/path,ca_der)
            for path in CA_PEM: _write(root/path,ca)
            for dest,src in COPIES.items(): _write(root/dest,_file(root/src))
