"""Create role-separated native pilot credentials once; never overwrite state.

Operator-only: the existing local CA signs synthetic leaf identities. No private
CA material is copied into a container-mounted directory.
"""
import datetime
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'deploy/local'))
from deploy.pilot import native_envoy, native_gateway_config
import capture_profiles
import capture_renew
import provision as base

STATE = ROOT / '.local-mvp'
PILOT = STATE / 'pilot'
NATIVE = PILOT / 'native'
PROFILE = capture_profiles.PILOT


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('native pilot certificate generation failed; partial state retained')
    return result.stdout


def write(path, data):
    with path.open('xb') as output:
        output.write(data)
    os.chmod(path, 0o600)


def live_policy(private):
    if os.path.lexists(private / 'renew.pending'):
        raise RuntimeError('policy renewal requires reconciliation')
    key = capture_renew.read_file(private/'policy.key', 16384)
    public = capture_renew.crypt('public', key, b'', profile=PROFILE, scratch=tempfile.gettempdir())
    if len(public) != 44 or public[-32:] != capture_renew.read_file(PROFILE.capture/'runtime'/'policy.raw', 32):
        raise RuntimeError('pilot policy signer drift')
    policy = capture_renew.checked_envelope(capture_renew.read_file(private/'policy.json', 16384), public, PROFILE, tempfile.gettempdir())
    expires = datetime.datetime.fromisoformat(policy['expires_at'].replace('Z', '+00:00'))
    if expires.tzinfo is None or datetime.datetime.now(datetime.timezone.utc) >= expires:
        raise RuntimeError('pilot policy expired; run capture_renew.py --profile pilot')
    if policy['collector_id'] != PROFILE.collector:
        raise RuntimeError('pilot policy identity drift')


def gateway_config():
    point = [base.IDS[1],base.IDS[2],base.IDS[3],PROFILE.deployment]
    return native_gateway_config.config(upstream_ip='pilot-destination',delivery_ip='pilot-capture-ingress',
        delivery_name='ingress',tenant=base.IDS[0],collector=PROFILE.collector,source=PROFILE.source,
        workload=point,policy_key_id='local')


def check():
    capture = PROFILE.capture
    for directory in (PILOT, capture, capture/'private', capture/'runtime', NATIVE, NATIVE/'gateway', NATIVE/'forwarder'):
        capture_renew.safe_dir(directory)
    live_policy(capture/'private')
    for name, expected in capture_renew.p.runtime_configs(PROFILE.collector).items():
        if json.loads(capture_renew.read_file(capture/'runtime'/name, 16384)) != expected:
            raise RuntimeError('pilot capture configuration drift')
    gateway, forwarder = NATIVE/'gateway', NATIVE/'forwarder'
    if json.loads(capture_renew.read_file(gateway/'gateway.json', 16384)) != gateway_config():
        raise RuntimeError('native gateway configuration drift')
    if json.loads(capture_renew.read_file(forwarder/'envoy.json', 65536)) != native_envoy.config():
        raise RuntimeError('native forwarder configuration drift')
    for name in ['server.der','server-key.der','forwarder-ca.der','forwarder.der','upstream-ca.der','upstream-client.der','upstream-client-key.der','delivery-ca.der','collector.der','collector-key.der','policy-public-key.bin']:
        capture_renew.read_file(gateway/name, 65536)
    for name in ['edge.pem','edge.key','pilot-ca.pem','observer-ca.pem','forwarder.pem','forwarder.key']:
        capture_renew.read_file(forwarder/name, 65536)
    with (STATE/'ca.crt').open('rb') as approved_file:
        approved_pem = approved_file.read(65537)
    if not 1 <= len(approved_pem) <= 65536:
        raise RuntimeError('approved CA drift')
    if any(capture_renew.read_file(forwarder/name, 65536) != approved_pem for name in ('pilot-ca.pem','observer-ca.pem')):
        raise RuntimeError('approved CA drift')
    approved_der = openssl('x509','-in',STATE/'ca.crt','-outform','DER')
    if capture_renew.read_file(capture/'runtime'/'ca.der', 65536) != approved_der:
        raise RuntimeError('approved CA drift')
    copies = [
        (gateway/'collector.der', capture/'runtime'/'collector.crt.der', 65536),
        (gateway/'collector-key.der', capture/'private'/'collector.key.der', 16384),
        (gateway/'policy-public-key.bin', capture/'runtime'/'policy.raw', 32),
        *[(gateway/name, capture/'runtime'/'ca.der', 65536) for name in ('forwarder-ca.der','upstream-ca.der','delivery-ca.der')],
    ]
    for actual, enrolled, limit in copies:
        if capture_renew.read_file(actual, limit) != capture_renew.read_file(enrolled, limit):
            raise RuntimeError('native credential drift')
    peer_der = openssl('x509','-in',forwarder/'forwarder.pem','-outform','DER')
    if peer_der != capture_renew.read_file(gateway/'forwarder.der', 65536):
        raise RuntimeError('native forwarder identity drift')
    print('Native pilot preflight passed.')


def prepare():
    os.umask(0o077)
    if not PILOT.is_dir() or not (STATE/'ca.crt').is_file() or not (STATE/'ca.key').is_file():
        raise RuntimeError('owned pilot and local CA required')
    capture = PROFILE.capture
    private, runtime = capture/'private', capture/'runtime'
    live_policy(private)
    needed = [runtime/'collector.crt.der', private/'collector.key.der', runtime/'ca.der', runtime/'policy.raw']
    if any(not path.is_file() for path in needed): raise RuntimeError('pilot capture credentials incomplete')
    # Exclusive mkdir refuses prior state, including partial or expired identities.
    NATIVE.mkdir(mode=0o700)
    gateway = NATIVE/'gateway'; gateway.mkdir(mode=0o700)
    forwarder = NATIVE/'forwarder'; forwarder.mkdir(mode=0o700)
    scratch = NATIVE/'private'; scratch.mkdir(mode=0o700)
    request = scratch/'request.cnf'; write(request, b'[req]\ndistinguished_name=dn\n[dn]\n')

    def certificate(name, destination, purpose, san, der):
        ext = scratch/(name+'.cnf')
        write(ext, ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+purpose+'\nsubjectAltName='+san+'\n').encode())
        key = scratch/(name+'.key'); csr = scratch/(name+'.csr'); cert = scratch/(name+'.crt')
        openssl('req','-new','-newkey','rsa:3072','-nodes','-sha256','-config',request,'-subj','/CN=local-native-pilot','-keyout',key,'-out',csr)
        openssl('x509','-req','-in',csr,'-CA',STATE/'ca.crt','-CAkey',STATE/'ca.key','-set_serial',str(secrets.randbits(127)+1),'-days','7','-sha256','-extfile',ext,'-out',cert)
        if der:
            openssl('x509','-in',cert,'-outform','DER','-out',destination/(name+'.der'))
            openssl('pkcs8','-topk8','-nocrypt','-in',key,'-outform','DER','-out',destination/(name+'-key.der'))
        else:
            shutil.copyfile(cert,destination/(name+'.pem'))
            shutil.copyfile(key,destination/(name+'.key'))
        for path in destination.iterdir(): os.chmod(path,0o600)
        return cert

    certificate('edge',forwarder,'serverAuth','DNS:pilot-gateway,DNS:pilot-destination',False)
    certificate('server',gateway,'serverAuth','DNS:native-gateway.test',True)
    forwarder_cert = certificate('forwarder',forwarder,'clientAuth','DNS:envoy-forwarder',False)
    certificate('upstream-client',gateway,'clientAuth','DNS:native-observer-upstream',True)
    openssl('x509','-in',forwarder_cert,'-outform','DER','-out',gateway/'forwarder.der')
    for target in ['forwarder-ca.der','upstream-ca.der','delivery-ca.der']:
        shutil.copyfile(runtime/'ca.der',gateway/target)
    shutil.copyfile(runtime/'collector.crt.der',gateway/'collector.der')
    write(gateway/'collector-key.der',capture_renew.read_file(private/'collector.key.der', 16384))
    shutil.copyfile(runtime/'policy.raw',gateway/'policy-public-key.bin')
    for target in ['pilot-ca.pem','observer-ca.pem']:
        shutil.copyfile(STATE/'ca.crt',forwarder/target)
    for directory in (gateway,forwarder):
        for path in directory.iterdir(): os.chmod(path,0o600)
    config = gateway_config()
    write(gateway/'gateway.json',(json.dumps(config,indent=2)+'\n').encode())
    write(forwarder/'envoy.json',(json.dumps(native_envoy.config(),separators=(',',':'))+'\n').encode())
    print('Native pilot identities prepared; private CA and signer remain operator-only.')


if __name__ == '__main__':
    if len(sys.argv) == 1: prepare()
    elif sys.argv[1:] == ['--check']: check()
    else: raise SystemExit('expected no arguments or --check')
