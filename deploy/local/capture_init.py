"""Create synthetic capture-only credentials once; existing state is never replaced."""
import base64
import datetime
import json
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
CAPTURE = STATE / 'capture'
TENANT = '00000000-0000-4000-8000-000000000001'
SERVICE = '00000000-0000-4000-8000-000000000003'
COLLECTOR = '00000000-0000-4000-8000-000000000201'


def run(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, timeout=30)
    if result.returncode: raise RuntimeError('synthetic capture credential generation failed')
    return result.stdout


def main():
    os.umask(0o077)
    if not (STATE / 'ca.key').is_file() or not (STATE / 'ca.crt').is_file():
        raise RuntimeError('local CA missing')
    CAPTURE.mkdir(mode=0o700)
    private = CAPTURE / 'private'; private.mkdir(mode=0o700)
    runtime = CAPTURE / 'runtime'; runtime.mkdir(mode=0o700)
    for name, purpose in [('server', 'serverAuth'), ('collector', 'clientAuth')]:
        config = private / (name + '.cnf')
        config.write_text('[req]\ndistinguished_name=dn\n[dn]\n[ext]\nbasicConstraints=CA:FALSE\nextendedKeyUsage=' + purpose + '\nsubjectAltName=DNS:localhost,DNS:ingress,IP:127.0.0.1\n')
        run('req','-new','-newkey','rsa:3072','-nodes','-sha256','-config',config,'-subj','/CN=local-capture-'+name,'-keyout',private/(name+'.key'),'-out',private/(name+'.csr'))
        run('x509','-req','-in',private/(name+'.csr'),'-CA',STATE/'ca.crt','-CAkey',STATE/'ca.key','-CAcreateserial','-days','30','-sha256','-extfile',config,'-extensions','ext','-out',private/(name+'.crt'))
        run('x509','-in',private/(name+'.crt'),'-outform','DER','-out',runtime/(name+'.crt.der'))
        run('pkcs8','-topk8','-nocrypt','-in',private/(name+'.key'),'-outform','DER','-out',private/(name+'.key.der'))
    (runtime/'server.key.der').write_bytes((private/'server.key.der').read_bytes())
    run('x509','-in',STATE/'ca.crt','-outform','DER','-out',runtime/'ca.der')
    run('genpkey','-algorithm','ED25519','-out',private/'policy.key')
    public = run('pkey','-in',private/'policy.key','-pubout','-outform','DER')
    if len(public) != 44: raise RuntimeError('policy key format invalid')
    (runtime/'policy.raw').write_bytes(public[-32:])
    for name in ['ingress','worker']:
        (runtime/(name+'.password')).write_text(secrets.token_urlsafe(32))
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = lambda d: d.isoformat(timespec='microseconds').replace('+00:00','Z')
    policy = dict(tenant_id=TENANT,collector_id=COLLECTOR,revision=1,issued_at=stamp(now-datetime.timedelta(minutes=1)),expires_at=stamp(now+datetime.timedelta(minutes=14)),enabled=True,service_ids=[SERVICE],techniques=['gateway'],approved_names=['GET','POST','id','name','status'],denied_templates=[],inspection_bytes=65536,depth_limit=32,queue_bytes=1048576,queue_ttl_seconds=3600,durable_queue_enabled=False,approved_route_segments=['orders'],parser_profiles=['http_json_v1'])
    payload = json.dumps(policy,separators=(',',':')).encode()
    (private/'message').write_bytes(b'apicontour/policy/1\n'+payload)
    run('pkeyutl','-sign','-rawin','-inkey',private/'policy.key','-in',private/'message','-out',private/'signature')
    enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
    envelope = dict(key_id='local',signature_profile='ed25519-v1',payload_base64url=enc(payload),signature_base64url=enc((private/'signature').read_bytes()))
    (private/'policy.json').write_text(json.dumps(envelope,separators=(',',':')))
    print('Synthetic capture credentials created; private state retained locally.')

if __name__ == '__main__': main()
