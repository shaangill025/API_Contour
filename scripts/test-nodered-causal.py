#!/usr/bin/env python3
"""Complete offline and synthetic TLS qualification for the fixed Node-RED profile."""
import hashlib
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'
SCOPE = ('Synthetic fixed-runtime opaque intent ownership only; no authenticated ingestion, '
         'wire witness, cross-instance proof, durable graph, performance or full MVP qualification.')


def command(args, *, timeout=30, expected=0):
    result = subprocess.run(args, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if (result.returncode == 0) != (expected == 0):
        raise RuntimeError('command failed: ' + args[0])
    return result


def snapshot():
    paths = [*ROOT.joinpath('collectors/nodered').rglob('*'),
             *ROOT.joinpath('tests/fixtures/nodered-causal').rglob('*'),
             ROOT / 'scripts/test-nodered-causal.py', ROOT / '.github/workflows/native.yml']
    result = {}
    for path in sorted(paths):
        if path.is_symlink():
            raise RuntimeError('symlink in qualification source')
        if path.is_file():
            result[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def container(case, run_id, mounts, args, *, timeout=50):
    name = 'contour-causal-' + run_id + '-' + case
    label = 'org.apicontour.causal-run=' + run_id
    base = ['docker','run','--name',name,'--label',label,'--pull','never','--network','none',
            '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--pids-limit','128','--memory','256m','--cpus','1',
            '--user',str(os.getuid())+':'+str(os.getgid()),
            '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777',
            '-e','NODE_OPTIONS=','-e','NODE_PATH=/usr/src/node-red/node_modules',
            '-v',str(ROOT / 'tests/fixtures/nodered-causal')+':/fixture:ro',
            '-v',str(ROOT / 'collectors/nodered')+':/adapter:ro']
    succeeded = False
    try:
        result = command(base+mounts+['--entrypoint','node',IMAGE]+args, timeout=timeout)
        succeeded = True
        sys.stdout.buffer.write(result.stdout); sys.stdout.buffer.flush()
    finally:
        # Resolve and validate immutable identity before removal; a reused name
        # must never authorize removal of a different container.
        cleanup_error = False
        owned_id = None
        try:
            inspected = subprocess.run(['docker','inspect','--format',
                '{{.Id}} {{ index .Config.Labels "org.apicontour.causal-run" }}',name],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
            if inspected.returncode == 0:
                fields = inspected.stdout.decode('utf8').strip().split()
                if len(fields) != 2 or not re.fullmatch(r'[0-9a-f]{64}', fields[0]) or fields[1] != run_id:
                    cleanup_error = True
                else:
                    owned_id = fields[0]
                    removed = subprocess.run(['docker','rm','-f',owned_id],stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT,timeout=20)
                    cleanup_error = removed.returncode != 0
            else:
                diagnostic = inspected.stdout.decode('utf8','replace').lower()
                if succeeded or not any(x in diagnostic for x in ('no such object', 'no such container')):
                    cleanup_error = True
        except Exception:
            cleanup_error = True
        if owned_id:
            try:
                remaining_id = subprocess.run(['docker','ps','-aq','--no-trunc','--filter','id='+owned_id],
                                               stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
                cleanup_error = cleanup_error or remaining_id.returncode != 0 or bool(remaining_id.stdout.strip())
            except Exception:
                cleanup_error = True
        try:
            remaining = subprocess.run(['docker','ps','-aq','--no-trunc','--filter','name=^/'+name+'$'],
                                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
            cleanup_error = cleanup_error or remaining.returncode != 0 or bool(remaining.stdout.strip())
        except Exception:
            cleanup_error = True
        if cleanup_error:
            raise RuntimeError('owned container cleanup failed: '+case)



def certificates(folder):
    for label in ('ca','unrelated-ca'):
        command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(folder/(label+'-key')),
                 '-out',str(folder/label),'-days','1','-subj','/CN=APIContour-causal-fixture-'+label,
                 '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
    for serial,label,dns in ((1,'server','localhost'),(2,'wrong-name','other.fixture.invalid')):
        extensions=folder/(label+'.extensions')
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+dns+'\n')
        command(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(folder/(label+'-key')),
                 '-out',str(folder/(label+'.csr')),'-subj','/CN='+dns])
        command(['openssl','x509','-req','-in',str(folder/(label+'.csr')),'-CA',str(folder/'ca'),
                 '-CAkey',str(folder/'ca-key'),'-set_serial',str(serial),'-days','1','-extfile',str(extensions),'-out',str(folder/label)])
    for label,ca,expected in (('server','ca',0),('wrong-name','ca',1),('server','unrelated-ca',1)):
        command(['openssl','verify','-purpose','sslserver','-verify_hostname','localhost','-CAfile',str(folder/ca),str(folder/label)],expected=expected)


def qualify():
    os.umask(0o077)
    before=snapshot()
    run_id=uuid.uuid4().hex
    temp=Path(tempfile.mkdtemp(prefix='apicontour-causal-'))
    failure=None
    try:
        inspected=subprocess.run(['docker','image','inspect',IMAGE],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
        if inspected.returncode != 0:
            diagnostic=inspected.stdout.decode('utf8','replace').lower()
            if 'no such image' not in diagnostic and 'image not found' not in diagnostic:
                raise RuntimeError('owned fixture image inspection failed')
            command(['docker','pull',IMAGE],timeout=300)
            command(['docker','image','inspect',IMAGE])
        # Offline modules need the same directory hierarchy as their relative requires.
        mounts=['-v',str(ROOT/'tests/fixtures/nodered-causal')+':/work/tests/fixtures/nodered-causal:ro',
                '-v',str(ROOT/'collectors/nodered')+':/work/collectors/nodered:ro']
        container('offline',run_id,mounts,['/work/tests/fixtures/nodered-causal/complete-offline-suite.js'],timeout=180)
        certs=temp/'certificates'; certs.mkdir(); certificates(certs)
        for case in ('http-regression','https','wrong-ca','wrong-name'):
            mounts=[]
            if case!='http-regression':
                mount=temp/('mount-'+case);mount.mkdir()
                for dest,src in (('ca','unrelated-ca' if case=='wrong-ca' else 'ca'),
                                 ('server','wrong-name' if case=='wrong-name' else 'server'),
                                 ('server-key','wrong-name-key' if case=='wrong-name' else 'server-key')):
                    shutil.copyfile(certs/src,mount/dest);(mount/dest).chmod(0o600)
                mounts=['-v',str(mount)+':/fixture-tls:ro']
            preload='/adapter/bootstrap.js' if case=='http-regression' else '/adapter/error-integration/bootstrap.js'
            fixture='/fixture/image-fixture.js' if case=='http-regression' else '/fixture/image-error-fixture.js'
            args=['--require',preload,fixture]+(['negative'] if case.startswith('wrong-') else [])
            print('CASE '+case,flush=True);container(case,run_id,mounts,args)
    except Exception as exc:
        failure=exc
    finally:
        try:
            shutil.rmtree(temp)
            if os.path.lexists(temp): raise RuntimeError('private temporary files remain')
        except Exception as exc:
            failure=RuntimeError('private temporary cleanup failed: '+type(exc).__name__)
        try:
            if snapshot()!=before: raise RuntimeError('qualification source changed')
        except Exception as exc:
            failure=exc
    if failure: raise failure
    print('PASS: pinned offline suite and four runtime cases. '+SCOPE,flush=True)


def main():
    if len(sys.argv)!=1: raise SystemExit('usage: python3 scripts/test-nodered-causal.py')
    try: qualify()
    except Exception as exc:
        print('FAIL: '+str(exc),file=sys.stderr);raise SystemExit(1)


if __name__=='__main__': main()
