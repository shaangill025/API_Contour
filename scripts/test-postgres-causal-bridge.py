#!/usr/bin/env python3
"""Offline-built synthetic causal bridge qualification over PostgreSQL TLS.

No arguments. A pinned, already-present PostgreSQL image is required; the probe
is built from current sources with Cargo --locked --offline. The temporary bridge
has masquerading disabled but does not promise to block all egress. Only a
loopback PostgreSQL port is published. The peer pin is a synthetic server
assertion, not an mTLS ingress test or producer attestation.
"""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).absolute().parent.parent
IMAGE='postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'
LABEL='org.apicontour.causal-bridge-test'
IDS=('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',
     'f6000000-0000-4000-8000-000000000001','f7000000-0000-4000-8000-000000000001',
     'f1000000-0000-4000-8000-000000000001','f2000000-0000-4000-8000-000000000001',
     'f3000000-0000-4000-8000-000000000001','f4000000-0000-4000-8000-000000000001',
     'f5000000-0000-4000-8000-000000000001','f9000000-0000-4000-8000-000000000001')
PROVISIONS=('approval','authority','catalog','comparison','declared','human','origin_ingress','review','v2_ingress')
MIGRATIONS=('0001_identity','0002_policy','0003_ingestion','0004_catalog','0005_declared','0006_approval',
            '0007_comparison','0008_review','0009_human','0010_public_contracts','0011_import_selectors',
            '0012_public_comparisons','0013_instance_registry','0014_observation_evidence')
OPT=('0015_origin_lifecycle','0016_v2_unattributed','0017_origin_proofs','0018_causal_runtime_registry','0019_causal_sessions')


def checked(path):
    if not path.is_absolute(): raise ValueError('absolute source path required')
    for p in (path,*path.parents):
        if p.is_symlink(): raise ValueError('symlink in source path')
    if not path.is_file(): raise ValueError('source file unavailable')
    return path.read_bytes()


def source_paths():
    fixed=[ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'crates/contour-postgres/Cargo.toml',
           ROOT/'crates/contour-core/Cargo.toml',ROOT/'crates/contour-auth/Cargo.toml',
           ROOT/'crates/contour-postgres/examples/causal_bridge_probe.rs',
           ROOT/'crates/contour-postgres/src/causal.rs',ROOT/'crates/contour-postgres/src/lib.rs',
           ROOT/'crates/contour-core/src/causal_grant.rs',ROOT/'crates/contour-core/src/policy.rs',
           ROOT/'crates/contour-core/src/causal_event.rs',
           ROOT/'crates/contour-postgres/tests/fixtures/causal_bridge.json',
           ROOT/'db/bootstrap.sql',ROOT/'db/tests/causal_runtime_registry_pre.sql',
           ROOT/'db/tests/causal_session_setup.sql',ROOT/'scripts/test-postgres-causal-bridge.py',
           ROOT/'tests/fixtures/causal-bridge/test_bridge_driver.py',
           ROOT/'db/opt-in-migrations/0020_causal_inbox.sql']
    fixed += [ROOT/('db/provision_'+name+'.sql') for name in PROVISIONS]
    fixed += [ROOT/('db/migrations/'+name+'.sql') for name in MIGRATIONS]
    fixed += [ROOT/('db/opt-in-migrations/'+name+'.sql') for name in OPT]
    for crate in ('contour-postgres','contour-core','contour-auth','contour-platform','contour-ingress','contour-delivery','contour-abi','contour-wasm'):
        fixed.append(ROOT/'crates'/crate/'Cargo.toml')
    for crate in ('contour-postgres','contour-core','contour-auth'):
        source=ROOT/'crates'/crate/'src'
        if source.is_symlink(): raise ValueError('symlink in qualification source')
        if not source.is_dir(): raise ValueError('source directory unavailable')
        def walk_error(error): raise error
        for parent,dirs,files in os.walk(source,followlinks=False,onerror=walk_error):
            if any((Path(parent)/name).is_symlink() for name in dirs+files):
                raise ValueError('symlink in qualification source')
        fixed += sorted(source.rglob('*.rs'))
        build=ROOT/'crates'/crate/'build.rs'
        if build.exists() or build.is_symlink(): fixed.append(build)
    for optional in (ROOT/'.cargo/config',ROOT/'.cargo/config.toml',ROOT/'rust-toolchain',ROOT/'rust-toolchain.toml'):
        if optional.exists() or optional.is_symlink(): fixed.append(optional)
    return sorted(set(fixed))


def digest_file(path):
    if not path.is_absolute(): raise ValueError('absolute source path required')
    for component in (path,*path.parents):
        if component.is_symlink(): raise ValueError('symlink in source path')
    if not path.is_file(): raise ValueError('source file unavailable')
    digest=hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda:handle.read(1_048_576),b''): digest.update(chunk)
    return digest.hexdigest()


def snapshot():
    return {str(p):digest_file(p) for p in source_paths()}



def resolve_cargo_artifact(lines, target_dir, package="contour-postgres", example="causal_bridge_probe"):
    """Select only this checkout's example from Cargo JSON, within fresh target."""
    if (package,example) not in (('contour-postgres','causal_bridge_probe'),('contour-ingress','causal_https_probe')):
        raise ValueError('unsupported cargo fixture')
    found=[]
    expected=ROOT/'crates'/package/'examples'/(example+'.rs')
    for line in lines:
        try: item=json.loads(line)
        except (ValueError,UnicodeDecodeError) as error: raise RuntimeError('invalid cargo artifact output') from error
        target=item.get('target') or {}
        if (item.get('reason')=='compiler-artifact' and target.get('name')==example
            and target.get('kind')==['example'] and target.get('src_path')==str(expected)
            and not (item.get('profile') or {}).get('test',False)):
            executable=item.get('executable')
            if not isinstance(executable,str): raise RuntimeError('missing cargo executable')
            path=Path(executable)
            if not path.is_absolute() or '..' in path.parts or '..' in target_dir.parts:
                raise RuntimeError('invalid cargo executable')
            # Metadata-only checks precede containment; never read an outside
            # executable, even when Cargo reports it as an artifact.
            for component in (path,*path.parents):
                if component.is_symlink(): raise ValueError('symlink in cargo executable')
            for component in (target_dir,*target_dir.parents):
                if component.is_symlink(): raise ValueError('symlink in cargo target')
            try:
                canonical_target=target_dir.resolve(strict=True)
                canonical_path=path.resolve(strict=True)
                canonical_path.relative_to(canonical_target)
            except (OSError,ValueError) as error:
                raise RuntimeError('cargo executable outside target') from error
            digest_file(path)
            if not os.access(path,os.X_OK): raise RuntimeError('cargo executable unavailable')
            found.append(path)
    if len(found)!=1: raise RuntimeError('ambiguous cargo executable')
    return found[0]


def run_process(args, *, data=None, cwd=None, env=None, timeout=30, limit=1_048_576, input_limit=4_194_304):
    """Bound stdin, both output pipes and wall time; kill and drain the group."""
    if data is not None and (not isinstance(data,bytes) or len(data)>input_limit):
        raise ValueError('fixture process input limit')
    process=subprocess.Popen(args,cwd=cwd,env=env,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    selector=selectors.DefaultSelector(); output={'stdout':bytearray(),'stderr':bytearray()}; total=0; offset=0
    try:
        for stream,name in ((process.stdout,'stdout'),(process.stderr,'stderr')):
            os.set_blocking(stream.fileno(),False); selector.register(stream,selectors.EVENT_READ,name)
        if data is not None:
            os.set_blocking(process.stdin.fileno(),False)
            if data: selector.register(process.stdin,selectors.EVENT_WRITE,'stdin')
            else: process.stdin.close()
        deadline=time.monotonic()+timeout
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0: raise TimeoutError('fixture process deadline')
            ready=selector.select(remaining)
            if not ready: raise TimeoutError('fixture process deadline')
            for key,_ in ready:
                if key.data=='stdin':
                    try: written=os.write(key.fileobj.fileno(),data[offset:offset+65536])
                    except (BrokenPipeError,ConnectionResetError): written=0; offset=len(data)
                    except BlockingIOError: continue
                    offset+=written
                    if offset>=len(data): selector.unregister(key.fileobj); key.fileobj.close()
                    continue
                try: chunk=os.read(key.fileobj.fileno(),min(65536,limit-total+1))
                except BlockingIOError: continue
                if not chunk: selector.unregister(key.fileobj); continue
                total+=len(chunk)
                if total>limit: raise RuntimeError('fixture process output limit exceeded')
                output[key.data].extend(chunk)
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('fixture process deadline')
        status=process.wait(timeout=remaining)
        return subprocess.CompletedProcess(None,status,bytes(output['stdout']),bytes(output['stderr']))
    except BaseException as error:
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: raise RuntimeError('fixture process cleanup failed') from None
        # Discard any remaining pipe contents without retaining diagnostics.
        for stream in (process.stdout,process.stderr):
            while True:
                try:
                    if not os.read(stream.fileno(),65536): break
                except BlockingIOError: break
        if isinstance(error,subprocess.TimeoutExpired): raise TimeoutError('fixture process deadline') from None
        raise
    finally:
        selector.close()
        for stream in (process.stdin,process.stdout,process.stderr):
            if stream is not None and not stream.closed: stream.close()


def bounded_process_output(args, *, cwd, env, timeout=300, limit=16_777_216):
    result=run_process(args,cwd=cwd,env=env,timeout=timeout,limit=limit)
    if result.returncode: raise RuntimeError('offline cargo build failed')
    return result.stdout.splitlines()


def build_probe(target_dir, package='contour-postgres', example='causal_bridge_probe'):
    if (package,example) not in (('contour-postgres','causal_bridge_probe'),('contour-ingress','causal_https_probe')):
        raise ValueError('unsupported cargo fixture')
    env=os.environ.copy(); env['CARGO_TARGET_DIR']=str(target_dir)
    output=bounded_process_output(['cargo','build','-p',package,'--example',example,
                                   '--locked','--offline','--message-format=json'],cwd=ROOT,env=env)
    return resolve_cargo_artifact(output,target_dir,package,example)


def command(args, *, data=None, timeout=30, env=None, expected=0):
    result=run_process(args,data=data,timeout=timeout,env=env)
    if result.returncode!=expected:
        # Only a five-character SQLSTATE is kept; never surface SQL or stderr.
        m=re.search(rb'(?:ERROR|FATAL):\s+([0-9A-Z]{5}):',result.stderr[:8192])
        raise RuntimeError('fixture command failed'+(' SQLSTATE '+m.group(1).decode() if m else ''))
    return result.stdout


def inspect_resource(kind, selector, *, allow_absent=False):
    cmd=['docker','inspect',selector] if kind=='container' else ['docker','network','inspect',selector]
    result=run_process(cmd,timeout=20)
    if result.returncode:
        err=result.stderr.decode('utf-8','replace').strip()
        absent=(err in ('Error: No such object: '+selector,'error: no such object: '+selector) if kind=='container' else
                err in ('Error: No such network: '+selector,'Error response from daemon: network '+selector+' not found'))
        if allow_absent and absent: return None
        raise RuntimeError('owned resource inspection failed')
    try: info=json.loads(result.stdout)
    except ValueError as error: raise RuntimeError('invalid resource inspection') from error
    if not isinstance(info,list) or len(info)!=1: raise RuntimeError('ambiguous resource inspection')
    item=info[0]
    if not re.fullmatch('[0-9a-f]{64}',item.get('Id','')): raise RuntimeError('foreign or malformed resource identity')
    return item


def inspect_owned(kind, name, label, *, allow_absent=False, known_id=None):
    if known_id is not None and not re.fullmatch('[0-9a-f]{64}',known_id): raise ValueError('invalid owned resource identity')
    item=inspect_resource(kind,known_id or name,allow_absent=allow_absent)
    if item is None: return None
    rid=item['Id']
    labels=(item.get('Config',{}).get('Labels') or {}) if kind=='container' else (item.get('Labels') or {})
    actual_name=item.get('Name','').lstrip('/')
    if labels.get(LABEL)!=label or (known_id is not None and rid!=known_id) or (known_id is None and actual_name!=name):
        raise RuntimeError('foreign or malformed resource identity')
    return item


def network_valid(info, network_id, expected_containers):
    """Verify topology and exact members after separate ownership inspection."""
    members=info.get('Containers')
    return (info.get('Id')==network_id and info.get('Internal') is False
            and info.get('Driver')=='bridge'
            and (info.get('Options') or {}).get('com.docker.network.bridge.enable_ip_masquerade')=='false'
            and isinstance(members,dict) and set(members)==set(expected_containers))



def require_empty_label_inventory(kind,run_id):
    """Read-only proof: no resource with this run's unique owner label remains."""
    if kind=='container':
        args=['docker','ps','-aq','--no-trunc','--filter','label='+LABEL+'='+run_id]
    elif kind=='network':
        args=['docker','network','ls','-q','--no-trunc','--filter','label='+LABEL+'='+run_id]
    else:
        raise ValueError('invalid resource kind')
    result=run_process(args,timeout=20)
    if result.returncode: raise RuntimeError('owned label inventory failed')
    try: lines=result.stdout.decode('ascii').splitlines()
    except UnicodeDecodeError as error: raise RuntimeError('owned label inventory ambiguous') from error
    if any(not re.fullmatch('[0-9a-f]{64}',line) for line in lines) or len(lines)!=len(set(lines)):
        raise RuntimeError('owned label inventory ambiguous')
    if lines: raise RuntimeError('owned label inventory not empty')


def cleanup(kind,name,run_id,known_id=None):
    # A known ID survives rename. Verify its label, never remove by a name that
    # might now belong to a different resource, then require both identities absent.
    info=inspect_owned(kind,name,run_id,allow_absent=True,known_id=known_id)
    if info is not None:
        rid=info['Id']
        command(['docker','rm','-f',rid] if kind=='container' else ['docker','network','rm',rid],timeout=30)
        if inspect_resource(kind,rid,allow_absent=True) is not None:
            raise RuntimeError('owned resource cleanup incomplete')
    if inspect_resource(kind,name,allow_absent=True) is not None:
        raise RuntimeError('owned resource name occupied')
    require_empty_label_inventory(kind,run_id)


def failure_category(error):
    """Return only fixed safe categories; never stringify subprocess timeouts."""
    if isinstance(error,subprocess.TimeoutExpired): return 'subprocess_timeout'
    if isinstance(error,TimeoutError):
        return {'overall fixture deadline':'overall_deadline',
                'final PostgreSQL readiness deadline':'postgres_readiness_deadline',
                'HBA reload deadline':'hba_reload_deadline',
                'offline cargo build deadline':'offline_cargo_build_deadline',
                'fixture process deadline':'fixture_process_deadline'}.get(str(error),'deadline')
    if isinstance(error,AssertionError):
        message=str(error)
        if message.startswith('unexpected negative outcome: '): return 'negative_outcome_mismatch'
        if message.startswith('negative caused durable writes: '): return 'negative_wrote_data'
        if message.startswith('inbox denial caused batch write: '): return 'inbox_denial_wrote_data'
        return {'initial causal state is not empty':'nonempty_initial_state',
                'positive issue or duplicate failed':'positive_probe_failed',
                'receipt, event or logical quota mismatch':'receipt_or_quota_mismatch'}.get(message,'assertion_failed')
    if isinstance(error,RuntimeError):
        message=str(error)
        if re.fullmatch(r'fixture command failed(?: SQLSTATE [0-9A-Z]{5})?',message): return 'fixture_command_failed'
        return {
            'owned resource inspection failed':'resource_inspection_failed',
            'invalid resource inspection':'resource_inspection_invalid',
            'ambiguous resource inspection':'resource_inspection_ambiguous',
            'foreign or malformed resource identity':'resource_identity_mismatch',
            'owned resource cleanup incomplete':'resource_cleanup_incomplete',
            'owned resource name occupied':'resource_name_occupied',
            'owned label inventory failed':'label_inventory_failed',
            'owned label inventory ambiguous':'label_inventory_ambiguous',
            'owned label inventory not empty':'label_inventory_not_empty',
            'network configuration mismatch':'network_configuration_mismatch',
            'container identity mismatch':'container_identity_mismatch',
            'container network mismatch':'container_network_mismatch',
            'unexpected exposed port':'unexpected_exposed_port',
            'loopback port mismatch':'loopback_port_mismatch',
            'loopback port invalid':'loopback_port_invalid',
            'pre-fixture policy marker mismatch':'policy_fixture_marker_mismatch',
            'migration ledger mismatch':'migration_ledger_mismatch',
            'HBA reload failed':'hba_reload_failed',
            'HBA configuration invalid':'hba_configuration_invalid',
            'SSL-only HBA proof failed':'hba_ssl_only_proof_failed',
            'configuration clock unavailable':'configuration_clock_unavailable',
            'invalid synthetic signature length':'synthetic_signature_invalid',
            'invalid synthetic public key':'synthetic_public_key_invalid',
            'fixture qualification or cleanup failed':'qualification_or_cleanup_failed',
            'offline cargo build failed':'offline_cargo_build_failed',
            'invalid cargo artifact output':'invalid_cargo_artifact_output',
            'missing cargo executable':'missing_cargo_executable',
            'invalid cargo executable':'invalid_cargo_executable',
            'cargo executable outside target':'cargo_executable_outside_target',
            'cargo executable unavailable':'cargo_executable_unavailable',
            'ambiguous cargo executable':'ambiguous_cargo_executable',
            'cargo output limit exceeded':'cargo_output_limit',
            'fixture process output limit exceeded':'fixture_process_output_limit',
            'fixture process cleanup failed':'fixture_process_cleanup_failed',
        }.get(message,'runtime_failure')
    if isinstance(error,ValueError): return 'invalid_fixture_input'
    return 'unexpected_internal_failure'


def signed_payload(template,domain,key,directory,name):
    raw=json.dumps(template,separators=(',',':'),ensure_ascii=True).encode()
    message=directory/(name+'.message'); message.write_bytes(domain+raw)
    signature=command(['openssl','pkeyutl','-sign','-inkey',str(key),'-rawin','-in',str(message)],timeout=15)
    if len(signature)!=64: raise RuntimeError('invalid synthetic signature length')
    encode=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
    envelope={'payload_base64url':encode(raw),'signature_base64url':encode(signature),'key_id':'fixture','signature_profile':'ed25519-v1'}
    return json.dumps(envelope,separators=(',',':')).encode()


def run_probe_cases(base,work,env,counts,state):
    """Run all explicit negative and positive probe cases with checked effects."""
    def stage(name): state['stages'].append(name)
    safe_outcomes={'Identity','Signature','Scope','Expired','InvalidBatch','Conflict','Corrupt','LogicalQuota','HistoryLimit','Busy','Database','Deadline','OutcomeUnknown','fixture issuer TLS failed','fixture inbox TLS failed'}
    def observe_failure(r):
        text=r.stderr.decode('utf-8','replace').strip()
        state['observed_error']=text if text in safe_outcomes else 'unclassified'
    def negative(name, change, expected):
        state['current_case']=name
        args=list(base); change(args)
        r=run_process(args,timeout=40,env=env)
        if r.returncode==0 or r.stdout.strip() or r.stderr.decode('utf-8','replace').strip()!=expected:
            observe_failure(r); raise AssertionError('unexpected negative outcome: '+name)
        if counts()!='0|0|0|0|0|0': raise AssertionError('negative caused durable writes: '+name)
        stage(name)
    if counts()!='0|0|0|0|0|0': raise AssertionError('initial causal state is not empty')
    negative('untrusted_tls_ca',lambda x:x.__setitem__(4,str(work/'untrusted.crt')),'fixture issuer TLS failed')
    negative('wrong_issuer_role',lambda x:x.__setitem__(5,'causal_inbox_login'),'Identity')
    negative('mixed_issuer_role',lambda x:x.__setitem__(5,'causal_mixed_login'),'Identity')
    negative('wrong_grant_key',lambda x:x.__setitem__(7,str(work/'policy.pub')),'Signature')
    negative('wrong_policy_key',lambda x:x.__setitem__(8,str(work/'grant.pub')),'Signature')
    negative('invalid_grant_signature',lambda x:x.__setitem__(9,str(work/'grant-invalid.json')),'Signature')
    negative('invalid_policy_signature',lambda x:x.__setitem__(10,str(work/'policy-invalid.json')),'Signature')
    negative('wrong_peer_pin',lambda x:x.__setitem__(12,'44'*32),'Scope')
    negative('wrong_source',lambda x:x.__setitem__(16,'f7000000-0000-4000-8000-000000000003'),'Identity')
    def inbox_negative(name,user):
        state['current_case']=name
        args=list(base); args[6]=user
        r=run_process(args,timeout=40,env=env)
        if r.returncode==0 or r.stdout.strip() or r.stderr.decode('utf-8','replace').strip()!='Identity':
            observe_failure(r); raise AssertionError('unexpected negative outcome: '+name)
        if counts()!='1|0|0|0|0|0': raise AssertionError('inbox denial caused batch write: '+name)
        stage(name)
    # The probe necessarily issues first. Exact nonce retry keeps the
    # same epoch; these cases assert no inbox/event/quota writes.
    inbox_negative('wrong_inbox_role','causal_issuer_login')
    inbox_negative('mixed_inbox_role','causal_mixed_login')
    state['current_case']='positive_commit_and_exact_duplicate'
    result=run_process(base,timeout=40,env=env)
    if result.returncode!=0 or result.stdout.strip()!=b'PASS: causal issue and exact committed batch retry' or result.stderr.strip():
        observe_failure(result); raise AssertionError('positive issue or duplicate failed')
    parts=counts().split('|')
    if len(parts)!=6 or parts[:3]!=['1','1','1'] or parts[5]!='1' or not parts[3].isdigit() or parts[3]!=parts[4] or int(parts[3])<=0: raise AssertionError('receipt, event or logical quota mismatch')
    state['receipt_counts']={'sessions':1,'batches':1,'events':1,'distinct_receipts':1,'used_bytes':int(parts[3])}
    stage('positive_commit_and_exact_duplicate')
    state.pop('current_case',None)
    state['status']='passed'


def main():
    if len(sys.argv)!=1: raise ValueError('qualification accepts no arguments')
    migration20=ROOT/'db/opt-in-migrations/0020_causal_inbox.sql'
    original=snapshot()
    probe=None; probe_hash=None
    os.umask(0o077)
    run_id=uuid.uuid4().hex; network_name='contour-causal-bridge-net-'+run_id; container_name='contour-causal-bridge-'+run_id
    result_dir=Path(tempfile.mkdtemp(prefix='contour-causal-bridge-'))
    os.chmod(result_dir,0o700)
    print('private result:',result_dir/'result.json',flush=True)
    state={'status':'failed','stages':[],'cleanup_container':False,'cleanup_network':False,'cleanup_build':False,
           'source_unchanged':False,'source_hashes':original,'boundary':'PostgreSQL TLS; synthetic peer pin; no mTLS ingress or producer attestation'}
    container_attempted=network_attempted=False
    container_id=network_id=None
    build_temp=None
    old_handler=signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError('overall fixture deadline')))
    signal.setitimer(signal.ITIMER_REAL,600)
    try:
        state['current_case']='offline_cargo_build'
        configured_target=Path(os.environ.get('CARGO_TARGET_DIR',str(ROOT/'target')))
        if not configured_target.is_absolute(): configured_target=ROOT/configured_target
        # A caller-selected target may itself be a symlink (for example /tmp
        # on macOS); resolve it before creating an owned child, never remove it.
        configured_target=Path(os.path.realpath(configured_target))
        for component in (configured_target,*configured_target.parents):
            if component.is_symlink(): raise ValueError('symlink in cargo target')
        configured_target.mkdir(parents=True,exist_ok=True)
        build_temp=tempfile.TemporaryDirectory(prefix='causal-bridge-build-',dir=configured_target)
        probe=build_probe(Path(build_temp.name))
        probe_hash=digest_file(probe)
        state['probe_sha256']=probe_hash
        with tempfile.TemporaryDirectory(prefix='private-',dir=result_dir) as temp:
            work=Path(temp); os.chmod(work,0o700)
            def stage(name): state['stages'].append(name)
            state['current_case']='image_inspection'
            command(['docker','image','inspect',IMAGE],timeout=20)
            state['current_case']='synthetic_input_generation'
            ca=work/'ca.crt'; ca_key=work/'ca.key'; server_key=work/'server.key'; server_cert=work/'server.crt'
            request=work/'request.cnf'; request.write_text('[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
            command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256','-config',str(request),'-extensions','ca','-subj','/CN=synthetic causal bridge CA','-keyout',str(ca_key),'-out',str(ca)],timeout=30)
            command(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-sha256','-config',str(request),'-keyout',str(server_key),'-out',str(work/'server.csr')],timeout=30)
            (work/'extensions').write_text('subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
            command(['openssl','x509','-req','-in',str(work/'server.csr'),'-CA',str(ca),'-CAkey',str(ca_key),'-CAcreateserial','-days','1','-extfile',str(work/'extensions'),'-out',str(server_cert)],timeout=30)
            command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256','-config',str(request),'-extensions','ca','-subj','/CN=untrusted synthetic CA','-keyout',str(work/'untrusted.key'),'-out',str(work/'untrusted.crt')],timeout=30)
            for name in ('grant','policy'):
                command(['openssl','genpkey','-algorithm','ED25519','-out',str(work/(name+'.key'))],timeout=15)
                public=command(['openssl','pkey','-in',str(work/(name+'.key')),'-pubout','-outform','DER'],timeout=15)
                if len(public)!=44 or not public.startswith(bytes.fromhex('302a300506032b6570032100')): raise RuntimeError('invalid synthetic public key')
                (work/(name+'.pub')).write_bytes(public[-32:])
            sample=json.loads(checked(ROOT/'crates/contour-postgres/tests/fixtures/causal_bridge.json'))
            def payload(name):
                text=sample[name]['payload_base64url']; return json.loads(base64.urlsafe_b64decode(text+'='*((-len(text))%4)))
            now=datetime.datetime.now(datetime.timezone.utc)
            stamp=lambda value:value.strftime('%Y-%m-%dT%H:%M:%SZ')
            issued=stamp(now-datetime.timedelta(seconds=10)); expires=stamp(now+datetime.timedelta(minutes=8))
            grant=payload('grant'); grant.update(tenant_id=IDS[0],runtime_id=IDS[1],collector_id=IDS[2],source_id=IDS[3],instance_id=IDS[8],lifecycle_id=IDS[9],revision=1,issued_at=issued,expires_at=expires)
            policy=payload('policy'); policy.update(tenant_id=IDS[0],collector_id=IDS[2],service_ids=[IDS[5]],revision=1,issued_at=issued,expires_at=expires)
            (work/'grant.json').write_bytes(signed_payload(grant,b'apicontour/causal-grant/1\n',work/'grant.key',work,'grant'))
            (work/'policy.json').write_bytes(signed_payload(policy,b'apicontour/policy/1\n',work/'policy.key',work,'policy'))
            for name in ('grant','policy'):
                invalid=json.loads((work/(name+'.json')).read_bytes())
                raw=base64.urlsafe_b64decode(invalid['signature_base64url']+'==')
                invalid['signature_base64url']=base64.urlsafe_b64encode(bytes([raw[0]^1])+raw[1:]).rstrip(b'=').decode()
                (work/(name+'-invalid.json')).write_text(json.dumps(invalid,separators=(',',':')))
            batch={'wire_version':1,'batch_id':str(uuid.uuid4()),'tenant_id':IDS[0],'runtime_id':IDS[1],'session_epoch':1,'first_seq':1,'last_seq':1,'events':[{'kind':'root','event_id':'1'*32,'seq':1,'root':'a'*32}]}
            (work/'batch.json').write_text(json.dumps(batch,separators=(',',':')))
            stage('synthetic_keys_and_inputs')
            state['current_case']='network_create'
            network_attempted=True
            net=command(['docker','network','create','--label',LABEL+'='+run_id,'--driver','bridge','--opt','com.docker.network.bridge.enable_ip_masquerade=false',network_name],timeout=30).decode().strip()
            if re.fullmatch('[0-9a-f]{64}',net): network_id=net
            state['current_case']='network_validation'
            net_info=inspect_owned('network',network_name,run_id)
            network_id=net_info['Id']; state['network_id']=network_id
            if not network_valid(net_info,net,()): raise RuntimeError('network configuration mismatch')
            password=secrets.token_hex(24)
            state['current_case']='container_create'
            container_attempted=True
            cid=command(['docker','create','--pull=never','--name',container_name,'--label',LABEL+'='+run_id,'--network',net,
                         '--publish','127.0.0.1::5432','--memory','512m','--cpus','1','--pids-limit','128',
                         '--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m',
                         '-e','POSTGRES_DB=contour_fixture','-e','POSTGRES_PASSWORD='+password,
                         '-e','POSTGRES_HOST_AUTH_METHOD=scram-sha-256',IMAGE,'sh','-c',
                         'chown postgres:postgres /tmp/server.key /tmp/server.crt && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c listen_addresses=* -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key'],timeout=30).decode().strip()
            if re.fullmatch('[0-9a-f]{64}',cid): container_id=cid
            state['current_case']='container_inspection'
            info=inspect_owned('container',container_name,run_id)
            container_id=info['Id']; state['container_id']=container_id
            if cid!=info['Id']: raise RuntimeError('container identity mismatch')
            for file in ('server.key','server.crt'):
                state['current_case']='copy_server_key' if file=='server.key' else 'copy_server_certificate'
                command(['docker','cp',str(work/file),cid+':/tmp/'+file],timeout=20)
            state['current_case']='container_start'
            command(['docker','start',cid],timeout=30)
            state['current_case']='postgres_readiness'
            deadline=time.monotonic()+60
            while True:
                result=run_process(['docker','exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -U postgres -d contour_fixture'],timeout=5)
                if result.returncode==0: break
                if time.monotonic()>=deadline: raise TimeoutError('final PostgreSQL readiness deadline')
                time.sleep(.2)
            state['current_case']='port_validation'
            info=inspect_owned('container',container_name,run_id)
            net_info=inspect_owned('network',network_name,run_id)
            if not network_valid(net_info,net,(cid,)): raise RuntimeError('network configuration mismatch')
            networks=info['NetworkSettings']['Networks']
            if len(networks)!=1 or next(iter(networks.values())).get('NetworkID')!=net: raise RuntimeError('container network mismatch')
            if set(info['NetworkSettings']['Ports'])!={'5432/tcp'}: raise RuntimeError('unexpected exposed port')
            ports=info['NetworkSettings']['Ports'].get('5432/tcp')
            if not isinstance(ports,list) or len(ports)!=1 or ports[0].get('HostIp')!='127.0.0.1' or not str(ports[0].get('HostPort','')).isdigit(): raise RuntimeError('loopback port mismatch')
            port=str(ports[0]['HostPort'])
            if not (1<=int(port)<=65535): raise RuntimeError('loopback port invalid')
            sql=['docker','exec','-i',cid,'psql','-XqAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-U','postgres','-d','contour_fixture']
            def execute(statement): return command(sql,data=statement.encode(),timeout=120).decode().strip()
            state['current_case']='baseline_migrations'
            execute(checked(ROOT/'db/bootstrap.sql').decode())
            for name in PROVISIONS: execute(checked(ROOT/('db/provision_'+name+'.sql')).decode())
            for name in MIGRATIONS: execute(checked(ROOT/('db/migrations/'+name+'.sql')).decode())
            for name in OPT[:3]: execute(checked(ROOT/('db/opt-in-migrations/'+name+'.sql')).decode())
            state['current_case']='runtime_and_inbox_seed'
            pre=checked(ROOT/'db/tests/causal_runtime_registry_pre.sql').decode()
            marker="INSERT INTO contour.policy_revisions VALUES ('"+IDS[0]+"','"+IDS[2]+"',1,decode('01','hex'));"
            if pre.count(marker)!=1: raise RuntimeError('pre-fixture policy marker mismatch')
            replacement="INSERT INTO contour.policy_revisions VALUES ('"+IDS[0]+"','"+IDS[2]+"',1,decode('"+(work/'policy.json').read_bytes().hex()+"','hex'));"
            execute(pre.replace(marker,replacement,1))
            execute(checked(ROOT/('db/opt-in-migrations/'+OPT[3]+'.sql')).decode())
            execute(checked(ROOT/'db/tests/causal_session_setup.sql').decode())
            execute(checked(ROOT/('db/opt-in-migrations/'+OPT[4]+'.sql')).decode())
            execute(checked(migration20).decode())
            if execute("SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;")!='{'+','.join(str(x) for x in range(1,21))+'}': raise RuntimeError('migration ledger mismatch')
            execute("CREATE ROLE causal_issuer_login LOGIN PASSWORD '"+password+"'; CREATE ROLE causal_inbox_login LOGIN PASSWORD '"+password+"'; CREATE ROLE causal_mixed_login LOGIN PASSWORD '"+password+"'; GRANT contour_causal_issuer TO causal_issuer_login,causal_mixed_login; GRANT contour_causal_inbox_writer TO causal_inbox_login,causal_mixed_login;")
            hba='local all all trust\nhostnossl all all all reject\nhostssl contour_fixture causal_issuer_login,causal_inbox_login,causal_mixed_login all scram-sha-256\nhostssl all all all reject\n'
            state['current_case']='tls_roles_and_hba'
            before_reload=execute('SELECT floor(extract(epoch FROM pg_conf_load_time())*1000000)::bigint;')
            if not before_reload.isdigit(): raise RuntimeError('configuration clock unavailable')
            command(['docker','exec','-i',cid,'sh','-c','cat > /var/lib/postgresql/data/pg_hba.conf'],data=hba.encode(),timeout=20)
            if execute('SELECT pg_reload_conf();')!='t': raise RuntimeError('HBA reload failed')
            reload_deadline=time.monotonic()+10
            while int(execute('SELECT floor(extract(epoch FROM pg_conf_load_time())*1000000)::bigint;'))<=int(before_reload):
                if time.monotonic()>=reload_deadline: raise TimeoutError('HBA reload deadline')
                time.sleep(.05)
            if execute('SELECT count(*) FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL;')!='0': raise RuntimeError('HBA configuration invalid')
            hba_proof=execute("SELECT (count(*)=4 AND count(*) FILTER (WHERE type='local' AND auth_method='trust')=1 AND count(*) FILTER (WHERE type='hostnossl' AND auth_method='reject')=1 AND count(*) FILTER (WHERE type='hostssl' AND auth_method='scram-sha-256')=1 AND count(*) FILTER (WHERE type='hostssl' AND auth_method='reject')=1)::text FROM pg_catalog.pg_hba_file_rules;")
            if hba_proof!='true': raise RuntimeError('SSL-only HBA proof failed')
            env={'PATH':os.defpath,'CONTOUR_CAUSAL_ISSUER_PASSWORD':password,'CONTOUR_CAUSAL_INBOX_PASSWORD':password}
            nonce=str(uuid.uuid4()); base=[str(probe),'localhost',port,'contour_fixture',str(ca),'causal_issuer_login','causal_inbox_login',str(work/'grant.pub'),str(work/'policy.pub'),str(work/'grant.json'),str(work/'policy.json'),str(work/'batch.json'),'33'*32,*IDS,nonce]
            def counts():
                return execute("SELECT (SELECT count(*) FROM contour.causal_sessions)::text||'|'||(SELECT count(*) FROM contour.causal_inbox_batches)::text||'|'||(SELECT count(*) FROM contour.causal_inbox_events)::text||'|'||coalesce((SELECT used_bytes::text FROM contour.origin_logical_usage WHERE tenant_id='"+IDS[0]+"'),'0')||'|'||coalesce((SELECT sum(octet_length(canonical_batch))::text FROM contour.causal_inbox_batches),'0')||'|'||(SELECT count(DISTINCT receipt_id) FROM contour.causal_inbox_batches)::text;")
            run_probe_cases(base,work,env,counts,state)
    except Exception as error:
        state['failure_type']=type(error).__name__
        state['failure_category']=failure_category(error)
        if isinstance(error,RuntimeError) and not isinstance(error,TimeoutError):
            match=re.fullmatch(r'fixture command failed SQLSTATE ([0-9A-Z]{5})',str(error))
            if match: state['sqlstate']=match.group(1)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0); signal.signal(signal.SIGALRM,old_handler)
        try:
            try:
                if container_attempted: cleanup('container',container_name,run_id,known_id=container_id)
                else: require_empty_label_inventory('container',run_id)
                state['cleanup_container']=True
            except Exception as error:
                state['container_cleanup_failure']=failure_category(error)
                raise
        finally:
            try:
                try:
                    if network_attempted: cleanup('network',network_name,run_id,known_id=network_id)
                    else: require_empty_label_inventory('network',run_id)
                    state['cleanup_network']=True
                except Exception as error:
                    state['network_cleanup_failure']=failure_category(error)
                    raise
            finally:
                try: state['source_unchanged']=(snapshot()==original and (probe is None or digest_file(probe)==probe_hash))
                finally:
                    try:
                        if build_temp is not None: build_temp.cleanup()
                        state['cleanup_build']=True
                    except Exception as error:
                        state['build_cleanup_failure']=failure_category(error)
                        raise
                    finally:
                        if not (state['cleanup_container'] and state['cleanup_network'] and state['cleanup_build'] and state['source_unchanged']): state['status']='failed'
                        (result_dir/'result.json').write_text(json.dumps(state,sort_keys=True,indent=2)+'\n')
    if state['status']!='passed': raise RuntimeError('fixture qualification or cleanup failed')
    print('PASS: '+state['boundary'])


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('FAIL:',type(error).__name__,file=sys.stderr)
        sys.exit(1)
