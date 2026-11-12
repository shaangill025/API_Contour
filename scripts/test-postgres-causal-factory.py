#!/usr/bin/env python3
"""Owned SQL24 and candidate factory component qualification.

Requires already available pinned PostgreSQL and Node-RED images and an
operator-selected local Docker CLI/socket. Never adopts an unknown mutation.
This fixture does not establish exporter admission, a wire join, or a graph.
"""
import base64
import contextlib
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import signal
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / 'crates/contour-ingress/examples/causal_factory_probe.rs'
COLLECTOR = ROOT / 'crates/contour-ingress/examples/causal_factory_collector.rs'
ASSETS = ROOT / 'tests/fixtures/causal-factory'
IMAGE = 'docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'
LABEL = 'org.apicontour.fixture-owner'
PROFILE = '00000000-0000-4000-8000-000000000503'
PROFILE_HASH = 'a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e'
PRODUCT_ID = 'fa000000-0000-4000-8000-000000000013'
EXPORT_ID = 'fa000000-0000-4000-8000-000000000014'
PROBE_STAGES = frozenset({
    'arguments', 'bind', 'binder TLS', 'binding', 'control', 'create',
    'database settings', 'database trust', 'docker policy', 'grant key',
    'hex identity', 'image', 'input', 'issue', 'issue journal', 'issuer TLS',
    'local cleanup deadline', 'local cleanup unproved', 'network', 'output',
    'password', 'peer', 'policy key', 'preflight', 'public key', 'relay closed',
    'runtime', 'sources', 'start', 'startup closed', 'unexpected completion',
    'bind_invalid', 'bind_expired', 'bind_transfer',
    'bind_journal_io', 'bind_journal_unsafe', 'bind_journal_busy',
    'bind_journal_mismatch', 'bind_journal_corrupt',
    'bind_database_identity', 'bind_database_signature', 'bind_database_scope',
    'bind_database_expired', 'bind_database_invalid_batch', 'bind_database_conflict',
    'bind_database_corrupt', 'bind_database_logical_quota', 'bind_database_history_limit',
    'bind_database_busy', 'bind_database_database', 'bind_database_deadline',
    'bind_database_outcome_unknown',
    'bind_invalid_not_started',
    'bind_invalid_preflight',
    'bind_invalid_sources',
    'bind_invalid_seal',
    'bind_invalid_mounts_before',
    'bind_invalid_target_before',
    'bind_invalid_target_start',
    'bind_invalid_target_sources_before',
    'bind_invalid_target_image',
    'bind_invalid_target_peer',
    'bind_invalid_target_first',
    'bind_invalid_target_network',
    'bind_invalid_target_second',
    'bind_invalid_target_actual',
    'bind_invalid_target_sources_after',
    'bind_invalid_target_finish',
    'bind_invalid_material',
    'bind_invalid_peer',
    'bind_invalid_generation',
    'bind_invalid_database',
    'bind_invalid_session',
    'bind_invalid_mounts_after',
    'bind_invalid_target_after',
    'bind_invalid_metadata',
    'bind_invalid_unix_stream',
    'bind_invalid_launch_journal',
    'bind_invalid_complete',
})


# Closed products of fixed observation stage, process class, and deadline state.
PROBE_OBSERVATIONS = frozenset(
    f'{stage} {error} {deadline}'
    for stage in ('bind_invalid_target_image', 'bind_invalid_target_peer',
                  'bind_invalid_target_first', 'bind_invalid_target_network',
                  'bind_invalid_target_second')
    for error in ('unsafe', 'busy', 'existing', 'io', 'timeout', 'output_limit',
                  'exit', 'cleanup_unknown')
    for deadline in ('deadline_reached', 'deadline_not_reached')
)
PROBE_STAGES = PROBE_STAGES | PROBE_OBSERVATIONS

def probe_stage(stderr):
    # Only a complete, exact static probe message is retained. In particular,
    # never decode or copy unknown diagnostics, partial messages, or payloads.
    if not isinstance(stderr, bytes) or len(stderr) > 96:
        return None
    return next((stage for stage in PROBE_STAGES
                 if stderr == b'factory probe: ' + stage.encode('ascii') + b'\n'), None)


def final_probe_stage(stderr, overflow, read_failed):
    return None if overflow or read_failed else probe_stage(stderr)


def load(path):
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ValueError('unsafe helper path')
    before = hashlib.sha256(path.read_bytes()).digest()
    module = runpy.run_path(str(path))
    if hashlib.sha256(path.read_bytes()).digest() != before:
        raise RuntimeError('helper changed')
    return module


def artifact(lines, target):
    found = []
    for line in lines:
        entry = json.loads(line)
        meta = entry.get('target') or {}
        if (entry.get('reason') == 'compiler-artifact' and meta.get('name') == 'causal_factory_probe'
                and meta.get('kind') == ['example'] and meta.get('src_path') == str(EXAMPLE)
                and not (entry.get('profile') or {}).get('test', False)):
            profile = entry.get('profile') or {}
            if profile.get('test') is not False or profile.get('opt_level') != '3' or profile.get('debug_assertions') is not False:
                raise RuntimeError('production release artifact required')
            path = Path(entry.get('executable') or '')
            if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
                raise RuntimeError('unsafe artifact')
            path.resolve(strict=True).relative_to(target.resolve(strict=True))
            if not path.is_file() or not os.access(path, os.X_OK):
                raise RuntimeError('artifact unavailable')
            found.append(path)
    if len(found) != 1:
        raise RuntimeError('ambiguous artifact')
    return found[0]


def source_snapshot(bridge):
    paths = set(bridge['source_paths']()) | {Path(__file__).resolve(), EXAMPLE, COLLECTOR, ASSETS / 'Dockerfile',
        ROOT / 'tests/fixtures/nodered-causal/private-causal-exporter-offline.js',
        ASSETS / 'stage_sources.py', ASSETS / 'tls_peer.js', ASSETS / 'test_tls_peer.js', ASSETS / 'test_driver.py',
        ASSETS / 'test_stage_sources.py', ROOT / 'scripts/test-postgres-causal-live-profile.py',
        ROOT / 'scripts/test-postgres-causal-https.py'}
    for crate in ('contour-ingress', 'contour-delivery'):
        source = ROOT / 'crates' / crate / 'src'
        for parent, dirs, files in os.walk(source, followlinks=False):
            if any((Path(parent) / name).is_symlink() for name in dirs + files):
                raise ValueError('source symlink')
        paths.update(source.rglob('*.rs'))
    manifest = json.loads((ROOT / 'collectors/nodered/live-integration/manifest.json').read_bytes())
    paths.add(ROOT / 'collectors/nodered/live-integration/manifest.json')
    paths.add(ROOT / 'collectors/nodered/live-integration/flows.json')
    for name in manifest['files']:
        if not name.startswith('/adapter/'):
            raise ValueError('manifest path')
        paths.add(ROOT / 'collectors/nodered' / name.removeprefix('/adapter/'))
    paths.update(ROOT / 'collectors/nodered/error-integration' / name for name in
                 ('wire-v2-image-manifest.json', 'wire-v2-image-manifest-x64.json'))
    return {str(p): bridge['digest_file'](p) for p in sorted(paths)}


def proxy_generation(info, cid, owner):
    state = info.get('State') or {}
    if (info.get('Id') != cid or info.get('Config', {}).get('Labels', {}).get('org.apicontour.causal.owner') != owner
            or info.get('RestartCount') != 0 or state.get('Status') != 'running' or state.get('Running') is not True
            or not isinstance(state.get('Pid'), int) or isinstance(state.get('Pid'), bool) or state['Pid'] <= 0
            or not isinstance(state.get('StartedAt'), str) or not state['StartedAt']
            or state['StartedAt'] == '0001-01-01T00:00:00Z'):
        raise RuntimeError('factory generation invalid')
    return (cid, state['Pid'], state['StartedAt'])


def fixture_generation(info, cid, owner, image):
    state = info.get('State') or {}
    if (info.get('Id') != cid or info.get('Image') != image
        or info.get('Config', {}).get('Labels', {}).get(LABEL) != owner
        or info.get('RestartCount') != 0 or state.get('Status') != 'running'
        or state.get('Running') is not True or not isinstance(state.get('Pid'),int)
        or isinstance(state['Pid'],bool) or state['Pid'] <= 0
        or not isinstance(state.get('StartedAt'),str) or not state['StartedAt']
        or state['StartedAt'] == '0001-01-01T00:00:00Z'):
        raise RuntimeError('collector generation invalid')
    return (cid,state['Pid'],state['StartedAt'])


def validate_advanced_session(nonce, fault_nonce, original, advanced, original_sql, advanced_sql):
    if (fault_nonce == nonce or not re.fullmatch('[1-9][0-9]* [0-9]+ [0-9]+',original)
        or not re.fullmatch('ADVANCED [1-9][0-9]* [0-9]+ [0-9]+',advanced)):
        raise RuntimeError('negative session mismatch')
    checked=advanced.removeprefix('ADVANCED ')
    old_epoch,old_issued,old_expires=map(int,original.split())
    new_epoch,new_issued,new_expires=map(int,checked.split())
    if (new_epoch <= old_epoch or old_issued >= old_expires or new_issued >= new_expires
        or original_sql != original or advanced_sql != checked):
        raise RuntimeError('negative session mismatch')
    return new_epoch


def validate_producer_batches(batches, tenant, runtime, epoch, marker_digests):
    """Check synthetic committed producer facts, never infer a causal edge."""
    if not batches or not marker_digests or len(marker_digests) != len(set(marker_digests)):
        raise AssertionError('missing producer evidence')
    markers = set(marker_digests)
    if any(not isinstance(x, str) or not re.fullmatch('[0-9a-f]{64}', x) for x in markers):
        raise AssertionError('invalid marker digest')
    seen_ids, seen_seqs, seen_batches, seen_markers = set(), set(), set(), set()
    kinds = set()
    for row in batches:
        if not isinstance(row, dict) or set(row) != {'canonical','digest','events'}:
            raise AssertionError('invalid batch evidence')
        try:
            raw = bytes.fromhex(row['canonical'])
            batch = json.loads(raw)
        except (ValueError, TypeError, UnicodeDecodeError):
            raise AssertionError('invalid canonical batch') from None
        encoded = json.dumps(batch, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        if (not isinstance(batch,dict) or not raw or len(raw) > 1048576 or encoded != raw
            or hashlib.sha256(b'apicontour/causal-events/1\n'+raw).hexdigest() != row['digest']
            or set(batch) != {'wire_version','batch_id','tenant_id','runtime_id','session_epoch','first_seq','last_seq','events'}
            or type(batch['wire_version']) is not int or batch['wire_version'] != 1 or batch['tenant_id'] != tenant or batch['runtime_id'] != runtime
            or type(batch['session_epoch']) is not int or batch['session_epoch'] != epoch
            or batch['batch_id'] in seen_batches or not isinstance(batch['events'], list)
            or not batch['events'] or len(batch['events']) > 500):
            raise AssertionError('batch identity or digest mismatch')
        try:
            if str(uuid.UUID(batch['batch_id'])) != batch['batch_id']:
                raise ValueError('canonical uuid')
        except (ValueError, TypeError, AttributeError):
            raise AssertionError('invalid batch identity') from None
        seen_batches.add(batch['batch_id'])
        observed = row['events']
        if not isinstance(observed, list) or len(observed) != len(batch['events']):
            raise AssertionError('event count mismatch')
        seqs = []
        for event, stored in zip(batch['events'], observed):
            fields = {'root': {'kind','event_id','seq','root'},
                      'delivery': {'kind','event_id','seq','root','activity','parent'},
                      'attempt': {'kind','event_id','seq','root','activity','attempt','marker_digest'}}
            if not isinstance(event, dict) or event.get('kind') not in fields or set(event) != fields[event['kind']]:
                raise AssertionError('unexpected producer event')
            if (type(event['seq']) is not int or event['seq'] <= 0 or event['seq'] in seen_seqs
                or not isinstance(event['event_id'],str) or not re.fullmatch('[0-9a-f]{32}',event['event_id'])
                or event['event_id'] in seen_ids
                or any(not isinstance(event[key],str) or not re.fullmatch('[0-9a-f]{32}',event[key])
                       for key in fields[event['kind']] & {'root','activity','parent','attempt'})):
                raise AssertionError('invalid producer event identity')
            event_raw = json.dumps(event,sort_keys=True,separators=(',', ':'),ensure_ascii=False).encode()
            digest = hashlib.sha256(b'apicontour/causal-event/1\n'+event_raw).hexdigest()
            if stored != {'event':event,'digest':digest}:
                raise AssertionError('committed event mismatch')
            if event['kind'] == 'attempt':
                marker = event['marker_digest']
                if marker not in markers or marker in seen_markers:
                    raise AssertionError('marker digest mismatch')
                seen_markers.add(marker)
            seen_ids.add(event['event_id']); seen_seqs.add(event['seq']); seqs.append(event['seq'])
            kinds.add(event['kind'])
        if seqs != sorted(seqs) or batch['first_seq'] != seqs[0] or batch['last_seq'] != seqs[-1]:
            raise AssertionError('event sequence mismatch')
    if kinds != {'root','delivery','attempt'} or seen_markers != markers:
        raise AssertionError('incomplete producer evidence')
    return seen_batches


def cleanup_with_evidence(primary, uncertain, factory_attempted, proxy_known, intent_exists,
                          cleanup_ack, stop_local, cleanup_remote):
    # Classify before attempting any fallible cleanup, so an exception cannot
    # erase the unknown-create state or permit removal of unknown resources.
    if factory_attempted and proxy_known is None and intent_exists:
        uncertain.append(('container', 'factory outcome unknown; journal retained'))
    if factory_attempted and not cleanup_ack:
        uncertain.append(('local', 'attach cleanup unproved'))
    failures = []
    try:
        stop_local()
    except BaseException as error:
        failures.append(error)
        uncertain.append(('local', 'probe supervisor cleanup failed'))
    if not uncertain:
        try:
            cleanup_remote()
        except BaseException as error:
            failures.append(error)
    if failures:
        raise BaseExceptionGroup('factory primary and cleanup', ([primary] if primary is not None else []) + failures)
    if primary is not None:
        raise primary


def qualify(work, docker, d, inspect, create, bridge, https, live, stage, executable,
            product_leaf, export_leaf, binary, socket, binary_hash, config, stages, owned, uncertain, diagnostic,
            exporter_inbox=False):
    import shutil
    token = secrets.token_hex(32)
    name = 'contour-factory-' + uuid.uuid4().hex
    proxy_known = None
    monitor = None
    collector_monitor = None
    collector_stopped = False
    monitor_stopped = False
    factory_attempted = False
    cleanup_ack = False
    generation = None
    primary = None
    journal = work / 'create'; journal.mkdir(mode=0o700)
    issue_dir = work / 'issue'; issue_dir.mkdir(mode=0o700)
    stage_dir = work / 'sources'; stage_dir.mkdir(mode=0o700)
    mounts = stage(ROOT, stage_dir)
    mounts += [work / n for n in ('ca.pem', 'export.key', 'export.pem', 'product.key',
                                   'product.pem', 'server.key', 'server.pem')]
    try:
        collector_image = None
        if exporter_inbox:
            image_tag = name+'-collector:fixture'
            uncertain.append(('image',image_tag))
            iidfile = work/'collector.iid'
            bridge['bounded_process_output'](docker+['build','--pull=false','--iidfile',str(iidfile),
                '--label',LABEL+'='+token,'-f',str(ASSETS/'Dockerfile'),'-t',image_tag,str(ROOT)],
                cwd=ROOT,env=os.environ.copy())
            iid=iidfile.read_text().strip()
            if not re.fullmatch('sha256:[0-9a-f]{64}',iid): raise RuntimeError('collector image receipt')
            collector_info=inspect('image',iid)
            if collector_info.get('Id')!=iid or collector_info.get('Config',{}).get('Labels',{}).get(LABEL)!=token:
                raise RuntimeError('collector image identity')
            uncertain.pop(); collector_image=iid; owned.append(('image',iid,token))
            diagnostic['collector_image']=iid
        image = inspect('image', IMAGE)
        image_id = image.get('Id', '')
        if not re.fullmatch('sha256:[0-9a-f]{64}', image_id):
            raise RuntimeError('image identity')
        digest_ref = IMAGE.replace(':5.0.9@', '@')
        if not any(s in (digest_ref.removeprefix('docker.io/'), digest_ref) for s in image.get('RepoDigests', [])):
            raise RuntimeError('image digest')
        inspect('image', bridge['IMAGE'])
        pg_net = create('network', ['network', 'create', '--label', LABEL+'='+token,
            '--driver', 'bridge', '--opt', 'com.docker.network.bridge.enable_ip_masquerade=false', name+'-pg'], name+'-pg', token)
        network = create('network', ['network', 'create', '--internal', '--label', LABEL+'='+token,
            '--driver', 'bridge', name+'-live'], name+'-live', token)
        if inspect('network', network).get('Internal') is not True:
            raise RuntimeError('network is not internal')
        password = secrets.token_hex(24)
        pg = create('container', ['create', '--pull=never', '--name', name+'-pg', '--label', LABEL+'='+token,
            '--network', pg_net, '--network-alias', 'causal-db', '--publish', '127.0.0.1::5432', '--memory', '512m', '--cpus', '1',
            '--pids-limit', '128', '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,noexec,size=256m',
            '-e', 'POSTGRES_DB=contour_fixture', '-e', 'POSTGRES_PASSWORD='+password,
            '-e', 'POSTGRES_HOST_AUTH_METHOD=scram-sha-256', bridge['IMAGE'], 'sh', '-c',
            'chown postgres:postgres /tmp/server.key /tmp/server.crt && chmod 600 /tmp/server.key && '
            'exec docker-entrypoint.sh postgres -c listen_addresses=* -c ssl=on -c ssl_cert_file=/tmp/server.crt '
            '-c ssl_key_file=/tmp/server.key -c log_line_prefix="%m [%p] %u " -c log_error_verbosity=verbose'], name+'-pg', token)
        d(['cp', str(work/'db.key'), pg+':/tmp/server.key'], timeout=20)
        d(['cp', str(work/'db.pem'), pg+':/tmp/server.crt'], timeout=20)
        d(['start', pg], timeout=30)
        deadline = time.monotonic()+60
        while True:
            result = bridge['run_process'](docker + ['exec', pg, 'sh', '-c',
                'test "$(cat /proc/1/comm)" = postgres && pg_isready -U postgres -d contour_fixture'], timeout=5)
            if result.returncode == 0: break
            if time.monotonic() >= deadline: raise TimeoutError('postgres readiness')
            time.sleep(.2)
        info = inspect('container', pg)
        ports = info['NetworkSettings']['Ports']
        bindings = ports.get('5432/tcp') if set(ports) == {'5432/tcp'} else None
        if not isinstance(bindings, list) or len(bindings) != 1 or bindings[0].get('HostIp') != '127.0.0.1':
            raise RuntimeError('postgres port binding')
        port = str(bindings[0].get('HostPort', ''))
        if not port.isdigit() or not 1 <= int(port) <= 65535: raise RuntimeError('postgres port')
        sql = ['exec', '-i', pg, 'psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose',
               '-U', 'postgres', '-d', 'contour_fixture']
        def execute(text): return d(sql, data=text.encode(), timeout=120).decode().strip()
        ids = list(bridge['IDS'])
        for index, value in {1:'fc000000-0000-4000-8000-000000000003', 2:'f6000000-0000-4000-8000-000000000003',
            3:'f7000000-0000-4000-8000-000000000003', 8:'f5000000-0000-4000-8000-000000000003',
            9:'f9000000-0000-4000-8000-000000000003'}.items(): ids[index] = value
        sample = json.loads((ROOT/'crates/contour-postgres/tests/fixtures/causal_bridge.json').read_bytes())
        def payload(key):
            value = sample[key]['payload_base64url']
            return json.loads(base64.urlsafe_b64decode(value+'='*((-len(value))%4)))
        now = datetime.datetime.now(datetime.timezone.utc)
        stamp = lambda value: value.strftime('%Y-%m-%dT%H:%M:%SZ')
        grant = payload('grant'); grant.update(tenant_id=ids[0],runtime_id=ids[1],collector_id=ids[2],
            source_id=ids[3],instance_id=ids[8],lifecycle_id=ids[9],revision=1,
            issued_at=stamp(now-datetime.timedelta(seconds=10)),expires_at=stamp(now+datetime.timedelta(minutes=8)),
            causal_profile='nodered_5_0_9_wire_v1',profile_sha256=PROFILE_HASH)
        policy = payload('policy'); policy.update(tenant_id=ids[0],collector_id=ids[2],service_ids=[ids[5]],
            revision=1,issued_at=grant['issued_at'],expires_at=grant['expires_at'])
        for name_part, value, domain in (('grant',grant,b'apicontour/causal-grant/1\n'),
                                          ('policy',policy,b'apicontour/policy/1\n')):
            (work/(name_part+'.json')).write_bytes(bridge['signed_payload'](value,domain,work/(name_part+'.key'),work,name_part))
        execute((ROOT/'db/bootstrap.sql').read_text())
        for name_part in bridge['PROVISIONS']: execute((ROOT/('db/provision_'+name_part+'.sql')).read_text())
        for name_part in bridge['MIGRATIONS']: execute((ROOT/('db/migrations/'+name_part+'.sql')).read_text())
        for name_part in live['OPT'][:3]: execute((ROOT/('db/opt-in-migrations/'+name_part+'.sql')).read_text())
        pre = (ROOT/'db/tests/causal_runtime_registry_pre.sql').read_text()
        marker = "INSERT INTO contour.policy_revisions VALUES ('"+ids[0]+"','"+ids[2]+"',1,decode('01','hex'));"
        if pre.count(marker) != 1: raise RuntimeError('policy fixture mismatch')
        pre = pre.replace(marker, "INSERT INTO contour.policy_revisions VALUES ('"+ids[0]+"','"+ids[2]+"',1,decode('"+(work/'policy.json').read_bytes().hex()+"','hex'));", 1)
        execute(pre)
        execute((ROOT/('db/opt-in-migrations/'+live['OPT'][3]+'.sql')).read_text())
        execute((ROOT/'db/tests/causal_session_setup.sql').read_text())
        for name_part in live['OPT'][4:]: execute((ROOT/('db/opt-in-migrations/'+name_part+'.sql')).read_text())
        if execute('SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;') != '{'+','.join(map(str,range(1,25)))+'}':
            raise RuntimeError('migration ledger')
        execute("CREATE ROLE causal_issuer_login LOGIN PASSWORD '"+password+"'; CREATE ROLE causal_provisioner_login LOGIN PASSWORD '"+password+"'; GRANT contour_causal_issuer TO causal_issuer_login; GRANT contour_causal_provisioner TO causal_provisioner_login;")
        inbox_hba = ''
        if exporter_inbox:
            execute("CREATE ROLE causal_inbox_login LOGIN PASSWORD '"+password+"'; GRANT contour_causal_inbox_writer TO causal_inbox_login;")
            inbox_hba = ',causal_inbox_login'
        hba = 'local all all trust\nhostnossl all all all reject\nhostssl contour_fixture causal_issuer_login,causal_provisioner_login'+inbox_hba+' all scram-sha-256\nhostssl all all all reject\n'
        reload_before = execute('SELECT floor(extract(epoch FROM pg_conf_load_time())*1000000)::bigint;')
        d(['exec','-i',pg,'sh','-c','cat > /var/lib/postgresql/data/pg_hba.conf'],data=hba.encode(),timeout=20)
        if execute('SELECT pg_reload_conf();') != 't': raise RuntimeError('HBA reload')
        deadline = time.monotonic()+10
        while int(execute('SELECT floor(extract(epoch FROM pg_conf_load_time())*1000000)::bigint;')) <= int(reload_before):
            if time.monotonic() >= deadline: raise TimeoutError('HBA reload')
            time.sleep(.05)
        if execute('SELECT count(*) FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL;') != '0':
            raise RuntimeError('HBA invalid')
        proof = execute("SELECT (count(*)=4 AND count(*) FILTER (WHERE type='local' AND auth_method='trust')=1 AND count(*) FILTER (WHERE type='hostnossl' AND auth_method='reject')=1 AND count(*) FILTER (WHERE type='hostssl' AND auth_method='scram-sha-256')=1 AND count(*) FILTER (WHERE type='hostssl' AND auth_method='reject')=1)::text FROM pg_catalog.pg_hba_file_rules;")
        if proof != 'true': raise RuntimeError('HBA policy mismatch')
        tenant, runtime, collector, source, project, service, environment, deployment, instance, lifecycle = ids
        prefix = f"BEGIN; SELECT set_config('apicontour.tenant_id','{tenant}',true); "
        execute(prefix+f"SET LOCAL ROLE contour_admin; SELECT contour.enroll_origin_credential('{tenant}','{PRODUCT_ID}','{lifecycle}',decode('{product_leaf}','hex')); COMMIT;")
        execute(prefix+f"SET LOCAL ROLE contour_causal_provisioner; SELECT contour.register_causal_profile('{tenant}','{PROFILE}',decode('{PROFILE_HASH}','hex')); COMMIT;")
        execute(prefix+f"SET LOCAL ROLE contour_causal_provisioner; SELECT contour.enroll_causal_runtime('{tenant}','{runtime}','{collector}','{source}','{project}','{service}','{environment}','{deployment}','{instance}','{lifecycle}','{PROFILE}',decode('{PROFILE_HASH}','hex'),decode('{export_leaf}','hex')); COMMIT;")
        stages.append('sql24_actual_leaf_enrolled')
        nonce = str(uuid.uuid4())
        for directory, names in (('peer', ('ca.pem','peer.pem','peer.key')), ('client-peer', ('ca.pem','client.pem','client.key'))):
            target = work/directory; target.mkdir(mode=0o700)
            for item in names: shutil.copyfile(work/item, target/item)
            if exporter_inbox and directory == 'client-peer':
                for item in ('export.pem','export.key'): shutil.copyfile(work/item,target/item)
            shutil.copyfile(ASSETS/'tls_peer.js', target/'tls_peer.js')
        def peer_create(suffix, directory, mode, aliases):
            args = ['create','--pull=never','--name',name+'-'+suffix,'--label',LABEL+'='+token,
                    '--network',network,'--user','0:0','--read-only','--entrypoint','/usr/local/bin/node']
            for alias in aliases: args += ['--network-alias',alias]
            if mode in ('serve','business'): args += ['--env','PRODUCT_LEAF='+product_leaf,'--env','EXPORT_LEAF='+export_leaf]
            args += ['--mount',f'type=bind,src={work/directory},dst=/fixture,readonly',IMAGE,'/fixture/tls_peer.js',mode]
            result = create('container',args,name+'-'+suffix,token); d(['start',result],timeout=30); return result
        server_peer = peer_create('server','peer','business' if exporter_inbox else 'serve',('pilot-gateway',) if exporter_inbox else ('pilot-gateway','causal-ingress'))
        client_peer = peer_create('client','client-peer','wait',())
        collector = None
        if exporter_inbox:
            collector_dir=work/'collector'; collector_dir.mkdir(mode=0o700)
            for item in ('ca.pem','grant.pub','policy.pub','grant.json','policy.json'):
                shutil.copyfile(work/item,collector_dir/item)
            for source_name, target_name in (('peer.pem','server.der'),('ca.pem','ca.der')):
                (collector_dir/target_name).write_bytes(bridge['command'](['openssl','x509','-in',str(work/source_name),'-outform','DER'],timeout=15))
            (collector_dir/'server-key.der').write_bytes(bridge['command'](['openssl','pkcs8','-topk8','-nocrypt','-in',str(work/'peer.key'),'-outform','DER'],timeout=15))
            collector_config={'host':'causal-db','port':5432,'database':'contour_fixture',
                'issuer_user':'causal_issuer_login','inbox_user':'causal_inbox_login',
                'database_ca':'/fixture/ca.pem','grant_public':'/fixture/grant.pub','policy_public':'/fixture/policy.pub',
                'grant':'/fixture/grant.json','policy':'/fixture/policy.json','peer':export_leaf,'ids':ids,'nonce':nonce,
                'server_certificate':'/fixture/server.der','server_key':'/fixture/server-key.der','client_ca':'/fixture/ca.der'}
            (collector_dir/'collector.json').write_text(json.dumps(collector_config,sort_keys=True))
            args=['create','-i','--pull=never','--name',name+'-collector','--label',LABEL+'='+token,
                  '--network',network,'--network-alias','causal-ingress','--user','0:0','--read-only',
                  '--env','CONTOUR_CAUSAL_ISSUER_PASSWORD='+password,'--env','CONTOUR_CAUSAL_INBOX_PASSWORD='+password,
                  '--mount',f'type=bind,src={collector_dir},dst=/fixture,readonly',collector_image]
            collector=create('container',args,name+'-collector',token)
            collector_monitor=live['strict_monitor'](https['ProbeProcess'],docker+['start','--attach','--interactive',collector],os.environ.copy())
            until=time.monotonic()+15
            while True:
                with collector_monitor.lock:
                    out=bytes(collector_monitor.buffers['out']); err=bytes(collector_monitor.buffers['err'])
                    bad=collector_monitor.overflow or collector_monitor.read_failed
                if bad or err or out not in (b'',b'WAITING\n'): raise RuntimeError('collector startup')
                if out == b'WAITING\n': break
                if collector_monitor.child.poll() is not None or time.monotonic()>=until: raise RuntimeError('collector startup')
                time.sleep(.05)
            d(['network','connect',pg_net,collector],timeout=30)
            collector_generation=fixture_generation(inspect('container',collector),collector,token,collector_image)
            diagnostic['collector_generation']=collector_generation
        net = inspect('network',network)
        expected_peers={server_peer,client_peer} | ({collector} if collector else set())
        if set(net.get('Containers', {})) != expected_peers:
            raise RuntimeError('unexpected network members')
        stage_hash = hashlib.sha256(json.dumps(source_snapshot(bridge),sort_keys=True).encode()).hexdigest()
        keys_hash = hashlib.sha256((work/'grant.pub').read_bytes()+(work/'policy.pub').read_bytes()).hexdigest()
        settings = {'host':'localhost','port':int(port),'database':'contour_fixture','issuer_user':'causal_issuer_login',
            'binder_user':'causal_provisioner_login','database_ca':str(work/'ca.pem'),
            'grant_public':str(work/'grant.pub'),'policy_public':str(work/'policy.pub'),'grant':str(work/'grant.json'),
            'policy':str(work/'policy.json'),'peer':export_leaf,'ids':ids,'nonce':nonce,
            'issue_dir':str(issue_dir),'journal_dir':str(journal),'source_identity':stage_hash,'key_identity':keys_hash,
            'docker_binary':str(binary),'docker_socket':str(socket),'docker_config':str(config),'docker_binary_sha256':binary_hash,
            'image':image_id[7:],'network':network,'network_name':name+'-live','network_owner':token,
            'peers':([{'cid':peer,'image':image_id[7:],'owner':token} for peer in (server_peer,client_peer)]
                     + ([{'cid':collector,'image':collector_image[7:],'owner':token}] if collector else [])),
            'mounts':[str(p) for p in mounts],'product_credential':PRODUCT_ID,'export_credential':EXPORT_ID,
            'batch_bytes':16384,'batch_events':16,'queue_bytes':65536,'queue_ttl_ms':5000}
        input_file = work/'factory.json'; input_file.write_text(json.dumps(settings,sort_keys=True))
        environment_vars = {'PATH':os.environ.get('PATH',os.defpath),'CONTOUR_CAUSAL_ISSUER_PASSWORD':password}
        factory_attempted = True
        monitor = live['strict_monitor'](https['ProbeProcess'], [str(executable),str(input_file)], environment_vars)
        deadline = time.monotonic()+120
        while time.monotonic() < deadline:
            with monitor.lock:
                out, err = bytes(monitor.buffers['out']), bytes(monitor.buffers['err'])
                bad = monitor.overflow or monitor.read_failed
            if bad or err or out not in (b'',b'READY\n'):
                diagnostic['phase'] = 'factory_readiness'
                diagnostic['probe_stage'] = probe_stage(err) if not bad else None
                raise RuntimeError('factory readiness output')
            if out == b'READY\n': break
            if monitor.child.poll() is not None:
                diagnostic['phase'] = 'factory_readiness'
                raise RuntimeError('factory exited before ready')
            time.sleep(.05)
        else:
            diagnostic['phase'] = 'factory_readiness'
            raise TimeoutError('factory readiness')
        receipt = (journal/'create.cid').read_bytes(); intent = (journal/'create.intent').read_bytes()
        prefix_bytes = b'apicontour/local-create-intent/1\n'
        if len(receipt) != 41 or not receipt.startswith(b'CCI-CID1\n') or len(intent) != len(prefix_bytes)+160 or not intent.startswith(prefix_bytes):
            raise RuntimeError('factory journal receipt')
        proxy_cid = receipt[9:].hex(); proxy_token = intent[len(prefix_bytes):len(prefix_bytes)+32].hex()
        proxy_info = inspect('container',proxy_cid)
        if proxy_info.get('Id') != proxy_cid or proxy_info.get('Config',{}).get('Labels',{}).get('org.apicontour.causal.owner') != proxy_token:
            raise RuntimeError('factory ownership receipt')
        generation = proxy_generation(proxy_info, proxy_cid, proxy_token)
        proxy_known = (proxy_cid,proxy_token)
        owned.append(('proxy', proxy_cid, proxy_token))
        stages.append('factory_ready')
        def check_generation():
            if proxy_generation(inspect('container', proxy_cid), proxy_cid, proxy_token) != generation:
                raise RuntimeError('factory generation changed')
            if collector and fixture_generation(inspect('container',collector),collector,token,collector_image) != collector_generation:
                raise RuntimeError('collector generation changed')
        if exporter_inbox:
            session_sql=("SELECT epoch::text||' '||floor(extract(epoch FROM issued_at)*1000000)::bigint::text||' '||"
                "floor(extract(epoch FROM expires_at)*1000000)::bigint::text FROM contour.causal_sessions WHERE tenant_id='"+tenant+
                "' AND runtime_id='"+runtime+"' AND nonce='"+nonce+"';")
            session=execute(session_sql)
            if not re.fullmatch('[1-9][0-9]* [0-9]+ [0-9]+',session): raise RuntimeError('original session missing')
            epoch=int(session.split()[0])
            collector_monitor.child.stdin.write(('GO '+session+'\n').encode()); collector_monitor.child.stdin.flush()
            expected_output=('WAITING\nREADY '+str(epoch)+'\n').encode()
            until=time.monotonic()+15
            while True:
                with collector_monitor.lock:
                    out=bytes(collector_monitor.buffers['out']); err=bytes(collector_monitor.buffers['err'])
                    bad=collector_monitor.overflow or collector_monitor.read_failed
                if bad or err or not expected_output.startswith(out): raise RuntimeError('collector readiness')
                if out==expected_output: break
                if collector_monitor.child.poll() is not None or time.monotonic()>=until: raise RuntimeError('collector readiness')
                time.sleep(.05)
            if execute(session_sql)!=session: raise RuntimeError('issue retry changed session')
            d(['cp',collector+':/usr/local/bin/causal_factory_collector',str(work/'collector.binary')],timeout=20)
            collector_hash=bridge['digest_file'](work/'collector.binary')
            diagnostic['collector_sha256']=collector_hash
            stages.append('collector_exact_session')
            def batches():
                sql=("SELECT coalesce(json_agg(json_build_object('canonical',encode(b.canonical_batch,'hex'),'digest',encode(b.batch_digest,'hex'),'events',"
                    "(SELECT coalesce(json_agg(json_build_object('event',jsonb_strip_nulls(jsonb_build_object('kind',x.kind,'event_id',x.event_id,'seq',x.seq,'root',x.root,'activity',x.activity,'parent',x.parent,'attempt',x.attempt,'marker_digest',x.marker_digest)),'digest',encode(x.event_digest,'hex')) ORDER BY x.seq),'[]'::json) FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.batch_id)=(b.tenant_id,b.runtime_id,b.session_epoch,b.batch_id))) ORDER BY b.batch_id),'[]'::json) FROM contour.causal_inbox_batches b WHERE b.tenant_id='"+tenant+"' AND b.runtime_id='"+runtime+"' AND b.session_epoch="+str(epoch)+";")
                return json.loads(execute(sql))
            def markers():
                logs=bridge['run_process'](docker+['logs',server_peer],timeout=15,limit=16384)
                if logs.returncode or logs.stderr or len(logs.stdout)>16384: raise RuntimeError('business output limit')
                data=logs.stdout
                lines=data.decode('ascii').splitlines()
                if any(not re.fullmatch('MARKER [0-9a-f]{64}',line) for line in lines): raise RuntimeError('business output')
                return [line[7:] for line in lines]
            def wait_facts(previous_roots,expected_markers):
                until=time.monotonic()+15
                while True:
                    current=batches(); current_markers=markers()
                    try:
                        if len(current_markers)!=expected_markers: raise AssertionError('marker count')
                        validate_producer_batches(current,tenant,runtime,epoch,current_markers)
                        roots={e['event']['root'] for b in current for e in b['events'] if e['event']['kind']=='root'}
                        if roots-previous_roots: return current,roots
                    except AssertionError: pass
                    if time.monotonic()>=until: raise RuntimeError('producer facts unavailable')
                    time.sleep(.05)
            check_generation()
            d(['exec',client_peer,'/usr/local/bin/node','/fixture/tls_peer.js','request'],timeout=15)
            first,roots=wait_facts(set(),2)
            check_generation()
            d(['exec',client_peer,'/usr/local/bin/node','/fixture/tls_peer.js','request'],timeout=15)
            final,_=wait_facts(roots,4)
            if len(final)<=len(first): raise RuntimeError('export acknowledgement not demonstrated')
            original=final[0]; raw=bytes.fromhex(original['canonical']); batch=json.loads(raw)
            replay=json.loads(d(['exec','-i',client_peer,'/usr/local/bin/node','/fixture/tls_peer.js','replay'],data=raw,timeout=15))
            expected_keys={'batch_id','runtime_id','session_epoch','batch_digest','receipt_id','accepted_at','status'}
            body=replay.get('body')
            if (replay.get('status')!=200 or not isinstance(body,dict) or set(body)!=expected_keys
                or body.get('status')!='duplicate' or body.get('batch_id')!=batch['batch_id']
                or body.get('runtime_id')!=runtime or body.get('session_epoch')!=epoch or body.get('batch_digest')!=original['digest']):
                raise RuntimeError('duplicate receipt mismatch')
            try:
                if str(uuid.UUID(body['receipt_id'])) != body['receipt_id']: raise ValueError('receipt')
                accepted=datetime.datetime.fromisoformat(body['accepted_at'].replace('Z','+00:00'))
                if accepted.tzinfo is None: raise ValueError('receipt')
                delta=accepted.astimezone(datetime.timezone.utc)-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
                accepted_us=(delta.days*86400+delta.seconds)*1000000+delta.microseconds
            except (ValueError,TypeError,AttributeError,KeyError):
                raise RuntimeError('duplicate receipt mismatch') from None
            receipt=execute("SELECT receipt_id::text||'|'||floor(extract(epoch FROM accepted_at)*1000000)::bigint::text FROM contour.causal_inbox_batches WHERE tenant_id='"+tenant+"' AND runtime_id='"+runtime+"' AND session_epoch="+str(epoch)+" AND batch_id='"+batch['batch_id']+"';")
            if receipt != body['receipt_id']+'|'+str(accepted_us): raise RuntimeError('duplicate receipt mismatch')
            if batches()!=final: raise RuntimeError('duplicate changed inbox')
            denied=json.loads(d(['exec','-i',client_peer,'/usr/local/bin/node','/fixture/tls_peer.js','wrong-leaf'],data=raw,timeout=15))
            https['expect_error']((denied.get('status'),denied.get('body')),403,'not_authorized')
            if batches()!=final: raise RuntimeError('wrong leaf changed inbox')
            mismatched=dict(batch,session_epoch=epoch+1)
            mismatched_raw=json.dumps(mismatched,sort_keys=True,separators=(',',':')).encode()
            denied=json.loads(d(['exec','-i',client_peer,'/usr/local/bin/node','/fixture/tls_peer.js','replay'],data=mismatched_raw,timeout=15))
            https['expect_error']((denied.get('status'),denied.get('body')),403,'not_authorized')
            if batches()!=final: raise RuntimeError('mismatched epoch changed inbox')
            stages.append('producer_ack_and_inbox')
        check_generation()
        d(['exec',client_peer,'/usr/local/bin/node','/fixture/tls_peer.js','request'],timeout=15)
        check_generation()
        stages.append('incoming_mtls_before_drop')
        monitor.child.stdin.write(b'STOP\n'); monitor.child.stdin.flush()
        monitor.child.wait(timeout=15)
        monitor_stopped = True
        monitor.stop(False)
        live['monitor_output'](monitor,b'READY\nCAPTURE_CLOSED\n')
        if monitor.child.returncode != 0: raise RuntimeError('factory control exit')
        cleanup_ack = True
        check_generation()
        d(['exec',client_peer,'/usr/local/bin/node','/fixture/tls_peer.js','request'],timeout=15)
        check_generation()
        stages.append('incoming_mtls_after_drop')
        if exporter_inbox:
            baseline=batches()
            # Explicit late fault only: issue a new nonce with the same signed
            # binding and 300-second claim to supersede the formerly valid
            # registry session. This is never used for startup or renewal.
            fault_nonce=str(uuid.uuid4())
            advanced=d(['exec',collector,'/usr/local/bin/causal_factory_collector',
                        '/fixture/collector.json','--advance',fault_nonce],timeout=15).decode('ascii').strip()
            new_session_sql=session_sql.replace("nonce='"+nonce+"'", "nonce='"+fault_nonce+"'")
            new_epoch=validate_advanced_session(nonce,fault_nonce,session,advanced,
                                                execute(session_sql),execute(new_session_sql))
            current_sql=(prefix+"SET LOCAL ROLE contour_causal_issuer; SELECT contour.check_causal_session('"+
                         tenant+"','"+runtime+"',"+str(new_epoch)+"); COMMIT;")
            if execute(current_sql).splitlines()[-1:]!=['t']:
                raise RuntimeError('new session not current')
            denied=json.loads(d(['exec','-i',client_peer,'/usr/local/bin/node','/fixture/tls_peer.js','replay'],data=raw,timeout=15))
            https['expect_error']((denied.get('status'),denied.get('body')),403,'not_authorized')
            if (batches()!=baseline or execute("SELECT count(*) FROM contour.causal_inbox_batches WHERE tenant_id='"+tenant+
                "' AND runtime_id='"+runtime+"' AND session_epoch<>"+str(epoch)+";")!='0'):
                raise RuntimeError('stale epoch changed inbox')
            stages.append('stale_epoch_refused')
            execute(prefix+f"SET LOCAL ROLE contour_causal_provisioner; SELECT contour.end_causal_runtime('{tenant}','{runtime}','export_revoked'); COMMIT;")
            if execute(current_sql).splitlines()[-1:]!=['f']:
                raise RuntimeError('current session survived revocation')
            denied=json.loads(d(['exec','-i',client_peer,'/usr/local/bin/node','/fixture/tls_peer.js','replay'],data=raw,timeout=15))
            https['expect_error']((denied.get('status'),denied.get('body')),403,'not_authorized')
            if batches()!=baseline: raise RuntimeError('revoked export changed inbox')
            collector_monitor.child.stdin.write(b'STOP\n'); collector_monitor.child.stdin.flush()
            collector_monitor.child.wait(timeout=15); collector_stopped=True
            collector_monitor.stop(False)
            live['monitor_output'](collector_monitor,expected_output+b'STOPPED\n')
            if collector_monitor.child.returncode != 0: raise RuntimeError('collector control exit')
            d(['cp',collector+':/usr/local/bin/causal_factory_collector',str(work/'collector.binary.final')],timeout=20)
            if bridge['digest_file'](work/'collector.binary.final') != collector_hash: raise RuntimeError('collector artifact changed')
            stages.append('revocation_current_session_refused')
    except BaseException as error:
        primary = error
    finally:
        def stop_local():
            if monitor is not None and not monitor_stopped:
                try:
                    monitor.stop(False)
                finally:
                    if diagnostic['phase'] == 'factory_readiness':
                        with monitor.lock:
                            diagnostic['probe_stage'] = final_probe_stage(
                                bytes(monitor.buffers['err']), monitor.overflow, monitor.read_failed)
            if collector_monitor is not None and not collector_stopped:
                collector_monitor.stop(False)
        def cleanup_remote():
            if proxy_known is not None:
                cid, owner = proxy_known
                if proxy_generation(inspect('container', cid), cid, owner) != generation:
                    raise RuntimeError('factory cleanup generation changed')
                d(['rm','--force',cid],timeout=30)
                require_absent(bridge, docker, 'container', cid)
                if not owned or owned[-1] != ('proxy', cid, owner):
                    raise RuntimeError('factory cleanup record')
                owned.pop()
            while owned:
                kind, ident, owner = owned[-1]
                current = inspect(kind, ident)
                labels = current.get('Labels') if kind == 'network' else current.get('Config',{}).get('Labels',{})
                if current.get('Id') != ident or not isinstance(labels,dict) or labels.get(LABEL) != owner:
                    raise RuntimeError('cleanup identity')
                command = (['network','rm',ident] if kind == 'network' else
                           ['image','rm','--force',ident] if kind == 'image' else ['rm','--force',ident])
                d(command,timeout=30)
                require_absent(bridge, docker, kind, ident)
                owned.pop()
        cleanup_with_evidence(primary, uncertain, factory_attempted, proxy_known,
                              (journal/'create.intent').exists(), cleanup_ack, stop_local, cleanup_remote)


def require_absent(bridge, docker, kind, ident):
    result = bridge['run_process'](docker + [kind, 'inspect', ident], timeout=20)
    stderr = result.stderr.decode('utf-8', 'replace').strip()
    messages = ({'Error: No such object: '+ident, 'Error: No such container: '+ident,
                 'Error response from daemon: No such container: '+ident} if kind == 'container' else
                {'Error: No such image: '+ident, 'Error response from daemon: No such image: '+ident} if kind == 'image' else
                {'Error: No such network: '+ident, 'Error response from daemon: network '+ident+' not found'})
    if result.returncode == 0 or result.stdout.strip() not in (b'', b'[]') or stderr not in messages:
        raise RuntimeError('cleanup absence unconfirmed')


def check_native_uid(platform, uid):
    if platform.startswith('linux') and uid != 1000:
        raise RuntimeError('native Linux fixture requires operator UID 1000 for 0600 mounts')


def main():
    if len(sys.argv) != 1:
        raise ValueError('no arguments accepted')
    check_native_uid(sys.platform, os.geteuid())
    exporter_inbox = os.environ.get('CONTOUR_FACTORY_EXPORTER_INBOX') == '1'
    bridge = load(ROOT / 'scripts/test-postgres-causal-bridge.py')
    https = load(ROOT / 'scripts/test-postgres-causal-https.py')
    live = load(ROOT / 'scripts/test-postgres-causal-live-profile.py')
    stage = load(ASSETS / 'stage_sources.py')['stage']
    before = source_snapshot(bridge)
    os.umask(0o077)
    binary = Path(os.environ['CONTOUR_FACTORY_DOCKER_BINARY'])
    socket = Path(os.environ['CONTOUR_FACTORY_DOCKER_SOCKET'])
    binary_hash = os.environ['CONTOUR_FACTORY_DOCKER_SHA256']
    if not binary.is_absolute() or not socket.is_absolute() or not re.fullmatch('[0-9a-f]{64}', binary_hash):
        raise ValueError('docker policy')
    if bridge['digest_file'](binary) != binary_hash:
        raise ValueError('docker binary receipt')
    result_dir = Path(tempfile.mkdtemp(prefix='contour-factory-result-')).resolve()
    os.chmod(result_dir, 0o700)
    print('private result:', result_dir / 'result.json', flush=True)
    started = time.monotonic()
    stages, failures = [], []
    diagnostic = {'phase': None, 'probe_stage': None, 'collector_image': None,
                  'collector_generation': None, 'collector_sha256': None}
    owned, uncertain = [], []
    probe = None
    probe_hash = None
    previous = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('overall deadline')))
    signal.setitimer(signal.ITIMER_REAL, 600)
    primary = None
    try:
      if exporter_inbox:
        result=bridge['command'](['node',str(ROOT/'tests/fixtures/nodered-causal/private-causal-exporter-offline.js')],timeout=15)
        if result!=b'PASS: offline exporter and receipt tests\n': raise RuntimeError('bad receipt offline test')
        stages.append('bad_receipt_offline')
      work_path = result_dir / 'work'
      work_path.mkdir(mode=0o700)
      with contextlib.nullcontext(str(work_path)) as temporary:
        work = Path(temporary).resolve()
        os.chmod(work, 0o700)
        config = work / 'docker-config'; config.mkdir(mode=0o700)
        target = work / 'target'; target.mkdir(mode=0o700)
        docker = [str(binary), '--host', 'unix://' + str(socket), '--config', str(config)]
        def run(args, **kwargs):
            return bridge['command'](args, **kwargs)
        def d(args, **kwargs):
            return run(docker + args, **kwargs)
        def inspect(kind, ident):
            raw = d([kind, 'inspect', ident], timeout=20)
            value = json.loads(raw)
            if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
                raise RuntimeError('invalid inspection')
            return value[0]
        def create(kind, args, name, token):
            # Once mutation begins, a lost response is never adopted by name.
            uncertain.append((kind, name))
            raw = d(args, timeout=30).decode('ascii').strip()
            if not re.fullmatch('[0-9a-f]{64}', raw):
                raise RuntimeError('mutation receipt invalid')
            info = inspect(kind, raw)
            if info.get('Id') != raw or (info.get('Labels') if kind == 'network' else info.get('Config', {}).get('Labels', {})).get(LABEL) != token:
                raise RuntimeError('mutation ownership mismatch')
            uncertain.pop()
            owned.append((kind, raw, token))
            return raw
        env = os.environ.copy(); env['CARGO_TARGET_DIR'] = str(target)
        lines = bridge['bounded_process_output'](['cargo', 'build', '-p', 'contour-ingress', '--example',
            'causal_factory_probe', '--release', '--locked', '--offline', '--message-format=json'], cwd=ROOT, env=env)
        executable = artifact(lines, target); probe_hash = bridge['digest_file'](executable)
        ca_config = work / 'ca.cnf'
        ca_config.write_text('[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-sha256',
             '-config', str(ca_config), '-extensions', 'ca', '-subj', '/CN=fixture CA', '-keyout', str(work/'ca.key'), '-out', str(work/'ca.pem')], timeout=30)
        def leaf(name, eku, sans):
            key, cert = work/(name+'.key'), work/(name+'.pem')
            request, ext = work/(name+'.csr'), work/(name+'.ext')
            ext.write_text('basicConstraints=CA:FALSE\nextendedKeyUsage='+eku+'\nsubjectAltName='+sans+'\n')
            run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-sha256','-config',str(ca_config),
                 '-subj','/CN='+name,'-keyout',str(key),'-out',str(request)],timeout=30)
            run(['openssl','x509','-req','-in',str(request),'-CA',str(work/'ca.pem'),'-CAkey',str(work/'ca.key'),
                 '-CAcreateserial','-days','1','-extfile',str(ext),'-out',str(cert)],timeout=30)
            os.chmod(key, 0o600)
            der = run(['openssl','x509','-in',str(cert),'-outform','DER'],timeout=15)
            return hashlib.sha256(der).hexdigest()
        leaf('db', 'serverAuth', 'DNS:localhost,DNS:causal-db')
        leaf('server', 'serverAuth', 'DNS:causal-node')
        leaf('peer', 'serverAuth', 'DNS:pilot-gateway,DNS:causal-ingress')
        product_leaf = leaf('product', 'clientAuth', 'DNS:product')
        export_leaf = leaf('export', 'clientAuth', 'DNS:export')
        leaf('client', 'clientAuth', 'DNS:client')
        for name in ('grant','policy'):
            run(['openssl','genpkey','-algorithm','ED25519','-out',str(work/(name+'.key'))],timeout=15)
            public = run(['openssl','pkey','-in',str(work/(name+'.key')),'-pubout','-outform','DER'],timeout=15)
            if len(public) != 44 or not public.startswith(bytes.fromhex('302a300506032b6570032100')):
                raise RuntimeError('public key encoding')
            (work/(name+'.pub')).write_bytes(public[-32:])
        # Remaining setup and cleanup is delegated to the helper below.
        qualify(work, docker, d, inspect, create, bridge, https, live, stage, executable,
                product_leaf, export_leaf, binary, socket, binary_hash, config, stages, owned, uncertain, diagnostic, exporter_inbox)
        if bridge['digest_file'](executable) != probe_hash or source_snapshot(bridge) != before:
            raise RuntimeError('source or artifact drift')
        stages.append('source_unchanged')
        expected_stages = ['bad_receipt_offline'] if exporter_inbox else []
        expected_stages += ['sql24_actual_leaf_enrolled', 'factory_ready']
        if exporter_inbox: expected_stages += ['collector_exact_session','producer_ack_and_inbox']
        expected_stages += ['incoming_mtls_before_drop','incoming_mtls_after_drop']
        if exporter_inbox: expected_stages += ['stale_epoch_refused','revocation_current_session_refused']
        expected_stages += ['source_unchanged']
        if stages != expected_stages:
            raise RuntimeError('qualification stages incomplete')
    except BaseException as error:
        primary = error
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, previous)
        except BaseException as error:
            failures.append(error)
        if owned or uncertain:
            failures.append(RuntimeError('owned or uncertain resources remain'))
        receipt = {'status': 'failed' if primary or failures else 'passed', 'stages': stages,
                   'source_hashes': before, 'probe_sha256': probe_hash,
                   'collector_image': diagnostic['collector_image'], 'collector_sha256': diagnostic['collector_sha256'],
                   'collector_generation': diagnostic['collector_generation'],
                   'elapsed_seconds': round(time.monotonic()-started, 3),
                   'failure_type': type(primary).__name__ if primary else None,
                   'failure_phase': diagnostic['phase'], 'probe_stage': diagnostic['probe_stage'],
                   'cleanup_failures': [type(x).__name__ for x in failures], 'owned_resources': owned, 'uncertain_resources': uncertain,
                   'boundary': ('factory producer-to-inbox qualification only; bad receipt tested offline; observer, receiver and graph unqualified'
                                if exporter_inbox else 'factory startup and incoming listener mTLS only; outbound completion, exporter ACK and wire graph unqualified')}
        pending = result_dir/'result.pending'; result = result_dir/'result.json'
        try:
            with pending.open('x', encoding='utf-8') as output:
                json.dump(receipt, output, sort_keys=True, indent=2); output.write('\n'); output.flush(); os.fsync(output.fileno())
            os.replace(pending, result)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise BaseExceptionGroup('qualification and cleanup', ([primary] if primary else []) + failures)
    if primary:
        raise primary
    print('PASS: factory startup and incoming listener mTLS component; outbound completion, exporter ACK and wire graph unqualified')


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        print('FAIL:', type(error).__name__, file=sys.stderr)
        sys.exit(1)
