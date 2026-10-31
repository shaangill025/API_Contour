#!/usr/bin/env python3
"""Owned synthetic sink qualification; does not inspect Native volatile memory."""
import importlib.util
import base64
import datetime
import secrets
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
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('native_pilot', ROOT/'scripts/test-native-pilot.py')
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)
MAX = 1024 * 1024
MAX_BATCHES = 256
SERVICES = ('replica1', 'replica2', 'destination', 'native-envoy', 'native-gateway', 'pilot-capture-ingress', 'pilot-capture-worker')
POSTGRES_IMAGE = 'postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'
REQUEST_SHAPE = '{"kind":"object","fields":{"probe":{"kind":"string"}},"additional":null}'


class MarkerFound(pilot.Failure):
    pass


class RetentionFailure(pilot.Failure):
    pass


def validate_retention(metadata):
    if metadata.get('Type') != 'json-file' or metadata.get('Config') != {}:
        raise RetentionFailure('privacy log retention unavailable')


def scan(data, markers):
    if len(data) > MAX:
        raise pilot.Failure('privacy evidence limit')
    if any(not marker or marker in data for marker in markers):
        raise MarkerFound('privacy marker observed')


def bounded(args, env, *, input_bytes=None, seconds=30):
    """Keep evidence in memory, cap bytes and absolute time, kill owned group."""
    proc = subprocess.Popen(args, cwd=ROOT, env=env, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    selector = selectors.DefaultSelector()
    deadline = time.monotonic()+seconds
    output = bytearray()
    try:
        if input_bytes is not None:
            if len(input_bytes) > 65536: raise pilot.Failure('privacy query limit')
            os.set_blocking(proc.stdin.fileno(), False)
            selector.register(proc.stdin, selectors.EVENT_WRITE, 'stdin')
        selector.register(proc.stdout, selectors.EVENT_READ, 'stdout')
        written = 0
        while selector.get_map():
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise pilot.Failure('privacy evidence deadline')
            for key, _ in selector.select(min(remaining, .2)):
                if key.data == 'stdin':
                    if written == len(input_bytes):
                        selector.unregister(proc.stdin); proc.stdin.close(); continue
                    count = os.write(proc.stdin.fileno(), input_bytes[written:written+4096])
                    written += count
                    continue
                data = os.read(key.fileobj.fileno(), min(65536, MAX+1-len(output)))
                if not data: selector.unregister(key.fileobj); continue
                output.extend(data)
                if len(output) > MAX: raise pilot.Failure('privacy evidence limit')
        remaining = deadline-time.monotonic()
        if remaining <= 0 or proc.wait(timeout=remaining): raise pilot.Failure('privacy evidence command failed')
        return bytes(output)
    finally:
        selector.close()
        if proc.poll() is None: pilot.kill_group(proc.pid); proc.wait(timeout=5)
        proc.stdout.close()
        if proc.stdin is not None and not proc.stdin.closed: proc.stdin.close()


def id_list(raw):
    lines = raw.decode('ascii').splitlines()
    if len(lines) > MAX_BATCHES: raise pilot.Failure('privacy batch limit')
    if len(set(lines)) != len(lines): raise pilot.Failure('duplicate privacy batch id')
    for item in lines:
        if str(uuid.UUID(item)) != item: raise pilot.Failure('invalid privacy batch id')
    return set(lines)


def decode_projection(raw, expected):
    """All selected rows and each bytea value are hex, never printed or saved."""
    seen = set()
    blobs = []
    for line in raw.splitlines():
        fields = line.split(b'|')
        if len(fields) < 3: raise pilot.Failure('invalid privacy projection')
        kind = fields[0].decode('ascii'); batch = fields[1].decode('ascii')
        if kind not in ('batch', 'payload', 'window') or batch not in expected: raise pilot.Failure('unscoped privacy projection')
        try: blobs.extend(bytes.fromhex(value.decode('ascii')) for value in fields[2:])
        except (ValueError, UnicodeError): raise pilot.Failure('invalid privacy projection encoding') from None
        seen.add((kind,batch))
    if any((kind,batch) not in seen for batch in expected for kind in ('batch','payload','window')):
        raise pilot.Failure('missing privacy projection')
    return blobs


def prepare_flow(source, marker):
    flow=json.loads(source)
    found=0
    for node in flow:
        if node.get('id') == 'pilot-fixed':
            rules=[rule for rule in node['rules'] if rule.get('p') == 'payload' and rule.get('t') == 'set']
            if len(rules)!=1: raise pilot.Failure('unexpected pilot flow')
            rules[0]['to']=json.dumps({'probe':marker},separators=(',',':'))
            found += 1
    if found != 1: raise pilot.Failure('unexpected pilot flow')
    return json.dumps(flow,separators=(',',':')).encode()


class Driver:
    def __init__(self, *, shutdown_negative=False):
        self.shutdown_negative = shutdown_negative
        self.base = pilot.Driver()
        self.folder = self.base.folder
        self.markers = [('SYNTHETIC_REQUEST_'+uuid.uuid4().hex).encode(), ('SYNTHETIC_RESPONSE_'+uuid.uuid4().hex).encode()]
        self.override = self.folder/'privacy-overlay.json'
        self.project = 'contour-privacy-'+uuid.uuid4().hex[:16]
        self.network = self.project+'-capture'
        self.frontend = self.project+'-frontend'
        self.database_container = None
        self.image = 'contour-privacy-candidate:'+uuid.uuid4().hex
        self.verifier = self.project+'-image-check'
        self.image_intent = False
        self.verifier_intent = False
        self.created = False
        self.containers = {}

    def setup_overlay(self):
        p=self.folder
        pilot.private_write(p/'privacy.json',json.dumps({'request':self.markers[0].decode(), 'response':self.markers[1].decode()}).encode())
        pilot.private_write(p/'flows.json',prepare_flow((ROOT/'deploy/pilot/flows.json').read_text(),self.markers[0].decode()))
        for name in ('admin','ingress','worker'):
            pilot.private_write(p/(name+'.password'),secrets.token_urlsafe(32).encode())
        pilot.private_write(p/'pg_hba.conf',b'local all all trust\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostssl all all ::0/0 scram-sha-256\n')
        os.chmod(p/'pg_hba.conf',0o644)
        fixture=ROOT/'tests/fixtures/native-privacy'
        mounts = [str(p/'flows.json')+':/pilot/flows.json:ro',str(p/'privacy.json')+':/pilot/privacy.json:ro',str(fixture/'probe.js')+':/pilot/privacy-probe.js:ro']
        config_common={'database_host':'postgres','database_port':5432,'database_name':'contour_local','ca_file':'/run/capture/database-ca.crt','tenant':pilot.TENANT,'collector':'00000000-0000-4000-8000-000000000301'}
        ingress=dict(config_common,database_user='contour_local_ingress',password_file='/run/capture/ingress.password',server_certificate_der='/run/capture/server.crt.der',server_key_der='/run/capture/server.key.der',client_ca_der='/run/capture/ca.der',collector_certificate_der='/run/capture/collector.crt.der',policy_key_file='/run/capture/policy.raw',listen='0.0.0.0:9445')
        worker=dict(config_common,database_user='contour_local_worker',password_file='/run/capture/worker.password')
        for name, config in [('ingress',ingress),('worker',worker)]:
            pilot.private_write(p/(name+'.json'),json.dumps(config).encode())
        logging={'driver':'json-file','options':{}}
        postgres={'image':POSTGRES_IMAGE, 'entrypoint':['sh','-c'],
            'command':['cp /run/local/server.key /tmp/server.key && cp /run/local/server.crt /tmp/server.crt && chown postgres:postgres /tmp/server.key /tmp/server.crt && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key -c hba_file=/run/config/pg_hba.conf'],
            'environment':{'POSTGRES_DB':'contour_local','POSTGRES_PASSWORD_FILE':'/run/secrets/admin-password','POSTGRES_HOST_AUTH_METHOD':'scram-sha-256'},
            'volumes':[str(ROOT/'.local-mvp/tls')+':/run/local:ro',str(p/'pg_hba.conf')+':/run/config/pg_hba.conf:ro',str(p/'admin.password')+':/run/secrets/admin-password:ro'],
            'tmpfs':['/var/lib/postgresql/data:rw,nosuid,nodev,size=512m'], 'networks':['capture'], 'logging':logging,
            'mem_limit':'768m','cpus':1,'pids_limit':128,'security_opt':['no-new-privileges:true'],'restart':'no'}
        override={'services':{'replica1':{'volumes':mounts},'replica2':{'volumes':mounts},
            'destination':{'volumes':[str(fixture/'destination.js')+':/pilot/destination.js:ro',str(p/'privacy.json')+':/pilot/privacy.json:ro']},
            'native-gateway':{'volumes':[str(p/'policy.raw')+':/run/native/policy-public-key.bin:ro']},
            'pilot-capture-ingress':{'volumes':[str(p/'ingress.json')+':/run/capture/ingress.json:ro',str(p/'ingress.password')+':/run/capture/ingress.password:ro',str(p/'policy.raw')+':/run/capture/policy.raw:ro']},
            'pilot-capture-worker':{'volumes':[str(p/'worker.json')+':/run/capture/worker.json:ro',str(p/'worker.password')+':/run/capture/worker.password:ro']},
            'postgres':postgres}, 'networks':{'capture':{'external':False,'name':self.network,'internal':True},'default':{'name':self.frontend,'internal':True}}}
        for service in SERVICES:
            override['services'].setdefault(service, {})['logging'] = logging
        for service in ('native-gateway','pilot-capture-ingress','pilot-capture-worker'):
            override['services'][service]['image'] = self.image
        if self.shutdown_negative:
            override['services']['destination']['environment']={'PRIVACY_TEST_SHUTDOWN_MARKER':'1'}
        pilot.private_write(self.override,json.dumps(override).encode())

    def command(self):
        return ['docker','compose','-p',self.project,'-f',str(ROOT/'deploy/pilot/compose.yaml'),'-f',str(ROOT/'deploy/pilot/native-overlay.yaml'),'-f',str(self.override),'--profile','native-capture']

    def compose(self, name, args, seconds=90):
        return self.base.run(name,self.command()+args,seconds)

    def sql(self, query):
        if any(marker.decode() in query for marker in self.markers): raise pilot.Failure('marker in privacy query')
        return bounded(self.command()+['exec','-T','-u','postgres','postgres','psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_local'],
                       self.base.env,input_bytes=query.encode(),seconds=30)

    def policy(self):
        p=self.folder
        bounded(['openssl','genpkey','-algorithm','ED25519','-out',str(p/'policy.key')],self.base.env)
        public=bounded(['openssl','pkey','-in',str(p/'policy.key'),'-pubout','-outform','DER'],self.base.env)
        if len(public)!=44: raise pilot.Failure('privacy policy key invalid')
        pilot.private_write(p/'policy.raw',public[-32:])
        now=datetime.datetime.now(datetime.timezone.utc)
        stamp=lambda value:value.isoformat(timespec='microseconds').replace('+00:00','Z')
        policy={'tenant_id':pilot.TENANT,'collector_id':'00000000-0000-4000-8000-000000000301','revision':1,
            'issued_at':stamp(now-datetime.timedelta(minutes=1)),'expires_at':stamp(now+datetime.timedelta(minutes=14)),
            'enabled':True,'service_ids':[pilot.SERVICE],'techniques':['gateway'],'approved_names':['POST','probe','result'],
            'denied_templates':[],'inspection_bytes':65536,'depth_limit':32,'queue_bytes':1048576,'queue_ttl_seconds':3600,
            'durable_queue_enabled':False,'approved_route_segments':['pilot'],'parser_profiles':['http_json_v1']}
        payload=json.dumps(policy,separators=(',',':')).encode()
        pilot.private_write(p/'policy.message',b'apicontour/policy/1\n'+payload)
        bounded(['openssl','pkeyutl','-sign','-rawin','-inkey',str(p/'policy.key'),'-in',str(p/'policy.message'),'-out',str(p/'policy.sig')],self.base.env)
        signature=(p/'policy.sig').read_bytes()
        if len(signature)!=64: raise pilot.Failure('privacy policy signature invalid')
        enc=lambda data:base64.urlsafe_b64encode(data).rstrip(b'=').decode()
        return json.dumps({'key_id':'local','signature_profile':'ed25519-v1','payload_base64url':enc(payload),'signature_base64url':enc(signature)},separators=(',',':')).encode()

    def provision_database(self, envelope):
        paths=['bootstrap.sql']+['provision_'+name+'.sql' for name in self.base.base.PROVISION]
        paths += ['migrations/'+path.name for path in self.base.base.MIGRATIONS]
        for path in paths: self.sql((ROOT/'db'/path).read_text())
        quote=self.base.base.sql_quote
        for role,group in [('ingress','contour_ingestion'),('worker','contour_catalog_worker')]:
            password=(self.folder/(role+'.password')).read_text()
            self.sql('CREATE ROLE contour_local_'+role+' LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '+quote(password)+'; GRANT '+group+' TO contour_local_'+role+'; GRANT CONNECT ON DATABASE contour_local TO contour_local_'+role+';')
        t,p,s,e,c,src,d,i,n=map(quote,[pilot.TENANT,pilot.PROJECT,pilot.SERVICE,pilot.ENVIRONMENT,'00000000-0000-4000-8000-000000000301',pilot.SOURCE,pilot.DEPLOYMENT,'00000000-0000-4000-8000-000000000304','00000000-0000-4000-8000-000000000305'])
        self.sql('BEGIN; '+f'INSERT INTO contour.tenants VALUES ({t}); INSERT INTO contour.projects VALUES ({t},{p}); INSERT INTO contour.services VALUES ({t},{s},{p}); INSERT INTO contour.environments VALUES ({t},{e},{p}); '+
            f"SELECT set_config('apicontour.tenant_id',{t},true); SET LOCAL ROLE contour_admin; INSERT INTO contour.deployments VALUES ({t},{d},{p},{s},{e}); SELECT contour.lock_collector({t},{c}); INSERT INTO contour.collectors VALUES ({t},{c}); INSERT INTO contour.workload_assignments VALUES ({t},{c},{p},{s},{e},{d}); INSERT INTO contour.workload_instances VALUES ({t},{p},{s},{e},{d},{i}); SELECT contour.register_instance_source({t},{src},{c},{p},{s},{e},{d},{n},{i}); INSERT INTO contour.source_authorization VALUES ({t},{src},{c},'gateway',ARRAY['http_json_v1']); INSERT INTO contour.policy_revisions VALUES ({t},{c},1,decode('{envelope.hex()}','hex')); UPDATE contour.collector_authorization SET active_revision=1,enabled=true WHERE tenant_id={t} AND collector_id={c}; COMMIT;")
        check=self.sql(f"SELECT (SELECT count(*) FROM contour.source_instance_bindings WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND deployment_id={d} AND instance_id={i}), (SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c}), (SELECT count(*) FROM contour.collector_authorization WHERE tenant_id={t} AND collector_id={c} AND active_revision=1 AND enabled AND revoked_at IS NULL);")
        if check.strip()!=b'1|1|1': raise pilot.Failure('privacy enrollment mismatch')
        exact=self.sql(f"SELECT (SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c} AND project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={d}), (SELECT count(*) FROM contour.source_authorization WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND technique='gateway' AND parser_profiles=ARRAY['http_json_v1']), (SELECT count(*) FROM contour.policy_revisions WHERE tenant_id={t} AND collector_id={c} AND revision=1 AND signed_envelope=decode('{envelope.hex()}','hex')), (SELECT count(*) FROM pg_roles WHERE rolname IN ('contour_local_ingress','contour_local_worker') AND rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL), (SELECT count(*) FROM pg_roles r WHERE r.rolname<>'contour_local_ingress' AND pg_has_role('contour_local_ingress',r.oid,'MEMBER') AND r.rolname IN ('contour_ingestion','contour_runtime')), (SELECT count(*) FROM pg_roles r WHERE r.rolname<>'contour_local_worker' AND pg_has_role('contour_local_worker',r.oid,'MEMBER') AND r.rolname='contour_catalog_worker');")
        if exact.strip()!=b'1|1|1|2|2|1': raise pilot.Failure('privacy role or enrollment mismatch')
        totals=self.sql(f"SELECT (SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c}), (SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c}), (SELECT count(*) FROM contour.source_authorization WHERE tenant_id={t} AND collector_id={c}), (SELECT count(*) FROM contour.source_instance_bindings WHERE tenant_id={t} AND collector_id={c}), (SELECT count(*) FROM contour.policy_revisions WHERE tenant_id={t} AND collector_id={c}), (SELECT count(*) FROM pg_roles r WHERE r.rolname<>'contour_local_ingress' AND pg_has_role('contour_local_ingress',r.oid,'MEMBER')), (SELECT count(*) FROM pg_roles r WHERE r.rolname<>'contour_local_worker' AND pg_has_role('contour_local_worker',r.oid,'MEMBER'));")
        if totals.strip()!=b'1|1|1|1|1|2|1': raise pilot.Failure('privacy authority is not exact')

    def prepare_database(self):
        # Check for pre-existing names before recording creation intent.
        existing=bounded(self.command()+['ps','--all','-q'],self.base.env)
        for network in (self.network,self.frontend):
            networks=bounded(['docker','network','ls','--filter','name='+network,'--format','{{.Name}}'],self.base.env).decode().splitlines()
            if network in networks: raise pilot.Failure('privacy resource collision')
        if existing.strip(): raise pilot.Failure('privacy resource collision')
        for image in (POSTGRES_IMAGE,pilot.IMAGES[0],pilot.IMAGES[1],*pilot.IMAGES[2:]):
            bounded(['docker','image','inspect',image],self.base.env)
        if self.image in self.image_tags(): raise pilot.Failure('privacy image collision')
        if self.verifier in self.verifier_names(): raise pilot.Failure('privacy image verifier collision')
        # Use the existing locked Dockerfile build without touching the shared app tag.
        # Intent precedes creation so a lost acknowledgement still gets cleanup.
        self.image_intent=True
        self.base.run('privacy-image-build',['docker','build','--pull=false',
            '-f',str(ROOT/'deploy/local/Dockerfile'),'-t',self.image,str(ROOT)],1800)
        bounded(['docker','image','inspect',self.image],self.base.env)
        self.verifier_intent=True
        bounded(['docker','run','--pull','never','--rm','--name',self.verifier,
            '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--entrypoint','/bin/sh',self.image,'-c',
            'test -x /usr/local/bin/local_gateway && test -x /usr/local/bin/local_capture'],self.base.env,seconds=30)
        envelope=self.policy()
        self.created=True
        self.compose('privacy-database-start',['up','-d','--pull','never','postgres'],90)
        deadline=time.monotonic()+30
        while True:
            try:
                bounded(self.command()+['exec','-T','postgres','pg_isready','-U','postgres','-d','contour_local'],self.base.env,seconds=3)
                break
            except pilot.Failure:
                if time.monotonic()>=deadline: raise
                time.sleep(.25)
        self.database_container=self.service_id('postgres')
        self.verify_container('postgres',self.database_container,{self.network})
        tmpfs=json.loads(bounded(['docker','inspect','--format','{{json .HostConfig.Tmpfs}}',self.database_container],self.base.env,seconds=15))
        if not isinstance(tmpfs,dict) or '/var/lib/postgresql/data' not in tmpfs:
            raise pilot.Failure('privacy database storage is not tmpfs')
        self.provision_database(envelope)

    def image_tags(self):
        result=bounded(['docker','image','ls','--filter','reference='+self.image,
                        '--format','{{.Repository}}:{{.Tag}}'],self.base.env)
        return result.decode().splitlines()

    def verifier_names(self):
        result=bounded(['docker','ps','--all','--filter','name='+self.verifier,
                        '--format','{{.Names}}'],self.base.env)
        return result.decode().splitlines()

    def cleanup(self):
        failures=[]
        if self.created:
            try: self.compose('privacy-cleanup',['down','--timeout','10','--remove-orphans','--volumes'],90)
            except BaseException as exc: failures.append(exc)
        if self.verifier_intent:
            try:
                if self.verifier in self.verifier_names():
                    bounded(['docker','rm','-f',self.verifier],self.base.env,seconds=30)
            except BaseException as exc: failures.append(exc)
        if self.image_intent:
            try:
                if self.image in self.image_tags():
                    bounded(['docker','image','rm',self.image],self.base.env,seconds=30)
            except BaseException as exc: failures.append(exc)
        for name in ('admin.password','ingress.password','worker.password','policy.key','policy.message','policy.sig','policy.raw'):
            try: (self.folder/name).unlink(missing_ok=True)
            except BaseException as exc: failures.append(exc)
        if failures: raise BaseExceptionGroup('privacy cleanup failed', failures)

    def existing_batches(self):
        return id_list(self.sql("SELECT batch_id::text FROM contour.ingestion_batches WHERE tenant_id='"+pilot.TENANT+"' AND collector_id='00000000-0000-4000-8000-000000000301' ORDER BY 1 LIMIT "+str(MAX_BATCHES+1)+";"))

    def ids(self):
        return id_list(self.sql("SELECT DISTINCT w.batch_id::text FROM contour.observation_windows w JOIN contour.operations o ON o.tenant_id=w.tenant_id AND o.operation_id=w.operation_id WHERE "+pilot.SCOPE+
            " AND w.source_id='"+pilot.SOURCE+"' AND w.project_id='"+pilot.PROJECT+"' AND w.service_id='"+pilot.SERVICE+"' AND w.environment_id='"+pilot.ENVIRONMENT+"' AND w.deployment_id='"+pilot.DEPLOYMENT+"' AND o.canonical_key IN (convert_to('"+pilot.operation_key('request')+"','UTF8'),convert_to('"+pilot.operation_key('response')+"','UTF8')) ORDER BY 1 LIMIT "+str(MAX_BATCHES+1)+";"))

    def selected(self, ids):
        if not ids: raise pilot.Failure('missing new privacy batches')
        return ','.join("'"+str(uuid.UUID(item))+"'" for item in sorted(ids))

    def assert_shapes(self, ids):
        selected=self.selected(ids)
        scope=("w.source_id='"+pilot.SOURCE+"' AND w.project_id='"+pilot.PROJECT+
               "' AND w.service_id='"+pilot.SERVICE+"' AND w.environment_id='"+pilot.ENVIRONMENT+
               "' AND w.deployment_id='"+pilot.DEPLOYMENT+"' AND w.visibility='structure' AND w.completeness='complete' AND NOT w.route_uncertain AND v.parser_profile='http_json_v1'")
        request="("+scope+" AND o.canonical_key=convert_to('"+pilot.operation_key('request')+"','UTF8') AND convert_from(v.structure_wire,'UTF8')::jsonb='"+REQUEST_SHAPE+"'::jsonb AND w.status_code IS NULL)"
        response="("+scope+" AND o.canonical_key=convert_to('"+pilot.operation_key('response')+"','UTF8') AND convert_from(v.structure_wire,'UTF8')::jsonb='"+pilot.RESPONSE+"'::jsonb AND w.status_code=200)"
        query=("SELECT count(*) FILTER (WHERE "+request+"),count(*) FILTER (WHERE "+response+"),count(*) FILTER (WHERE NOT COALESCE(("+request+" OR "+response+"),false)) FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id) JOIN contour.operations o ON o.tenant_id=w.tenant_id AND o.operation_id=w.operation_id WHERE "+pilot.SCOPE+" AND w.batch_id IN ("+selected+");")
        values=self.sql(query).strip().split(b'|')
        if len(values)!=3 or int(values[0])<2 or int(values[1])<2 or int(values[2])!=0: raise pilot.Failure('privacy shapes not complete')

    def projections(self, ids):
        selected=self.selected(ids)
        where="tenant_id='"+pilot.TENANT+"' AND collector_id='00000000-0000-4000-8000-000000000301' AND batch_id IN ("+selected+")"
        # Row JSON covers every scalar; separately decode all bytea columns.
        payload="SELECT 'payload|'||p.batch_id::text||'|'||encode(convert_to(row_to_json(p)::text,'UTF8'),'hex')||'|'||encode(p.checked_batch,'hex') FROM contour.ingestion_payloads p WHERE "+where
        windows="SELECT 'window|'||w.batch_id::text||'|'||encode(convert_to(row_to_json(w)::text,'UTF8'),'hex')||'|'||encode(w.request_header_names,'hex')||'|'||encode(w.response_header_names,'hex')||'|'||encode(w.query_parameter_names,'hex')||'|'||encode(convert_to(row_to_json(v)::text,'UTF8'),'hex')||'|'||encode(v.structure_wire,'hex')||'|'||encode(v.canonical_structure,'hex')||'|'||encode(convert_to(row_to_json(o)::text,'UTF8'),'hex')||'|'||encode(o.canonical_key,'hex') FROM contour.observation_windows w JOIN contour.variants v USING(tenant_id,variant_id,operation_id,collector_id) JOIN contour.operations o ON o.tenant_id=w.tenant_id AND o.operation_id=w.operation_id WHERE "+pilot.SCOPE+" AND w.batch_id IN ("+selected+")"
        batches="SELECT 'batch|'||b.batch_id::text||'|'||encode(convert_to(row_to_json(b)::text,'UTF8'),'hex')||'|'||encode(b.request_digest,'hex') FROM contour.ingestion_batches b WHERE "+where
        for blob in decode_projection(self.sql(batches+' UNION ALL '+payload+' UNION ALL '+windows+';'),ids): scan(blob,self.markers)

    def service_id(self, service, *, all_containers=False):
        args=['ps']+(['--all'] if all_containers else [])+['-q',service]
        value=self.compose('privacy-container-'+service,args,30).decode().strip()
        if len(value)!=64 or any(c not in '0123456789abcdef' for c in value): raise pilot.Failure('missing privacy container')
        return value

    def verify_container(self, service, container, expected_networks):
        metadata=json.loads(bounded(['docker','inspect','--format','{{json .HostConfig.LogConfig}}',container],self.base.env,seconds=15))
        validate_retention(metadata)
        networks=json.loads(bounded(['docker','inspect','--format','{{json .NetworkSettings.Networks}}',container],self.base.env,seconds=15))
        ports=json.loads(bounded(['docker','inspect','--format','{{json .HostConfig.PortBindings}}',container],self.base.env,seconds=15))
        if set(networks)!=expected_networks or ports not in (None,{}):
            raise pilot.Failure('privacy container network mismatch')

    def started_services(self):
        for service in SERVICES:
            value=self.service_id(service)
            networks=({self.network} if service in ('pilot-capture-ingress','pilot-capture-worker') else
                      {self.network,self.frontend} if service=='native-gateway' else {self.frontend})
            self.verify_container(service,value,networks)
            self.containers[service]=value

    def logs(self):
        if set(self.containers)!=set(SERVICES): raise pilot.Failure('missing privacy log sources')
        for service,container in self.containers.items():
            current=self.compose('privacy-current-'+service,['ps','--all','-q',service],30).decode().strip()
            if current != container: raise pilot.Failure('privacy container replaced')
            scan(bounded(['docker','logs',container],self.base.env,seconds=20),self.markers)

    def product(self):
        for replica in ('replica1','replica2'):
            value=json.loads(self.compose('privacy-product-'+replica,['exec','-T',replica,'node','/pilot/privacy-probe.js'],15))
            if value != {'ok':True}: raise pilot.Failure('privacy product failed')

    def stop_and_scan(self, before, ids):
        # Keep containers and logs until every process has exited, including
        # shutdown handlers that may write after the last request completes.
        self.compose('privacy-stop-all',['stop','--timeout','10',*SERVICES],90)
        if set(self.containers) != set(SERVICES): raise pilot.Failure('missing privacy containers')
        for service, container in self.containers.items():
            current=self.compose('privacy-stopped-'+service,['ps','--all','-q',service],30).decode().strip()
            if current != container: raise pilot.Failure('privacy container replaced')
            state=json.loads(bounded(['docker','inspect','--format','{{json .State}}',container],self.base.env,seconds=15))
            if state.get('Running') is not False or state.get('Status') != 'exited':
                raise pilot.Failure('privacy container not stopped')
        if self.existing_batches()-before != ids: raise pilot.Failure('privacy accepted set changed')
        self.projections(ids)
        self.logs()
        if self.existing_batches()-before != ids or self.ids()-before != ids:
            raise pilot.Failure('privacy accepted set changed')
        self.compose('privacy-stop-database',['stop','--timeout','10','postgres'],40)
        if self.service_id('postgres',all_containers=True) != self.database_container:
            raise pilot.Failure('privacy database replaced')
        state=json.loads(bounded(['docker','inspect','--format','{{json .State}}',self.database_container],self.base.env,seconds=15))
        if state.get('Running') is not False or state.get('Status') != 'exited':
            raise pilot.Failure('privacy database not stopped')
        scan(bounded(['docker','logs',self.database_container],self.base.env,seconds=20),self.markers)

    def run(self):
        self.setup_overlay()
        self.prepare_database()
        before=self.existing_batches()
        self.compose('privacy-start',['up','-d','--pull','never','--no-recreate',*SERVICES],90)
        self.started_services()
        deadline=time.monotonic()+35
        while True:
            try: self.product(); break
            except (pilot.Failure,ValueError):
                if time.monotonic()>=deadline: raise
                time.sleep(.5)
        previous=None
        stable_since=time.monotonic()
        while True:
            ids=self.existing_batches()-before
            observed=self.ids()-before
            if ids != previous:
                previous=ids; stable_since=time.monotonic()
            try:
                if not ids or observed != ids: raise pilot.Failure('privacy batches not projected')
                self.assert_shapes(ids)
                if time.monotonic()-stable_since >= 3: break
            except pilot.Failure:
                if time.monotonic()>=deadline: raise
            if time.monotonic()>=deadline: raise pilot.Failure('privacy batches did not settle')
            time.sleep(.5)
        self.stop_and_scan(before, ids)
        print('native synthetic reachable logs and scoped persisted projections: passed',flush=True)
        print('native volatile queue, process memory, dumps and other sinks: uninspected',flush=True)


def main():
    if sys.argv[1:] == ['--self-test']:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OfflineTests))
        return 0 if result.wasSuccessful() else 1
    if sys.argv[1:] not in ([], ['--shutdown-negative']): raise pilot.Failure('unsupported argument')
    driver=Driver(shutdown_negative=sys.argv[1:] == ['--shutdown-negative'])
    pilot.with_restoration(driver.run,driver.cleanup)
    return 0


class OfflineTests(unittest.TestCase):
    def test_private_overlay_pins_unrotated_logs_for_every_service(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            driver=Driver.__new__(Driver)
            driver.folder=Path(directory)
            driver.markers=[b'fixture-request',b'fixture-response']
            driver.shutdown_negative=False
            driver.network='test-privacy-capture'
            driver.frontend='test-privacy-frontend'
            driver.project='test-privacy'
            driver.image='contour-privacy-candidate:test123'
            driver.override=driver.folder/'privacy-overlay.json'
            driver.setup_overlay()
            services=json.loads(driver.override.read_text())['services']
            self.assertEqual(set(services),set(SERVICES)|{'postgres'})
            for service in SERVICES:
                self.assertEqual(services[service]['logging'], {'driver':'json-file','options':{}})
            for service in ('native-gateway','pilot-capture-ingress','pilot-capture-worker'):
                self.assertEqual(services[service]['image'],driver.image)
                self.assertNotEqual(services[service]['image'],'apicontour-local-app')
            self.assertNotIn('environment',services['destination'])
            overlay=json.loads(driver.override.read_text())
            self.assertEqual(overlay['networks']['capture'],{'external':False,'name':driver.network,'internal':True})
            self.assertEqual(overlay['networks']['default'],{'name':driver.frontend,'internal':True})
            postgres=services['postgres']
            self.assertNotIn('ports',postgres)
            self.assertEqual(postgres['networks'],['capture'])
            self.assertTrue(any(v.startswith('/var/lib/postgresql/data:') for v in postgres['tmpfs']))
            self.assertNotIn('apicontour-local_default',driver.override.read_text())
            self.assertEqual(driver.command()[2:4],['-p',driver.project])

    def test_sql_uses_only_owned_project(self):
        driver=Driver.__new__(Driver)
        driver.project='owned-privacy-project'
        driver.override=Path('/private/tmp/owned-overlay.json')
        driver.markers=[b'request-marker',b'response-marker']
        driver.base=mock.Mock(env={})
        with mock.patch(__name__+'.bounded',return_value=b'1') as run:
            self.assertEqual(driver.sql('SELECT 1;'),b'1')
        command=run.call_args.args[0]
        self.assertEqual(command[2:4],['-p','owned-privacy-project'])
        self.assertIn('postgres',command)
        self.assertNotIn('apicontour-local_default',command)
        self.assertEqual(run.call_args.kwargs['input_bytes'],b'SELECT 1;')

    def test_owned_cleanup_preserves_original_and_cleanup_failure(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            driver=Driver.__new__(Driver)
            driver.folder=Path(directory); driver.created=True
            driver.verifier_intent=False; driver.image_intent=False
            driver.compose=mock.Mock(side_effect=RuntimeError('cleanup'))
            (driver.folder/'policy.key').write_text('synthetic')
            def fail(): raise KeyboardInterrupt()
            with self.assertRaises(BaseExceptionGroup) as caught:
                pilot.with_restoration(fail,driver.cleanup)
            self.assertIsInstance(caught.exception.exceptions[0],KeyboardInterrupt)
            self.assertIsInstance(caught.exception.exceptions[1],BaseExceptionGroup)
            self.assertFalse((driver.folder/'policy.key').exists())
            self.assertEqual(driver.compose.call_args.args[1],['down','--timeout','10','--remove-orphans','--volumes'])

    def test_image_build_is_owned_and_before_policy(self):
        driver=Driver.__new__(Driver)
        driver.project='fixture-project'; driver.network='fixture-capture'; driver.frontend='fixture-front'
        driver.override=Path('/private/tmp/fixture-overlay.json')
        driver.image='contour-privacy-candidate:unique'; driver.verifier='fixture-verifier'
        driver.image_intent=False; driver.verifier_intent=False; driver.created=False
        driver.base=mock.Mock(env={})
        driver.image_tags=lambda: []
        driver.verifier_names=lambda: []
        driver.policy=mock.Mock(side_effect=RuntimeError('stop before database'))
        def bounded_fake(args, env, **kwargs):
            if args[:3]==['docker','run','--pull']:
                self.assertTrue(driver.image_intent)
                self.assertTrue(driver.verifier_intent)
                self.assertEqual(args[args.index('--network')+1],'none')
                self.assertIn(driver.image,args)
            return b''
        def build(name, args, seconds):
            self.assertTrue(driver.image_intent)
            self.assertFalse(driver.policy.called)
            self.assertEqual(name,'privacy-image-build')
            self.assertNotIn('--network=none',args)
            self.assertIn('--pull=false',args)
            self.assertEqual(args[args.index('-t')+1],driver.image)
            self.assertNotIn('apicontour-local-app',args)
        driver.base.run.side_effect=build
        with mock.patch(__name__+'.bounded',side_effect=bounded_fake):
            with self.assertRaises(RuntimeError): driver.prepare_database()
        self.assertTrue(driver.policy.called)
        self.assertFalse(driver.created)

    def test_cleanup_removes_only_owned_verifier_and_image_tag(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            driver=Driver.__new__(Driver)
            driver.folder=Path(directory); driver.created=False
            driver.verifier='fixture-owned-verifier'; driver.image='contour-privacy-candidate:owned'
            driver.verifier_intent=True; driver.image_intent=True
            driver.base=mock.Mock(env={})
            driver.verifier_names=lambda: ['some-other-container',driver.verifier]
            driver.image_tags=lambda: ['some-other-image:tag',driver.image]
            with mock.patch(__name__+'.bounded',return_value=b'') as run:
                driver.cleanup()
            self.assertEqual([call.args[0] for call in run.call_args_list],
                [['docker','rm','-f',driver.verifier],['docker','image','rm',driver.image]])

    def test_retention_rejects_unexpected_driver_or_rotation(self):
        validate_retention({'Type':'json-file','Config':{}})
        for metadata in ({'Type':'local','Config':{'max-size':'-1'}},
                         {'Type':'json-file','Config':{'max-size':'10m'}},
                         {'Type':'json-file','Config':{'mode':'non-blocking'}}, {'Type':'none','Config':{}}, {'Type':'json-file'}):
            with self.assertRaises(RetentionFailure): validate_retention(metadata)

    def test_shutdown_marker_scanned_after_all_services_stop(self):
        driver=Driver.__new__(Driver)
        driver.base=mock.Mock(env={})
        driver.containers={name:'a'*64 for name in SERVICES}
        driver.markers=[b'request-marker',b'response-marker']
        events=[]
        state={'stopped':False, 'log':b''}
        def compose(name, args, seconds=90):
            if args[0]=='stop':
                self.assertEqual(tuple(args[3:]),SERVICES)
                state['stopped']=True
                state['log'] += b'request-marker'
                events.append('stop')
                return b''
            self.assertTrue(state['stopped'])
            return b'a'*64+b'\n'
        def inspect(args, env, **kwargs):
            self.assertTrue(state['stopped'])
            return b'{"Running":false,"Status":"exited"}'
        driver.compose=compose
        driver.existing_batches=lambda: {'batch'}
        driver.ids=lambda: {'batch'}
        driver.projections=lambda ids: events.append('projections')
        def logs():
            events.append('logs')
            scan(state['log'],driver.markers)
        driver.logs=logs
        with mock.patch(__name__+'.bounded',side_effect=inspect):
            with self.assertRaises(MarkerFound): driver.stop_and_scan(set(),{'batch'})
        self.assertEqual(events,['stop','projections','logs'])

    def test_default_fixture_has_no_shutdown_negative_control(self):
        source=(ROOT/'tests/fixtures/native-privacy/destination.js').read_text()
        self.assertIn("process.env.PRIVACY_TEST_SHUTDOWN_MARKER === '1'",source)
        self.assertNotIn('PRIVACY_TEST_SHUTDOWN_MARKER',(ROOT/'deploy/pilot/destination.js').read_text())

    def test_scanners_fail_positive_and_oversized(self):
        markers=[b'request-marker',b'response-marker']
        for marker in markers:
            with self.assertRaises(pilot.Failure): scan(b'prefix'+marker+b'suffix',markers)
            for kind in ('batch','payload','window'):
                batch='00000000-0000-4000-8000-000000000001'
                rows=[]
                for candidate in ('batch','payload','window'):
                    value=marker if candidate == kind else b'clean'
                    rows.append(candidate+'|'+batch+'|'+value.hex())
                blobs=decode_projection(('\n'.join(rows)+'\n').encode(),{batch})
                with self.assertRaises(pilot.Failure):
                    for blob in blobs: scan(blob,markers)
        scan(b'clean',markers)
        with self.assertRaises(pilot.Failure): scan(b'x'*(MAX+1),markers)

    def test_bounded_runner_rejects_overflow_and_deadline(self):
        self.assertEqual(bounded([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],dict(os.environ),input_bytes=b'ok',seconds=3),b'ok')
        with self.assertRaises(pilot.Failure):
            bounded([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"x"*1048577)'],dict(os.environ),seconds=3)
        with self.assertRaises(pilot.Failure):
            bounded([sys.executable,'-c','import time;time.sleep(2)'],dict(os.environ),seconds=.1)

    def test_projection_requires_every_kind_and_valid_hex(self):
        batch='00000000-0000-4000-8000-000000000001'
        data=('batch|'+batch+'|6566\npayload|'+batch+'|6162\nwindow|'+batch+'|6364\n').encode()
        self.assertEqual(decode_projection(data,{batch}),[b'ef',b'ab',b'cd'])
        for bad in (b'',data.replace(b'6364',b'zz'),data.splitlines()[0]+b'\n'):
            with self.assertRaises(pilot.Failure): decode_projection(bad,{batch})
    def test_flow_only_changes_fixed_payload(self):
        source=(ROOT/'deploy/pilot/flows.json').read_text(); before=json.loads(source)
        after=json.loads(prepare_flow(source,'fixture'))
        target=next(n for n in after if n.get('id')=='pilot-fixed')
        self.assertEqual(json.loads(target['rules'][0]['to']),{'probe':'fixture'})
        target['rules'][0]['to']=next(n for n in before if n.get('id')=='pilot-fixed')['rules'][0]['to']
        self.assertEqual(after,before)
    def test_ids_reject_missing_invalid_duplicate_and_overflow(self):
        value='00000000-0000-4000-8000-000000000001'
        self.assertEqual(id_list((value+'\n').encode()),{value})
        for raw in (b'bad\n',(value+'\n'+value+'\n').encode()):
            with self.assertRaises((pilot.Failure,ValueError)): id_list(raw)
        with self.assertRaises(pilot.Failure): id_list(('\n'.join(str(uuid.UUID(int=i+1)) for i in range(MAX_BATCHES+1))).encode())

if __name__=='__main__':
    try: code=main()
    except RetentionFailure:
        print('native privacy log retention unavailable',file=sys.stderr); code=1
    except MarkerFound:
        print('native privacy marker detected',file=sys.stderr); code=1
    except BaseException:
        print('native privacy qualification failed',file=sys.stderr); code=1
    sys.exit(code)
