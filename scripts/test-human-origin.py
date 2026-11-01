"""Opt-in synthetic 17 human catalog fixture; called only by --human-origin."""
import base64
import copy
import json
from pathlib import Path
import runpy
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
ACTOR = '00000000-0000-0000-0000-00000000ef01'
ISSUER = 'https://idp.example.test/realms/demo'


def run_smoke(execute, body):
    """Restricted reader privileges and tenant/argument guards, before data tests."""
    reader = 'contour_catalog_reader_tls'
    assert execute("SELECT has_table_privilege('%s','contour.origin_proofs','SELECT'),has_table_privilege('%s','contour.ingestion_payloads','SELECT'),has_table_privilege('%s','contour.catalog_origin_projection','SELECT'),has_table_privilege('%s','contour.catalog_origin_heads','SELECT,INSERT,UPDATE,DELETE,TRUNCATE');" % (reader,reader,reader,reader)) == 'f|f|f|f'
    tenant = body['tenant_id']; item = '00000000-0000-0000-0000-000000000001'
    other = 'bbbbbbbb-0000-0000-0000-000000000000' if tenant != 'bbbbbbbb-0000-0000-0000-000000000000' else 'aaaaaaaa-0000-0000-0000-000000000000'
    # Real reader role, tenant-local context, no private-table access or
    # unbounded/partial helper arguments. Exception blocks require 42501.
    execute("""BEGIN; SET LOCAL ROLE contour_catalog_reader_tls;
      SELECT set_config('apicontour.tenant_id','%(tenant)s',true);
      DO $$ DECLARE rejected boolean; BEGIN
        rejected:=false; BEGIN DELETE FROM contour.catalog_origin_heads; EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'head delete granted'; END IF;
        rejected:=false; BEGIN UPDATE contour.catalog_origin_heads SET observed_at=observed_at; EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'head update granted'; END IF;
        rejected:=false; BEGIN PERFORM * FROM contour.human_origin_candidates('%(other)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s',NULL,1); EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'cross tenant accepted'; END IF;
        rejected:=false; BEGIN PERFORM * FROM contour.human_origin_candidates('%(tenant)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s',NULL,NULL); EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'unbounded candidate request accepted'; END IF;
        rejected:=false; BEGIN PERFORM * FROM contour.human_origin_operation('%(tenant)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s',NULL,NULL,NULL,NULL); EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'partial origin scope accepted'; END IF;
      END $$; ROLLBACK;""" % dict(tenant=tenant,other=other,id=item))


def run_cases(execute, submit, body, expected_origins, port, directory, environment):
    # The authority fixture deliberately starts with a sparse component schema.
    # Extend only this opt-in mode with the ordinary human business schema.
    for name in ['declared','approval','comparison','review','human']:
        execute((ROOT / ('db/provision_' + name + '.sql')).read_text())
    for version in range(5, 13):
        path = next((ROOT / 'db/migrations').glob('%04d_*.sql' % version))
        execute(path.read_text())
    execute("CREATE ROLE contour_human_reader_tls LOGIN PASSWORD '%s'; GRANT contour_catalog_reader,contour_approval_reader,contour_human_lookup TO contour_human_reader_tls;" % environment['CONTOUR_FIXTURE_PASSWORD'])
    tenant = body['tenant_id']; target = body['records'][0]['record']
    target_scope = [tenant,target['project_id'],target['service_id'],target['environment_id']]
    scopes = [(target['project_id'],target['service_id'])] + [(o['origin_project_id'],o['origin_service_id']) for o in expected_origins]
    execute("SET ROLE contour_human_provisioner; INSERT INTO contour.human_actors VALUES ('%s',true); INSERT INTO contour.human_identities VALUES ('%s','synthetic-user','%s',true); INSERT INTO contour.human_tenant_memberships VALUES ('%s','%s',true);" % (ACTOR,ISSUER,ACTOR,tenant,ACTOR))
    for project in sorted({p for p,_ in scopes}):
        execute("SET ROLE contour_human_provisioner; INSERT INTO contour.human_project_memberships VALUES ('%s','%s','%s',true);" % (tenant,project,ACTOR))
    for project,service in sorted(set(scopes)):
        execute("SET ROLE contour_human_provisioner; INSERT INTO contour.human_service_roles VALUES ('%s','%s','%s','%s','viewer',true);" % (tenant,project,service,ACTOR))

    def token(subject):
        now = int(time.time()); claims = {'iss':ISSUER,'sub':subject,'aud':'apicontour','iat':now,'exp':now+600,'nonce':'server-generated-one-use-nonce'}
        enc = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=')
        data = enc({'alg':'RS256','kid':'synthetic-rsa'}) + b'.' + enc(claims)
        sig = subprocess.run(['openssl','dgst','-sha256','-keyform','DER','-sign',str(ROOT/'crates/contour-auth/tests/fixtures/synthetic-rsa.der')], input=data,capture_output=True,timeout=5,check=True).stdout
        path = directory / ('human-origin-token-'+subject); path.write_bytes(data+b'.'+base64.urlsafe_b64encode(sig).rstrip(b'=')); return path
    normal, unknown = token('synthetic-user'), token('unknown-user')

    # Origin 0 was closed by the enclosing fixture. Origin 1 remains active:
    # use it for a second operation to test keyset pagination for one origin.
    second = copy.deepcopy(body)
    second['batch_id'] = '00000000-0000-4000-8000-00000000be01'
    second['records'] = [copy.deepcopy(body['records'][1])]
    second['records'][0]['record']['record_id'] = '00000000-0000-4000-8000-00000000be02'
    second['records'][0]['record']['direction'] = 'request'
    submit(second,status='accepted')
    target_dir = json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],text=True,timeout=15))['target_directory']
    probe = Path(target_dir)/'debug/examples/catalog_probe'
    process = subprocess.run([str(probe),str(port),str(directory/'ca.crt'),second['batch_id'],'Processed',tenant,body['collector_id'],'5000'], input='\n',capture_output=True,text=True,env=environment,timeout=15,check=True)
    assert process.stdout.strip() == 'Processed' and not process.stderr
    where = "p.tenant_id='%s' AND p.collector_id='%s' AND p.batch_id='%s'" % (tenant,body['collector_id'],body['batch_id'])
    records = json.loads(execute("SELECT json_agg(row_to_json(x) ORDER BY record_id) FROM (SELECT p.origin_project_id AS project_id,p.origin_service_id AS service_id,p.origin_environment_id AS environment_id,p.origin_deployment_id AS deployment_id,p.instance_id,p.collector_id,p.batch_id,p.record_id,w.operation_id,w.last_seen,w.visibility,w.completeness FROM contour.catalog_origin_projection p JOIN contour.observation_windows w USING(tenant_id,collector_id,batch_id,record_id) WHERE %s) x;" % where))
    assert len(records) == 2
    records.reverse()  # Active origin first; the closed origin remains historically visible.
    first = records[0]
    keys = [tenant,target['project_id'],target['service_id'],target['environment_id'],*[first[k] for k in ('project_id','service_id','environment_id','deployment_id','instance_id')]]
    predicate = "(tenant_id,project_id,service_id,environment_id,origin_project_id,origin_service_id,origin_environment_id,origin_deployment_id,instance_id)=(%s)" % ','.join("'%s'" % key for key in keys)
    expected_operations = json.loads(execute("SELECT json_agg(operation_id::text ORDER BY operation_id) FROM contour.catalog_origin_heads WHERE %s;" % predicate))
    runpy.run_path(str(ROOT/'scripts/test-human-catalog.py'))['run_origin_cases'](execute,port,directory,environment,normal,unknown,target_scope,ACTOR,records,expected_operations)
