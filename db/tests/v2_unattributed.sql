-- Synthetic privilege and binding checks under a real restricted login.
SELECT fixture.assert(session_user='contour_v2_ingress_test','real V2 ingress login');
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='contour_v2_ingress'
 AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member='contour_v2_ingress'::regrole), 'restricted non-inheriting group');
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM pg_class c, LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid='contour.ingestion_v2_metadata'::regclass AND a.grantee=0 AND a.privilege_type='INSERT')
 AND NOT has_table_privilege(current_user,'contour.ingestion_v2_metadata','UPDATE,DELETE,TRUNCATE')
 AND NOT has_column_privilege(current_user,'contour.ingestion_batches','accepted_at','INSERT')
 AND NOT has_column_privilege(current_user,'contour.ingestion_batches','receipt_id','INSERT'), 'least privilege');
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM contour.ingestion_v2_metadata), 'missing tenant hides metadata');
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count) VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-00000000c001',decode(repeat('aa',32),'hex'),2,1)$q$,'42501');
SELECT fixture.expect_state('UPDATE contour.ingestion_v2_metadata SET source_id=source_id','42501');
SELECT fixture.expect_state('DELETE FROM contour.ingestion_v2_metadata','42501');
SELECT fixture.expect_state('TRUNCATE contour.ingestion_v2_metadata','42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count,accepted_at) VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-00000000c001',decode(repeat('aa',32),'hex'),2,1,clock_timestamp())$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count,receipt_id) VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-00000000c001',decode(repeat('aa',32),'hex'),2,1,gen_random_uuid())$q$,'42501');
INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
 VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-00000000c001',decode(repeat('aa',32),'hex'),2,1);
INSERT INTO contour.ingestion_payloads VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-00000000c001',2,decode('7b7d','hex'));
INSERT INTO contour.ingestion_v2_metadata
 SELECT tenant_id,collector_id,batch_id,'00000000-0000-4000-8000-00000000c002',2,request_digest,accepted_at,
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',1,'http_json_v1','unattributed'
 FROM contour.ingestion_batches WHERE batch_id='00000000-0000-4000-8000-00000000c001';
SELECT fixture.assert((SELECT count(*)=1 FROM contour.ingestion_v2_metadata),'tenant A sees own metadata');
-- Reuse a composite row but alter each binding, with distinct record IDs.
DO $$ DECLARE m contour.ingestion_v2_metadata; BEGIN
 SELECT * INTO m FROM contour.ingestion_v2_metadata;
 m.record_id='00000000-0000-4000-8000-00000000c003'; m.attribution_class='verified';
 BEGIN INSERT INTO contour.ingestion_v2_metadata SELECT m.*; RAISE EXCEPTION 'class accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 m.attribution_class='unattributed'; m.request_digest=decode(repeat('bb',32),'hex');
 BEGIN INSERT INTO contour.ingestion_v2_metadata SELECT m.*; RAISE EXCEPTION 'digest accepted'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 m.request_digest=decode(repeat('aa',32),'hex'); m.accepted_at=m.accepted_at+interval '1 second';
 BEGIN INSERT INTO contour.ingestion_v2_metadata SELECT m.*; RAISE EXCEPTION 'time accepted'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 m.accepted_at=m.accepted_at-interval '1 second'; m.deployment_id='00000000-0000-0000-0000-000000000002';
 BEGIN INSERT INTO contour.ingestion_v2_metadata SELECT m.*; RAISE EXCEPTION 'destination accepted'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 m.deployment_id='00000000-0000-0000-0000-000000000001'; m.source_id='00000000-0000-0000-0000-000000000002';
 BEGIN INSERT INTO contour.ingestion_v2_metadata SELECT m.*; RAISE EXCEPTION 'source accepted'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 m.source_id='00000000-0000-0000-0000-000000000001'; m.policy_revision=999999;
 BEGIN INSERT INTO contour.ingestion_v2_metadata SELECT m.*; RAISE EXCEPTION 'policy accepted'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
END $$;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM contour.ingestion_v2_metadata), 'tenant B cannot read A');
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count) VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-00000000c004',decode(repeat('aa',32),'hex'),2,1)$q$,'42501');
INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
 VALUES ('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-00000000c004',decode(repeat('bb',32),'hex'),2,1);
INSERT INTO contour.ingestion_v2_metadata
 SELECT tenant_id,collector_id,batch_id,'00000000-0000-4000-8000-00000000c005',2,request_digest,accepted_at,
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',1,'http_json_v1','unattributed'
 FROM contour.ingestion_batches WHERE batch_id='00000000-0000-4000-8000-00000000c004';
SELECT fixture.assert((SELECT count(*)=1 FROM contour.ingestion_v2_metadata), 'tenant B sees only B');
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*)=1 FROM contour.ingestion_v2_metadata), 'tenant A cannot read B');
ROLLBACK;
