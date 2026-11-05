-- Fixture-only fault tests. Harness sets origin_admission_test.{tenant,collector,
-- source,active,closed,credential_revoked,grant_revoked}. DDL/fault injection is
-- transaction-local and rolled back. Running at 20 must fail on the first tagged
-- assertion; at 21 every assertion must pass.
CREATE OR REPLACE FUNCTION pg_temp.assert_resolution(leaf text, expected_state text, expected_constraint text, malformed boolean DEFAULT false, invalid_clock boolean DEFAULT false) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE t uuid:=current_setting('origin_admission_test.tenant')::uuid;
 c uuid:=current_setting('origin_admission_test.collector')::uuid;
 m contour.ingestion_v2_metadata; state text; constraint_name text; caught boolean:=false;
 w jsonb:=jsonb_build_object('kind','downstream_mtls_leaf_sha256_v1','leaf_sha256',leaf);
BEGIN
 m.tenant_id:=t; m.collector_id:=c; m.accepted_at:=CASE WHEN invalid_clock THEN 'infinity'::timestamptz ELSE clock_timestamp() END;
 m.source_id:=current_setting('origin_admission_test.source')::uuid;
 m.project_id:='00000000-0000-0000-0000-000000000001'; m.service_id:=m.project_id;
 m.environment_id:=m.project_id; m.deployment_id:=m.project_id;
 IF malformed THEN w:='{}'::jsonb; END IF;
 BEGIN
   PERFORM contour.resolve_origin_record_checked(t,c,m,w);
 EXCEPTION WHEN OTHERS THEN
   GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE, constraint_name=CONSTRAINT_NAME;
   caught:=true;
 END;
 IF NOT caught OR state IS DISTINCT FROM expected_state OR constraint_name IS DISTINCT FROM expected_constraint THEN
   RAISE EXCEPTION 'resolution classification mismatch: expected %/%, got %/%',expected_state,expected_constraint,state,constraint_name;
 END IF;
END $$;
BEGIN;
SELECT set_config('apicontour.tenant_id',current_setting('origin_admission_test.tenant'),true);
SELECT pg_temp.assert_resolution(current_setting('origin_admission_test.active'),'42501','');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id',current_setting('origin_admission_test.tenant'),true);
SELECT contour.begin_origin_ingress(current_setting('origin_admission_test.tenant')::uuid,current_setting('origin_admission_test.collector')::uuid);
DO $$ DECLARE
 t uuid:=current_setting('origin_admission_test.tenant')::uuid;
 c uuid:=current_setting('origin_admission_test.collector')::uuid;
 m contour.ingestion_v2_metadata; result contour.origin_resolution; expected uuid;
BEGIN
 m.tenant_id:=t; m.collector_id:=c; m.accepted_at:=clock_timestamp();
 m.source_id:=current_setting('origin_admission_test.source')::uuid;
 m.project_id:='00000000-0000-0000-0000-000000000001'; m.service_id:=m.project_id;
 m.environment_id:=m.project_id; m.deployment_id:=m.project_id;
 SELECT credential_id INTO STRICT expected FROM contour.origin_credentials WHERE tenant_id=t AND leaf_sha256=decode(current_setting('origin_admission_test.active'),'hex');
 result:=contour.resolve_origin_record_checked(t,c,m,jsonb_build_object('kind','downstream_mtls_leaf_sha256_v1','leaf_sha256',current_setting('origin_admission_test.active')));
 IF result.credential_id IS DISTINCT FROM expected THEN RAISE EXCEPTION 'active origin did not resolve'; END IF;
END $$;
SELECT pg_temp.assert_resolution(repeat('0',64),'23514','origin_live_resolution_unavailable');
SELECT pg_temp.assert_resolution(current_setting('origin_admission_test.closed'),'23514','origin_live_resolution_unavailable');
SELECT pg_temp.assert_resolution(current_setting('origin_admission_test.credential_revoked'),'23514','origin_live_resolution_unavailable');
SELECT pg_temp.assert_resolution(current_setting('origin_admission_test.grant_revoked'),'23514','origin_live_resolution_unavailable');
SELECT pg_temp.assert_resolution(current_setting('origin_admission_test.active'),'23514','',true,false);
SELECT pg_temp.assert_resolution(current_setting('origin_admission_test.active'),'23514','',false,true);
-- An unrelated real check violation must retain its own constraint identity.
DO $$ DECLARE s text; c text; caught boolean:=false; BEGIN
 BEGIN INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES (gen_random_uuid(),-1);
 EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS s=RETURNED_SQLSTATE,c=CONSTRAINT_NAME; caught:=true; END;
 IF NOT caught OR s IS DISTINCT FROM '23514' OR c IS DISTINCT FROM 'origin_logical_usage_used_bytes_check' THEN
   RAISE EXCEPTION 'unrelated integrity classification mismatch'; END IF;
END $$;
-- Duplicate a live grant with its original epoch to force the normally prevented
-- final SELECT INTO STRICT too_many_rows branch. Triggers are restored immediately.
SET LOCAL session_replication_role=replica;
INSERT INTO contour.origin_observer_grants
 SELECT g.tenant_id,gen_random_uuid(),g.lifecycle_id,g.source_id,g.collector_id,g.project_id,g.service_id,g.environment_id,g.deployment_id,g.granted_at,g.fact_epoch
 FROM contour.origin_observer_grants g JOIN contour.origin_credentials c USING(tenant_id,lifecycle_id)
 WHERE g.tenant_id=current_setting('origin_admission_test.tenant')::uuid
 AND c.leaf_sha256=decode(current_setting('origin_admission_test.active'),'hex');
SET LOCAL session_replication_role=origin;
SELECT pg_temp.assert_resolution(current_setting('origin_admission_test.active'),'23514','');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id',current_setting('origin_admission_test.tenant'),true);
-- Drop before creating a context row, while there are no pending deferred triggers.
-- The key and both inserted rows return to their prior state on rollback.
ALTER TABLE contour.origin_ingress_context DROP CONSTRAINT origin_ingress_context_pkey;
SELECT contour.begin_origin_ingress(current_setting('origin_admission_test.tenant')::uuid,current_setting('origin_admission_test.collector')::uuid);
INSERT INTO contour.origin_ingress_context SELECT * FROM contour.origin_ingress_context
 WHERE transaction_id=txid_current() AND backend_pid=pg_backend_pid();
SELECT pg_temp.assert_resolution(current_setting('origin_admission_test.active'),'23514','');
ROLLBACK;
