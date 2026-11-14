-- Disposable SQL30 database only. Data vector and role checks; behavioral TLS checks are separate.
DO $test$
DECLARE body bytea; encoded bytea;
BEGIN
 IF NOT has_function_privilege('contour_causal_gateway_reader','contour.current_causal_gateway(uuid,uuid,text,bytea)','EXECUTE')
 OR has_function_privilege('contour_causal_evidence_provisioner','contour.current_causal_gateway(uuid,uuid,text,bytea)','EXECUTE')
 OR has_table_privilege('contour_causal_gateway_reader','contour.causal_gateway_enrollments','SELECT')
 OR has_function_privilege('contour_causal_gateway_reader','contour.close_causal_gateway(uuid,uuid,text,text)','EXECUTE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname='contour_causal_gateway_reader' AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb))
 THEN RAISE EXCEPTION 'gateway reader privilege mismatch'; END IF;
 body:=convert_to($vector${"backend_client_leaf":"3333333333333333333333333333333333333333333333333333333333333333","collector_id":"00000000-0000-4000-8000-000000000001","deployment_id":"00000000-0000-4000-8000-000000000001","environment_id":"00000000-0000-4000-8000-000000000001","expires_at":"2026-11-12T23:59:00.000000Z","gateway_id":"00000000-0000-4000-8000-000000000001","generation":"123456789abcdef0123456789abcdef0","instance_id":"00000000-0000-4000-8000-000000000001","issued_at":"2026-11-12T23:54:00.000000Z","observer_leaf":"2222222222222222222222222222222222222222222222222222222222222222","policy_expires":"2026-11-13T00:00:00.000000Z","policy_issued":"2026-11-12T23:00:00.000000Z","policy_revision":"1","project_id":"00000000-0000-4000-8000-000000000001","provision_nonce":"1111111111111111111111111111111111111111111111111111111111111111","service_id":"00000000-0000-4000-8000-000000000001","source_id":"00000000-0000-4000-8000-000000000001","tenant_id":"00000000-0000-4000-8000-000000000001","ttl_microseconds":"300000000"}$vector$,'UTF8');
 encoded:=contour.gateway_enrollment_metadata(ROW(
 '00000000-0000-4000-8000-000000000001'::uuid,'00000000-0000-4000-8000-000000000001'::uuid,
 '00000000-0000-4000-8000-000000000001'::uuid,'00000000-0000-4000-8000-000000000001'::uuid,
 '00000000-0000-4000-8000-000000000001'::uuid,'00000000-0000-4000-8000-000000000001'::uuid,
 '00000000-0000-4000-8000-000000000001'::uuid,'00000000-0000-4000-8000-000000000001'::uuid,
 '00000000-0000-4000-8000-000000000001'::uuid,decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
 1,decode('01','hex'),'2026-11-12T23:00:00Z'::timestamptz,'2026-11-13T00:00:00Z'::timestamptz,300000000)::contour.gateway_enrollment_claim,
 '123456789abcdef0123456789abcdef0','2026-11-12T23:54:00Z'::timestamptz,'2026-11-12T23:59:00Z'::timestamptz);
 IF body IS DISTINCT FROM encoded OR encode(sha256(body),'hex')<>'04aba7282078a9f130d69e551c2c6a8fc10d827e6f8cec25ece803acfcb40731' THEN RAISE EXCEPTION 'gateway vector mismatch'; END IF;
END $test$;

-- Run after causal_runtime_registry_pre.sql in a fresh disposable database.
SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false);
SELECT set_config('test.gateway_now',clock_timestamp()::text,false);
CREATE FUNCTION pg_temp.gateway_reader_claim() RETURNS contour.gateway_enrollment_claim LANGUAGE sql AS $$
 SELECT ROW('f0000000-0000-4000-8000-000000000001'::uuid,'fe000000-0000-4000-8000-000000000001'::uuid,
 'f6000000-0000-4000-8000-000000000001'::uuid,'f7000000-0000-4000-8000-000000000001'::uuid,
 'f1000000-0000-4000-8000-000000000001'::uuid,'f2000000-0000-4000-8000-000000000001'::uuid,
 'f3000000-0000-4000-8000-000000000001'::uuid,'f4000000-0000-4000-8000-000000000001'::uuid,
 'f5000000-0000-4000-8000-000000000001'::uuid,decode(repeat('a1',32),'hex'),
 decode(repeat('a2',32),'hex'),decode(repeat('a3',32),'hex'),1,decode('01','hex'),
 current_setting('test.gateway_now')::timestamptz-interval '1 minute',current_setting('test.gateway_now')::timestamptz+interval '10 minutes',900000000)::contour.gateway_enrollment_claim
$$;
CREATE TEMP TABLE gateway_reader_result(generation text,issued_at timestamptz,expires_at timestamptz);
GRANT SELECT,INSERT ON gateway_reader_result TO contour_causal_evidence_provisioner;
SET ROLE contour_causal_evidence_provisioner;
-- SQL18 runtime source is not a gateway source; rejection must precede mutation.
DO $$ BEGIN
 BEGIN PERFORM contour.enroll_causal_gateway(pg_temp.gateway_reader_claim()); RAISE EXCEPTION 'runtime source accepted as gateway'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
BEGIN;
SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001');
UPDATE contour.source_authorization SET technique='gateway' WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND source_id='f7000000-0000-4000-8000-000000000001';
COMMIT;
SET ROLE contour_causal_evidence_provisioner;
INSERT INTO gateway_reader_result SELECT * FROM contour.enroll_causal_gateway(pg_temp.gateway_reader_claim());
RESET ROLE;
GRANT SELECT ON gateway_reader_result TO contour_causal_gateway_reader;
SET ROLE contour_causal_gateway_reader;
-- Every reader operation is a separate implicit transaction: a successful call
-- retains transaction advisory locks and begin_origin_operation forbids reentry.
DO $$ DECLARE r record; BEGIN
 SELECT * INTO STRICT r FROM contour.current_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000001',(SELECT generation FROM gateway_reader_result),decode(repeat('a3',32),'hex'));
 IF r.metadata_sha256 IS DISTINCT FROM sha256(r.metadata) OR r.expires_at IS DISTINCT FROM (SELECT expires_at FROM gateway_reader_result) THEN RAISE EXCEPTION 'gateway result mismatch'; END IF;
END $$;
SELECT contour.current_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000001',(SELECT generation FROM gateway_reader_result),decode(repeat('a3',32),'hex'));
DO $$ BEGIN
 BEGIN PERFORM contour.current_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000001',(SELECT generation FROM gateway_reader_result),decode(repeat('a4',32),'hex')); RAISE EXCEPTION 'wrong leaf accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.current_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000001',repeat('a',32),decode(repeat('a3',32),'hex')); RAISE EXCEPTION 'wrong generation accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.current_causal_gateway('f0000000-0000-4000-8000-000000000002','fe000000-0000-4000-8000-000000000001',(SELECT generation FROM gateway_reader_result),decode(repeat('a3',32),'hex')); RAISE EXCEPTION 'wrong tenant accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
BEGIN; SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001');
UPDATE contour.collector_authorization SET enabled=false WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND collector_id='f6000000-0000-4000-8000-000000000001'; COMMIT;
SET ROLE contour_causal_gateway_reader;
DO $$ BEGIN
 BEGIN PERFORM contour.current_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000001',(SELECT generation FROM gateway_reader_result),decode(repeat('a3',32),'hex')); RAISE EXCEPTION 'revoked policy accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
BEGIN; SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001');
UPDATE contour.collector_authorization SET enabled=true WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND collector_id='f6000000-0000-4000-8000-000000000001'; COMMIT;
SET ROLE contour_causal_evidence_provisioner;
SELECT contour.close_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000001',(SELECT generation FROM gateway_reader_result),'operator_revoked');
RESET ROLE;
SET ROLE contour_causal_gateway_reader;
DO $$ BEGIN
 BEGIN PERFORM contour.current_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000001',(SELECT generation FROM gateway_reader_result),decode(repeat('a3',32),'hex')); RAISE EXCEPTION 'closed gateway accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
