-- Run only after an independently reviewed migration 26 on an isolated disposable database.
-- Catalog and bounded behavioral checks; concurrent provisioning requires a separate driver.
DO $$
DECLARE n text; BEGIN
 IF (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,26)) THEN RAISE EXCEPTION 'ledger mismatch'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='contour_causal_evidence_provisioner' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls) THEN RAISE EXCEPTION 'provisioner role invalid'; END IF;
 FOREACH n IN ARRAY ARRAY['causal_gateway_enrollments','causal_gateway_terminal_reservations','causal_gateway_terminals'] LOOP
  IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace s ON s.oid=c.relnamespace WHERE s.nspname='contour' AND c.relname=n AND c.relrowsecurity AND c.relforcerowsecurity) THEN RAISE EXCEPTION 'RLS missing for %',n; END IF;
  IF has_table_privilege('contour_causal_evidence_provisioner','contour.'||n,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE') THEN RAISE EXCEPTION 'raw privilege for %',n; END IF;
 END LOOP;
 IF has_table_privilege('contour_causal_evidence_provisioner','contour.causal_leaf_reservations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') THEN RAISE EXCEPTION 'raw leaf access'; END IF;
 IF pg_has_role('contour_causal_evidence_provisioner','contour_runtime','MEMBER') OR NOT has_function_privilege('contour_causal_evidence_provisioner','contour.enroll_causal_gateway(contour.gateway_enrollment_claim)','EXECUTE') OR NOT has_function_privilege('contour_causal_evidence_provisioner','contour.close_causal_gateway(uuid,uuid,text,text)','EXECUTE') OR has_function_privilege('contour_runtime','contour.enroll_causal_gateway(contour.gateway_enrollment_claim)','EXECUTE') OR has_function_privilege('contour_runtime','contour.close_causal_gateway(uuid,uuid,text,text)','EXECUTE') THEN RAISE EXCEPTION 'function ACL invalid'; END IF;
 IF EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='contour.close_causal_gateway(uuid,uuid,text,text)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE') THEN RAISE EXCEPTION 'PUBLIC closure'; END IF;
 IF EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='contour.enroll_causal_gateway(contour.gateway_enrollment_claim)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE') THEN RAISE EXCEPTION 'PUBLIC enrollment'; END IF;
END $$;
-- Atomic global uniqueness, both class orders; transaction rolls all synthetic rows back.
BEGIN;
SET LOCAL ROLE contour_owner;
DO $$
DECLARE a text; b text; leaf bytea; seq integer:=0; BEGIN
 FOREACH a IN ARRAY ARRAY['product','export','gateway_observer','gateway_backend','receiver_backend','receiver_evidence'] LOOP
  FOREACH b IN ARRAY ARRAY['product','export','gateway_observer','gateway_backend','receiver_backend','receiver_evidence'] LOOP
   seq:=seq+1; leaf:=decode(lpad(to_hex(seq),64,'0'),'hex');
   INSERT INTO contour.causal_leaf_reservations VALUES(leaf,a);
   BEGIN
    INSERT INTO contour.causal_leaf_reservations VALUES(leaf,b);
    RAISE EXCEPTION 'duplicate leaf accepted: % / %',a,b;
   EXCEPTION WHEN unique_violation THEN NULL; END;
  END LOOP;
 END LOOP;
END $$;
ROLLBACK;
-- Synthetic issuer assertions; requires causal_runtime_registry_pre.sql seed,
-- its valid tenant/source authorization and signed-envelope placeholder 01.
-- No fixture below verifies cryptographic signatures or certificate possession.
SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false);
SELECT set_config('test.gateway_now',clock_timestamp()::text,false);
CREATE FUNCTION pg_temp.gateway_claim() RETURNS contour.gateway_enrollment_claim LANGUAGE sql AS $$
 SELECT ROW('f0000000-0000-4000-8000-000000000001'::uuid,'fe000000-0000-4000-8000-000000000001'::uuid,
 'f6000000-0000-4000-8000-000000000001'::uuid,'f7000000-0000-4000-8000-000000000001'::uuid,
 'f1000000-0000-4000-8000-000000000001'::uuid,'f2000000-0000-4000-8000-000000000001'::uuid,
 'f3000000-0000-4000-8000-000000000001'::uuid,'f4000000-0000-4000-8000-000000000001'::uuid,
 'f5000000-0000-4000-8000-000000000001'::uuid,decode(repeat('a1',32),'hex'),
 decode(repeat('a2',32),'hex'),decode(repeat('a3',32),'hex'),1,decode('01','hex'),
 current_setting('test.gateway_now')::timestamptz-interval '1 minute',current_setting('test.gateway_now')::timestamptz+interval '10 minutes',900000000)::contour.gateway_enrollment_claim
$$;
CREATE TEMP TABLE gateway_result(generation text,issued_at timestamptz,expires_at timestamptz);
GRANT SELECT,INSERT ON gateway_result TO contour_causal_evidence_provisioner;
SET ROLE contour_causal_evidence_provisioner;
-- SQL18 runtime source is not a gateway source; rejection must precede mutation.
DO $$ BEGIN
 BEGIN PERFORM contour.enroll_causal_gateway(pg_temp.gateway_claim()); RAISE EXCEPTION 'runtime source accepted as gateway'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
BEGIN;
SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001');
UPDATE contour.source_authorization SET technique='gateway' WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND source_id='f7000000-0000-4000-8000-000000000001';
COMMIT;
SET ROLE contour_causal_evidence_provisioner;
INSERT INTO gateway_result SELECT * FROM contour.enroll_causal_gateway(pg_temp.gateway_claim());
DO $$ DECLARE x record; BEGIN
 SELECT * INTO x FROM contour.enroll_causal_gateway(pg_temp.gateway_claim());
 IF NOT EXISTS(SELECT 1 FROM gateway_result r WHERE (r.generation,r.issued_at,r.expires_at)=(x.generation,x.issued_at,x.expires_at)) THEN RAISE EXCEPTION 'exact retry changed lease'; END IF;
END $$;
DO $$ DECLARE x contour.gateway_enrollment_claim:=pg_temp.gateway_claim(); BEGIN
 x.provision_nonce:=decode(repeat('b1',32),'hex'); x.observer_leaf:=decode(repeat('b2',32),'hex'); x.backend_client_leaf:=decode(repeat('b3',32),'hex');
 BEGIN PERFORM contour.enroll_causal_gateway(x); RAISE EXCEPTION 'new nonce accepted for active gateway'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
RESET ROLE;
-- A disabled current policy must be checked before returning an old receipt.
BEGIN; SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001');
UPDATE contour.collector_authorization SET enabled=false WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND collector_id='f6000000-0000-4000-8000-000000000001'; COMMIT;
SET ROLE contour_causal_evidence_provisioner;
DO $$ BEGIN
 BEGIN PERFORM contour.enroll_causal_gateway(pg_temp.gateway_claim()); RAISE EXCEPTION 'disabled policy leaked receipt'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
BEGIN; SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001');
UPDATE contour.collector_authorization SET enabled=true WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND collector_id='f6000000-0000-4000-8000-000000000001'; COMMIT;
-- Future tenant floor simulates clock rollback; restore only in this disposable fixture.
CREATE TEMP TABLE gateway_floor_before AS SELECT clock_floor FROM contour.origin_tenant_state WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
GRANT SELECT ON gateway_floor_before TO contour_owner;
SET ROLE contour_owner;
UPDATE contour.origin_tenant_state SET clock_floor=clock_timestamp()+interval '1 hour' WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
RESET ROLE;
SET ROLE contour_causal_evidence_provisioner;
DO $$ BEGIN
 BEGIN PERFORM contour.enroll_causal_gateway(pg_temp.gateway_claim()); RAISE EXCEPTION 'clock rollback leaked receipt'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
SET ROLE contour_owner;
UPDATE contour.origin_tenant_state SET clock_floor=(SELECT clock_floor FROM gateway_floor_before) WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
RESET ROLE;
SET ROLE contour_causal_evidence_provisioner;
DO $$ DECLARE x contour.gateway_enrollment_claim:=pg_temp.gateway_claim(); BEGIN
 x.backend_client_leaf:=decode(repeat('a4',32),'hex');
 BEGIN PERFORM contour.enroll_causal_gateway(x); RAISE EXCEPTION 'changed nonce claim accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
DO $$ DECLARE x contour.gateway_enrollment_claim:=pg_temp.gateway_claim(); BEGIN
 x.provision_nonce:=decode(repeat('a5',32),'hex'); x.policy_expires:=clock_timestamp()-interval '1 second';
 BEGIN PERFORM contour.enroll_causal_gateway(x); RAISE EXCEPTION 'expired policy accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
CREATE TEMP TABLE gateway_usage_before AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
GRANT SELECT ON gateway_usage_before TO contour_owner;
SET ROLE contour_owner;
UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
RESET ROLE;
SET ROLE contour_causal_evidence_provisioner;
DO $$ DECLARE x contour.gateway_enrollment_claim:=pg_temp.gateway_claim(); BEGIN
 x.gateway_id:='fe000000-0000-4000-8000-000000000002'; x.provision_nonce:=decode(repeat('a6',32),'hex');
 x.observer_leaf:=decode(repeat('a7',32),'hex'); x.backend_client_leaf:=decode(repeat('a8',32),'hex');
 BEGIN PERFORM contour.enroll_causal_gateway(x); RAISE EXCEPTION 'quota failure accepted'; EXCEPTION WHEN program_limit_exceeded THEN NULL; END;
END $$;
-- Prepaid operator closure must succeed even while the shared quota is full.
SELECT contour.close_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000001',(SELECT generation FROM gateway_result),'operator_revoked');
RESET ROLE;
SET ROLE contour_owner;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM contour.causal_leaf_reservations WHERE leaf_sha256 IN (decode(repeat('a7',32),'hex'),decode(repeat('a8',32),'hex'))) THEN RAISE EXCEPTION 'quota left reservation'; END IF;
 IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001')<>1073741824 THEN RAISE EXCEPTION 'closure changed prepaid quota'; END IF;
END $$;
UPDATE contour.origin_logical_usage SET used_bytes=(SELECT used_bytes FROM gateway_usage_before) WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
RESET ROLE;
SET ROLE contour_causal_evidence_provisioner;
SELECT contour.close_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000001',(SELECT generation FROM gateway_result),'operator_revoked');
DO $$ BEGIN
 BEGIN PERFORM contour.enroll_causal_gateway(pg_temp.gateway_claim()); RAISE EXCEPTION 'closed enrollment retry accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
RESET ROLE;
-- Expiration must reject an exact retry, but prepaid closure remains possible.
CREATE TEMP TABLE expiring_gateway(generation text,issued_at timestamptz,expires_at timestamptz);
GRANT SELECT,INSERT ON expiring_gateway TO contour_causal_evidence_provisioner;
SET ROLE contour_causal_evidence_provisioner;
DO $$ DECLARE x contour.gateway_enrollment_claim:=pg_temp.gateway_claim(); r record; BEGIN
 x.gateway_id:='fe000000-0000-4000-8000-000000000003'; x.provision_nonce:=decode(repeat('c1',32),'hex');
 x.observer_leaf:=decode(repeat('c2',32),'hex'); x.backend_client_leaf:=decode(repeat('c3',32),'hex'); x.ttl_microseconds:=2000000;
 SELECT * INTO r FROM contour.enroll_causal_gateway(x); INSERT INTO expiring_gateway VALUES(r.generation,r.issued_at,r.expires_at);
END $$;
SELECT pg_sleep(2.2);
DO $$ DECLARE x contour.gateway_enrollment_claim:=pg_temp.gateway_claim(); BEGIN
 x.gateway_id:='fe000000-0000-4000-8000-000000000003'; x.provision_nonce:=decode(repeat('c1',32),'hex');
 x.observer_leaf:=decode(repeat('c2',32),'hex'); x.backend_client_leaf:=decode(repeat('c3',32),'hex'); x.ttl_microseconds:=2000000;
 BEGIN PERFORM contour.enroll_causal_gateway(x); RAISE EXCEPTION 'expired lease returned receipt'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
SELECT contour.close_causal_gateway('f0000000-0000-4000-8000-000000000001','fe000000-0000-4000-8000-000000000003',(SELECT generation FROM expiring_gateway),'expired');
RESET ROLE;
