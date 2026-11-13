-- Execute on an isolated SQL28 test database only after an independently
-- reviewed candidate is made applicable; not a production qualification.
\echo receiver-case=vector
DO $test$
DECLARE body bytea; result bytea; rejected boolean;
BEGIN
 IF to_regprocedure('contour.receiver_enrollment_commitment(bytea)') IS NULL THEN RAISE EXCEPTION 'reviewed SQL28 fixture required'; END IF;
 IF NOT has_function_privilege('contour_causal_evidence_provisioner','contour.enroll_causal_receiver(contour.receiver_enrollment_claim)','EXECUTE')
 OR NOT has_function_privilege('contour_causal_evidence_provisioner','contour.close_causal_receiver(uuid,uuid,numeric,text,text)','EXECUTE')
 OR has_function_privilege('contour_causal_evidence_provisioner','contour.current_causal_receiver(uuid,uuid,numeric,text,bytea)','EXECUTE')
 OR NOT has_function_privilege('contour_causal_receiver_reader','contour.current_causal_receiver(uuid,uuid,numeric,text,bytea)','EXECUTE')
 OR has_function_privilege('contour_causal_receiver_reader','contour.enroll_causal_receiver(contour.receiver_enrollment_claim)','EXECUTE')
 OR has_function_privilege('contour_causal_receiver_reader','contour.close_causal_receiver(uuid,uuid,numeric,text,text)','EXECUTE')
 OR has_table_privilege('contour_causal_receiver_reader','contour.causal_receiver_enrollments','SELECT')
 OR has_table_privilege('contour_causal_evidence_provisioner','contour.causal_receiver_enrollments','SELECT')
 OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname='contour_causal_receiver_reader' AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb))
 THEN RAISE EXCEPTION 'receiver privileges incorrect'; END IF;
 body:=convert_to($vector${"artifact_sha256":"707e7b359fb757c668d8a22c999e067556b5f2a785f9c3333c12fca7debfa660","backend_leaf_sha256":"1111111111111111111111111111111111111111111111111111111111111111","enrollment_generation":"123456789abcdef0123456789abcdef0","evidence_credential_id":"00000000-0000-4000-8000-000000000006","evidence_leaf_sha256":"2222222222222222222222222222222222222222222222222222222222222222","expires_at":"2026-11-12T23:59:00.123456Z","export_leaf_sha256":"3333333333333333333333333333333333333333333333333333333333333333","grant_digest":"4444444444444444444444444444444444444444444444444444444444444444","instance_id":"00000000-0000-4000-8000-000000000003","issued_at":"2026-11-12T23:54:00.123456Z","lifecycle_id":"00000000-0000-4000-8000-000000000004","policy_envelope_sha256":"823412d1eacb67956220e532959f0104603057c88704863ca38e7cd188fda812","policy_revision":"1","product_credential_id":"00000000-0000-4000-8000-000000000005","product_leaf_sha256":"5555555555555555555555555555555555555555555555555555555555555555","profile_id":"00000000-0000-4000-8000-000000000504","profile_manifest_sha256":"c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0","runtime_id":"00000000-0000-4000-8000-000000000002","session_epoch":"1","session_nonce":"00000000-0000-4000-8000-000000000007","tenant_id":"00000000-0000-4000-8000-000000000001","version":1}$vector$,'UTF8');
 IF octet_length(body)<>1351 THEN RAISE EXCEPTION 'receiver vector length mismatch'; END IF;
 EXECUTE 'SELECT contour.receiver_enrollment_commitment($1)' INTO result USING body;
 IF encode(result,'hex')<>'e523b6d0e5fca7a065c84f8f4204fa9acdbcbb40bcae5f2400e1f31b2f89f91f' THEN RAISE EXCEPTION 'receiver vector mismatch'; END IF;
 rejected:=false;
 BEGIN EXECUTE 'SELECT contour.receiver_enrollment_commitment($1)' USING decode('','hex');
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'empty body accepted'; END IF;
 rejected:=false;
 BEGIN EXECUTE 'SELECT contour.receiver_enrollment_commitment($1)' USING decode(repeat('00',4097),'hex');
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'oversized body accepted'; END IF;
END $test$;

-- Behavioral fixture: run ONLY on a disposable database prepared with
-- causal_runtime_registry_pre.sql and an independently reviewed test-only SQL28.
-- SQL issuer assertions here are synthetic; no 504 factory, signatures or peer
-- authentication are established. Each public call must be its own transaction.
\echo receiver-case=setup
SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false);
SELECT set_config('test.receiver_now',clock_timestamp()::text,false);
SET ROLE contour_causal_provisioner;
\echo receiver-case=profile
SELECT contour.register_causal_profile('f0000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000504',decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'));
\echo receiver-case=runtime
SELECT contour.enroll_causal_runtime('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009','f6000000-0000-4000-8000-000000000001','f7000000-0000-4000-8000-000000000001','f1000000-0000-4000-8000-000000000001','f2000000-0000-4000-8000-000000000001','f3000000-0000-4000-8000-000000000001','f4000000-0000-4000-8000-000000000001','f5000000-0000-4000-8000-000000000001','f9000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000504',decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'),decode(repeat('b9',32),'hex'));
RESET ROLE;
CREATE FUNCTION pg_temp.receiver_session() RETURNS contour.causal_session_claim LANGUAGE sql AS $$ SELECT ROW(
 'f0000000-0000-4000-8000-000000000001'::uuid,'fc000000-0000-4000-8000-000000000009'::uuid,
 'f6000000-0000-4000-8000-000000000001'::uuid,'f7000000-0000-4000-8000-000000000001'::uuid,
 'f1000000-0000-4000-8000-000000000001'::uuid,'f2000000-0000-4000-8000-000000000001'::uuid,
 'f3000000-0000-4000-8000-000000000001'::uuid,'f4000000-0000-4000-8000-000000000001'::uuid,
 'f5000000-0000-4000-8000-000000000001'::uuid,'f9000000-0000-4000-8000-000000000001'::uuid,
 decode(repeat('b9',32),'hex'),'nodered_5_0_9_receiver_v1',decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'),
 'fe000000-0000-4000-8000-000000000009'::uuid,1,decode(repeat('ab',32),'hex'),
 current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',
 1,decode('01','hex'),current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',900000000,10,1024,1024,60)::contour.causal_session_claim $$;
SET ROLE contour_causal_issuer;
\echo receiver-case=session
SELECT * FROM contour.issue_causal_session(pg_temp.receiver_session());
RESET ROLE;
CREATE FUNCTION pg_temp.receiver_claim() RETURNS contour.receiver_enrollment_claim LANGUAGE sql AS $$ SELECT ROW(
 'f0000000-0000-4000-8000-000000000001'::uuid,'fc000000-0000-4000-8000-000000000009'::uuid,1,
 'f5000000-0000-4000-8000-000000000001'::uuid,'f9000000-0000-4000-8000-000000000001'::uuid,
 'fa000000-0000-4000-8000-000000000001'::uuid,decode(repeat('11',32),'hex'),decode(repeat('b9',32),'hex'),
 decode(repeat('ba',32),'hex'),decode(repeat('bb',32),'hex'),decode(repeat('bc',32),'hex'),
 current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',
 current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',300000000)::contour.receiver_enrollment_claim $$;
CREATE TEMP TABLE receiver_result(generation text,credential_id uuid,issued_at timestamptz,expires_at timestamptz,commitment bytea);
GRANT SELECT,INSERT ON receiver_result TO contour_causal_evidence_provisioner;
GRANT SELECT ON receiver_result TO contour_causal_receiver_reader;
CREATE TEMP TABLE receiver_usage_before AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
SET ROLE contour_causal_evidence_provisioner;
\echo receiver-case=enroll
INSERT INTO receiver_result SELECT * FROM contour.enroll_causal_receiver(pg_temp.receiver_claim());
\echo receiver-case=retry
DO $$ DECLARE r record; BEGIN
 SELECT * INTO r FROM contour.enroll_causal_receiver(pg_temp.receiver_claim());
 IF NOT EXISTS(SELECT 1 FROM receiver_result x WHERE (x.generation,x.credential_id,x.issued_at,x.expires_at,x.commitment)=(r.generation,r.credential_id,r.issued_at,r.expires_at,r.commitment)) THEN RAISE EXCEPTION 'retry changed receipt'; END IF;
END $$;
\echo receiver-case=changed-claim
DO $$ DECLARE x contour.receiver_enrollment_claim:=pg_temp.receiver_claim(); BEGIN
 x.provision_nonce:=decode(repeat('bd',32),'hex');
 BEGIN PERFORM contour.enroll_causal_receiver(x); RAISE EXCEPTION 'changed claim accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
RESET ROLE;
\echo receiver-case=quota
DO $$ BEGIN
 IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001') <>(SELECT used_bytes FROM receiver_usage_before)+(SELECT charged_bytes+1024 FROM contour.causal_receiver_enrollments WHERE runtime_id='fc000000-0000-4000-8000-000000000009') THEN RAISE EXCEPTION 'enrollment/retry quota mismatch'; END IF;
END $$;
\echo receiver-case=current
SET ROLE contour_causal_receiver_reader;
DO $$ DECLARE r record; BEGIN
 SELECT * INTO STRICT r FROM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009',1,(SELECT generation FROM receiver_result),decode(repeat('bb',32),'hex'));
 IF r.commitment IS DISTINCT FROM (SELECT commitment FROM receiver_result) THEN RAISE EXCEPTION 'selector changed commitment'; END IF;
END $$;
\echo receiver-case=selectors
DO $$ DECLARE g text:=(SELECT generation FROM receiver_result); BEGIN
 BEGIN PERFORM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009',1,g,decode(repeat('bd',32),'hex')); RAISE EXCEPTION 'wrong peer selector accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009',2,g,decode(repeat('bb',32),'hex')); RAISE EXCEPTION 'wrong epoch accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009',1,repeat('a',32),decode(repeat('bb',32),'hex')); RAISE EXCEPTION 'wrong generation accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000002','fc000000-0000-4000-8000-000000000009',1,g,decode(repeat('bb',32),'hex')); RAISE EXCEPTION 'wrong tenant accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
\echo receiver-case=missing-reservation
-- A missing exact reservation cannot be masked by unrelated quota usage.
BEGIN;
ALTER TABLE contour.causal_receiver_terminal_reservations DISABLE TRIGGER receiver_immutable;
DELETE FROM contour.causal_receiver_terminal_reservations WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND runtime_id='fc000000-0000-4000-8000-000000000009' AND session_epoch=1;
SET LOCAL ROLE contour_causal_receiver_reader;
DO $$ BEGIN
 BEGIN PERFORM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009',1,(SELECT generation FROM receiver_result),decode(repeat('bb',32),'hex')); RAISE EXCEPTION 'missing reservation accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
ROLLBACK;
\echo receiver-case=clock
-- Future floor rejects a stale retry; rollback restores the real floor.
BEGIN;
UPDATE contour.origin_tenant_state SET clock_floor=clock_timestamp()+interval '1 hour' WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
SET LOCAL ROLE contour_causal_evidence_provisioner;
DO $$ BEGIN
 BEGIN PERFORM contour.enroll_causal_receiver(pg_temp.receiver_claim()); RAISE EXCEPTION 'clock rollback accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
ROLLBACK;
\echo receiver-case=second-credential
-- Separate current receiver: revocation cannot mask the primary closure checks.
SET ROLE contour_admin;
SELECT contour.enroll_origin_credential('f0000000-0000-4000-8000-000000000001','fa000000-0000-4000-8000-000000000009','f9000000-0000-4000-8000-000000000001',decode(repeat('b5',32),'hex'));
RESET ROLE;
SET ROLE contour_causal_provisioner;
\echo receiver-case=profile-second
SELECT contour.register_causal_profile('f0000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000504',decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'));
\echo receiver-case=runtime-second
SELECT contour.enroll_causal_runtime('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000008','f6000000-0000-4000-8000-000000000001','f7000000-0000-4000-8000-000000000001','f1000000-0000-4000-8000-000000000001','f2000000-0000-4000-8000-000000000001','f3000000-0000-4000-8000-000000000001','f4000000-0000-4000-8000-000000000001','f5000000-0000-4000-8000-000000000001','f9000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000504',decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'),decode(repeat('b8',32),'hex'));
RESET ROLE;
CREATE FUNCTION pg_temp.receiver_session_rev() RETURNS contour.causal_session_claim LANGUAGE sql AS $$ SELECT ROW(
 'f0000000-0000-4000-8000-000000000001'::uuid,'fc000000-0000-4000-8000-000000000008'::uuid,
 'f6000000-0000-4000-8000-000000000001'::uuid,'f7000000-0000-4000-8000-000000000001'::uuid,
 'f1000000-0000-4000-8000-000000000001'::uuid,'f2000000-0000-4000-8000-000000000001'::uuid,
 'f3000000-0000-4000-8000-000000000001'::uuid,'f4000000-0000-4000-8000-000000000001'::uuid,
 'f5000000-0000-4000-8000-000000000001'::uuid,'f9000000-0000-4000-8000-000000000001'::uuid,
 decode(repeat('b8',32),'hex'),'nodered_5_0_9_receiver_v1',decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'),
 'fe000000-0000-4000-8000-000000000008'::uuid,1,decode(repeat('ab',32),'hex'),
 current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',
 1,decode('01','hex'),current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',900000000,10,1024,1024,60)::contour.causal_session_claim $$;
SET ROLE contour_causal_issuer;
\echo receiver-case=session-second
SELECT * FROM contour.issue_causal_session(pg_temp.receiver_session_rev());
RESET ROLE;
CREATE FUNCTION pg_temp.receiver_claim_rev() RETURNS contour.receiver_enrollment_claim LANGUAGE sql AS $$ SELECT ROW(
 'f0000000-0000-4000-8000-000000000001'::uuid,'fc000000-0000-4000-8000-000000000008'::uuid,1,
 'f5000000-0000-4000-8000-000000000001'::uuid,'f9000000-0000-4000-8000-000000000001'::uuid,
 'fa000000-0000-4000-8000-000000000009'::uuid,decode(repeat('b5',32),'hex'),decode(repeat('b8',32),'hex'),
 decode(repeat('ca',32),'hex'),decode(repeat('cb',32),'hex'),decode(repeat('cc',32),'hex'),
 current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',
 current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',300000000)::contour.receiver_enrollment_claim $$;
CREATE TEMP TABLE receiver_result_rev(generation text,credential_id uuid,issued_at timestamptz,expires_at timestamptz,commitment bytea);
GRANT SELECT,INSERT ON receiver_result_rev TO contour_causal_evidence_provisioner;
GRANT SELECT ON receiver_result_rev TO contour_causal_receiver_reader;
SET ROLE contour_causal_evidence_provisioner;
\echo receiver-case=enroll-second
INSERT INTO receiver_result_rev SELECT * FROM contour.enroll_causal_receiver(pg_temp.receiver_claim_rev());
RESET ROLE;
SET ROLE contour_causal_receiver_reader;
\echo receiver-case=current-second
SELECT * FROM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000008',1,(SELECT generation FROM receiver_result_rev),decode(repeat('cb',32),'hex'));
RESET ROLE;
SET ROLE contour_admin;
\echo receiver-case=revoke
SELECT contour.end_origin('f0000000-0000-4000-8000-000000000001','credential_revoked','fa000000-0000-4000-8000-000000000009');
RESET ROLE;
SET ROLE contour_causal_receiver_reader;
DO $$ BEGIN
 BEGIN PERFORM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000008',1,(SELECT generation FROM receiver_result_rev),decode(repeat('cb',32),'hex')); RAISE EXCEPTION 'revoked exact credential accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
\echo receiver-case=primary-current
-- Confirm this distinct receiver remains current immediately before closure.
SET ROLE contour_causal_receiver_reader;
SELECT * FROM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009',1,(SELECT generation FROM receiver_result),decode(repeat('bb',32),'hex'));
RESET ROLE;
\echo receiver-case=close
-- A full quota must not prevent prepaid closure or create a second charge.
CREATE TEMP TABLE receiver_usage_saved AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
SET ROLE contour_causal_evidence_provisioner;
SELECT contour.close_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009',1,(SELECT generation FROM receiver_result),'operator_revoked');
\echo receiver-case=close-retry
SELECT contour.close_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009',1,(SELECT generation FROM receiver_result),'operator_revoked');
\echo receiver-case=closed-retry
DO $$ BEGIN
 BEGIN PERFORM contour.enroll_causal_receiver(pg_temp.receiver_claim()); RAISE EXCEPTION 'closed retry accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
RESET ROLE;
\echo receiver-case=closure-wire
DO $$ DECLARE j jsonb; raw bytea; BEGIN
 IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001')<>1073741824 THEN RAISE EXCEPTION 'closure charged quota'; END IF;
 SELECT canonical_body INTO STRICT raw FROM contour.causal_receiver_terminals WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND runtime_id='fc000000-0000-4000-8000-000000000009' AND session_epoch=1;
 j:=convert_from(raw,'UTF8')::jsonb;
 IF raw<>convert_to(contour.causal_json_canonical(j),'UTF8') OR (SELECT count(*) FROM jsonb_object_keys(j))<>9
 OR j->>'kind'<>'receiver' OR j->>'tenant_id'<>'f0000000-0000-4000-8000-000000000001'
 OR j->>'runtime_id'<>'fc000000-0000-4000-8000-000000000009' OR j->>'session_epoch'<>'1'
 OR j->>'reason'<>'operator_revoked' OR j->'gateway_id'<>'null'::jsonb OR j->'gateway_generation'<>'null'::jsonb
 OR j->'wire_version'<>'1'::jsonb OR j->>'effective_at' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$'
 THEN RAISE EXCEPTION 'closure wire mismatch'; END IF;
END $$;
UPDATE contour.origin_logical_usage SET used_bytes=(SELECT used_bytes FROM receiver_usage_saved) WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
SET ROLE contour_causal_receiver_reader;
DO $$ BEGIN
 BEGIN PERFORM contour.current_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000009',1,(SELECT generation FROM receiver_result),decode(repeat('bb',32),'hex')); RAISE EXCEPTION 'closed receiver readable'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
\echo receiver-case=purpose
-- Six global leaf purposes must collide regardless of insertion order.
BEGIN;
SET LOCAL ROLE contour_owner;
DO $$ DECLARE a text; b text; leaf bytea; n integer:=0; BEGIN
 FOREACH a IN ARRAY ARRAY['product','export','gateway_observer','gateway_backend','receiver_backend','receiver_evidence'] LOOP
  FOREACH b IN ARRAY ARRAY['product','export','gateway_observer','gateway_backend','receiver_backend','receiver_evidence'] LOOP
   n:=n+1; leaf:=decode(lpad(to_hex(n+10000),64,'0'),'hex');
   INSERT INTO contour.causal_leaf_reservations VALUES(leaf,a);
   BEGIN INSERT INTO contour.causal_leaf_reservations VALUES(leaf,b); RAISE EXCEPTION 'purpose collision accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
  END LOOP;
 END LOOP;
END $$;
ROLLBACK;
\echo receiver-case=acl
SET ROLE contour_causal_receiver_reader;
DO $$ BEGIN
 BEGIN PERFORM count(*) FROM contour.causal_receiver_enrollments; RAISE EXCEPTION 'raw read accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN DELETE FROM contour.causal_receiver_enrollments; RAISE EXCEPTION 'raw delete accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
\echo receiver-case=immutable
SET ROLE contour_owner;
DO $$ BEGIN
 BEGIN UPDATE contour.causal_receiver_enrollments SET metadata=metadata; RAISE EXCEPTION 'immutable update accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN DELETE FROM contour.causal_receiver_enrollments; RAISE EXCEPTION 'immutable delete accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
