-- Synthetic assertions, not signatures. Requires pre-18 registry fixture and a
-- live first runtime enrolled on leaf 33; use only a disposable database.
SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false);
SELECT set_config('test.session_time',clock_timestamp()::text,false);
CREATE FUNCTION pg_temp.claim(n uuid,rev numeric DEFAULT 1,digest bytea DEFAULT decode(repeat('ab',32),'hex')) RETURNS contour.causal_session_claim
LANGUAGE sql AS $$ SELECT ROW(
 'f0000000-0000-4000-8000-000000000001'::uuid,'fc000000-0000-4000-8000-000000000001'::uuid,
 'f6000000-0000-4000-8000-000000000001'::uuid,'f7000000-0000-4000-8000-000000000001'::uuid,
 'f1000000-0000-4000-8000-000000000001'::uuid,'f2000000-0000-4000-8000-000000000001'::uuid,
 'f3000000-0000-4000-8000-000000000001'::uuid,'f4000000-0000-4000-8000-000000000001'::uuid,
 'f5000000-0000-4000-8000-000000000001'::uuid,'f9000000-0000-4000-8000-000000000001'::uuid,
 decode(repeat('33',32),'hex'),'nodered_5_0_9_v1',decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex'),n,rev,digest,
 current_setting('test.session_time')::timestamptz-interval '1 minute',current_setting('test.session_time')::timestamptz+interval '10 minutes',
 1,decode('01','hex'),current_setting('test.session_time')::timestamptz-interval '1 minute',current_setting('test.session_time')::timestamptz+interval '10 minutes',
 900000000,10,1024,1024,60)::contour.causal_session_claim $$;
DO $$ BEGIN
 IF pg_has_role('contour_causal_issuer','contour_runtime','MEMBER') OR NOT EXISTS (SELECT 1 FROM pg_class WHERE oid='contour.causal_sessions'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR has_table_privilege('contour_causal_issuer','contour.causal_sessions','INSERT')
 OR has_table_privilege('contour_causal_issuer','contour.causal_sessions','SELECT')
 OR has_function_privilege('contour_causal_issuer','contour.causal_session_locked(contour.causal_session_claim,numeric,timestamptz)','EXECUTE')
 OR has_function_privilege('contour_causal_issuer','contour.causal_runtime_authority_locked(contour.causal_session_claim,timestamptz)','EXECUTE')
 OR has_function_privilege('contour_causal_issuer','contour.causal_policy_exact(uuid,uuid,numeric,bytea)','EXECUTE')
 OR NOT has_function_privilege('contour_owner','contour.causal_policy_exact(uuid,uuid,numeric,bytea)','EXECUTE')
 OR has_function_privilege('contour_runtime','contour.issue_causal_session(contour.causal_session_claim)','EXECUTE')
 OR has_function_privilege('contour_causal_provisioner','contour.check_causal_session(uuid,uuid,numeric)','EXECUTE')
 OR EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            WHERE p.oid IN ('contour.issue_causal_session(contour.causal_session_claim)'::regprocedure,'contour.causal_session_locked(contour.causal_session_claim,numeric,timestamptz)'::regprocedure,'contour.causal_policy_exact(uuid,uuid,numeric,bytea)'::regprocedure) AND a.grantee=0)
 THEN RAISE EXCEPTION 'session ACL or RLS mismatch'; END IF;
END $$;
CREATE TEMP TABLE session_result (epoch numeric, issued_at timestamptz, expires_at timestamptz);
GRANT SELECT, INSERT ON session_result TO contour_causal_issuer;
SET ROLE contour_causal_issuer;
DO $$ DECLARE r record; BEGIN
 SELECT * INTO r FROM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000001'));
 IF r.epoch<>1 OR r.expires_at<>current_setting('test.session_time')::timestamptz+interval '10 minutes' THEN RAISE EXCEPTION 'first issue or lease bound failed'; END IF;
 INSERT INTO session_result VALUES (r.epoch,r.issued_at,r.expires_at);
END $$;
DO $$ DECLARE r record; BEGIN
 SELECT * INTO r FROM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000001'));
 IF NOT EXISTS (SELECT 1 FROM session_result z WHERE z.epoch=r.epoch AND z.issued_at=r.issued_at AND z.expires_at=r.expires_at) THEN RAISE EXCEPTION 'exact retry changed lease'; END IF;
END $$;
RESET ROLE;
-- Observer grants belong to origin-proof authorization; their revocation must
-- not revoke this separately bound runtime. Positive check follows revocation.
SET ROLE contour_admin;
SELECT contour.grant_origin_observer('f0000000-0000-4000-8000-000000000001','fb000000-0000-4000-8000-000000000001','f9000000-0000-4000-8000-000000000001','f7000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001','f1000000-0000-4000-8000-000000000001','f2000000-0000-4000-8000-000000000001','f3000000-0000-4000-8000-000000000001','f4000000-0000-4000-8000-000000000001');
SELECT contour.end_origin('f0000000-0000-4000-8000-000000000001','grant_revoked','fb000000-0000-4000-8000-000000000001');
-- An old revoked product leaf does not disable a runtime if another live
-- product credential remains bound to its lifecycle.
SELECT contour.enroll_origin_credential('f0000000-0000-4000-8000-000000000001','fa000000-0000-4000-8000-000000000004','f9000000-0000-4000-8000-000000000001',decode(repeat('55',32),'hex'));
SELECT contour.end_origin('f0000000-0000-4000-8000-000000000001','credential_revoked','fa000000-0000-4000-8000-000000000001');
RESET ROLE;
SET ROLE contour_causal_issuer;
DO $$ BEGIN IF NOT contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1) THEN RAISE EXCEPTION 'current session denied'; END IF; END $$;
DO $$ BEGIN
 BEGIN PERFORM count(*) FROM contour.causal_sessions; RAISE EXCEPTION 'direct session read allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN INSERT INTO contour.causal_sessions DEFAULT VALUES; RAISE EXCEPTION 'direct session write allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
SET ROLE contour_owner;
DO $$ BEGIN IF (SELECT count(*) FROM contour.causal_sessions)<>1 THEN RAISE EXCEPTION 'owner tenant control missing'; END IF; END $$;
DO $$ BEGIN
 IF NOT contour.causal_policy_exact('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001',1,decode('01','hex')) OR contour.causal_policy_exact('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001',1,decode('02','hex')) THEN RAISE EXCEPTION 'exact head control failed'; END IF;
 IF contour.causal_session_locked(pg_temp.claim('fe000000-0000-4000-8000-000000000001'),NULL,clock_timestamp()) IS DISTINCT FROM false THEN RAISE EXCEPTION 'null epoch accepted'; END IF;
 BEGIN PERFORM contour.causal_session_locked(pg_temp.claim('fe000000-0000-4000-8000-000000000001'),1,clock_timestamp()); RAISE EXCEPTION 'unlocked predicate accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN DELETE FROM contour.causal_sessions WHERE epoch=1; RAISE EXCEPTION 'session delete allowed'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN UPDATE contour.causal_sessions SET epoch=epoch WHERE epoch=1; RAISE EXCEPTION 'session update allowed'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;

SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000002',false);
DO $$ BEGIN IF EXISTS (SELECT 1 FROM contour.causal_sessions) THEN RAISE EXCEPTION 'tenant RLS leak'; END IF; END $$;
RESET ROLE;
SET ROLE contour_causal_issuer;
DO $$ BEGIN
 BEGIN PERFORM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000010')); RAISE EXCEPTION 'cross-tenant issue accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false);
DO $$ BEGIN
 BEGIN PERFORM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000001',1,decode(repeat('cd',32),'hex'))); RAISE EXCEPTION 'conflicting nonce accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000002',1,decode(repeat('cd',32),'hex'))); RAISE EXCEPTION 'equivocation accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
BEGIN;
SELECT * FROM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000003',2));
ROLLBACK;
DO $$ DECLARE r record; BEGIN
 SELECT * INTO r FROM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000003',1));
 IF r.epoch<>2 THEN RAISE EXCEPTION 'rollback leaked epoch or grant revision'; END IF;
END $$;
DO $$ BEGIN IF contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1) THEN RAISE EXCEPTION 'superseded session accepted'; END IF; END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000001')); RAISE EXCEPTION 'superseded retry accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
DO $$ BEGIN
 PERFORM pg_advisory_xact_lock(42);
 BEGIN PERFORM contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',2); RAISE EXCEPTION 'held lock accepted'; EXCEPTION WHEN serialization_failure THEN NULL; END;
END $$;
RESET ROLE;
-- Each rejected operation is in an exception subtransaction, so its locks are
-- released before the next case. Assertion failures use a different SQLSTATE.
SET ROLE contour_causal_issuer;
DO $$ DECLARE x contour.causal_session_claim; i integer; BEGIN
 FOR i IN 1..16 LOOP
  x:=pg_temp.claim('fe000000-0000-4000-8000-000000000010');
  CASE i
   WHEN 1 THEN x.source_id:='f7000000-0000-4000-8000-000000000003';
   WHEN 2 THEN x.instance_id:='f5000000-0000-4000-8000-000000000003';
   WHEN 3 THEN x.lifecycle_id:='f9000000-0000-4000-8000-000000000003';
   WHEN 4 THEN x.export_leaf:=decode(repeat('44',32),'hex');
   WHEN 5 THEN x.profile_name:='other';
   WHEN 6 THEN x.profile_hash:=decode(repeat('cd',32),'hex');
   WHEN 7 THEN x.policy_envelope:=decode('02','hex');
   WHEN 8 THEN x.policy_revision:=2;
   WHEN 9 THEN x.grant_expires:=current_setting('test.session_time')::timestamptz-interval '1 second';
   WHEN 10 THEN x.policy_expires:=current_setting('test.session_time')::timestamptz-interval '1 second';
   WHEN 11 THEN x.runtime_id:='fc000000-0000-4000-8000-000000000003';
   WHEN 12 THEN x.collector_id:='f6000000-0000-4000-8000-000000000003';
   WHEN 13 THEN x.project_id:='f1000000-0000-4000-8000-000000000002';
   WHEN 14 THEN x.service_id:='f2000000-0000-4000-8000-000000000002';
   WHEN 15 THEN x.environment_id:='f3000000-0000-4000-8000-000000000002';
   WHEN 16 THEN x.deployment_id:='f4000000-0000-4000-8000-000000000002';
  END CASE;
  BEGIN PERFORM contour.issue_causal_session(x); RAISE EXCEPTION 'invalid scope or lease accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 END LOOP;
END $$;
DO $$ DECLARE x contour.causal_session_claim; i integer; BEGIN
 FOR i IN 1..10 LOOP
  x:=pg_temp.claim('fe000000-0000-4000-8000-000000000010');
  CASE i
   WHEN 1 THEN x.grant_revision:=0;
   WHEN 2 THEN x.grant_revision:=18446744073709551616;
   WHEN 3 THEN x.grant_revision:=1.5;
   WHEN 4 THEN x.grant_expires:='infinity'::timestamptz;
   WHEN 5 THEN x.ttl_microseconds:=900000001;
   WHEN 6 THEN x.ttl_microseconds:=0;
   WHEN 7 THEN x.grant_issued:='-infinity'::timestamptz;
   WHEN 8 THEN x.policy_issued:='-infinity'::timestamptz;
   WHEN 9 THEN x.policy_expires:='infinity'::timestamptz;
   WHEN 10 THEN x.policy_revision:=18446744073709551616;
  END CASE;
  BEGIN PERFORM contour.issue_causal_session(x); RAISE EXCEPTION 'invalid assertion accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 END LOOP;
END $$;
DO $$ DECLARE r record; BEGIN
 SELECT * INTO r FROM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000004',2));
 IF r.epoch<>3 THEN RAISE EXCEPTION 'revision advance failed'; END IF;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000005',1)); RAISE EXCEPTION 'revision rollback accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
-- A one-second lease eventually expires; a retry never extends it.
DO $$ DECLARE x contour.causal_session_claim; r record; BEGIN
 x:=pg_temp.claim('fe000000-0000-4000-8000-000000000006',2); x.ttl_microseconds:=1000000;
 SELECT * INTO r FROM contour.issue_causal_session(x);
 IF r.expires_at-r.issued_at<>interval '1 second' THEN RAISE EXCEPTION 'TTL rounding'; END IF;
END $$;
SELECT pg_sleep(1.1);
DO $$ BEGIN IF contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',4) THEN RAISE EXCEPTION 'expired session accepted'; END IF; END $$;
DO $$ DECLARE x contour.causal_session_claim; BEGIN
 x:=pg_temp.claim('fe000000-0000-4000-8000-000000000006',2); x.ttl_microseconds:=1000000;
 BEGIN PERFORM contour.issue_causal_session(x); RAISE EXCEPTION 'expired retry accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000013',1)); RAISE EXCEPTION 'expired highwater forgotten'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ DECLARE r record; BEGIN
 SELECT * INTO r FROM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000007',2));
 IF r.epoch<>5 THEN RAISE EXCEPTION 'post-expiry issue failed'; END IF;
END $$;
RESET ROLE;
-- Trusted fixture-only synthetic rows test numeric exhaustion and clock rollback;
-- no persistent session is modified. No issuer receives direct table access.
BEGIN;
INSERT INTO contour.causal_sessions SELECT tenant_id,runtime_id,18446744073709551615,'fe000000-0000-4000-8000-000000000099',claim,issued_at,expires_at FROM contour.causal_sessions WHERE epoch=5;
SET LOCAL ROLE contour_causal_issuer;
DO $$ BEGIN
 BEGIN PERFORM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000009',2)); RAISE EXCEPTION 'epoch exhaustion accepted'; EXCEPTION WHEN numeric_value_out_of_range THEN NULL; END;
END $$;
ROLLBACK;
BEGIN;
INSERT INTO contour.causal_sessions SELECT tenant_id,runtime_id,100,'fe000000-0000-4000-8000-000000000098',claim,clock_timestamp()+interval '1 minute',clock_timestamp()+interval '2 minutes' FROM contour.causal_sessions WHERE epoch=5;
SET LOCAL ROLE contour_causal_issuer;
DO $$ BEGIN
 BEGIN PERFORM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000009',2)); RAISE EXCEPTION 'rollback clock accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
ROLLBACK;
-- Same revision but arbitrary old envelope cannot pass the exact-head check.
BEGIN; SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001');
INSERT INTO contour.policy_revisions VALUES ('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001',2,decode('02','hex'));
UPDATE contour.collector_authorization SET active_revision=2 WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND collector_id='f6000000-0000-4000-8000-000000000001';
COMMIT;
SET ROLE contour_causal_issuer;
DO $$ BEGIN IF contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',5) THEN RAISE EXCEPTION 'old head session accepted'; END IF; END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000004',2)); RAISE EXCEPTION 'old head retry accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;

-- New current policy is a positive control before disabling/revoking it.
SET ROLE contour_causal_issuer;
DO $$ DECLARE x contour.causal_session_claim; r record; BEGIN
 x:=pg_temp.claim('fe000000-0000-4000-8000-000000000008',2); x.policy_revision:=2; x.policy_envelope:=decode('02','hex');
 SELECT * INTO r FROM contour.issue_causal_session(x);
 IF r.epoch<>6 THEN RAISE EXCEPTION 'new policy issue failed'; END IF;
END $$;
DO $$ BEGIN IF NOT contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',6) THEN RAISE EXCEPTION 'new policy control failed'; END IF; END $$;
-- Independently verified policy and grant deadlines each cap an otherwise
-- longer requested TTL. Both are exact microsecond timestamptz comparisons.
DO $$ DECLARE x contour.causal_session_claim; r record; BEGIN
 x:=pg_temp.claim('fe000000-0000-4000-8000-000000000011',2); x.policy_revision:=2; x.policy_envelope:=decode('02','hex');
 x.policy_expires:=current_setting('test.session_time')::timestamptz+interval '4 minutes';
 x.grant_expires:=current_setting('test.session_time')::timestamptz+interval '5 minutes';
 SELECT * INTO r FROM contour.issue_causal_session(x);
 IF r.epoch<>7 OR r.expires_at<>x.policy_expires THEN RAISE EXCEPTION 'policy deadline cap failed'; END IF;
END $$;
DO $$ DECLARE x contour.causal_session_claim; r record; BEGIN
 x:=pg_temp.claim('fe000000-0000-4000-8000-000000000012',2); x.policy_revision:=2; x.policy_envelope:=decode('02','hex');
 x.policy_expires:=current_setting('test.session_time')::timestamptz+interval '5 minutes';
 x.grant_expires:=current_setting('test.session_time')::timestamptz+interval '4 minutes';
 SELECT * INTO r FROM contour.issue_causal_session(x);
 IF r.epoch<>8 OR r.expires_at<>x.grant_expires THEN RAISE EXCEPTION 'grant deadline cap failed'; END IF;
END $$;
RESET ROLE;
BEGIN; SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001'); UPDATE contour.source_authorization SET parser_profiles=ARRAY['http_xml_v1'] WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND source_id='f7000000-0000-4000-8000-000000000001'; COMMIT;
SET ROLE contour_causal_issuer;
DO $$ BEGIN IF contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',8) THEN RAISE EXCEPTION 'source drift accepted'; END IF; END $$;
RESET ROLE;
BEGIN; SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001'); UPDATE contour.source_authorization SET parser_profiles=ARRAY['http_json_v1'] WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND source_id='f7000000-0000-4000-8000-000000000001'; COMMIT;
SET ROLE contour_causal_issuer;
DO $$ BEGIN IF NOT contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',8) THEN RAISE EXCEPTION 'restored source denied'; END IF; END $$;
RESET ROLE;
BEGIN; SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001'); UPDATE contour.collector_authorization SET enabled=false WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND collector_id='f6000000-0000-4000-8000-000000000001'; COMMIT;
SET ROLE contour_causal_issuer;
DO $$ BEGIN IF contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',8) THEN RAISE EXCEPTION 'disabled collector accepted'; END IF; END $$;
RESET ROLE;
BEGIN; SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001'); UPDATE contour.collector_authorization SET enabled=true WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND collector_id='f6000000-0000-4000-8000-000000000001'; COMMIT;
SET ROLE contour_causal_issuer;
DO $$ BEGIN IF NOT contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',8) THEN RAISE EXCEPTION 'reenabled collector denied'; END IF; END $$;
RESET ROLE;
BEGIN; SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('f0000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001'); UPDATE contour.collector_authorization SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND collector_id='f6000000-0000-4000-8000-000000000001'; COMMIT;
SET ROLE contour_causal_issuer;
DO $$ BEGIN IF contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',8) THEN RAISE EXCEPTION 'revoked collector accepted'; END IF; END $$;
RESET ROLE;
