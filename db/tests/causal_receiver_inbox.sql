-- Synthetic parser controls; execute only after independently reviewed SQL29.
-- This is not mTLS, deployment, commit or causal-edge evidence.
BEGIN;
SET LOCAL ROLE contour_owner;
DO $test$
DECLARE raw bytea; bad bytea; value jsonb; rejected boolean; n integer:=0;
BEGIN
 raw:=convert_to($wire${"binding_digest":"6666666666666666666666666666666666666666666666666666666666666666","delivery_handle":"44444444444444444444444444444444","gateway_generation":"11111111111111111111111111111111","gateway_id":"123e4567-e89b-12d3-a456-426614174000","local_root":"55555555555555555555555555555555","receiver_runtime_id":"123e4567-e89b-12d3-a456-426614174000","receiver_session_epoch":"18446744073709551615","tenant_id":"123e4567-e89b-12d3-a456-426614174000","wire_version":1}$wire$,'UTF8');
 value:=contour.receiver_inbox_wire(raw);
 IF value->>'receiver_session_epoch'<>'18446744073709551615'
 OR encode(sha256(convert_to(E'apicontour/causal-evidence/receiver/1\n','UTF8')||raw),'hex')<>'46c6225cfb2fd61b6656f0afa83d24ac0c6200d975aa4d10b99b9bdf3b739052'
 THEN RAISE EXCEPTION 'receiver vector mismatch'; END IF;
 FOREACH bad IN ARRAY ARRAY[
  raw||convert_to(' ','UTF8'),
  convert_to(replace(convert_from(raw,'UTF8'),'"wire_version":1','"wire_version":1.0'),'UTF8'),
  convert_to(replace(convert_from(raw,'UTF8'),'"wire_version":1','"wire_version":"1"'),'UTF8'),
  convert_to(replace(convert_from(raw,'UTF8'),'"wire_version":1','"wire_version":1,"wire_version":1'),'UTF8'),
  convert_to(replace(convert_from(raw,'UTF8'),'"wire_version":1','"unknown":0,"wire_version":1'),'UTF8'),
  convert_to(replace(convert_from(raw,'UTF8'),'18446744073709551615','18446744073709551616'),'UTF8'),
  convert_to(replace(convert_from(raw,'UTF8'),'18446744073709551615','01'),'UTF8'),
  convert_to(replace(convert_from(raw,'UTF8'),'"18446744073709551615"','1'),'UTF8'),
  convert_to(replace(convert_from(raw,'UTF8'),'123e4567-e89b-12d3-a456-426614174000','123E4567-e89b-12d3-a456-426614174000'),'UTF8'),
  convert_to(repeat(' ',4097),'UTF8'), decode('ff','hex')
 ] LOOP
  rejected:=false;
  BEGIN PERFORM contour.receiver_inbox_wire(bad); EXCEPTION WHEN check_violation THEN rejected:=true; END;
  IF NOT rejected THEN RAISE EXCEPTION 'receiver malformed accepted'; END IF;
  n:=n+1;
 END LOOP;
 IF n<>11 THEN RAISE EXCEPTION 'receiver negative controls incomplete'; END IF;
END $test$;
ROLLBACK;
-- The owning synthetic harness must supply four independently valid pairs,
-- on distinct handles, with active SQL28 receiver enrollment and gateway,
-- committed producer session/marker, and verified V2 REQUEST/origin proof.
-- pair names: observer-first, receiver-first, mismatch, quota. No fixture assertion
-- below substitutes for TLS peer authentication.
DO $$ BEGIN
 IF to_regclass('pg_temp.receiver_pairs') IS NULL THEN RAISE EXCEPTION 'synthetic receiver pairs required'; END IF;
 IF (SELECT count(*) FROM receiver_pairs)<>4 OR
    (SELECT array_agg(name ORDER BY name) FROM receiver_pairs) IS DISTINCT FROM ARRAY['mismatch','observer-first','quota','receiver-first']::text[]
 THEN RAISE EXCEPTION 'synthetic receiver pairs invalid'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='contour_causal_receiver_writer' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
 OR NOT has_function_privilege('contour_causal_receiver_writer','contour.accept_causal_receiver(bytea,contour.verified_receiver_claim)','EXECUTE')
 OR has_function_privilege('contour_runtime','contour.accept_causal_receiver(bytea,contour.verified_receiver_claim)','EXECUTE')
 OR has_function_privilege('contour_causal_receiver_writer','contour.causal_json_canonical(jsonb)','EXECUTE')
 OR has_table_privilege('contour_causal_receiver_writer','contour.causal_receiver_inbox','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 OR has_table_privilege('contour_causal_receiver_writer','contour.causal_receiver_assignments','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 OR has_table_privilege('contour_causal_receiver_writer','contour.causal_receiver_tombstones','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 THEN RAISE EXCEPTION 'receiver privileges incorrect'; END IF;
END $$;
GRANT SELECT ON receiver_pairs TO contour_causal_receiver_writer,contour_causal_observer_writer,contour_admin;
CREATE TEMP TABLE receiver_receipts(name text PRIMARY KEY, receipt bytea NOT NULL);
GRANT SELECT,INSERT ON receiver_receipts TO contour_causal_receiver_writer;
\echo receiver-case=observer-first
SET ROLE contour_causal_observer_writer;
SELECT contour.accept_causal_observer(observer_raw,observer_proof) IS NOT NULL FROM receiver_pairs WHERE name='observer-first';
RESET ROLE;
SET ROLE contour_causal_receiver_writer;
INSERT INTO receiver_receipts SELECT name,contour.accept_causal_receiver(receiver_raw,receiver_proof) FROM receiver_pairs WHERE name='observer-first';
RESET ROLE;
CREATE TEMP TABLE receiver_usage AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT (convert_from(receiver_raw,'UTF8')::jsonb->>'tenant_id')::uuid FROM receiver_pairs WHERE name='observer-first');
GRANT SELECT ON receiver_usage TO contour_causal_receiver_writer;
-- Prepare canonical adversarial inputs as the fixture owner. The restricted
-- writer must not gain access to private canonicalization helpers for a test.
CREATE TEMP TABLE receiver_mutations AS
 SELECT name,
 convert_to(contour.causal_json_canonical(jsonb_set(convert_from(receiver_raw,'UTF8')::jsonb,'{local_root}',to_jsonb(repeat('f',32)))),'UTF8') AS changed_root,
 convert_to(contour.causal_json_canonical(jsonb_set(convert_from(receiver_raw,'UTF8')::jsonb,'{receiver_session_epoch}',to_jsonb(((convert_from(receiver_raw,'UTF8')::jsonb->>'receiver_session_epoch')::numeric+1)::text))),'UTF8') AS changed_epoch,
 convert_to(contour.causal_json_canonical(jsonb_set(convert_from(receiver_raw,'UTF8')::jsonb,'{gateway_id}',to_jsonb('00000000-0000-4000-8000-00000000ceff'::text))),'UTF8') AS changed_gateway,
 convert_to(contour.causal_json_canonical(jsonb_set(convert_from(receiver_raw,'UTF8')::jsonb,'{tenant_id}',to_jsonb('00000000-0000-4000-8000-00000000cefe'::text))),'UTF8') AS changed_tenant
 FROM receiver_pairs WHERE name='observer-first';
GRANT SELECT ON receiver_mutations TO contour_causal_receiver_writer;
SET ROLE contour_causal_receiver_writer;
DO $$ DECLARE r bytea; BEGIN
 SELECT contour.accept_causal_receiver(receiver_raw,receiver_proof) INTO STRICT r FROM receiver_pairs WHERE name='observer-first';
 IF r IS DISTINCT FROM (SELECT receipt FROM receiver_receipts WHERE name='observer-first') THEN RAISE EXCEPTION 'receiver retry changed receipt'; END IF;
END $$;
DO $$ DECLARE pair record; altered bytea; proof contour.verified_receiver_claim; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='observer-first';
 proof:=pair.receiver_proof;proof.evidence_peer_leaf:=decode(repeat('ff',32),'hex');
 BEGIN PERFORM contour.accept_causal_receiver(pair.receiver_raw,proof); RAISE EXCEPTION 'wrong receiver peer admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
 SELECT changed_root INTO STRICT altered FROM receiver_mutations WHERE name=pair.name;
 BEGIN PERFORM contour.accept_causal_receiver(altered,pair.receiver_proof); RAISE EXCEPTION 'changed receiver assignment admitted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
DO $$ DECLARE pair record; proof contour.verified_receiver_claim; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='observer-first';
 proof:=pair.receiver_proof;proof.enrollment_generation:=repeat('f',32);
 BEGIN PERFORM contour.accept_causal_receiver(pair.receiver_raw,proof); RAISE EXCEPTION 'wrong receiver generation admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ DECLARE pair record; changed bytea; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='observer-first';
 SELECT changed_epoch INTO STRICT changed FROM receiver_mutations WHERE name=pair.name;
 BEGIN PERFORM contour.accept_causal_receiver(changed,pair.receiver_proof); RAISE EXCEPTION 'wrong receiver epoch admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
 SELECT changed_gateway INTO STRICT changed FROM receiver_mutations WHERE name=pair.name;
 BEGIN PERFORM contour.accept_causal_receiver(changed,pair.receiver_proof); RAISE EXCEPTION 'wrong gateway admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
 SELECT changed_tenant INTO STRICT changed FROM receiver_mutations WHERE name=pair.name;
 BEGIN PERFORM contour.accept_causal_receiver(changed,pair.receiver_proof); RAISE EXCEPTION 'wrong tenant admitted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT (convert_from(receiver_raw,'UTF8')::jsonb->>'tenant_id')::uuid FROM receiver_pairs WHERE name='observer-first')) IS DISTINCT FROM (SELECT used_bytes FROM receiver_usage)
 THEN RAISE EXCEPTION 'receiver retry or rejection changed quota'; END IF;
END $$;
-- Old payload cutoff and future tenant floor each refuse a current retry;
-- trigger changes and floor manipulation are rolled back in this disposable DB.
BEGIN;
ALTER TABLE contour.causal_receiver_inbox DISABLE TRIGGER receiver_inbox_immutable;
WITH stamp AS (SELECT clock_timestamp()-interval '25 hours' AS at)
UPDATE contour.causal_receiver_inbox i SET accepted_at=stamp.at,expires_at=stamp.at+interval '24 hours' FROM stamp
 WHERE i.delivery_handle=(SELECT convert_from(receiver_raw,'UTF8')::jsonb->>'delivery_handle' FROM receiver_pairs WHERE name='observer-first');
SET LOCAL ROLE contour_causal_receiver_writer;
DO $$ DECLARE pair record; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='observer-first';
 BEGIN PERFORM contour.accept_causal_receiver(pair.receiver_raw,pair.receiver_proof); RAISE EXCEPTION 'expired receiver receipt returned'; EXCEPTION WHEN unique_violation OR check_violation THEN NULL; END;
END $$;
ROLLBACK;
BEGIN;
UPDATE contour.origin_tenant_state SET clock_floor=clock_timestamp()+interval '1 hour' WHERE tenant_id=(SELECT (convert_from(receiver_raw,'UTF8')::jsonb->>'tenant_id')::uuid FROM receiver_pairs WHERE name='observer-first');
SET LOCAL ROLE contour_causal_receiver_writer;
DO $$ DECLARE pair record; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='observer-first';
 BEGIN PERFORM contour.accept_causal_receiver(pair.receiver_raw,pair.receiver_proof); RAISE EXCEPTION 'backward clock returned receiver receipt'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
ROLLBACK;
\echo receiver-case=receiver-first
SET ROLE contour_causal_receiver_writer;
INSERT INTO receiver_receipts SELECT name,contour.accept_causal_receiver(receiver_raw,receiver_proof) FROM receiver_pairs WHERE name='receiver-first';
DO $$ DECLARE pair record; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='receiver-first';
 BEGIN PERFORM contour.accept_causal_receiver(pair.receiver_raw,pair.receiver_proof); RAISE EXCEPTION 'pre-observer retry returned receipt'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
-- Deliberate corrupt/orphan controls are transactional and restore all rows.
BEGIN;
ALTER TABLE contour.causal_receiver_inbox DISABLE TRIGGER receiver_inbox_immutable;
DELETE FROM contour.causal_receiver_inbox WHERE delivery_handle=(SELECT convert_from(receiver_raw,'UTF8')::jsonb->>'delivery_handle' FROM receiver_pairs WHERE name='receiver-first');
SET LOCAL ROLE contour_causal_observer_writer;
DO $$ DECLARE pair record; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='receiver-first';
 BEGIN PERFORM contour.accept_causal_observer(pair.observer_raw,pair.observer_proof); RAISE EXCEPTION 'orphan assignment accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
ROLLBACK;
BEGIN;
ALTER TABLE contour.causal_receiver_inbox DISABLE TRIGGER receiver_inbox_immutable;
UPDATE contour.causal_receiver_inbox SET fact_digest=decode(repeat('ff',32),'hex') WHERE delivery_handle=(SELECT convert_from(receiver_raw,'UTF8')::jsonb->>'delivery_handle' FROM receiver_pairs WHERE name='receiver-first');
SET LOCAL ROLE contour_causal_observer_writer;
DO $$ DECLARE pair record; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='receiver-first';
 BEGIN PERFORM contour.accept_causal_observer(pair.observer_raw,pair.observer_proof); RAISE EXCEPTION 'corrupt assignment accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
ROLLBACK;
SET ROLE contour_causal_observer_writer;
SELECT contour.accept_causal_observer(observer_raw,observer_proof) IS NOT NULL FROM receiver_pairs WHERE name='receiver-first';
RESET ROLE;
SET ROLE contour_causal_receiver_writer;
DO $$ DECLARE r bytea; BEGIN
 SELECT contour.accept_causal_receiver(receiver_raw,receiver_proof) INTO STRICT r FROM receiver_pairs WHERE name='receiver-first';
 IF r IS DISTINCT FROM (SELECT receipt FROM receiver_receipts WHERE name='receiver-first') THEN RAISE EXCEPTION 'receiver retry changed receipt'; END IF;
END $$;
RESET ROLE;
\echo receiver-case=receiver-first-mismatch
SET ROLE contour_causal_receiver_writer;
INSERT INTO receiver_receipts SELECT name,contour.accept_causal_receiver(receiver_raw,receiver_proof) FROM receiver_pairs WHERE name='mismatch';
RESET ROLE;
SET ROLE contour_causal_observer_writer;
DO $$ DECLARE pair record; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='mismatch';
 BEGIN PERFORM contour.accept_causal_observer(pair.observer_raw,pair.observer_proof); RAISE EXCEPTION 'mismatched receiver assignment accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;

DO $$ DECLARE b jsonb; BEGIN
 SELECT (convert_from(observer_raw,'UTF8')::jsonb)->'binding' INTO STRICT b FROM receiver_pairs WHERE name='mismatch';
 IF EXISTS(SELECT 1 FROM contour.causal_observer_inbox o WHERE (o.tenant_id,o.gateway_id,o.gateway_generation,o.delivery_handle)=((b->>'tenant_id')::uuid,(b->>'gateway_id')::uuid,b->>'gateway_generation',b->>'delivery_handle'))
 THEN RAISE EXCEPTION 'mismatched observer persisted'; END IF;
END $$;

\echo receiver-case=quota
CREATE TEMP TABLE receiver_quota_before AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT (convert_from(receiver_raw,'UTF8')::jsonb->>'tenant_id')::uuid FROM receiver_pairs WHERE name='quota');
UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id=(SELECT (convert_from(receiver_raw,'UTF8')::jsonb->>'tenant_id')::uuid FROM receiver_pairs WHERE name='quota');
SET ROLE contour_causal_receiver_writer;
DO $$ DECLARE pair record; BEGIN
 SELECT * INTO STRICT pair FROM receiver_pairs WHERE name='quota';
 BEGIN PERFORM contour.accept_causal_receiver(pair.receiver_raw,pair.receiver_proof); RAISE EXCEPTION 'receiver quota admitted'; EXCEPTION WHEN program_limit_exceeded THEN NULL; END;
END $$;
RESET ROLE;
DO $$ DECLARE b jsonb; BEGIN
 SELECT convert_from(receiver_raw,'UTF8')::jsonb INTO STRICT b FROM receiver_pairs WHERE name='quota';
 IF EXISTS(SELECT 1 FROM contour.causal_receiver_assignments a WHERE (a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle)=((b->>'tenant_id')::uuid,(b->>'gateway_id')::uuid,b->>'gateway_generation',b->>'delivery_handle'))
 OR (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(b->>'tenant_id')::uuid)<>1073741824
 THEN RAISE EXCEPTION 'receiver quota wrote partial state'; END IF;
END $$;
UPDATE contour.origin_logical_usage SET used_bytes=(SELECT used_bytes FROM receiver_quota_before) WHERE tenant_id=(SELECT (convert_from(receiver_raw,'UTF8')::jsonb->>'tenant_id')::uuid FROM receiver_pairs WHERE name='quota');
-- Test-only race inputs, visible only to the dedicated writer. The owning
-- qualifier drops this synthetic staging table after checking both outcomes.
CREATE UNLOGGED TABLE public.receiver29_race_seed(name text PRIMARY KEY,raw bytea NOT NULL,proof contour.verified_receiver_claim NOT NULL);
REVOKE ALL ON public.receiver29_race_seed FROM PUBLIC;
GRANT SELECT ON public.receiver29_race_seed TO contour_causal_receiver_writer,contour_admin;
INSERT INTO public.receiver29_race_seed
 SELECT v.name,convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(jsonb_set(convert_from(p.receiver_raw,'UTF8')::jsonb,
  '{delivery_handle}',to_jsonb(v.handle)),'{local_root}',to_jsonb(v.root)),'{binding_digest}',
  to_jsonb(encode(sha256(convert_to(E'apicontour/causal-evidence/binding/1\n','UTF8')||
   convert_to(contour.causal_json_canonical(jsonb_set((convert_from(p.observer_raw,'UTF8')::jsonb)->'binding','{delivery_handle}',to_jsonb(v.handle))),'UTF8')),'hex')))),'UTF8'),p.receiver_proof
 FROM receiver_pairs p CROSS JOIN (VALUES('left',repeat('fc',16),repeat('fb',16)),('right',repeat('fd',16),repeat('fb',16)),('control',repeat('fe',16),repeat('fa',16))) v(name,root,handle) WHERE p.name='quota';
