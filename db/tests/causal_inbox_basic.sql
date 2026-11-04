-- Requires causal_runtime_registry_pre.sql, migration 18, causal_session_setup.sql,
-- migrations 19 and 20. This is a disposable database with synthetic assertions.
SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false);
CREATE FUNCTION pg_temp.inbox_claim() RETURNS contour.causal_session_claim LANGUAGE sql AS $$ SELECT ROW(
 'f0000000-0000-4000-8000-000000000001'::uuid,'fc000000-0000-4000-8000-000000000001'::uuid,
 'f6000000-0000-4000-8000-000000000001'::uuid,'f7000000-0000-4000-8000-000000000001'::uuid,
 'f1000000-0000-4000-8000-000000000001'::uuid,'f2000000-0000-4000-8000-000000000001'::uuid,
 'f3000000-0000-4000-8000-000000000001'::uuid,'f4000000-0000-4000-8000-000000000001'::uuid,
 'f5000000-0000-4000-8000-000000000001'::uuid,'f9000000-0000-4000-8000-000000000001'::uuid,
 decode(repeat('33',32),'hex'),'nodered_5_0_9_v1',decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex'),
 'fe000000-0000-4000-8000-000000000001'::uuid,1,decode(repeat('ab',32),'hex'),
 clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes',1,decode('01','hex'),
 clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes',900000000,500,1048576,1024,60)::contour.causal_session_claim $$;
SET ROLE contour_causal_issuer;
SELECT * FROM contour.issue_causal_session(pg_temp.inbox_claim());
RESET ROLE;
CREATE FUNCTION pg_temp.inbox_payload(b uuid, seq integer, id text, root text) RETURNS bytea LANGUAGE sql AS $$
 SELECT convert_to(format('{"batch_id":"%s","events":[{"event_id":"%s","kind":"root","root":"%s","seq":%s}],"first_seq":%s,"last_seq":%s,"runtime_id":"fc000000-0000-4000-8000-000000000001","session_epoch":1,"tenant_id":"f0000000-0000-4000-8000-000000000001","wire_version":1}',b,id,root,seq,seq,seq),'UTF8') $$;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='contour_causal_inbox_writer' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
 OR has_table_privilege('contour_causal_inbox_writer','contour.causal_inbox_batches','SELECT')
 OR has_table_privilege('contour_causal_inbox_writer','contour.causal_inbox_events','INSERT')
 OR has_function_privilege('contour_causal_inbox_writer','contour.causal_session_locked(contour.causal_session_claim,numeric,timestamptz)','EXECUTE')
 OR NOT has_function_privilege('contour_causal_inbox_writer','contour.accept_causal_batch(uuid,uuid,numeric,bytea,bytea,bytea)','EXECUTE')
 OR EXISTS (SELECT 1 FROM pg_class WHERE oid IN ('contour.causal_inbox_batches'::regclass,'contour.causal_inbox_events'::regclass) AND (NOT relrowsecurity OR NOT relforcerowsecurity))
 THEN RAISE EXCEPTION 'inbox ACL or RLS mismatch'; END IF;
END $$;
CREATE TEMP TABLE inbox_receipt (receipt_id uuid, accepted_at timestamptz, duplicate boolean);
GRANT ALL ON inbox_receipt TO contour_causal_inbox_writer;
SET ROLE contour_causal_inbox_writer;
INSERT INTO inbox_receipt SELECT * FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32)));
DO $$ DECLARE r record; BEGIN
 SELECT * INTO r FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32)));
 IF NOT r.duplicate OR NOT EXISTS(SELECT 1 FROM inbox_receipt x WHERE x.receipt_id=r.receipt_id AND x.accepted_at=r.accepted_at AND NOT x.duplicate) THEN RAISE EXCEPTION 'receipt retry mismatch'; END IF;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('44',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32))); RAISE EXCEPTION 'wrong peer accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('cd',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32))); RAISE EXCEPTION 'wrong grant accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000002',1,repeat('2',32),repeat('b',32))); RAISE EXCEPTION 'overlapping sequence accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000002',2,repeat('1',32),repeat('b',32))); RAISE EXCEPTION 'overlapping event id accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000002',2,repeat('2',32),repeat('a',32))); RAISE EXCEPTION 'duplicate root accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
RESET ROLE;
SET ROLE contour_owner;
DO $$ DECLARE n bigint; BEGIN
 SELECT used_bytes INTO n FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
 IF n IS DISTINCT FROM octet_length(pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32)))::bigint OR (SELECT count(*) FROM contour.causal_inbox_events)<>1 THEN RAISE EXCEPTION 'quota or index mismatch'; END IF;
END $$;
RESET ROLE;
-- A full transaction rollback must remove its facts, receipt, and quota charge.
BEGIN;
SET LOCAL ROLE contour_causal_inbox_writer;
SELECT * FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000003',3,repeat('3',32),repeat('c',32)));
ROLLBACK;
SET ROLE contour_owner;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM contour.causal_inbox_batches WHERE batch_id='aa000000-0000-4000-8000-000000000003') OR
 (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001') IS DISTINCT FROM octet_length(pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32)))::bigint
 THEN RAISE EXCEPTION 'rollback leaked admission'; END IF;
END $$;
RESET ROLE;
CREATE FUNCTION pg_temp.inbox_event(b uuid, event_text text, seq integer) RETURNS bytea LANGUAGE sql AS $$
 SELECT convert_to(format('{"batch_id":"%s","events":[%s],"first_seq":%s,"last_seq":%s,"runtime_id":"fc000000-0000-4000-8000-000000000001","session_epoch":1,"tenant_id":"f0000000-0000-4000-8000-000000000001","wire_version":1}',b,event_text,seq,seq),'UTF8') $$;
-- A delivery with an unresolved parent is valid; subsequent conflicting facts are not.
SET ROLE contour_causal_inbox_writer;
SELECT * FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_event('aa000000-0000-4000-8000-000000000005',format('{"activity":"%s","event_id":"%s","kind":"delivery","parent":"%s","root":"%s","seq":5}',repeat('b',32),repeat('5',32),repeat('c',32),repeat('a',32)),5));
DO $$ BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_event('aa000000-0000-4000-8000-000000000006',format('{"activity":"%s","attempt":"%s","event_id":"%s","kind":"attempt","marker_digest":"%s","root":"%s","seq":6}',repeat('b',32),repeat('d',32),repeat('6',32),repeat('e',64),repeat('f',32)),6)); RAISE EXCEPTION 'cross root accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_event('aa000000-0000-4000-8000-000000000006',format('{"event_id":"%s","first_missing_seq":5,"kind":"loss","last_missing_seq":5,"reason":"overflow","seq":6}',repeat('6',32)),6)); RAISE EXCEPTION 'loss covered existing event'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
SELECT * FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_event('aa000000-0000-4000-8000-000000000010',format('{"event_id":"%s","first_missing_seq":8,"kind":"loss","last_missing_seq":9,"reason":"overflow","seq":10}',repeat('a',32)),10));
DO $$ BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000008',8,repeat('8',32),repeat('8',32))); RAISE EXCEPTION 'event entered old loss'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
RESET ROLE;
-- The initial positive admission above is a control for these authority failures.
SET ROLE contour_causal_inbox_writer;
DO $$ DECLARE p bytea:=pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000020',20,repeat('a',32),repeat('f',32)); BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',99,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),p); RAISE EXCEPTION 'missing session accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000002','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),p); RAISE EXCEPTION 'wrong tenant accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),convert_to('{','UTF8')); RAISE EXCEPTION 'malformed batch accepted'; EXCEPTION WHEN data_exception OR check_violation THEN NULL; END;
END $$;
RESET ROLE;
SET ROLE contour_causal_issuer;
DO $$ BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000020',20,repeat('a',32),repeat('f',32))); RAISE EXCEPTION 'wrong role accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
