-- Disposable PostgreSQL only. Seed pg_temp.observer_seed(raw bytea, proof contour.verified_observer_claim) first;
-- exactly one committed V2 REQUEST/proof+catalog projection, gateway enrollment, and active producer session/marker are required.
-- Synthetic issuer assertions are not cryptographic or TLS proof. Run with ON_ERROR_STOP and autocommit.
DO $$ DECLARE n text; BEGIN
 IF (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,27)) THEN RAISE EXCEPTION 'ledger mismatch'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='contour_causal_observer_writer' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls) THEN RAISE EXCEPTION 'invalid writer'; END IF;
 FOREACH n IN ARRAY ARRAY['causal_observer_inbox','causal_observer_attempt_reservations','causal_observer_epoch_reservations'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace WHERE ns.nspname='contour' AND c.relname=n AND c.relrowsecurity AND c.relforcerowsecurity) OR has_table_privilege('contour_causal_observer_writer','contour.'||n,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE') THEN RAISE EXCEPTION 'raw or RLS violation: %',n; END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='contour.accept_causal_observer(bytea,contour.verified_observer_claim)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE') OR has_function_privilege('contour_runtime','contour.accept_causal_observer(bytea,contour.verified_observer_claim)','EXECUTE') THEN RAISE EXCEPTION 'observer writer overexposed'; END IF;
END $$;
SET ROLE contour_owner;
DO $$ DECLARE raw bytea:=convert_to($wire${"batch_id":"123e4567-e89b-12d3-a456-426614174000","binding":{"collector_id":"123e4567-e89b-12d3-a456-426614174000","delivery_handle":"44444444444444444444444444444444","gateway_generation":"11111111111111111111111111111111","gateway_id":"123e4567-e89b-12d3-a456-426614174000","marker_digest":"3333333333333333333333333333333333333333333333333333333333333333","producer_attempt_id":"22222222222222222222222222222222","producer_runtime_id":"123e4567-e89b-12d3-a456-426614174000","producer_session_epoch":"9007199254740993","receiver_runtime_id":"123e4567-e89b-12d3-a456-426614174000","receiver_session_epoch":"18446744073709551615","record_id":"123e4567-e89b-12d3-a456-426614174000","retry_of":null,"tenant_id":"123e4567-e89b-12d3-a456-426614174000","wire_version":1},"signed_marker":"ac1.fixture.signature","wire_version":1}$wire$,'UTF8'); j jsonb; BEGIN
 j:=contour.observer_wire(raw);
 IF j->'binding'->>'producer_session_epoch'<>'9007199254740993' THEN RAISE EXCEPTION 'epoch lost'; END IF;
 BEGIN PERFORM contour.observer_wire(convert_to(replace(convert_from(raw,'UTF8'),'"retry_of":null','"retry_of":null,"retry_of":null'),'UTF8')); RAISE EXCEPTION 'duplicate accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM contour.observer_wire(convert_to(replace(convert_from(raw,'UTF8'),',"retry_of":null',''),'UTF8')); RAISE EXCEPTION 'missing null accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM contour.observer_wire(convert_to(replace(convert_from(raw,'UTF8'),'"wire_version":1','"wire_version":1.0'),'UTF8')); RAISE EXCEPTION 'wrong version type accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF to_regclass('pg_temp.observer_seed') IS NULL THEN RAISE EXCEPTION 'trusted synthetic observer seed required'; END IF;
END $$;
CREATE TEMP TABLE observer_receipts(receipt bytea);
GRANT SELECT,INSERT ON observer_receipts TO contour_causal_observer_writer;
GRANT SELECT ON observer_seed TO contour_causal_observer_writer,contour_owner;
SET ROLE contour_causal_observer_writer;
-- First fact may precede producer-attempt and receiver facts, but not the committed V2 proof/projection.
INSERT INTO observer_receipts SELECT contour.accept_causal_observer(raw,proof) FROM observer_seed;
RESET ROLE;
CREATE TEMP TABLE observer_usage AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT ((proof).producer_claim).tenant_id FROM observer_seed);
GRANT SELECT ON observer_usage TO contour_owner;
SET ROLE contour_causal_observer_writer;
DO $$ DECLARE r bytea; BEGIN
 SELECT contour.accept_causal_observer(raw,proof) INTO STRICT r FROM observer_seed;
 IF r IS DISTINCT FROM (SELECT receipt FROM observer_receipts) THEN RAISE EXCEPTION 'exact retry changed receipt'; END IF;
END $$;
RESET ROLE;
SET ROLE contour_owner;
DO $$ BEGIN
 IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT ((proof).producer_claim).tenant_id FROM observer_seed)) IS DISTINCT FROM (SELECT used_bytes FROM observer_usage) THEN RAISE EXCEPTION 'exact retry changed quota'; END IF;
END $$;
RESET ROLE;
SET ROLE contour_causal_observer_writer;
DO $$ DECLARE r bytea; p contour.verified_observer_claim; x contour.causal_session_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_seed; x:=p.producer_claim; x.policy_expires:=clock_timestamp()-interval '1 second'; p.producer_claim:=x;
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'stale authority leaked receipt'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_seed; p.marker_public:=decode(repeat('ff',32),'hex');
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'wrong key admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_seed; p.marker_generation:=decode(repeat('dd',32),'hex');
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'wrong generation admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_seed; p.marker_wire_digest:=decode(repeat('cc',32),'hex');
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'wrong marker digest admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_seed; p.gateway_peer_leaf:=decode(repeat('ee',32),'hex');
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'wrong gateway admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
-- Canonical variants are constructed by the owner from the existing valid input.
CREATE TEMP TABLE observer_variants(name text, raw bytea, proof contour.verified_observer_claim);
GRANT INSERT ON observer_variants TO contour_owner;
SET ROLE contour_owner;
INSERT INTO observer_variants
 SELECT 'wrong-record',convert_to(contour.causal_json_canonical(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,record_id}',to_jsonb('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::text))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'wrong-runtime',convert_to(contour.causal_json_canonical(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,producer_runtime_id}',to_jsonb('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'::text))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'wrong-collector',convert_to(contour.causal_json_canonical(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,collector_id}',to_jsonb('cccccccc-cccc-cccc-cccc-cccccccccccc'::text))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'wrong-tenant',convert_to(contour.causal_json_canonical(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,tenant_id}',to_jsonb('dddddddd-dddd-dddd-dddd-dddddddddddd'::text))),'UTF8'),proof FROM observer_seed;
RESET ROLE;
GRANT SELECT ON observer_variants TO contour_causal_observer_writer;
SET ROLE contour_causal_observer_writer;
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT * FROM observer_variants LOOP
  BEGIN PERFORM contour.accept_causal_observer(c.raw,c.proof); RAISE EXCEPTION 'invalid observer accepted: %',c.name;
  EXCEPTION WHEN check_violation OR insufficient_privilege OR unique_violation THEN NULL; END;
 END LOOP;
END $$;
RESET ROLE;
-- New, correctly linked backend delivery cannot consume quota or write a partial row when full.
CREATE TEMP TABLE observer_retry(raw bytea, proof contour.verified_observer_claim);
GRANT INSERT,SELECT ON observer_retry TO contour_owner;
GRANT SELECT ON observer_retry TO contour_causal_observer_writer;
SET ROLE contour_owner;
INSERT INTO observer_retry
 SELECT convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,
 '{binding,delivery_handle}',to_jsonb(repeat('e',32))),'{binding,retry_of}',to_jsonb((convert_from(raw,'UTF8')::jsonb)->'binding'->>'delivery_handle'))),'UTF8'),proof FROM observer_seed;
UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id=(SELECT ((proof).producer_claim).tenant_id FROM observer_seed);
RESET ROLE;
SET ROLE contour_causal_observer_writer;
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_retry;
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'full quota admitted retry'; EXCEPTION WHEN program_limit_exceeded THEN NULL; END;
END $$;
RESET ROLE;
SET ROLE contour_owner;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM contour.causal_observer_inbox WHERE delivery_handle=repeat('e',32)) THEN RAISE EXCEPTION 'quota failure wrote observer'; END IF;
 IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT ((proof).producer_claim).tenant_id FROM observer_seed))<>1073741824 THEN RAISE EXCEPTION 'quota failure changed usage'; END IF;
END $$;
UPDATE contour.origin_logical_usage SET used_bytes=(SELECT used_bytes FROM observer_usage) WHERE tenant_id=(SELECT ((proof).producer_claim).tenant_id FROM observer_seed);
RESET ROLE;
-- After restoring capacity the same linked retry can be stored exactly once.
SET ROLE contour_causal_observer_writer;
INSERT INTO observer_receipts SELECT contour.accept_causal_observer(raw,proof) FROM observer_retry;
DO $$ DECLARE r bytea; BEGIN
 SELECT contour.accept_causal_observer(raw,proof) INTO STRICT r FROM observer_retry;
 IF NOT EXISTS(SELECT 1 FROM observer_receipts WHERE receipt=r) THEN RAISE EXCEPTION 'linked retry changed receipt'; END IF;
END $$;
RESET ROLE;
-- Materialize canonical adversarial delivery graphs under owner; no DB source/proof is fabricated.
CREATE TEMP TABLE observer_graph_cases(name text, raw bytea, proof contour.verified_observer_claim);
GRANT INSERT ON observer_graph_cases TO contour_owner;
GRANT SELECT ON observer_graph_cases TO contour_causal_observer_writer;
SET ROLE contour_owner;
INSERT INTO observer_graph_cases
 SELECT 'second-first',convert_to(contour.causal_json_canonical(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,delivery_handle}',to_jsonb(repeat('b',32)))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'self-loop',convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,delivery_handle}',to_jsonb(repeat('c',32))),'{binding,retry_of}',to_jsonb(repeat('c',32)))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'pending-parent',convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,delivery_handle}',to_jsonb(repeat('d',32))),'{binding,retry_of}',to_jsonb(repeat('f',32)))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'fork-a1',convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,delivery_handle}',to_jsonb(repeat('4',32))),'{binding,retry_of}',to_jsonb(repeat('a',32)))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'fork-a2',convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,delivery_handle}',to_jsonb(repeat('5',32))),'{binding,retry_of}',to_jsonb(repeat('a',32)))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'fork-b1',convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,delivery_handle}',to_jsonb(repeat('7',32))),'{binding,retry_of}',to_jsonb(repeat('6',32)))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'fork-b2',convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,delivery_handle}',to_jsonb(repeat('8',32))),'{binding,retry_of}',to_jsonb(repeat('6',32)))),'UTF8'),proof FROM observer_seed
 UNION ALL SELECT 'close-cycle',convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,'{binding,delivery_handle}',to_jsonb(repeat('f',32))),'{binding,retry_of}',to_jsonb(repeat('d',32)))),'UTF8'),proof FROM observer_seed;
RESET ROLE;
SET ROLE contour_causal_observer_writer;
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_graph_cases WHERE name='second-first';
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'second first delivery admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_graph_cases WHERE name='self-loop';
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'self-loop admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
-- A missing predecessor is stored unresolved; its later cycle-forming predecessor is refused.
INSERT INTO observer_receipts SELECT contour.accept_causal_observer(raw,proof) FROM observer_graph_cases WHERE name='pending-parent';
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_graph_cases WHERE name='close-cycle';
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'retry cycle admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
-- Each missing predecessor may have only one successor, in either arrival order.
SET ROLE contour_causal_observer_writer;
INSERT INTO observer_receipts SELECT contour.accept_causal_observer(raw,proof) FROM observer_graph_cases WHERE name='fork-a1';
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_graph_cases WHERE name='fork-a2';
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'missing-parent fork accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
INSERT INTO observer_receipts SELECT contour.accept_causal_observer(raw,proof) FROM observer_graph_cases WHERE name='fork-b2';
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_graph_cases WHERE name='fork-b1';
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'reverse missing-parent fork accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
RESET ROLE;
-- Build two detached 31-delivery fragments. A late joining predecessor creates
-- a 63-delivery chain; one successor reaches 64 and the next must roll back.
-- This section uses psql's gexec and requires ON_ERROR_STOP and autocommit.
CREATE TEMP TABLE observer_chain_cases(seq integer, raw bytea, proof contour.verified_observer_claim);
GRANT INSERT ON observer_chain_cases TO contour_owner;
GRANT SELECT ON observer_chain_cases TO contour_causal_observer_writer;
SET ROLE contour_owner;
INSERT INTO observer_chain_cases
 SELECT n,convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(seed.raw,'UTF8')::jsonb,
 '{binding,delivery_handle}',to_jsonb(lpad(to_hex(1000+n),32,'0'))),'{binding,retry_of}',to_jsonb(lpad(to_hex(999+n),32,'0')))),'UTF8'),seed.proof
 FROM observer_seed seed CROSS JOIN generate_series(1,31) n
 UNION ALL
 SELECT 31+n,convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(seed.raw,'UTF8')::jsonb,
 '{binding,delivery_handle}',to_jsonb(lpad(to_hex(2000+n),32,'0'))),'{binding,retry_of}',to_jsonb(lpad(to_hex(CASE WHEN n=1 THEN 3000 ELSE 1999+n END),32,'0')))),'UTF8'),seed.proof
 FROM observer_seed seed CROSS JOIN generate_series(1,31) n
 UNION ALL
 SELECT 63,convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,
 '{binding,delivery_handle}',to_jsonb(lpad(to_hex(3000),32,'0'))),'{binding,retry_of}',to_jsonb(lpad(to_hex(1031),32,'0')))),'UTF8'),proof FROM observer_seed
 UNION ALL
 SELECT 64,convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,
 '{binding,delivery_handle}',to_jsonb(lpad(to_hex(3001),32,'0'))),'{binding,retry_of}',to_jsonb(lpad(to_hex(2031),32,'0')))),'UTF8'),proof FROM observer_seed
 UNION ALL
 SELECT 65,convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,
 '{binding,delivery_handle}',to_jsonb(lpad(to_hex(3002),32,'0'))),'{binding,retry_of}',to_jsonb(lpad(to_hex(3001),32,'0')))),'UTF8'),proof FROM observer_seed;
RESET ROLE;
SET ROLE contour_causal_observer_writer;
SELECT format('INSERT INTO observer_receipts SELECT contour.accept_causal_observer(raw,proof) FROM observer_chain_cases WHERE seq=%s;',seq) FROM observer_chain_cases WHERE seq<=64 ORDER BY seq \gexec
RESET ROLE;
CREATE TEMP TABLE observer_chain_usage AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT ((proof).producer_claim).tenant_id FROM observer_seed);
GRANT SELECT ON observer_chain_usage TO contour_owner;
SET ROLE contour_causal_observer_writer;
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_chain_cases WHERE seq=65;
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION '65th delivery admitted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
SET ROLE contour_owner;
DO $$ BEGIN
 IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT ((proof).producer_claim).tenant_id FROM observer_seed)) IS DISTINCT FROM (SELECT used_bytes FROM observer_chain_usage)
 OR EXISTS(SELECT 1 FROM contour.causal_observer_inbox WHERE delivery_handle=lpad(to_hex(3002),32,'0')) THEN RAISE EXCEPTION 'chain refusal changed quota or wrote fact'; END IF;
END $$;
RESET ROLE;
-- Two 32-delivery fragments cannot be joined by a late parent (65 total).
SET ROLE contour_owner;
INSERT INTO observer_chain_cases
 SELECT 100+n,convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(seed.raw,'UTF8')::jsonb,
 '{binding,delivery_handle}',to_jsonb(lpad(to_hex(4000+n),32,'0'))),'{binding,retry_of}',to_jsonb(lpad(to_hex(3999+n),32,'0')))),'UTF8'),seed.proof
 FROM observer_seed seed CROSS JOIN generate_series(1,32) n
 UNION ALL
 SELECT 132+n,convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(seed.raw,'UTF8')::jsonb,
 '{binding,delivery_handle}',to_jsonb(lpad(to_hex(5000+n),32,'0'))),'{binding,retry_of}',to_jsonb(lpad(to_hex(CASE WHEN n=1 THEN 6000 ELSE 4999+n END),32,'0')))),'UTF8'),seed.proof
 FROM observer_seed seed CROSS JOIN generate_series(1,32) n
 UNION ALL
 SELECT 165,convert_to(contour.causal_json_canonical(jsonb_set(jsonb_set(convert_from(raw,'UTF8')::jsonb,
 '{binding,delivery_handle}',to_jsonb(lpad(to_hex(6000),32,'0'))),'{binding,retry_of}',to_jsonb(lpad(to_hex(4032),32,'0')))),'UTF8'),proof FROM observer_seed;
RESET ROLE;
SET ROLE contour_causal_observer_writer;
SELECT format('INSERT INTO observer_receipts SELECT contour.accept_causal_observer(raw,proof) FROM observer_chain_cases WHERE seq=%s;',seq) FROM observer_chain_cases WHERE seq BETWEEN 101 AND 164 ORDER BY seq \gexec
DO $$ DECLARE r bytea; p contour.verified_observer_claim; BEGIN
 SELECT raw,proof INTO STRICT r,p FROM observer_chain_cases WHERE seq=165;
 BEGIN PERFORM contour.accept_causal_observer(r,p); RAISE EXCEPTION 'late parent joined oversized fragments'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
