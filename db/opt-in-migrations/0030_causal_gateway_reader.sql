-- Current gateway data is a point observation, not peer or deployment proof.
-- Requires migrations 1 through 29; never installed in the default schema.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security') <> 'on' OR current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,29))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted gateway reader migration required' USING ERRCODE='42501'; END IF;
END $$;
CREATE ROLE contour_causal_gateway_reader NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET LOCAL ROLE contour_owner;
CREATE FUNCTION contour.current_causal_gateway(t uuid, gateway uuid, gen text, backend_leaf bytea)
RETURNS TABLE(metadata bytea, metadata_sha256 bytea, issued_at timestamptz, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old contour.causal_gateway_enrollments; checked contour.causal_gateway_enrollments;
 leaf bytea; floor_at timestamptz; initial_at timestamptz; final_at timestamptz;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 IF gateway IS NULL OR gen IS NULL OR gen COLLATE "C" !~ '^[0-9a-f]{32}$' OR gen=repeat('0',32)
 OR backend_leaf IS NULL OR octet_length(backend_leaf)<>32
 THEN RAISE EXCEPTION 'gateway unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_gateway_enrollments e WHERE (e.tenant_id,e.gateway_id,e.generation)=(t,gateway,gen);
 IF NOT FOUND THEN RAISE EXCEPTION 'gateway unavailable' USING ERRCODE='23514'; END IF;
 FOR leaf IN SELECT DISTINCT ON (k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM
  (VALUES((old.claim).observer_leaf),((old.claim).backend_client_leaf)) leaves(v)) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 PERFORM contour.lock_origin_collector(t,(old.claim).collector_id);
 PERFORM contour.ensure_origin_tenant_state(t);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=t FOR UPDATE;
 PERFORM 1 FROM contour.origin_logical_usage WHERE tenant_id=t AND used_bytes>=1024 FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'gateway unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO checked FROM contour.causal_gateway_enrollments e WHERE (e.tenant_id,e.gateway_id,e.generation)=(t,gateway,gen);
 initial_at:=clock_timestamp();
 IF checked IS DISTINCT FROM old OR initial_at IS NULL OR NOT isfinite(initial_at)
 OR initial_at<timestamptz '0001-01-01 00:00:00+00' OR initial_at>=timestamptz '10000-01-01 00:00:00+00'
 OR (floor_at IS NOT NULL AND initial_at<floor_at) OR initial_at<old.issued_at OR initial_at>=old.expires_at
 OR (old.claim).tenant_id IS DISTINCT FROM t OR (old.claim).gateway_id IS DISTINCT FROM gateway
 OR (old.claim).backend_client_leaf IS DISTINCT FROM backend_leaf
 OR NOT contour.gateway_claim_current(old.claim,initial_at)
 OR old.metadata IS DISTINCT FROM contour.gateway_enrollment_metadata(old.claim,old.generation,old.issued_at,old.expires_at)
 OR EXISTS(SELECT 1 FROM contour.causal_gateway_enrollments e WHERE e.tenant_id=t AND e.gateway_id=gateway AND e.generation<>gen AND e.issued_at>=old.issued_at)
 OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals z WHERE (z.tenant_id,z.gateway_id,z.generation)=(t,gateway,gen))
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations l WHERE l.leaf_sha256=(old.claim).observer_leaf AND l.leaf_class='gateway_observer')
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations l WHERE l.leaf_sha256=(old.claim).backend_client_leaf AND l.leaf_class='gateway_backend')
 OR NOT EXISTS(SELECT 1 FROM contour.causal_gateway_terminal_reservations r WHERE (r.tenant_id,r.gateway_id,r.generation,r.charged_bytes)=(t,gateway,gen,1024))
 THEN RAISE EXCEPTION 'gateway unavailable' USING ERRCODE='23514'; END IF;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR final_at>=old.expires_at OR NOT contour.gateway_claim_current(old.claim,final_at)
 THEN RAISE EXCEPTION 'gateway unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=final_at WHERE tenant_id=t;
 RETURN QUERY SELECT old.metadata,sha256(old.metadata),old.issued_at,old.expires_at;
END $$;
REVOKE ALL ON FUNCTION contour.current_causal_gateway(uuid,uuid,text,bytea) FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer,contour_causal_evidence_provisioner,contour_causal_receiver_reader;
GRANT USAGE ON SCHEMA contour TO contour_causal_gateway_reader;
GRANT EXECUTE ON FUNCTION contour.current_causal_gateway(uuid,uuid,text,bytea) TO contour_causal_gateway_reader;
INSERT INTO contour.schema_migrations(version) VALUES(30);
COMMIT;
