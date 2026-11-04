-- Internal data-only inbox. No row proves transport, producer identity or causality.
-- Retention/pinning/cleanup is deliberately deferred; all evidence is retained and
-- admission stops at the shared logical quota. A caller must await COMMIT.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security') <> 'on' OR current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,19))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted inbox migration required' USING ERRCODE='42501'; END IF;
END $$;
CREATE ROLE contour_causal_inbox_writer NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET LOCAL ROLE contour_owner;
CREATE TABLE contour.causal_inbox_batches (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, session_epoch numeric NOT NULL, batch_id uuid NOT NULL,
 canonical_batch bytea NOT NULL CHECK (octet_length(canonical_batch) BETWEEN 1 AND 1048576),
 batch_digest bytea NOT NULL CHECK (octet_length(batch_digest)=32), event_count integer NOT NULL CHECK (event_count BETWEEN 1 AND 500),
 receipt_id uuid NOT NULL, accepted_at timestamptz NOT NULL CHECK (isfinite(accepted_at)), receipt_digest bytea NOT NULL CHECK (octet_length(receipt_digest)=32),
 PRIMARY KEY(tenant_id,runtime_id,session_epoch,batch_id), UNIQUE(receipt_id),
 FOREIGN KEY(tenant_id,runtime_id,session_epoch) REFERENCES contour.causal_sessions
);
CREATE TABLE contour.causal_inbox_events (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, session_epoch numeric NOT NULL, batch_id uuid NOT NULL,
 seq numeric NOT NULL, event_id text NOT NULL, kind text NOT NULL, root text, activity text, parent text, attempt text,
 marker_digest text, first_missing_seq numeric, last_missing_seq numeric, reason text, event_digest bytea NOT NULL,
 PRIMARY KEY(tenant_id,runtime_id,session_epoch,seq), UNIQUE(tenant_id,runtime_id,session_epoch,event_id),
 FOREIGN KEY(tenant_id,runtime_id,session_epoch,batch_id) REFERENCES contour.causal_inbox_batches
);
CREATE INDEX causal_inbox_activity ON contour.causal_inbox_events(tenant_id,runtime_id,session_epoch,activity);
CREATE INDEX causal_inbox_root ON contour.causal_inbox_events(tenant_id,runtime_id,session_epoch,root);
CREATE INDEX causal_inbox_attempt ON contour.causal_inbox_events(tenant_id,runtime_id,session_epoch,attempt);
CREATE INDEX causal_inbox_batch_events ON contour.causal_inbox_events(tenant_id,runtime_id,session_epoch,batch_id);
ALTER TABLE contour.causal_inbox_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.causal_inbox_batches FORCE ROW LEVEL SECURITY;
ALTER TABLE contour.causal_inbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.causal_inbox_events FORCE ROW LEVEL SECURITY;
CREATE POLICY causal_inbox_batches_owner ON contour.causal_inbox_batches TO contour_owner USING(tenant_id=contour.tenant_context()) WITH CHECK(tenant_id=contour.tenant_context());
CREATE POLICY causal_inbox_events_owner ON contour.causal_inbox_events TO contour_owner USING(tenant_id=contour.tenant_context()) WITH CHECK(tenant_id=contour.tenant_context());
REVOKE ALL ON contour.causal_inbox_batches,contour.causal_inbox_events FROM PUBLIC;
CREATE TRIGGER causal_inbox_batch_immutable BEFORE UPDATE OR DELETE ON contour.causal_inbox_batches FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER causal_inbox_event_immutable BEFORE UPDATE OR DELETE ON contour.causal_inbox_events FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER causal_inbox_batch_no_truncate BEFORE TRUNCATE ON contour.causal_inbox_batches FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER causal_inbox_event_no_truncate BEFORE TRUNCATE ON contour.causal_inbox_events FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();
-- JSONB is used only as a parser. Re-encoding and byte comparison rejects duplicate
-- keys, escaped aliases, whitespace, alternate numbers and ordering malleability.
CREATE FUNCTION contour.causal_json_canonical(j jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE typ text:=jsonb_typeof(j); result text;
BEGIN
 IF typ='object' THEN SELECT '{'||coalesce(string_agg(to_jsonb(key)::text||':'||contour.causal_json_canonical(value),',' ORDER BY key COLLATE "C"),'')||'}' INTO result FROM jsonb_each(j);
 ELSIF typ='array' THEN SELECT '['||coalesce(string_agg(contour.causal_json_canonical(value),',' ORDER BY ord),'')||']' INTO result FROM jsonb_array_elements(j) WITH ORDINALITY a(value,ord);
 ELSE result:=j::text; END IF;
 RETURN result;
END $$;
CREATE FUNCTION contour.causal_u64(j jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_typeof(j)='number' AND (j::text COLLATE "C") ~ '^(0|[1-9][0-9]{0,19})$' AND (j::text)::numeric<=18446744073709551615,false)
$$;
CREATE FUNCTION contour.causal_hex(j jsonb,n integer) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_typeof(j)='string' AND length(j#>>'{}')=n AND ((j#>>'{}') COLLATE "C") !~ '[^0-9a-f]',false)
$$;
CREATE FUNCTION contour.causal_parse(raw bytea) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE j jsonb; e jsonb; prev numeric:=0; seq numeric; ids text[]:='{}'; roots text[]:='{}'; a jsonb; b jsonb; k text;
BEGIN
 IF octet_length(raw) NOT BETWEEN 1 AND 1048576 THEN RAISE EXCEPTION 'invalid causal batch size' USING ERRCODE='23514'; END IF;
 j:=convert_from(raw,'UTF8')::jsonb;
 IF convert_to(contour.causal_json_canonical(j),'UTF8')<>raw OR jsonb_typeof(j)<>'object'
 OR j-ARRAY['batch_id','events','first_seq','last_seq','runtime_id','session_epoch','tenant_id','wire_version'] <> '{}'::jsonb
 OR (SELECT count(*) FROM jsonb_object_keys(j))<>8 OR (j->'wire_version')::text IS DISTINCT FROM '1'
 OR NOT contour.causal_u64(j->'session_epoch') OR (j->>'session_epoch')::numeric=0
 OR NOT contour.causal_u64(j->'first_seq') OR NOT contour.causal_u64(j->'last_seq')
 OR jsonb_typeof(j->'events')<>'array' OR jsonb_array_length(j->'events') NOT BETWEEN 1 AND 500
 THEN RAISE EXCEPTION 'invalid causal envelope' USING ERRCODE='23514'; END IF;
 FOREACH k IN ARRAY ARRAY['batch_id','tenant_id','runtime_id'] LOOP
  IF jsonb_typeof(j->k)<>'string' OR length(j->>k)<>36 OR (j->>k COLLATE "C") !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'invalid causal uuid' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOR e IN SELECT value FROM jsonb_array_elements(j->'events') LOOP
  k:=e->>'kind';
  IF jsonb_typeof(e)<>'object' OR NOT contour.causal_hex(e->'event_id',32) OR NOT contour.causal_u64(e->'seq') THEN RAISE EXCEPTION 'invalid causal event' USING ERRCODE='23514'; END IF;
  seq:=(e->>'seq')::numeric;
  IF seq<=prev OR e->>'event_id'=ANY(ids) THEN RAISE EXCEPTION 'duplicate causal event' USING ERRCODE='23514'; END IF;
  prev:=seq; ids:=array_append(ids,e->>'event_id');
  IF k='root' THEN
   IF e-ARRAY['kind','event_id','seq','root']<>'{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(e))<>4 OR NOT contour.causal_hex(e->'root',32) OR e->>'root'=ANY(roots) THEN RAISE EXCEPTION 'invalid root' USING ERRCODE='23514'; END IF;
   roots:=array_append(roots,e->>'root');
  ELSIF k='delivery' THEN
   IF e-ARRAY['kind','event_id','seq','root','activity','parent']<>'{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(e))<>6 OR NOT contour.causal_hex(e->'root',32) OR NOT contour.causal_hex(e->'activity',32) OR NOT contour.causal_hex(e->'parent',32) OR e->>'activity'=e->>'parent' THEN RAISE EXCEPTION 'invalid delivery' USING ERRCODE='23514'; END IF;
  ELSIF k='attempt' THEN
   IF e-ARRAY['kind','event_id','seq','root','activity','attempt','marker_digest']<>'{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(e))<>7 OR NOT contour.causal_hex(e->'root',32) OR NOT contour.causal_hex(e->'activity',32) OR NOT contour.causal_hex(e->'attempt',32) OR NOT contour.causal_hex(e->'marker_digest',64) THEN RAISE EXCEPTION 'invalid attempt' USING ERRCODE='23514'; END IF;
  ELSIF k='loss' THEN
   IF e-ARRAY['kind','event_id','seq','first_missing_seq','last_missing_seq','reason']<>'{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(e))<>6 OR NOT contour.causal_u64(e->'first_missing_seq') OR NOT contour.causal_u64(e->'last_missing_seq') OR (e->>'first_missing_seq')::numeric=0 OR (e->>'first_missing_seq')::numeric>(e->>'last_missing_seq')::numeric OR (e->>'last_missing_seq')::numeric>=seq OR coalesce(e->>'reason','') NOT IN ('overflow','expired','canceled','guard_invalidated','dispatch_missing','restart','unsupported') THEN RAISE EXCEPTION 'invalid loss' USING ERRCODE='23514'; END IF;
  ELSE RAISE EXCEPTION 'unknown causal event' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF (j->'events'->0->>'seq')::numeric<>(j->>'first_seq')::numeric OR prev<>(j->>'last_seq')::numeric THEN RAISE EXCEPTION 'invalid causal range' USING ERRCODE='23514'; END IF;
 FOR a IN SELECT value FROM jsonb_array_elements(j->'events') LOOP
  FOR b IN SELECT value FROM jsonb_array_elements(j->'events') LOOP
   IF (a->>'kind'='loss' AND (b->>'seq')::numeric BETWEEN (a->>'first_missing_seq')::numeric AND (a->>'last_missing_seq')::numeric)
   OR (a->>'kind'='root' AND b->>'kind'='delivery' AND a->>'root'=b->>'activity')
   OR (a->>'kind'='root' AND b->>'kind'='attempt' AND a->>'root'=b->>'activity' AND b->>'root'<>b->>'activity')
   OR (a->>'kind' IN ('delivery','attempt') AND b->>'kind' IN ('delivery','attempt') AND a->>'activity'=b->>'activity' AND a->>'root'<>b->>'root')
   OR (a->>'kind'='delivery' AND b->>'kind'='delivery' AND a->>'activity'=b->>'activity' AND a->>'parent'<>b->>'parent')
   OR (a->>'kind'='attempt' AND b->>'kind'='attempt' AND a->>'attempt'=b->>'attempt' AND (a->>'root',a->>'activity',a->>'marker_digest')<>(b->>'root',b->>'activity',b->>'marker_digest'))
   THEN RAISE EXCEPTION 'contradictory causal batch' USING ERRCODE='23514'; END IF;
  END LOOP;
 END LOOP;
 RETURN j;
END $$;
CREATE FUNCTION contour.causal_decoded_events(j jsonb) RETURNS TABLE(seq numeric,event_id text,kind text,root text,activity text,parent text,attempt text,marker_digest text,first_missing_seq numeric,last_missing_seq numeric,reason text,event_digest bytea)
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT (e->>'seq')::numeric,e->>'event_id',e->>'kind',e->>'root',e->>'activity',e->>'parent',e->>'attempt',e->>'marker_digest',
 (e->>'first_missing_seq')::numeric,(e->>'last_missing_seq')::numeric,e->>'reason',
 sha256(convert_to(E'apicontour/causal-event/1\n'||contour.causal_json_canonical(e),'UTF8'))
 FROM jsonb_array_elements(j->'events') x(e)
$$;
CREATE FUNCTION contour.causal_receipt_digest(t uuid, runtime uuid, ep numeric, bid uuid, receipt uuid, accepted timestamptz, batch_digest bytea, event_count integer) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT sha256(convert_to(E'apicontour/causal-receipt/1\n','UTF8')||uuid_send(t)||uuid_send(runtime)||convert_to(trunc(ep)::text,'UTF8')||decode('00','hex')||uuid_send(bid)||uuid_send(receipt)||timestamptz_send(accepted)||batch_digest||int4send(event_count))
$$;
CREATE FUNCTION contour.accept_causal_batch(t uuid, runtime uuid, ep numeric, peer_leaf bytea, verified_grant_digest bytea, canonical_batch bytea)
RETURNS TABLE(receipt_id uuid,accepted_at timestamptz,duplicate boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding contour.causal_runtime_bindings; s contour.causal_sessions; old contour.causal_inbox_batches; j jsonb; stored jsonb; bid uuid; now_at timestamptz; used bigint; n integer;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 SELECT * INTO binding FROM contour.causal_runtime_bindings b WHERE b.tenant_id=t AND b.runtime_id=runtime;
 IF NOT FOUND THEN RAISE EXCEPTION 'session unavailable' USING ERRCODE='23514'; END IF;
 PERFORM contour.lock_origin_credential(binding.export_leaf_sha256);
 PERFORM contour.lock_origin_collector(t,binding.collector_id);
 SELECT * INTO s FROM contour.causal_sessions x WHERE x.tenant_id=t AND x.runtime_id=runtime AND x.epoch=ep;
 now_at:=clock_timestamp();
 IF NOT FOUND OR peer_leaf IS DISTINCT FROM binding.export_leaf_sha256 OR peer_leaf IS DISTINCT FROM (s.claim).export_leaf OR verified_grant_digest IS DISTINCT FROM (s.claim).grant_digest OR NOT contour.causal_session_locked(s.claim,ep,now_at)
 THEN RAISE EXCEPTION 'session unavailable' USING ERRCODE='23514'; END IF;
 j:=contour.causal_parse(canonical_batch);
 IF (j->>'tenant_id')::uuid IS DISTINCT FROM t OR (j->>'runtime_id')::uuid IS DISTINCT FROM runtime OR (j->>'session_epoch')::numeric IS DISTINCT FROM ep OR octet_length(canonical_batch)>(s.claim).max_batch_bytes OR jsonb_array_length(j->'events')>(s.claim).max_batch_events
 THEN RAISE EXCEPTION 'batch scope or limit mismatch' USING ERRCODE='23514'; END IF;
 bid:=(j->>'batch_id')::uuid;
 SELECT * INTO old FROM contour.causal_inbox_batches x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.batch_id)=(t,runtime,ep,bid);
 IF FOUND THEN
  -- Only stored-byte data/semantic failures become integrity failures. Do not
  -- catch operational errors, cancellations, or malformed incoming requests.
  BEGIN
   stored:=contour.causal_parse(old.canonical_batch);
  EXCEPTION WHEN data_exception OR check_violation THEN
   RAISE EXCEPTION 'stored causal batch corrupted' USING ERRCODE='23514';
  END;
  IF old.batch_digest IS DISTINCT FROM sha256(convert_to(E'apicontour/causal-events/1\n','UTF8')||old.canonical_batch)
  OR (stored->>'tenant_id')::uuid IS DISTINCT FROM t OR (stored->>'runtime_id')::uuid IS DISTINCT FROM runtime OR (stored->>'session_epoch')::numeric IS DISTINCT FROM ep OR (stored->>'batch_id')::uuid IS DISTINCT FROM bid
  OR old.event_count IS DISTINCT FROM jsonb_array_length(stored->'events') OR old.receipt_id IS NULL OR old.accepted_at IS NULL OR NOT isfinite(old.accepted_at) OR old.receipt_digest IS DISTINCT FROM contour.causal_receipt_digest(t,runtime,ep,bid,old.receipt_id,old.accepted_at,old.batch_digest,old.event_count)
  OR EXISTS (SELECT 1 FROM ((SELECT * FROM contour.causal_decoded_events(stored) EXCEPT SELECT x.seq,x.event_id,x.kind,x.root,x.activity,x.parent,x.attempt,x.marker_digest,x.first_missing_seq,x.last_missing_seq,x.reason,x.event_digest FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.batch_id)=(t,runtime,ep,bid)) UNION ALL
  (SELECT x.seq,x.event_id,x.kind,x.root,x.activity,x.parent,x.attempt,x.marker_digest,x.first_missing_seq,x.last_missing_seq,x.reason,x.event_digest FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.batch_id)=(t,runtime,ep,bid) EXCEPT SELECT * FROM contour.causal_decoded_events(stored))) difference)
  THEN RAISE EXCEPTION 'stored causal batch corrupted' USING ERRCODE='23514'; END IF;
  IF old.canonical_batch IS DISTINCT FROM canonical_batch THEN RAISE EXCEPTION 'causal batch conflict' USING ERRCODE='23505'; END IF;
  IF NOT contour.causal_session_locked(s.claim,ep,now_at) THEN RAISE EXCEPTION 'session unavailable at final lease check' USING ERRCODE='23514'; END IF;
  RETURN QUERY SELECT old.receipt_id,old.accepted_at,true; RETURN;
 END IF;
 -- A session admits at most 4,096 events in total. This is a work bound,
 -- independent of the 1 GiB logical quota; it can stop admission much earlier.
 -- Session renewal does not transfer this history or establish continuity.
 -- Q serializes this namespace. The ordered, bounded read uses the primary
 -- (tenant,runtime,epoch,seq) key; it never ignores an admitted history row.
 SELECT count(*) INTO n FROM (SELECT x.seq FROM contour.causal_inbox_events x
  WHERE (x.tenant_id,x.runtime_id,x.session_epoch)=(t,runtime,ep) ORDER BY x.seq LIMIT 4097) bounded;
 IF n+jsonb_array_length(j->'events')>4096 THEN
  RAISE EXCEPTION 'causal session history limit exhausted' USING ERRCODE='54000',CONSTRAINT='causal_session_history_limit';
 END IF;
 -- Materialize the bounded, indexed history once. The worst case is 500 x
 -- 4,096 fact comparisons, including both LOSS arrival orders; no DAG search.
 IF EXISTS (WITH history AS MATERIALIZED (
  SELECT x.* FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch)=(t,runtime,ep)
  ORDER BY x.seq LIMIT 4096), incoming AS MATERIALIZED (
  SELECT * FROM contour.causal_decoded_events(j))
  SELECT 1 FROM history x CROSS JOIN incoming e WHERE
   (x.seq=e.seq OR x.event_id=e.event_id OR
    (x.kind='loss' AND e.seq BETWEEN x.first_missing_seq AND x.last_missing_seq) OR
    (e.kind='loss' AND x.seq BETWEEN e.first_missing_seq AND e.last_missing_seq) OR
    (x.kind='root' AND e.kind='root' AND x.root=e.root) OR
    (x.kind='root' AND e.kind='delivery' AND x.root=e.activity) OR
    (e.kind='root' AND x.kind='delivery' AND e.root=x.activity) OR
    (x.kind='root' AND e.kind='attempt' AND x.root=e.activity AND e.root<>e.activity) OR
    (e.kind='root' AND x.kind='attempt' AND e.root=x.activity AND x.root<>x.activity) OR
    (x.kind IN ('delivery','attempt') AND e.kind IN ('delivery','attempt') AND x.activity=e.activity AND x.root<>e.root) OR
    (x.kind='delivery' AND e.kind='delivery' AND x.activity=e.activity AND x.parent<>e.parent) OR
    (x.kind='attempt' AND e.kind='attempt' AND x.attempt=e.attempt AND (x.root,x.activity,x.marker_digest)<>(e.root,e.activity,e.marker_digest))))
 THEN RAISE EXCEPTION 'causal fact conflict' USING ERRCODE='23505'; END IF;
 INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES(t,0) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT x.used_bytes INTO STRICT used FROM contour.origin_logical_usage x WHERE x.tenant_id=t FOR UPDATE;
 IF octet_length(canonical_batch)>1073741824-used THEN RAISE EXCEPTION 'origin logical quota exhausted' USING ERRCODE='54000',CONSTRAINT='origin_logical_quota_exhausted'; END IF;
 old.receipt_id:=gen_random_uuid(); old.accepted_at:=clock_timestamp();
 old.batch_digest:=sha256(convert_to(E'apicontour/causal-events/1\n','UTF8')||canonical_batch);
 old.event_count:=jsonb_array_length(j->'events');
 INSERT INTO contour.causal_inbox_batches(tenant_id,runtime_id,session_epoch,batch_id,canonical_batch,batch_digest,event_count,receipt_id,accepted_at,receipt_digest)
 VALUES(t,runtime,ep,bid,canonical_batch,old.batch_digest,old.event_count,old.receipt_id,old.accepted_at,contour.causal_receipt_digest(t,runtime,ep,bid,old.receipt_id,old.accepted_at,old.batch_digest,old.event_count)) RETURNING * INTO old;
 INSERT INTO contour.causal_inbox_events SELECT t,runtime,ep,bid,x.* FROM contour.causal_decoded_events(j) x;
 UPDATE contour.origin_logical_usage SET used_bytes=used+octet_length(canonical_batch) WHERE tenant_id=t;
 IF NOT contour.causal_session_locked(s.claim,ep,now_at) THEN RAISE EXCEPTION 'session unavailable at final lease check' USING ERRCODE='23514'; END IF;
 RETURN QUERY SELECT old.receipt_id,old.accepted_at,false;
END $$;
REVOKE ALL ON FUNCTION contour.causal_json_canonical(jsonb),contour.causal_u64(jsonb),contour.causal_hex(jsonb,integer),contour.causal_parse(bytea),contour.causal_decoded_events(jsonb),contour.causal_receipt_digest(uuid,uuid,numeric,uuid,uuid,timestamptz,bytea,integer),contour.accept_causal_batch(uuid,uuid,numeric,bytea,bytea,bytea) FROM PUBLIC;
GRANT USAGE ON SCHEMA contour TO contour_causal_inbox_writer;
GRANT EXECUTE ON FUNCTION contour.accept_causal_batch(uuid,uuid,numeric,bytea,bytea,bytea) TO contour_causal_inbox_writer;
INSERT INTO contour.schema_migrations(version) VALUES(20);
COMMIT;
