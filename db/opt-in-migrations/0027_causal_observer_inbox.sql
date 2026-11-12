-- Trusted issuer assertions only: SQL does not verify mTLS or marker signatures.
-- This inbox stores unresolved observer evidence; it does not create edges.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security')<>'on' OR current_setting('transaction_isolation')<>'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,26))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted observer migration required' USING ERRCODE='42501'; END IF;
END $$;
CREATE ROLE contour_causal_observer_writer NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET LOCAL ROLE contour_owner;
CREATE TYPE contour.verified_observer_claim AS (
 gateway_peer_leaf bytea, producer_claim contour.causal_session_claim, producer_epoch numeric,
 marker_public bytea, marker_generation bytea, marker_root text, marker_activity text,
 marker_attempt text, marker_wire_digest bytea
);
CREATE TABLE contour.causal_observer_epoch_reservations (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, session_epoch numeric NOT NULL,
 charged_bytes integer NOT NULL CHECK(charged_bytes=1024),
 PRIMARY KEY(tenant_id,runtime_id,session_epoch), FOREIGN KEY(tenant_id,runtime_id,session_epoch) REFERENCES contour.causal_sessions
);
CREATE TABLE contour.causal_observer_attempt_reservations (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, session_epoch numeric NOT NULL, attempt text NOT NULL,
 gateway_id uuid NOT NULL, gateway_generation text NOT NULL, collector_id uuid NOT NULL, batch_id uuid NOT NULL, record_id uuid NOT NULL, marker_digest text NOT NULL, marker_root text NOT NULL, marker_activity text NOT NULL,
 metadata bytea NOT NULL, charged_bytes integer NOT NULL CHECK(charged_bytes=octet_length(metadata)+256),
 PRIMARY KEY(tenant_id,runtime_id,session_epoch,attempt)
);
-- Fact and receipt share one row; each has its own 256-byte logical metadata charge.
CREATE TABLE contour.causal_observer_inbox (
 tenant_id uuid NOT NULL, gateway_id uuid NOT NULL, gateway_generation text NOT NULL, delivery_handle text NOT NULL,
 runtime_id uuid NOT NULL, session_epoch numeric NOT NULL, attempt text NOT NULL, collector_id uuid NOT NULL, batch_id uuid NOT NULL, record_id uuid NOT NULL,
 retry_of text, canonical_fact bytea NOT NULL CHECK(octet_length(canonical_fact) BETWEEN 1 AND 4096), fact_digest bytea NOT NULL CHECK(octet_length(fact_digest)=32),
 marker_root text NOT NULL, marker_activity text NOT NULL, marker_public bytea NOT NULL CHECK(octet_length(marker_public)=32),
 proof_id uuid NOT NULL, receipt_id uuid NOT NULL, receipt bytea NOT NULL CHECK(octet_length(receipt) BETWEEN 1 AND 1024),
 accepted_at timestamptz NOT NULL CHECK(isfinite(accepted_at)), expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at=accepted_at+interval '24 hours'),
 charged_bytes integer NOT NULL CHECK(charged_bytes=octet_length(canonical_fact)+octet_length(receipt)+512),
 PRIMARY KEY(tenant_id,gateway_id,gateway_generation,delivery_handle), UNIQUE(receipt_id),
 FOREIGN KEY(tenant_id,runtime_id,session_epoch,attempt) REFERENCES contour.causal_observer_attempt_reservations,
 FOREIGN KEY(tenant_id,proof_id) REFERENCES contour.origin_proofs
);
-- One immediate successor per delivery, including a predecessor not yet received.
CREATE UNIQUE INDEX causal_observer_one_successor ON contour.causal_observer_inbox(tenant_id,gateway_id,gateway_generation,retry_of) WHERE retry_of IS NOT NULL;
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['causal_observer_epoch_reservations','causal_observer_attempt_reservations','causal_observer_inbox'] LOOP
  EXECUTE format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY observer_owner ON contour.%I TO contour_owner USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context())',n);
  EXECUTE format('REVOKE ALL ON contour.%I FROM PUBLIC,contour_runtime,contour_causal_observer_writer',n);
  EXECUTE format('CREATE TRIGGER observer_immutable BEFORE UPDATE OR DELETE ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()',n);
  EXECUTE format('CREATE TRIGGER observer_no_truncate BEFORE TRUNCATE ON contour.%I FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row()',n);
 END LOOP;
END $$;

-- jsonb canonical byte equality rejects duplicate keys, unknown keys and noncanonical encodings.
CREATE FUNCTION contour.observer_wire(raw bytea) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE j jsonb; b jsonb; k text; v text;
BEGIN
 IF octet_length(raw) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'observer wire invalid' USING ERRCODE='23514'; END IF;
 j:=convert_from(raw,'UTF8')::jsonb;
 IF jsonb_typeof(j)<>'object' OR j-ARRAY['wire_version','binding','batch_id','signed_marker']<>'{}'::jsonb OR NOT (j ?& ARRAY['wire_version','binding','batch_id','signed_marker'])
 OR (j->'wire_version')::text<>'1' OR jsonb_typeof(j->'batch_id')<>'string' OR (j->>'batch_id') COLLATE "C" !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR jsonb_typeof(j->'signed_marker')<>'string' OR octet_length(j->>'signed_marker') NOT BETWEEN 4 AND 1024 OR left(j->>'signed_marker',4)<>'ac1.' OR (j->>'signed_marker') COLLATE "C" ~ '[^!-~]'
 OR convert_to(contour.causal_json_canonical(j),'UTF8')<>raw THEN RAISE EXCEPTION 'observer wire invalid' USING ERRCODE='23514'; END IF;
 b:=j->'binding';
 IF jsonb_typeof(b)<>'object' OR b-ARRAY['wire_version','tenant_id','gateway_id','gateway_generation','collector_id','record_id','producer_runtime_id','producer_session_epoch','producer_attempt_id','marker_digest','receiver_runtime_id','receiver_session_epoch','delivery_handle','retry_of']<>'{}'::jsonb
 OR NOT (b ?& ARRAY['wire_version','tenant_id','gateway_id','gateway_generation','collector_id','record_id','producer_runtime_id','producer_session_epoch','producer_attempt_id','marker_digest','receiver_runtime_id','receiver_session_epoch','delivery_handle','retry_of']) OR (b->'wire_version')::text<>'1' OR octet_length(convert_to(contour.causal_json_canonical(b),'UTF8'))>2048
 THEN RAISE EXCEPTION 'observer wire invalid' USING ERRCODE='23514'; END IF;
 FOREACH k IN ARRAY ARRAY['tenant_id','gateway_id','collector_id','record_id','producer_runtime_id','receiver_runtime_id'] LOOP
  IF jsonb_typeof(b->k)<>'string' OR (b->>k) COLLATE "C" !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'observer wire invalid' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['gateway_generation','producer_attempt_id','delivery_handle'] LOOP
  IF jsonb_typeof(b->k)<>'string' OR (b->>k) COLLATE "C" !~ '^[0-9a-f]{32}$' THEN RAISE EXCEPTION 'observer wire invalid' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF jsonb_typeof(b->'marker_digest')<>'string' OR (b->>'marker_digest') COLLATE "C" !~ '^[0-9a-f]{64}$'
 OR (b->'retry_of'<>'null'::jsonb AND (jsonb_typeof(b->'retry_of')<>'string' OR (b->>'retry_of') COLLATE "C" !~ '^[0-9a-f]{32}$')) THEN RAISE EXCEPTION 'observer wire invalid' USING ERRCODE='23514'; END IF;
 FOREACH k IN ARRAY ARRAY['producer_session_epoch','receiver_session_epoch'] LOOP
  v:=b->>k;
  IF jsonb_typeof(b->k)<>'string' OR v COLLATE "C" !~ '^[1-9][0-9]{0,19}$' OR v::numeric>18446744073709551615 THEN RAISE EXCEPTION 'observer wire invalid' USING ERRCODE='23514'; END IF;
 END LOOP;
 RETURN j;
EXCEPTION WHEN invalid_text_representation OR character_not_in_repertoire THEN RAISE EXCEPTION 'observer wire invalid' USING ERRCODE='23514';
END $$;

CREATE FUNCTION contour.accept_causal_observer(raw bytea, proof contour.verified_observer_claim) RETURNS bytea
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j jsonb; b jsonb; x contour.causal_session_claim; t uuid; gwid uuid; gen text; handle text; prev text;
 collector uuid; rec uuid; bid uuid; runtime uuid; ep numeric; attempt text; md text; leaf bytea; col uuid;
 gateway contour.causal_gateway_enrollments; gateway2 contour.causal_gateway_enrollments;
 binding contour.causal_runtime_bindings; marker contour.causal_marker_bindings; w contour.observation_windows;
 origin contour.origin_proofs; verified record; batch_payload bytea; record_json jsonb; old contour.causal_observer_inbox;
 reservation contour.causal_observer_attempt_reservations; meta bytea; stored_receipt bytea; fact_hash bytea;
 initial_at timestamptz; final_at timestamptz; floor_at timestamptz; used bigint; charge bigint; extra bigint:=0; receipt_id uuid; receipt_cutoff timestamptz; ancestor_count integer; descendant_count integer; closes_cycle boolean;
BEGIN
 j:=contour.observer_wire(raw); b:=j->'binding'; x:=proof.producer_claim;
 t:=(b->>'tenant_id')::uuid; gwid:=(b->>'gateway_id')::uuid; gen:=b->>'gateway_generation'; handle:=b->>'delivery_handle'; prev:=b->>'retry_of';
 collector:=(b->>'collector_id')::uuid; rec:=(b->>'record_id')::uuid; bid:=(j->>'batch_id')::uuid;
 runtime:=(b->>'producer_runtime_id')::uuid; ep:=(b->>'producer_session_epoch')::numeric; attempt:=b->>'producer_attempt_id'; md:=b->>'marker_digest';
 PERFORM contour.begin_origin_operation(t);
 IF x IS NULL OR proof.gateway_peer_leaf IS NULL OR octet_length(proof.gateway_peer_leaf)<>32 OR proof.marker_public IS NULL OR octet_length(proof.marker_public)<>32
 OR proof.marker_generation IS NULL OR octet_length(proof.marker_generation)<>32 OR proof.marker_wire_digest IS NULL OR octet_length(proof.marker_wire_digest)<>32
 OR proof.marker_root IS NULL OR proof.marker_root COLLATE "C" !~ '^[0-9a-f]{32}$' OR proof.marker_activity IS NULL OR proof.marker_activity COLLATE "C" !~ '^[0-9a-f]{32}$'
 OR proof.marker_attempt IS DISTINCT FROM attempt OR encode(proof.marker_wire_digest,'hex') IS DISTINCT FROM md
 OR sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||(j->>'signed_marker'),'UTF8')) IS DISTINCT FROM proof.marker_wire_digest
 OR x.tenant_id IS DISTINCT FROM t OR x.runtime_id IS DISTINCT FROM runtime OR proof.producer_epoch IS DISTINCT FROM ep OR prev=handle
 THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO gateway FROM contour.causal_gateway_enrollments g WHERE (g.tenant_id,g.gateway_id,g.generation)=(t,gwid,gen);
 IF NOT FOUND THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO binding FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,runtime);
 IF NOT FOUND THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO marker FROM contour.causal_marker_bindings m WHERE (m.tenant_id,m.runtime_id,m.epoch)=(t,runtime,ep);
 IF NOT FOUND THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 FOR leaf IN SELECT DISTINCT ON (k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM (VALUES(proof.gateway_peer_leaf),((gateway.claim).observer_leaf),((gateway.claim).backend_client_leaf),(binding.export_leaf_sha256),(marker.product_leaf_sha256)) leaves(v)) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 FOR col IN SELECT DISTINCT ON (k) v FROM (SELECT v,contour.collector_lock_key(t,v) k FROM (VALUES(collector),(binding.collector_id)) cols(v)) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_collector(t,col); END LOOP;
 PERFORM contour.ensure_origin_tenant_state(t);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=t FOR UPDATE;
 INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES(t,0) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT used_bytes INTO STRICT used FROM contour.origin_logical_usage WHERE tenant_id=t FOR UPDATE;
 SELECT * INTO gateway2 FROM contour.causal_gateway_enrollments g WHERE (g.tenant_id,g.gateway_id,g.generation)=(t,gwid,gen);
 initial_at:=clock_timestamp();
 IF gateway2 IS DISTINCT FROM gateway OR proof.gateway_peer_leaf IS DISTINCT FROM (gateway.claim).observer_leaf OR collector IS DISTINCT FROM (gateway.claim).collector_id
 OR initial_at IS NULL OR NOT isfinite(initial_at) OR (floor_at IS NOT NULL AND initial_at<floor_at) OR initial_at>=gateway.expires_at OR initial_at<gateway.issued_at
 OR NOT contour.gateway_claim_current(gateway.claim,initial_at)
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations r WHERE r.leaf_sha256=(gateway.claim).observer_leaf AND r.leaf_class='gateway_observer')
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations r WHERE r.leaf_sha256=(gateway.claim).backend_client_leaf AND r.leaf_class='gateway_backend') OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals z WHERE (z.tenant_id,z.gateway_id,z.generation)=(t,gwid,gen))
 OR NOT contour.causal_session_locked(x,ep,initial_at)
 OR proof.marker_public IS DISTINCT FROM marker.marker_public_key OR proof.marker_generation IS DISTINCT FROM marker.generation OR marker.nonce IS DISTINCT FROM x.nonce
 OR marker.lifecycle_id IS DISTINCT FROM binding.lifecycle_id OR marker.instance_id IS DISTINCT FROM binding.instance_id OR marker.profile_id IS DISTINCT FROM binding.profile_id OR marker.artifact_sha256 IS DISTINCT FROM binding.artifact_sha256
 OR NOT contour.causal_marker_product_current(t,binding,marker.product_credential_id,marker.product_leaf_sha256,initial_at)
 THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 -- SQL25 performs the full committed batch, witness and bidirectional projection checks.
 SELECT * INTO STRICT w FROM contour.observation_windows q WHERE (q.tenant_id,q.collector_id,q.batch_id,q.record_id)=(t,collector,bid,rec);
 SELECT * INTO STRICT verified FROM contour.human_observation_origin(t,w.project_id,w.service_id,w.environment_id,w.operation_id,w.observation_id);
 SELECT * INTO STRICT origin FROM contour.origin_proofs p WHERE (p.tenant_id,p.collector_id,p.batch_id,p.record_id)=(t,collector,bid,rec);
 SELECT p.checked_batch INTO STRICT batch_payload FROM contour.ingestion_payloads p WHERE (p.tenant_id,p.collector_id,p.batch_id,p.payload_format)=(t,collector,bid,2);
 SELECT item.value->'record' INTO STRICT record_json FROM jsonb_array_elements((convert_from(batch_payload,'UTF8')::jsonb)->'records') item(value) WHERE item.value->'record'->>'record_id'=rec::text;
 IF record_json->>'direction' IS DISTINCT FROM 'request' OR origin.source_id IS DISTINCT FROM (gateway.claim).source_id
 OR (origin.origin_project_id,origin.origin_service_id,origin.origin_environment_id,origin.origin_deployment_id,origin.instance_id,origin.lifecycle_id,origin.credential_id,origin.leaf_sha256)
 IS DISTINCT FROM (x.project_id,x.service_id,x.environment_id,x.deployment_id,x.instance_id,x.lifecycle_id,marker.product_credential_id,marker.product_leaf_sha256)
 OR (verified.origin_project_id,verified.origin_service_id,verified.origin_environment_id,verified.origin_deployment_id,verified.instance_id,verified.lifecycle_id,verified.credential_id)
 IS DISTINCT FROM (origin.origin_project_id,origin.origin_service_id,origin.origin_environment_id,origin.origin_deployment_id,origin.instance_id,origin.lifecycle_id,origin.credential_id)
 THEN RAISE EXCEPTION 'observer origin unavailable' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM contour.causal_inbox_events e WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.attempt)=(t,runtime,ep,'attempt',attempt) AND (e.root,e.activity,e.marker_digest) IS DISTINCT FROM (proof.marker_root,proof.marker_activity,md))
 THEN RAISE EXCEPTION 'observer attempt unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(t,gwid,gen,handle);
 IF FOUND THEN
  IF old.canonical_fact IS DISTINCT FROM raw OR (old.runtime_id,old.session_epoch,old.attempt,old.collector_id,old.batch_id,old.record_id,old.retry_of) IS DISTINCT FROM (runtime,ep,attempt,collector,bid,rec,prev) OR old.marker_root IS DISTINCT FROM proof.marker_root OR old.marker_activity IS DISTINCT FROM proof.marker_activity OR old.marker_public IS DISTINCT FROM proof.marker_public OR initial_at>=old.expires_at
  THEN RAISE EXCEPTION 'observer unavailable' USING ERRCODE='23505'; END IF;
  SELECT * INTO STRICT reservation FROM contour.causal_observer_attempt_reservations r WHERE (r.tenant_id,r.runtime_id,r.session_epoch,r.attempt)=(t,runtime,ep,attempt);
  meta:=convert_to(contour.causal_json_canonical(jsonb_build_object('tenant_id',t,'runtime_id',runtime,'session_epoch',ep::text,'attempt',attempt,'gateway_id',gwid,'gateway_generation',gen,'collector_id',collector,'batch_id',bid,'record_id',rec,'marker_digest',md,'marker_root',proof.marker_root,'marker_activity',proof.marker_activity)),'UTF8');
  IF (reservation.gateway_id,reservation.gateway_generation,reservation.collector_id,reservation.batch_id,reservation.record_id,reservation.marker_digest,reservation.marker_root,reservation.marker_activity) IS DISTINCT FROM (gwid,gen,collector,bid,rec,md,proof.marker_root,proof.marker_activity)
  OR reservation.metadata IS DISTINCT FROM meta OR reservation.charged_bytes<>octet_length(meta)+256
  OR NOT EXISTS(SELECT 1 FROM contour.causal_observer_epoch_reservations r WHERE (r.tenant_id,r.runtime_id,r.session_epoch,r.charged_bytes)=(t,runtime,ep,1024))
  THEN RAISE EXCEPTION 'observer unavailable' USING ERRCODE='23514'; END IF;
  fact_hash:=sha256(convert_to(E'apicontour/causal-evidence/observer/1\n','UTF8')||raw);
  IF old.fact_digest IS DISTINCT FROM fact_hash OR old.proof_id IS DISTINCT FROM origin.proof_id
  OR old.receipt IS DISTINCT FROM convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','observer','fact_digest',encode(fact_hash,'hex'),'receipt_id',old.receipt_id,'status','stored')),'UTF8')
  THEN RAISE EXCEPTION 'observer unavailable' USING ERRCODE='23514'; END IF;
  stored_receipt:=old.receipt; receipt_cutoff:=old.expires_at;
 ELSE
  meta:=convert_to(contour.causal_json_canonical(jsonb_build_object('tenant_id',t,'runtime_id',runtime,'session_epoch',ep::text,'attempt',attempt,'gateway_id',gwid,'gateway_generation',gen,'collector_id',collector,'batch_id',bid,'record_id',rec,'marker_digest',md,'marker_root',proof.marker_root,'marker_activity',proof.marker_activity)),'UTF8');
  SELECT * INTO reservation FROM contour.causal_observer_attempt_reservations r WHERE (r.tenant_id,r.runtime_id,r.session_epoch,r.attempt)=(t,runtime,ep,attempt);
  IF FOUND THEN
   IF (reservation.gateway_id,reservation.gateway_generation,reservation.collector_id,reservation.batch_id,reservation.record_id,reservation.marker_digest,reservation.marker_root,reservation.marker_activity) IS DISTINCT FROM (gwid,gen,collector,bid,rec,md,proof.marker_root,proof.marker_activity) OR reservation.metadata IS DISTINCT FROM meta OR reservation.charged_bytes<>octet_length(meta)+256
   THEN RAISE EXCEPTION 'observer unavailable' USING ERRCODE='23505'; END IF;
  ELSE
   extra:=octet_length(meta)+256;
  END IF;
  IF prev IS NULL AND EXISTS(SELECT 1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.runtime_id,q.session_epoch,q.attempt)=(t,runtime,ep,attempt) AND q.retry_of IS NULL) THEN RAISE EXCEPTION 'observer retry unavailable' USING ERRCODE='23514'; END IF;
  IF prev IS NOT NULL AND EXISTS(SELECT 1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.retry_of)=(t,gwid,gen,prev)) THEN RAISE EXCEPTION 'observer retry unavailable' USING ERRCODE='23505'; END IF;
  IF prev IS NOT NULL AND EXISTS(SELECT 1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(t,gwid,gen,prev) AND (q.runtime_id,q.session_epoch,q.attempt,q.collector_id,q.batch_id,q.record_id) IS DISTINCT FROM (runtime,ep,attempt,collector,bid,rec)) THEN RAISE EXCEPTION 'observer retry unavailable' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT 1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.retry_of)=(t,gwid,gen,handle) AND (q.runtime_id,q.session_epoch,q.attempt,q.collector_id,q.batch_id,q.record_id) IS DISTINCT FROM (runtime,ep,attempt,collector,bid,rec)) THEN RAISE EXCEPTION 'observer retry unavailable' USING ERRCODE='23514'; END IF;
  -- At most 64 stored deliveries in any connected retry chain. Count both
  -- sides when a late predecessor joins existing fragments; never traverse
  -- more than 64 rows on either side, including in corrupt cyclic state.
  WITH RECURSIVE ancestors(h,p,depth) AS (
   SELECT q.delivery_handle,q.retry_of,1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(t,gwid,gen,prev)
   UNION ALL SELECT q.delivery_handle,q.retry_of,a.depth+1 FROM ancestors a JOIN contour.causal_observer_inbox q ON (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(t,gwid,gen,a.p) WHERE a.depth<64
  ), descendants(h,depth) AS (
   SELECT q.delivery_handle,1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.retry_of)=(t,gwid,gen,handle)
   UNION ALL SELECT q.delivery_handle,d.depth+1 FROM descendants d JOIN contour.causal_observer_inbox q ON (q.tenant_id,q.gateway_id,q.gateway_generation,q.retry_of)=(t,gwid,gen,d.h) WHERE d.depth<64
  )
  SELECT (SELECT count(*) FROM ancestors),(SELECT count(*) FROM descendants),coalesce((SELECT bool_or(p=handle) FROM ancestors),false)
  INTO ancestor_count,descendant_count,closes_cycle;
  IF closes_cycle OR ancestor_count+descendant_count+1>64 THEN RAISE EXCEPTION 'observer retry unavailable' USING ERRCODE='23514'; END IF;
  fact_hash:=sha256(convert_to(E'apicontour/causal-evidence/observer/1\n','UTF8')||raw); receipt_id:=gen_random_uuid();
  stored_receipt:=convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','observer','fact_digest',encode(fact_hash,'hex'),'receipt_id',receipt_id,'status','stored')),'UTF8');
  charge:=octet_length(raw)+octet_length(stored_receipt)+512+extra;
  IF NOT EXISTS(SELECT 1 FROM contour.causal_observer_epoch_reservations r WHERE (r.tenant_id,r.runtime_id,r.session_epoch)=(t,runtime,ep)) THEN charge:=charge+1024; END IF;
  IF charge>1073741824-used THEN RAISE EXCEPTION 'origin logical quota exhausted' USING ERRCODE='54000',CONSTRAINT='origin_logical_quota_exhausted'; END IF;
  IF extra>0 THEN INSERT INTO contour.causal_observer_attempt_reservations VALUES(t,runtime,ep,attempt,gwid,gen,collector,bid,rec,md,proof.marker_root,proof.marker_activity,meta,extra); END IF;
  INSERT INTO contour.causal_observer_epoch_reservations VALUES(t,runtime,ep,1024) ON CONFLICT DO NOTHING;
  INSERT INTO contour.causal_observer_inbox VALUES(t,gwid,gen,handle,runtime,ep,attempt,collector,bid,rec,prev,raw,fact_hash,proof.marker_root,proof.marker_activity,proof.marker_public,origin.proof_id,receipt_id,stored_receipt,initial_at,initial_at+interval '24 hours',octet_length(raw)+octet_length(stored_receipt)+512);
  UPDATE contour.origin_logical_usage SET used_bytes=used+charge WHERE tenant_id=t;
  receipt_cutoff:=initial_at+interval '24 hours';
 END IF;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR (floor_at IS NOT NULL AND final_at<floor_at) OR final_at>=gateway.expires_at OR final_at>=receipt_cutoff OR NOT contour.gateway_claim_current(gateway.claim,final_at)
 OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals z WHERE (z.tenant_id,z.gateway_id,z.generation)=(t,gwid,gen)) OR NOT contour.causal_session_locked(x,ep,final_at)
 OR NOT contour.causal_marker_product_current(t,binding,marker.product_credential_id,marker.product_leaf_sha256,final_at)
 THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=final_at WHERE tenant_id=t;
 RETURN stored_receipt;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN RAISE EXCEPTION 'observer unavailable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON TYPE contour.verified_observer_claim FROM PUBLIC,contour_runtime;
GRANT USAGE ON TYPE contour.verified_observer_claim TO contour_causal_observer_writer;
REVOKE ALL ON FUNCTION contour.observer_wire(bytea),contour.accept_causal_observer(bytea,contour.verified_observer_claim) FROM PUBLIC,contour_runtime,contour_causal_observer_writer;
GRANT USAGE ON SCHEMA contour TO contour_causal_observer_writer;
GRANT EXECUTE ON FUNCTION contour.accept_causal_observer(bytea,contour.verified_observer_claim) TO contour_causal_observer_writer;
INSERT INTO contour.schema_migrations(version) VALUES(27);
COMMIT;
