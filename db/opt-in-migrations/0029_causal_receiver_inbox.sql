-- Opt-in synthetic/privileged receiver evidence inbox; no causal edge or deployment authority.
-- SQL does not authenticate mTLS or assert deployment/workload possession.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security')<>'on' OR current_setting('transaction_isolation')<>'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,28))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted receiver inbox migration required' USING ERRCODE='42501'; END IF;
END $$;
CREATE ROLE contour_causal_receiver_writer NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET LOCAL ROLE contour_owner;
-- This claim is supplied only by the independently authenticated owning
-- service; it is not a certificate or possession verifier.
CREATE TYPE contour.verified_receiver_claim AS (
 evidence_peer_leaf bytea, enrollment_generation text, evidence_credential_id uuid
);
CREATE TABLE contour.causal_receiver_assignments (
 tenant_id uuid NOT NULL, gateway_id uuid NOT NULL, gateway_generation text NOT NULL, delivery_handle text NOT NULL,
 receiver_runtime_id uuid NOT NULL, receiver_session_epoch numeric NOT NULL, local_root text NOT NULL, binding_digest text NOT NULL,
 enrollment_generation text NOT NULL, evidence_credential_id uuid NOT NULL, evidence_peer_leaf bytea NOT NULL CHECK(octet_length(evidence_peer_leaf)=32),
 metadata bytea NOT NULL CHECK(octet_length(metadata) BETWEEN 1 AND 4096),
 charged_bytes bigint NOT NULL CHECK(charged_bytes=octet_length(metadata)+256),
 PRIMARY KEY(tenant_id,gateway_id,gateway_generation,delivery_handle),
 FOREIGN KEY(tenant_id,gateway_id,gateway_generation) REFERENCES contour.causal_gateway_enrollments,
 FOREIGN KEY(tenant_id,receiver_runtime_id,receiver_session_epoch) REFERENCES contour.causal_receiver_enrollments
);
-- A separately charged replay tombstone is retained while authority is open.
CREATE TABLE contour.causal_receiver_tombstones (
 tenant_id uuid NOT NULL, gateway_id uuid NOT NULL, gateway_generation text NOT NULL, delivery_handle text NOT NULL,
 fact_digest bytea NOT NULL CHECK(octet_length(fact_digest)=32), metadata bytea NOT NULL CHECK(octet_length(metadata) BETWEEN 1 AND 4096),
 charged_bytes bigint NOT NULL CHECK(charged_bytes=octet_length(metadata)+256),
 PRIMARY KEY(tenant_id,gateway_id,gateway_generation,delivery_handle),
 FOREIGN KEY(tenant_id,gateway_id,gateway_generation,delivery_handle) REFERENCES contour.causal_receiver_assignments
);
CREATE TABLE contour.causal_receiver_inbox (
 tenant_id uuid NOT NULL, gateway_id uuid NOT NULL, gateway_generation text NOT NULL, delivery_handle text NOT NULL,
 canonical_fact bytea NOT NULL CHECK(octet_length(canonical_fact) BETWEEN 1 AND 4096),
 fact_digest bytea NOT NULL CHECK(octet_length(fact_digest)=32), receipt_id uuid NOT NULL,
 receipt bytea NOT NULL CHECK(octet_length(receipt) BETWEEN 1 AND 1024),
 accepted_at timestamptz NOT NULL CHECK(isfinite(accepted_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at=accepted_at+interval '24 hours'),
 charged_bytes bigint NOT NULL CHECK(charged_bytes=octet_length(canonical_fact)+octet_length(receipt)+512),
 PRIMARY KEY(tenant_id,gateway_id,gateway_generation,delivery_handle), UNIQUE(receipt_id),
 FOREIGN KEY(tenant_id,gateway_id,gateway_generation,delivery_handle) REFERENCES contour.causal_receiver_assignments
);
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['causal_receiver_assignments','causal_receiver_tombstones','causal_receiver_inbox'] LOOP
  EXECUTE format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY receiver_inbox_owner ON contour.%I TO contour_owner USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context())',n);
  EXECUTE format('REVOKE ALL ON contour.%I FROM PUBLIC,contour_runtime,contour_causal_receiver_writer',n);
  EXECUTE format('CREATE TRIGGER receiver_inbox_immutable BEFORE UPDATE OR DELETE ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()',n);
  EXECUTE format('CREATE TRIGGER receiver_inbox_no_truncate BEFORE TRUNCATE ON contour.%I FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row()',n);
 END LOOP;
END $$;
CREATE FUNCTION contour.receiver_inbox_wire(raw bytea) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE j jsonb; k text; epoch text;
BEGIN
 IF octet_length(raw) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'receiver wire invalid' USING ERRCODE='23514'; END IF;
 j:=convert_from(raw,'UTF8')::jsonb;
 IF jsonb_typeof(j)<>'object'
 OR j-ARRAY['wire_version','tenant_id','gateway_id','gateway_generation','delivery_handle','receiver_runtime_id','receiver_session_epoch','local_root','binding_digest']<>'{}'::jsonb
 OR NOT (j ?& ARRAY['wire_version','tenant_id','gateway_id','gateway_generation','delivery_handle','receiver_runtime_id','receiver_session_epoch','local_root','binding_digest'])
 OR jsonb_typeof(j->'wire_version')<>'number' OR (j->'wire_version')::text<>'1'
 OR convert_to(contour.causal_json_canonical(j),'UTF8')<>raw
 THEN RAISE EXCEPTION 'receiver wire invalid' USING ERRCODE='23514'; END IF;
 FOREACH k IN ARRAY ARRAY['tenant_id','gateway_id','receiver_runtime_id'] LOOP
  IF jsonb_typeof(j->k)<>'string' OR (j->>k) COLLATE "C" !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'receiver wire invalid' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['gateway_generation','delivery_handle','local_root'] LOOP
  IF jsonb_typeof(j->k)<>'string' OR (j->>k) COLLATE "C" !~ '^[0-9a-f]{32}$'
  THEN RAISE EXCEPTION 'receiver wire invalid' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF jsonb_typeof(j->'binding_digest')<>'string' OR (j->>'binding_digest') COLLATE "C" !~ '^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'receiver wire invalid' USING ERRCODE='23514'; END IF;
 epoch:=j->>'receiver_session_epoch';
 IF jsonb_typeof(j->'receiver_session_epoch')<>'string' OR epoch COLLATE "C" !~ '^[1-9][0-9]{0,19}$' OR epoch::numeric>18446744073709551615
 THEN RAISE EXCEPTION 'receiver wire invalid' USING ERRCODE='23514'; END IF;
 RETURN j;
EXCEPTION WHEN invalid_text_representation OR character_not_in_repertoire THEN RAISE EXCEPTION 'receiver wire invalid' USING ERRCODE='23514';
END $$;
-- These helpers require all tenant, credential and collector gates already held.
-- The service must authenticate its caller before submitting a claim.
CREATE FUNCTION contour.receiver_assignment_metadata(a contour.causal_receiver_assignments) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT convert_to(contour.causal_json_canonical(jsonb_build_object(
  'tenant_id',a.tenant_id,'gateway_id',a.gateway_id,'gateway_generation',a.gateway_generation,
  'delivery_handle',a.delivery_handle,'receiver_runtime_id',a.receiver_runtime_id,
  'receiver_session_epoch',a.receiver_session_epoch::text,'local_root',a.local_root,'binding_digest',a.binding_digest,
  'enrollment_generation',a.enrollment_generation,'evidence_credential_id',a.evidence_credential_id,
  'evidence_peer_leaf',encode(a.evidence_peer_leaf,'hex'))),'UTF8')
$$;
CREATE FUNCTION contour.receiver_tombstone_metadata(a contour.causal_receiver_assignments, digest bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT convert_to(contour.causal_json_canonical(jsonb_build_object('tenant_id',a.tenant_id,'gateway_id',a.gateway_id,
  'gateway_generation',a.gateway_generation,'delivery_handle',a.delivery_handle,'fact_digest',encode(digest,'hex'))),'UTF8')
$$;
CREATE FUNCTION contour.receiver_enrollment_current(a contour.causal_receiver_assignments, at_time timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE r contour.causal_receiver_enrollments; s contour.causal_sessions; b contour.causal_runtime_bindings;
BEGIN
 SELECT * INTO STRICT r FROM contour.causal_receiver_enrollments x
  WHERE (x.tenant_id,x.runtime_id,x.session_epoch)=(a.tenant_id,a.receiver_runtime_id,a.receiver_session_epoch) FOR SHARE;
 SELECT * INTO STRICT s FROM contour.causal_sessions x
  WHERE (x.tenant_id,x.runtime_id,x.epoch)=(a.tenant_id,a.receiver_runtime_id,a.receiver_session_epoch) FOR SHARE;
 SELECT * INTO STRICT b FROM contour.causal_runtime_bindings x
  WHERE (x.tenant_id,x.runtime_id)=(a.tenant_id,a.receiver_runtime_id) FOR SHARE;
 RETURN coalesce(a.tenant_id=contour.tenant_context() AND isfinite(at_time)
  AND a.enrollment_generation=r.enrollment_generation AND a.evidence_credential_id=r.evidence_credential_id
  AND a.evidence_peer_leaf=(r.claim).evidence_leaf AND at_time>=r.issued_at AND at_time<r.expires_at
  AND a.metadata=contour.receiver_assignment_metadata(a) AND a.charged_bytes=octet_length(a.metadata)+256
  AND r.metadata=contour.receiver_enrollment_metadata(r.claim,s,r.enrollment_generation,r.evidence_credential_id,r.issued_at,r.expires_at)
  AND r.commitment=contour.receiver_enrollment_commitment(r.metadata)
  AND contour.receiver_claim_current(r.claim,s,b,at_time)
  AND NOT EXISTS(SELECT 1 FROM contour.causal_receiver_terminals z WHERE (z.tenant_id,z.runtime_id,z.session_epoch)=(r.tenant_id,r.runtime_id,r.session_epoch))
  AND EXISTS(SELECT 1 FROM contour.causal_receiver_terminal_reservations z WHERE (z.tenant_id,z.runtime_id,z.session_epoch,z.charged_bytes)=(r.tenant_id,r.runtime_id,r.session_epoch,1024))
  AND EXISTS(SELECT 1 FROM contour.causal_leaf_reservations z WHERE z.leaf_sha256=(r.claim).product_leaf AND z.leaf_class='product')
  AND EXISTS(SELECT 1 FROM contour.causal_leaf_reservations z WHERE z.leaf_sha256=(r.claim).export_leaf AND z.leaf_class='export')
  AND EXISTS(SELECT 1 FROM contour.causal_leaf_reservations z WHERE z.leaf_sha256=(r.claim).backend_leaf AND z.leaf_class='receiver_backend')
  AND EXISTS(SELECT 1 FROM contour.causal_leaf_reservations z WHERE z.leaf_sha256=(r.claim).evidence_leaf AND z.leaf_class='receiver_evidence'),false);
EXCEPTION WHEN no_data_found OR too_many_rows THEN RETURN false;
END $$;
CREATE FUNCTION contour.receiver_assignment_current(a contour.causal_receiver_assignments, at_time timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE i contour.causal_receiver_inbox; tomb contour.causal_receiver_tombstones; wire jsonb;
BEGIN
 IF NOT contour.receiver_enrollment_current(a,at_time) THEN RETURN false; END IF;
 SELECT * INTO STRICT i FROM contour.causal_receiver_inbox x
  WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle);
 SELECT * INTO STRICT tomb FROM contour.causal_receiver_tombstones x
  WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle);
 wire:=contour.receiver_inbox_wire(i.canonical_fact);
 RETURN coalesce((wire->>'tenant_id',wire->>'gateway_id',wire->>'gateway_generation',wire->>'delivery_handle',wire->>'receiver_runtime_id',wire->>'receiver_session_epoch',wire->>'local_root',wire->>'binding_digest')
      =(a.tenant_id::text,a.gateway_id::text,a.gateway_generation,a.delivery_handle,a.receiver_runtime_id::text,a.receiver_session_epoch::text,a.local_root,a.binding_digest)
  AND i.fact_digest=sha256(convert_to(E'apicontour/causal-evidence/receiver/1\n','UTF8')||i.canonical_fact)
  AND tomb.fact_digest=i.fact_digest AND tomb.metadata=contour.receiver_tombstone_metadata(a,i.fact_digest) AND tomb.charged_bytes=octet_length(tomb.metadata)+256
  AND i.receipt=convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','receiver','fact_digest',encode(i.fact_digest,'hex'),'receipt_id',i.receipt_id,'status','stored')),'UTF8')
  AND i.charged_bytes=octet_length(i.canonical_fact)+octet_length(i.receipt)+512
  AND at_time>=i.accepted_at AND at_time<i.expires_at,false);
EXCEPTION WHEN no_data_found OR too_many_rows THEN RETURN false;
END $$;
CREATE FUNCTION contour.receiver_observer_current(a contour.causal_receiver_assignments, at_time timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o contour.causal_observer_inbox; j jsonb; binding jsonb; x contour.causal_session_claim;
 ps contour.causal_sessions; pb contour.causal_runtime_bindings; m contour.causal_marker_bindings;
 gw contour.causal_gateway_enrollments; ar contour.causal_observer_attempt_reservations;
 w contour.observation_windows; origin contour.origin_proofs; verified record; payload bytea; request_record jsonb; meta bytea;
BEGIN
 SELECT * INTO STRICT gw FROM contour.causal_gateway_enrollments q WHERE (q.tenant_id,q.gateway_id,q.generation)=(a.tenant_id,a.gateway_id,a.gateway_generation);
 SELECT * INTO STRICT o FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle);
 SELECT * INTO STRICT ps FROM contour.causal_sessions q WHERE (q.tenant_id,q.runtime_id,q.epoch)=(o.tenant_id,o.runtime_id,o.session_epoch) FOR SHARE;
 SELECT * INTO STRICT pb FROM contour.causal_runtime_bindings q WHERE (q.tenant_id,q.runtime_id)=(o.tenant_id,o.runtime_id) FOR SHARE;
 SELECT * INTO STRICT m FROM contour.causal_marker_bindings q WHERE (q.tenant_id,q.runtime_id,q.epoch)=(o.tenant_id,o.runtime_id,o.session_epoch) FOR SHARE;
 SELECT * INTO STRICT ar FROM contour.causal_observer_attempt_reservations q WHERE (q.tenant_id,q.runtime_id,q.session_epoch,q.attempt)=(o.tenant_id,o.runtime_id,o.session_epoch,o.attempt);
 j:=contour.observer_wire(o.canonical_fact);binding:=j->'binding';x:=ps.claim;
 meta:=convert_to(contour.causal_json_canonical(jsonb_build_object('tenant_id',o.tenant_id,'runtime_id',o.runtime_id,'session_epoch',o.session_epoch::text,'attempt',o.attempt,'gateway_id',o.gateway_id,'gateway_generation',o.gateway_generation,'collector_id',o.collector_id,'batch_id',o.batch_id,'record_id',o.record_id,'marker_digest',encode(sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||(j->>'signed_marker'),'UTF8')),'hex'),'marker_root',o.marker_root,'marker_activity',o.marker_activity)),'UTF8');
 IF (binding->>'tenant_id',binding->>'gateway_id',binding->>'gateway_generation',binding->>'delivery_handle',binding->>'receiver_runtime_id',binding->>'receiver_session_epoch')
    IS DISTINCT FROM (a.tenant_id::text,a.gateway_id::text,a.gateway_generation,a.delivery_handle,a.receiver_runtime_id::text,a.receiver_session_epoch::text)
 OR a.binding_digest IS DISTINCT FROM encode(sha256(convert_to(E'apicontour/causal-evidence/binding/1\n','UTF8')||convert_to(contour.causal_json_canonical(binding),'UTF8')),'hex')
 OR (binding->>'producer_runtime_id',binding->>'producer_session_epoch',binding->>'producer_attempt_id',binding->>'collector_id',binding->>'record_id',j->>'batch_id',binding->>'retry_of')
    IS DISTINCT FROM (o.runtime_id::text,o.session_epoch::text,o.attempt,o.collector_id::text,o.record_id::text,o.batch_id::text,o.retry_of)
 OR at_time<o.accepted_at OR at_time>=o.expires_at OR o.fact_digest IS DISTINCT FROM sha256(convert_to(E'apicontour/causal-evidence/observer/1\n','UTF8')||o.canonical_fact)
 OR o.receipt IS DISTINCT FROM convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','observer','fact_digest',encode(o.fact_digest,'hex'),'receipt_id',o.receipt_id,'status','stored')),'UTF8')
 OR o.charged_bytes<>octet_length(o.canonical_fact)+octet_length(o.receipt)+512
 OR (ar.gateway_id,ar.gateway_generation,ar.collector_id,ar.batch_id,ar.record_id,ar.marker_digest,ar.marker_root,ar.marker_activity)
    IS DISTINCT FROM (o.gateway_id,o.gateway_generation,o.collector_id,o.batch_id,o.record_id,binding->>'marker_digest',o.marker_root,o.marker_activity)
 OR o.collector_id IS DISTINCT FROM (gw.claim).collector_id
 OR binding->>'marker_digest' IS DISTINCT FROM encode(sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||(j->>'signed_marker'),'UTF8')),'hex')
 OR ar.metadata IS DISTINCT FROM meta OR ar.charged_bytes<>octet_length(meta)+256
 OR NOT EXISTS(SELECT 1 FROM contour.causal_observer_epoch_reservations q WHERE (q.tenant_id,q.runtime_id,q.session_epoch,q.charged_bytes)=(o.tenant_id,o.runtime_id,o.session_epoch,1024))
 OR o.marker_public IS DISTINCT FROM m.marker_public_key OR m.nonce IS DISTINCT FROM x.nonce
 OR (m.lifecycle_id,m.instance_id,m.profile_id,m.artifact_sha256) IS DISTINCT FROM (pb.lifecycle_id,pb.instance_id,pb.profile_id,pb.artifact_sha256)
 OR NOT contour.causal_session_locked(x,o.session_epoch,at_time)
 OR NOT contour.causal_marker_product_current(a.tenant_id,pb,m.product_credential_id,m.product_leaf_sha256,at_time)
 OR EXISTS(SELECT 1 FROM contour.causal_inbox_events e WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.attempt)=(o.tenant_id,o.runtime_id,o.session_epoch,'attempt',o.attempt) AND (e.root,e.activity,e.marker_digest) IS DISTINCT FROM (o.marker_root,o.marker_activity,binding->>'marker_digest'))
 THEN RETURN false; END IF;
 SELECT * INTO STRICT w FROM contour.observation_windows q WHERE (q.tenant_id,q.collector_id,q.batch_id,q.record_id)=(o.tenant_id,o.collector_id,o.batch_id,o.record_id);
 SELECT * INTO STRICT verified FROM contour.human_observation_origin(a.tenant_id,w.project_id,w.service_id,w.environment_id,w.operation_id,w.observation_id);
 SELECT * INTO STRICT origin FROM contour.origin_proofs q WHERE (q.tenant_id,q.collector_id,q.batch_id,q.record_id)=(o.tenant_id,o.collector_id,o.batch_id,o.record_id);
 SELECT q.checked_batch INTO STRICT payload FROM contour.ingestion_payloads q WHERE (q.tenant_id,q.collector_id,q.batch_id,q.payload_format)=(o.tenant_id,o.collector_id,o.batch_id,2);
 SELECT item.value->'record' INTO STRICT request_record FROM jsonb_array_elements((convert_from(payload,'UTF8')::jsonb)->'records') item(value) WHERE item.value->'record'->>'record_id'=o.record_id::text;
 RETURN coalesce(request_record->>'direction'='request' AND origin.proof_id=o.proof_id AND origin.source_id=(gw.claim).source_id
  AND (origin.origin_project_id,origin.origin_service_id,origin.origin_environment_id,origin.origin_deployment_id,origin.instance_id,origin.lifecycle_id,origin.credential_id,origin.leaf_sha256)=(x.project_id,x.service_id,x.environment_id,x.deployment_id,x.instance_id,x.lifecycle_id,m.product_credential_id,m.product_leaf_sha256)
  AND (verified.origin_project_id,verified.origin_service_id,verified.origin_environment_id,verified.origin_deployment_id,verified.instance_id,verified.lifecycle_id,verified.credential_id)=(origin.origin_project_id,origin.origin_service_id,origin.origin_environment_id,origin.origin_deployment_id,origin.instance_id,origin.lifecycle_id,origin.credential_id),false);
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION contour.receiver_observer_current(contour.causal_receiver_assignments,timestamptz) FROM PUBLIC,contour_runtime,contour_causal_receiver_writer;
REVOKE ALL ON FUNCTION contour.receiver_tombstone_metadata(contour.causal_receiver_assignments,bytea),contour.receiver_assignment_metadata(contour.causal_receiver_assignments),contour.receiver_enrollment_current(contour.causal_receiver_assignments,timestamptz),contour.receiver_assignment_current(contour.causal_receiver_assignments,timestamptz) FROM PUBLIC,contour_runtime,contour_causal_receiver_writer;

REVOKE ALL ON TYPE contour.verified_receiver_claim FROM PUBLIC,contour_runtime,contour_causal_receiver_writer;
REVOKE ALL ON FUNCTION contour.receiver_inbox_wire(bytea) FROM PUBLIC,contour_runtime,contour_causal_receiver_writer;
-- Symmetric receiver-first check: original SQL27 admission remains otherwise intact.
CREATE OR REPLACE FUNCTION contour.accept_causal_observer(raw bytea, proof contour.verified_observer_claim) RETURNS bytea
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j jsonb; b jsonb; x contour.causal_session_claim; t uuid; gwid uuid; gen text; handle text; prev text;
 collector uuid; rec uuid; bid uuid; runtime uuid; ep numeric; attempt_value text; md text; leaf bytea; col uuid;
 gateway contour.causal_gateway_enrollments; gateway2 contour.causal_gateway_enrollments;
 binding contour.causal_runtime_bindings; marker contour.causal_marker_bindings; w contour.observation_windows;
 origin contour.origin_proofs; verified record; batch_payload bytea; record_json jsonb; old contour.causal_observer_inbox;
 reservation contour.causal_observer_attempt_reservations; meta bytea; stored_receipt bytea; fact_hash bytea;
 rassign contour.causal_receiver_assignments; rassign2 contour.causal_receiver_assignments; r_enrollment contour.causal_receiver_enrollments; r_enrollment2 contour.causal_receiver_enrollments; r_binding contour.causal_runtime_bindings; r_binding2 contour.causal_runtime_bindings;
 initial_at timestamptz; final_at timestamptz; floor_at timestamptz; used bigint; charge bigint; extra bigint:=0; receipt_id uuid; receipt_cutoff timestamptz; ancestor_count integer; descendant_count integer; closes_cycle boolean;
BEGIN
 j:=contour.observer_wire(raw); b:=j->'binding'; x:=proof.producer_claim;
 t:=(b->>'tenant_id')::uuid; gwid:=(b->>'gateway_id')::uuid; gen:=b->>'gateway_generation'; handle:=b->>'delivery_handle'; prev:=b->>'retry_of';
 collector:=(b->>'collector_id')::uuid; rec:=(b->>'record_id')::uuid; bid:=(j->>'batch_id')::uuid;
 runtime:=(b->>'producer_runtime_id')::uuid; ep:=(b->>'producer_session_epoch')::numeric; attempt_value:=b->>'producer_attempt_id'; md:=b->>'marker_digest';
 PERFORM contour.begin_origin_operation(t);
 IF x IS NULL OR proof.gateway_peer_leaf IS NULL OR octet_length(proof.gateway_peer_leaf)<>32 OR proof.marker_public IS NULL OR octet_length(proof.marker_public)<>32
 OR proof.marker_generation IS NULL OR octet_length(proof.marker_generation)<>32 OR proof.marker_wire_digest IS NULL OR octet_length(proof.marker_wire_digest)<>32
 OR proof.marker_root IS NULL OR proof.marker_root COLLATE "C" !~ '^[0-9a-f]{32}$' OR proof.marker_activity IS NULL OR proof.marker_activity COLLATE "C" !~ '^[0-9a-f]{32}$'
 OR proof.marker_attempt IS DISTINCT FROM attempt_value OR encode(proof.marker_wire_digest,'hex') IS DISTINCT FROM md
 OR sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||(j->>'signed_marker'),'UTF8')) IS DISTINCT FROM proof.marker_wire_digest
 OR x.tenant_id IS DISTINCT FROM t OR x.runtime_id IS DISTINCT FROM runtime OR proof.producer_epoch IS DISTINCT FROM ep OR prev=handle
 THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO gateway FROM contour.causal_gateway_enrollments g WHERE (g.tenant_id,g.gateway_id,g.generation)=(t,gwid,gen);
 IF NOT FOUND THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO binding FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,runtime);
 IF NOT FOUND THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO marker FROM contour.causal_marker_bindings m WHERE (m.tenant_id,m.runtime_id,m.epoch)=(t,runtime,ep);
 IF NOT FOUND THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO rassign FROM contour.causal_receiver_assignments a WHERE (a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle)=(t,gwid,gen,handle);
 IF FOUND THEN
  SELECT * INTO r_enrollment FROM contour.causal_receiver_enrollments r WHERE (r.tenant_id,r.runtime_id,r.session_epoch)=(t,rassign.receiver_runtime_id,rassign.receiver_session_epoch);
  IF NOT FOUND THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO r_binding FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,rassign.receiver_runtime_id);
  IF NOT FOUND THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 FOR leaf IN SELECT DISTINCT ON (k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM (VALUES(proof.gateway_peer_leaf),((gateway.claim).observer_leaf),((gateway.claim).backend_client_leaf),(binding.export_leaf_sha256),(marker.product_leaf_sha256),((r_enrollment.claim).product_leaf),((r_enrollment.claim).export_leaf),((r_enrollment.claim).backend_leaf),((r_enrollment.claim).evidence_leaf)) leaves(v) WHERE v IS NOT NULL) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 FOR col IN SELECT DISTINCT ON (k) v FROM (SELECT v,contour.collector_lock_key(t,v) k FROM (VALUES(collector),(binding.collector_id),(r_binding.collector_id)) cols(v) WHERE v IS NOT NULL) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_collector(t,col); END LOOP;
 PERFORM contour.ensure_origin_tenant_state(t);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=t FOR UPDATE;
 INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES(t,0) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT used_bytes INTO STRICT used FROM contour.origin_logical_usage WHERE tenant_id=t FOR UPDATE;
 SELECT * INTO gateway2 FROM contour.causal_gateway_enrollments g WHERE (g.tenant_id,g.gateway_id,g.generation)=(t,gwid,gen);
 SELECT * INTO rassign2 FROM contour.causal_receiver_assignments a WHERE (a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle)=(t,gwid,gen,handle);
 IF rassign.tenant_id IS NOT NULL THEN
  SELECT * INTO r_enrollment2 FROM contour.causal_receiver_enrollments r WHERE (r.tenant_id,r.runtime_id,r.session_epoch)=(t,rassign.receiver_runtime_id,rassign.receiver_session_epoch);
  SELECT * INTO r_binding2 FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,rassign.receiver_runtime_id);
 END IF;
 initial_at:=clock_timestamp();
 IF rassign2 IS DISTINCT FROM rassign OR r_enrollment2 IS DISTINCT FROM r_enrollment OR r_binding2 IS DISTINCT FROM r_binding OR (rassign.tenant_id IS NOT NULL AND (
  rassign.receiver_runtime_id IS DISTINCT FROM (b->>'receiver_runtime_id')::uuid
  OR rassign.receiver_session_epoch IS DISTINCT FROM (b->>'receiver_session_epoch')::numeric
  OR rassign.binding_digest IS DISTINCT FROM encode(sha256(convert_to(E'apicontour/causal-evidence/binding/1\n','UTF8')||convert_to(contour.causal_json_canonical(b),'UTF8')),'hex')
  OR NOT contour.receiver_assignment_current(rassign,initial_at)))
 OR gateway2 IS DISTINCT FROM gateway OR proof.gateway_peer_leaf IS DISTINCT FROM (gateway.claim).observer_leaf OR collector IS DISTINCT FROM (gateway.claim).collector_id
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
 IF EXISTS(SELECT 1 FROM contour.causal_inbox_events e WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.attempt)=(t,runtime,ep,'attempt',attempt_value) AND (e.root,e.activity,e.marker_digest) IS DISTINCT FROM (proof.marker_root,proof.marker_activity,md))
 THEN RAISE EXCEPTION 'observer attempt unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(t,gwid,gen,handle);
 IF FOUND THEN
  IF old.canonical_fact IS DISTINCT FROM raw OR (old.runtime_id,old.session_epoch,old.attempt,old.collector_id,old.batch_id,old.record_id,old.retry_of) IS DISTINCT FROM (runtime,ep,attempt_value,collector,bid,rec,prev) OR old.marker_root IS DISTINCT FROM proof.marker_root OR old.marker_activity IS DISTINCT FROM proof.marker_activity OR old.marker_public IS DISTINCT FROM proof.marker_public OR initial_at>=old.expires_at
  THEN RAISE EXCEPTION 'observer unavailable' USING ERRCODE='23505'; END IF;
  SELECT * INTO STRICT reservation FROM contour.causal_observer_attempt_reservations r WHERE (r.tenant_id,r.runtime_id,r.session_epoch,r.attempt)=(t,runtime,ep,attempt_value);
  meta:=convert_to(contour.causal_json_canonical(jsonb_build_object('tenant_id',t,'runtime_id',runtime,'session_epoch',ep::text,'attempt',attempt_value,'gateway_id',gwid,'gateway_generation',gen,'collector_id',collector,'batch_id',bid,'record_id',rec,'marker_digest',md,'marker_root',proof.marker_root,'marker_activity',proof.marker_activity)),'UTF8');
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
  meta:=convert_to(contour.causal_json_canonical(jsonb_build_object('tenant_id',t,'runtime_id',runtime,'session_epoch',ep::text,'attempt',attempt_value,'gateway_id',gwid,'gateway_generation',gen,'collector_id',collector,'batch_id',bid,'record_id',rec,'marker_digest',md,'marker_root',proof.marker_root,'marker_activity',proof.marker_activity)),'UTF8');
  SELECT * INTO reservation FROM contour.causal_observer_attempt_reservations r WHERE (r.tenant_id,r.runtime_id,r.session_epoch,r.attempt)=(t,runtime,ep,attempt_value);
  IF FOUND THEN
   IF (reservation.gateway_id,reservation.gateway_generation,reservation.collector_id,reservation.batch_id,reservation.record_id,reservation.marker_digest,reservation.marker_root,reservation.marker_activity) IS DISTINCT FROM (gwid,gen,collector,bid,rec,md,proof.marker_root,proof.marker_activity) OR reservation.metadata IS DISTINCT FROM meta OR reservation.charged_bytes<>octet_length(meta)+256
   THEN RAISE EXCEPTION 'observer unavailable' USING ERRCODE='23505'; END IF;
  ELSE
   extra:=octet_length(meta)+256;
  END IF;
  IF prev IS NULL AND EXISTS(SELECT 1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.runtime_id,q.session_epoch,q.attempt)=(t,runtime,ep,attempt_value) AND q.retry_of IS NULL) THEN RAISE EXCEPTION 'observer retry unavailable' USING ERRCODE='23514'; END IF;
  IF prev IS NOT NULL AND EXISTS(SELECT 1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.retry_of)=(t,gwid,gen,prev)) THEN RAISE EXCEPTION 'observer retry unavailable' USING ERRCODE='23505'; END IF;
  IF prev IS NOT NULL AND EXISTS(SELECT 1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(t,gwid,gen,prev) AND (q.runtime_id,q.session_epoch,q.attempt,q.collector_id,q.batch_id,q.record_id) IS DISTINCT FROM (runtime,ep,attempt_value,collector,bid,rec)) THEN RAISE EXCEPTION 'observer retry unavailable' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT 1 FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.retry_of)=(t,gwid,gen,handle) AND (q.runtime_id,q.session_epoch,q.attempt,q.collector_id,q.batch_id,q.record_id) IS DISTINCT FROM (runtime,ep,attempt_value,collector,bid,rec)) THEN RAISE EXCEPTION 'observer retry unavailable' USING ERRCODE='23514'; END IF;
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
  IF extra>0 THEN INSERT INTO contour.causal_observer_attempt_reservations VALUES(t,runtime,ep,attempt_value,gwid,gen,collector,bid,rec,md,proof.marker_root,proof.marker_activity,meta,extra); END IF;
  INSERT INTO contour.causal_observer_epoch_reservations VALUES(t,runtime,ep,1024) ON CONFLICT DO NOTHING;
  INSERT INTO contour.causal_observer_inbox VALUES(t,gwid,gen,handle,runtime,ep,attempt_value,collector,bid,rec,prev,raw,fact_hash,proof.marker_root,proof.marker_activity,proof.marker_public,origin.proof_id,receipt_id,stored_receipt,initial_at,initial_at+interval '24 hours',octet_length(raw)+octet_length(stored_receipt)+512);
  UPDATE contour.origin_logical_usage SET used_bytes=used+charge WHERE tenant_id=t;
  receipt_cutoff:=initial_at+interval '24 hours';
 END IF;
 final_at:=clock_timestamp();
 IF (rassign.tenant_id IS NOT NULL AND NOT contour.receiver_assignment_current(rassign,final_at)) OR final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR (floor_at IS NOT NULL AND final_at<floor_at) OR final_at>=gateway.expires_at OR final_at>=receipt_cutoff OR NOT contour.gateway_claim_current(gateway.claim,final_at)
 OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals z WHERE (z.tenant_id,z.gateway_id,z.generation)=(t,gwid,gen)) OR NOT contour.causal_session_locked(x,ep,final_at)
 OR NOT contour.causal_marker_product_current(t,binding,marker.product_credential_id,marker.product_leaf_sha256,final_at)
 THEN RAISE EXCEPTION 'observer authority unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=final_at WHERE tenant_id=t;
 RETURN stored_receipt;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN RAISE EXCEPTION 'observer unavailable' USING ERRCODE='23514';
END $$;

-- Trusted caller supplies the independently authenticated receiver peer assertion.
CREATE FUNCTION contour.accept_causal_receiver(raw bytea, proof contour.verified_receiver_claim) RETURNS bytea
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j jsonb; t uuid; gwid uuid; gen text; handle text; runtime uuid; ep numeric;
 gateway contour.causal_gateway_enrollments; gateway2 contour.causal_gateway_enrollments;
 receiver contour.causal_receiver_enrollments; receiver2 contour.causal_receiver_enrollments;
 rbind contour.causal_runtime_bindings; rbind2 contour.causal_runtime_bindings; ob contour.causal_observer_inbox; ob2 contour.causal_observer_inbox;
 pbind contour.causal_runtime_bindings; pbind2 contour.causal_runtime_bindings; marker contour.causal_marker_bindings; marker2 contour.causal_marker_bindings;
 a contour.causal_receiver_assignments; old contour.causal_receiver_assignments; saved contour.causal_receiver_inbox;
 leaf bytea; col uuid; initial_at timestamptz; final_at timestamptz; floor_at timestamptz; used bigint;
 charge bigint; fact_hash bytea; receipt_id uuid; receipt bytea; tomb_meta bytea; cutoff timestamptz;
BEGIN
 j:=contour.receiver_inbox_wire(raw);t:=(j->>'tenant_id')::uuid;gwid:=(j->>'gateway_id')::uuid;
 gen:=j->>'gateway_generation';handle:=j->>'delivery_handle';runtime:=(j->>'receiver_runtime_id')::uuid;ep:=(j->>'receiver_session_epoch')::numeric;
 PERFORM contour.begin_origin_operation(t);
 IF proof IS NULL OR proof.evidence_peer_leaf IS NULL OR octet_length(proof.evidence_peer_leaf)<>32
 OR proof.enrollment_generation IS NULL OR proof.enrollment_generation COLLATE "C" !~ '^[0-9a-f]{32}$' OR proof.enrollment_generation=repeat('0',32)
 OR proof.evidence_credential_id IS NULL THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT gateway FROM contour.causal_gateway_enrollments g WHERE (g.tenant_id,g.gateway_id,g.generation)=(t,gwid,gen);
 SELECT * INTO STRICT receiver FROM contour.causal_receiver_enrollments r WHERE (r.tenant_id,r.runtime_id,r.session_epoch)=(t,runtime,ep);
 SELECT * INTO STRICT rbind FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,runtime);
 SELECT * INTO ob FROM contour.causal_observer_inbox o WHERE (o.tenant_id,o.gateway_id,o.gateway_generation,o.delivery_handle)=(t,gwid,gen,handle);
 IF FOUND THEN
  SELECT * INTO STRICT pbind FROM contour.causal_runtime_bindings p WHERE (p.tenant_id,p.runtime_id)=(t,ob.runtime_id);
  SELECT * INTO STRICT marker FROM contour.causal_marker_bindings m WHERE (m.tenant_id,m.runtime_id,m.epoch)=(t,ob.runtime_id,ob.session_epoch);
 END IF;
 FOR leaf IN SELECT DISTINCT ON(k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM
  (VALUES(proof.evidence_peer_leaf),((gateway.claim).observer_leaf),((gateway.claim).backend_client_leaf),((receiver.claim).product_leaf),((receiver.claim).export_leaf),((receiver.claim).backend_leaf),((receiver.claim).evidence_leaf),(pbind.export_leaf_sha256),(marker.product_leaf_sha256)) leaves(v) WHERE v IS NOT NULL) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 FOR col IN SELECT DISTINCT ON(k) v FROM (SELECT v,contour.collector_lock_key(t,v) k FROM
  (VALUES((gateway.claim).collector_id),(rbind.collector_id),(pbind.collector_id)) cols(v) WHERE v IS NOT NULL) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_collector(t,col); END LOOP;
 PERFORM contour.ensure_origin_tenant_state(t);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=t FOR UPDATE;
 INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES(t,0) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT used_bytes INTO STRICT used FROM contour.origin_logical_usage WHERE tenant_id=t FOR UPDATE;
 SELECT * INTO STRICT gateway2 FROM contour.causal_gateway_enrollments g WHERE (g.tenant_id,g.gateway_id,g.generation)=(t,gwid,gen) FOR SHARE;
 SELECT * INTO STRICT receiver2 FROM contour.causal_receiver_enrollments r WHERE (r.tenant_id,r.runtime_id,r.session_epoch)=(t,runtime,ep) FOR SHARE;
 SELECT * INTO ob2 FROM contour.causal_observer_inbox o WHERE (o.tenant_id,o.gateway_id,o.gateway_generation,o.delivery_handle)=(t,gwid,gen,handle);
 SELECT * INTO rbind2 FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,runtime);
 IF ob.tenant_id IS NOT NULL THEN
  SELECT * INTO pbind2 FROM contour.causal_runtime_bindings p WHERE (p.tenant_id,p.runtime_id)=(t,ob.runtime_id);
  SELECT * INTO marker2 FROM contour.causal_marker_bindings m WHERE (m.tenant_id,m.runtime_id,m.epoch)=(t,ob.runtime_id,ob.session_epoch);
 END IF;
 a.tenant_id:=t;a.gateway_id:=gwid;a.gateway_generation:=gen;a.delivery_handle:=handle;
 a.receiver_runtime_id:=runtime;a.receiver_session_epoch:=ep;a.local_root:=j->>'local_root';a.binding_digest:=j->>'binding_digest';
 a.enrollment_generation:=proof.enrollment_generation;a.evidence_credential_id:=proof.evidence_credential_id;a.evidence_peer_leaf:=proof.evidence_peer_leaf;
 a.metadata:=contour.receiver_assignment_metadata(a);a.charged_bytes:=octet_length(a.metadata)+256;
 initial_at:=clock_timestamp();
 IF gateway2 IS DISTINCT FROM gateway OR receiver2 IS DISTINCT FROM receiver OR rbind2 IS DISTINCT FROM rbind OR pbind2 IS DISTINCT FROM pbind OR marker2 IS DISTINCT FROM marker OR ob2 IS DISTINCT FROM ob
 OR initial_at IS NULL OR NOT isfinite(initial_at) OR (floor_at IS NOT NULL AND initial_at<floor_at)
 OR initial_at<gateway.issued_at OR initial_at>=gateway.expires_at OR NOT contour.gateway_claim_current(gateway.claim,initial_at)
 OR gateway.metadata IS DISTINCT FROM contour.gateway_enrollment_metadata(gateway.claim,gateway.generation,gateway.issued_at,gateway.expires_at)
 OR gateway.charged_bytes<>octet_length(gateway.metadata)+octet_length((gateway.claim).policy_envelope)+256
 OR NOT EXISTS(SELECT 1 FROM contour.causal_gateway_terminal_reservations q WHERE (q.tenant_id,q.gateway_id,q.generation,q.charged_bytes)=(t,gwid,gen,1024))
 OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals q WHERE (q.tenant_id,q.gateway_id,q.generation)=(t,gwid,gen))
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations q WHERE q.leaf_sha256=(gateway.claim).observer_leaf AND q.leaf_class='gateway_observer')
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations q WHERE q.leaf_sha256=(gateway.claim).backend_client_leaf AND q.leaf_class='gateway_backend')
 OR NOT contour.receiver_enrollment_current(a,initial_at)
 OR (ob.tenant_id IS NOT NULL AND NOT contour.receiver_observer_current(a,initial_at))
 THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_receiver_assignments q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(t,gwid,gen,handle);
 IF FOUND THEN
  IF ob.tenant_id IS NULL THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
  IF old IS DISTINCT FROM a OR NOT contour.receiver_assignment_current(old,initial_at) THEN RAISE EXCEPTION 'receiver assignment unavailable' USING ERRCODE='23505'; END IF;
  SELECT * INTO STRICT saved FROM contour.causal_receiver_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(t,gwid,gen,handle);
  IF saved.canonical_fact IS DISTINCT FROM raw THEN RAISE EXCEPTION 'receiver assignment unavailable' USING ERRCODE='23505'; END IF;
  receipt:=saved.receipt;cutoff:=saved.expires_at;
 ELSE
  fact_hash:=sha256(convert_to(E'apicontour/causal-evidence/receiver/1\n','UTF8')||raw);receipt_id:=gen_random_uuid();
  receipt:=convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','receiver','fact_digest',encode(fact_hash,'hex'),'receipt_id',receipt_id,'status','stored')),'UTF8');
  tomb_meta:=contour.receiver_tombstone_metadata(a,fact_hash);
  charge:=a.charged_bytes+octet_length(tomb_meta)+256+octet_length(raw)+octet_length(receipt)+512;
  IF charge>1073741824-used THEN RAISE EXCEPTION 'origin logical quota exhausted' USING ERRCODE='54000',CONSTRAINT='origin_logical_quota_exhausted'; END IF;
  INSERT INTO contour.causal_receiver_assignments SELECT (a).*;
  INSERT INTO contour.causal_receiver_tombstones VALUES(t,gwid,gen,handle,fact_hash,tomb_meta,octet_length(tomb_meta)+256);
  INSERT INTO contour.causal_receiver_inbox VALUES(t,gwid,gen,handle,raw,fact_hash,receipt_id,receipt,initial_at,initial_at+interval '24 hours',octet_length(raw)+octet_length(receipt)+512);
  UPDATE contour.origin_logical_usage SET used_bytes=used+charge WHERE tenant_id=t;
  cutoff:=initial_at+interval '24 hours';
 END IF;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR (floor_at IS NOT NULL AND final_at<floor_at) OR final_at>=gateway.expires_at OR final_at>=cutoff
 OR NOT contour.gateway_claim_current(gateway.claim,final_at) OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals q WHERE (q.tenant_id,q.gateway_id,q.generation)=(t,gwid,gen))
 OR NOT contour.receiver_assignment_current(a,final_at)
 OR (ob.tenant_id IS NOT NULL AND NOT contour.receiver_observer_current(a,final_at))
 THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=final_at WHERE tenant_id=t;
 RETURN receipt;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN RAISE EXCEPTION 'receiver unavailable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION contour.accept_causal_receiver(bytea,contour.verified_receiver_claim) FROM PUBLIC,contour_runtime,contour_causal_receiver_writer;
GRANT USAGE ON SCHEMA contour TO contour_causal_receiver_writer;
GRANT USAGE ON TYPE contour.verified_receiver_claim TO contour_causal_receiver_writer;
GRANT EXECUTE ON FUNCTION contour.accept_causal_receiver(bytea,contour.verified_receiver_claim) TO contour_causal_receiver_writer;
INSERT INTO contour.schema_migrations(version) VALUES(29);
COMMIT;
