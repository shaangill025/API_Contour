-- Candidate authorized for disposable qualification only; production use is
-- not qualified. SQL does not establish certificate, TLS or deployment proof.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR pg_catalog.current_setting('row_security') <> 'on'
 OR pg_catalog.current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,27))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted profile migration required' USING ERRCODE='42501'; END IF;
END $$;
CREATE ROLE contour_causal_receiver_reader NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.causal_runtime_profiles
 DROP CONSTRAINT causal_runtime_profiles_profile_artifact_check,
 ADD CONSTRAINT causal_runtime_profiles_profile_artifact_check CHECK (((profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')) OR (profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000503'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex')) OR (profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000504'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'))));
ALTER TABLE contour.causal_runtime_bindings
 DROP CONSTRAINT causal_runtime_bindings_profile_artifact_check,
 ADD CONSTRAINT causal_runtime_bindings_profile_artifact_check CHECK (((profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')) OR (profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000503'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex')) OR (profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000504'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'))));
CREATE OR REPLACE FUNCTION contour.register_causal_profile(t uuid,profile uuid,artifact bytea) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing contour.causal_runtime_profiles;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 IF NOT ((profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid AND artifact IS NOT DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')) OR (profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000503'::uuid AND artifact IS NOT DISTINCT FROM decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex')) OR (profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000504'::uuid AND artifact IS NOT DISTINCT FROM decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'))) THEN RAISE EXCEPTION 'profile unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO existing FROM contour.causal_runtime_profiles WHERE tenant_id=t AND profile_id=profile;
 IF FOUND THEN
  IF existing.artifact_sha256=artifact AND existing.point_kind='node_in' AND existing.method='POST' AND existing.route='/run'
     AND existing.technique='runtime' AND existing.parser_profile='http_json_v1' THEN RETURN profile; END IF;
  RAISE EXCEPTION 'profile unavailable' USING ERRCODE='23505';
 END IF;
 INSERT INTO contour.causal_runtime_profiles VALUES (t,profile,artifact,'node_in','POST','/run','runtime','http_json_v1',pg_catalog.clock_timestamp());
 RETURN profile;
END $$;

CREATE OR REPLACE FUNCTION contour.enroll_causal_runtime(t uuid,runtime uuid,c uuid,src uuid,p uuid,s uuid,e uuid,d uuid,i uuid,lifecycle uuid,profile uuid,artifact bytea,leaf bytea) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing contour.causal_runtime_bindings; at_time timestamptz;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 PERFORM contour.lock_origin_credential(leaf);
 PERFORM contour.lock_origin_collector(t,c);
 IF runtime IS NULL OR lifecycle IS NULL OR NOT ((profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid AND artifact IS NOT DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')) OR (profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000503'::uuid AND artifact IS NOT DISTINCT FROM decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex')) OR (profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000504'::uuid AND artifact IS NOT DISTINCT FROM decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex'))) THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23514'; END IF;
 IF NOT contour.causal_legacy_authorized(t,c,src,p,s,e,d,i) OR NOT EXISTS (
  SELECT 1 FROM contour.causal_runtime_profiles x WHERE x.tenant_id=t AND x.profile_id=profile AND x.artifact_sha256=artifact
   AND x.point_kind='node_in' AND x.method='POST' AND x.route='/run' AND x.technique='runtime' AND x.parser_profile='http_json_v1')
 OR NOT EXISTS (SELECT 1 FROM contour.origin_lifecycles l WHERE l.tenant_id=t AND l.lifecycle_id=lifecycle
   AND l.project_id=p AND l.service_id=s AND l.environment_id=e AND l.deployment_id=d AND l.instance_id=i
   AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=t AND z.lifecycle_id=lifecycle AND z.event_kind='lifecycle_closed')
   AND EXISTS (SELECT 1 FROM contour.origin_credentials oc WHERE oc.tenant_id=t AND oc.lifecycle_id=lifecycle
     AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=t AND z.credential_id=oc.credential_id AND z.event_kind='credential_revoked')))
 THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23514'; END IF;
 at_time:=pg_catalog.clock_timestamp();
 IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR at_time<contour.origin_history_highwater(t,lifecycle) THEN RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514'; END IF;
 SELECT * INTO existing FROM contour.causal_runtime_bindings WHERE tenant_id=t AND runtime_id=runtime;
 IF FOUND THEN
  IF existing.collector_id=c AND existing.source_id=src AND existing.project_id=p AND existing.service_id=s AND existing.environment_id=e
    AND existing.deployment_id=d AND existing.instance_id=i AND existing.lifecycle_id=lifecycle AND existing.profile_id=profile
    AND existing.artifact_sha256=artifact AND existing.export_leaf_sha256=leaf AND existing.enrolled_at<=at_time
    AND EXISTS (SELECT 1 FROM contour.causal_leaf_reservations WHERE leaf_sha256=leaf AND leaf_class='export')
    AND NOT EXISTS (SELECT 1 FROM contour.causal_runtime_terminal_events z WHERE z.tenant_id=t AND z.runtime_id=runtime)
  THEN RETURN runtime; END IF;
  RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23505';
 END IF;
 INSERT INTO contour.causal_leaf_reservations VALUES (leaf,'export');
 INSERT INTO contour.causal_runtime_bindings VALUES (t,runtime,c,src,p,s,e,d,i,lifecycle,profile,artifact,leaf,at_time);
 RETURN runtime;
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23505';
END $$;

CREATE OR REPLACE FUNCTION contour.causal_runtime_authority_locked(x contour.causal_session_claim, now_at timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE b contour.causal_runtime_bindings; checked_at timestamptz;
BEGIN
 PERFORM contour.require_origin_locks(x.tenant_id,x.collector_id,x.export_leaf);
 checked_at:=pg_catalog.clock_timestamp();
 IF now_at IS NULL OR NOT isfinite(now_at) OR checked_at IS NULL OR NOT isfinite(checked_at) OR checked_at<now_at THEN RETURN false; END IF;
 now_at:=checked_at;
 SELECT * INTO b FROM contour.causal_runtime_bindings WHERE tenant_id=x.tenant_id AND runtime_id=x.runtime_id;
 IF NOT FOUND OR now_at IS NULL OR NOT isfinite(now_at) THEN RETURN false; END IF;
 RETURN coalesce(
  b.collector_id=x.collector_id AND b.source_id=x.source_id AND b.project_id=x.project_id
  AND b.service_id=x.service_id AND b.environment_id=x.environment_id AND b.deployment_id=x.deployment_id
  AND b.instance_id=x.instance_id AND b.lifecycle_id=x.lifecycle_id AND b.export_leaf_sha256=x.export_leaf
  AND b.artifact_sha256=x.profile_hash
  AND ((b.profile_id='00000000-0000-4000-8000-000000000501'::uuid AND x.profile_name='nodered_5_0_9_v1' AND x.profile_hash=decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex'))
   OR (b.profile_id='00000000-0000-4000-8000-000000000503'::uuid AND x.profile_name='nodered_5_0_9_wire_v1' AND x.profile_hash=decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex'))
   OR (b.profile_id='00000000-0000-4000-8000-000000000504'::uuid AND x.profile_name='nodered_5_0_9_receiver_v1' AND x.profile_hash=decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex')))
  AND b.enrolled_at<=now_at AND now_at>=contour.origin_history_highwater(x.tenant_id,x.lifecycle_id)
  AND now_at>=x.grant_issued AND now_at<x.grant_expires AND now_at>=x.policy_issued AND now_at<x.policy_expires
  AND contour.causal_legacy_authorized(x.tenant_id,x.collector_id,x.source_id,x.project_id,x.service_id,x.environment_id,x.deployment_id,x.instance_id)
  AND contour.causal_policy_exact(x.tenant_id,x.collector_id,x.policy_revision,x.policy_envelope)
  AND EXISTS (SELECT 1 FROM contour.causal_runtime_profiles p WHERE p.tenant_id=x.tenant_id AND p.profile_id=b.profile_id AND p.artifact_sha256=x.profile_hash AND p.point_kind='node_in' AND p.method='POST' AND p.route='/run' AND p.technique='runtime' AND p.parser_profile='http_json_v1')
  AND EXISTS (SELECT 1 FROM contour.causal_leaf_reservations l WHERE l.leaf_sha256=x.export_leaf AND l.leaf_class='export')
  AND NOT EXISTS (SELECT 1 FROM contour.causal_runtime_terminal_events z WHERE z.tenant_id=x.tenant_id AND z.runtime_id=x.runtime_id)
  AND EXISTS (SELECT 1 FROM contour.origin_lifecycles l WHERE l.tenant_id=x.tenant_id AND l.lifecycle_id=x.lifecycle_id
   AND l.project_id=x.project_id AND l.service_id=x.service_id AND l.environment_id=x.environment_id AND l.deployment_id=x.deployment_id AND l.instance_id=x.instance_id
   AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=l.tenant_id AND z.lifecycle_id=l.lifecycle_id AND z.event_kind='lifecycle_closed')
   AND EXISTS (SELECT 1 FROM contour.origin_credentials oc WHERE oc.tenant_id=l.tenant_id AND oc.lifecycle_id=l.lifecycle_id
    AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=oc.tenant_id AND z.credential_id=oc.credential_id AND z.event_kind='credential_revoked')))
  ,false);
END $$;


-- Immutable receiver enrollment records; identity and generation are issued
-- by the fixed-purpose provisioner. They do not authenticate a peer.
CREATE TYPE contour.receiver_enrollment_claim AS (
 tenant_id uuid, runtime_id uuid, session_epoch numeric, instance_id uuid, lifecycle_id uuid, product_credential uuid,
 product_leaf bytea, export_leaf bytea, backend_leaf bytea, evidence_leaf bytea,
 provision_nonce bytea, backend_not_before timestamptz, backend_not_after timestamptz,
 evidence_not_before timestamptz, evidence_not_after timestamptz, ttl_microseconds bigint
);
REVOKE ALL ON TYPE contour.receiver_enrollment_claim FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer,contour_causal_evidence_provisioner;

CREATE TABLE contour.causal_receiver_enrollments (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, session_epoch numeric NOT NULL
  CHECK (session_epoch=trunc(session_epoch) AND session_epoch BETWEEN 1 AND 18446744073709551615),
 enrollment_generation text NOT NULL CHECK (enrollment_generation COLLATE "C" ~ '^[0-9a-f]{32}$' AND enrollment_generation<>repeat('0',32)),
 evidence_credential_id uuid NOT NULL, claim contour.receiver_enrollment_claim NOT NULL,
 issued_at timestamptz NOT NULL CHECK (isfinite(issued_at) AND issued_at>=timestamptz '0001-01-01 00:00:00+00'),
 expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at<timestamptz '10000-01-01 00:00:00+00' AND expires_at>issued_at AND expires_at-issued_at<=interval '15 minutes'),
 metadata bytea NOT NULL CHECK (octet_length(metadata) BETWEEN 1 AND 4096),
 commitment bytea NOT NULL CHECK (octet_length(commitment)=32),
 charged_bytes bigint NOT NULL CHECK (charged_bytes=octet_length(metadata)+256),
 PRIMARY KEY (tenant_id,runtime_id,session_epoch),
 UNIQUE (enrollment_generation), UNIQUE (evidence_credential_id),
 FOREIGN KEY (tenant_id,runtime_id,session_epoch) REFERENCES contour.causal_sessions(tenant_id,runtime_id,epoch),
 CHECK ((claim).tenant_id IS NOT DISTINCT FROM tenant_id AND (claim).runtime_id IS NOT DISTINCT FROM runtime_id AND (claim).session_epoch IS NOT DISTINCT FROM session_epoch),
 CHECK ((claim).instance_id IS NOT NULL AND (claim).lifecycle_id IS NOT NULL AND
        (claim).product_credential IS NOT NULL AND (claim).product_credential<>evidence_credential_id),
 CHECK ((claim).product_leaf IS NOT NULL AND octet_length((claim).product_leaf)=32 AND
        (claim).export_leaf IS NOT NULL AND octet_length((claim).export_leaf)=32 AND
        (claim).backend_leaf IS NOT NULL AND octet_length((claim).backend_leaf)=32 AND
        (claim).evidence_leaf IS NOT NULL AND octet_length((claim).evidence_leaf)=32 AND
        (claim).product_leaf<>(claim).export_leaf AND (claim).product_leaf<>(claim).backend_leaf AND
        (claim).product_leaf<>(claim).evidence_leaf AND (claim).export_leaf<>(claim).backend_leaf AND
        (claim).export_leaf<>(claim).evidence_leaf AND (claim).backend_leaf<>(claim).evidence_leaf),
 CHECK ((claim).provision_nonce IS NOT NULL AND octet_length((claim).provision_nonce)=32),
 CHECK ((claim).ttl_microseconds IS NOT NULL AND (claim).ttl_microseconds BETWEEN 1 AND 900000000 AND
        expires_at<=issued_at+(claim).ttl_microseconds*interval '1 microsecond'),
 CHECK ((claim).backend_not_before IS NOT NULL AND isfinite((claim).backend_not_before) AND
        (claim).backend_not_after IS NOT NULL AND isfinite((claim).backend_not_after) AND
        (claim).evidence_not_before IS NOT NULL AND isfinite((claim).evidence_not_before) AND
        (claim).evidence_not_after IS NOT NULL AND isfinite((claim).evidence_not_after) AND
        (claim).backend_not_before<=(claim).backend_not_after AND
        (claim).evidence_not_before<=(claim).evidence_not_after AND
        issued_at>=(claim).backend_not_before AND expires_at<=(claim).backend_not_after AND
        issued_at>=(claim).evidence_not_before AND expires_at<=(claim).evidence_not_after)
);
CREATE UNIQUE INDEX causal_receiver_nonce ON contour.causal_receiver_enrollments
 (tenant_id,runtime_id,((claim).provision_nonce));
CREATE TABLE contour.causal_receiver_terminal_reservations (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, session_epoch numeric NOT NULL,
 charged_bytes integer NOT NULL CHECK (charged_bytes=1024),
 PRIMARY KEY (tenant_id,runtime_id,session_epoch),
 FOREIGN KEY (tenant_id,runtime_id,session_epoch) REFERENCES contour.causal_receiver_enrollments
);
CREATE TABLE contour.causal_receiver_terminals (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, session_epoch numeric NOT NULL,
 reason text NOT NULL CHECK (reason IN ('expired','operator_revoked')),
 effective_at timestamptz NOT NULL CHECK (isfinite(effective_at)),
 canonical_body bytea NOT NULL CHECK (octet_length(canonical_body) BETWEEN 1 AND 768),
 PRIMARY KEY (tenant_id,runtime_id,session_epoch),
 FOREIGN KEY (tenant_id,runtime_id,session_epoch) REFERENCES contour.causal_receiver_terminal_reservations
);
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['causal_receiver_enrollments','causal_receiver_terminal_reservations','causal_receiver_terminals'] LOOP
  EXECUTE format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY receiver_owner ON contour.%I TO contour_owner USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context())',n);
  EXECUTE format('REVOKE ALL ON contour.%I FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer,contour_causal_evidence_provisioner',n);
  EXECUTE format('CREATE TRIGGER receiver_immutable BEFORE UPDATE OR DELETE ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()',n);
  EXECUTE format('CREATE TRIGGER receiver_no_truncate BEFORE TRUNCATE ON contour.%I FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row()',n);
 END LOOP;
END $$;
-- Encoding helper is data only. Its callers must establish authority separately.
CREATE FUNCTION contour.receiver_enrollment_metadata(x contour.receiver_enrollment_claim,
 s contour.causal_sessions, gen text, credential uuid, issued timestamptz, expires timestamptz)
RETURNS bytea LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE body bytea;
BEGIN
 IF x.tenant_id IS NULL OR x.runtime_id IS NULL OR x.instance_id IS NULL OR x.lifecycle_id IS NULL
 OR x.product_credential IS NULL OR credential IS NULL OR s.nonce IS NULL
 OR x.session_epoch IS NULL OR x.session_epoch<>trunc(x.session_epoch) OR x.session_epoch NOT BETWEEN 1 AND 18446744073709551615
 OR (s.claim).policy_revision IS NULL OR (s.claim).policy_revision<>trunc((s.claim).policy_revision) OR (s.claim).policy_revision NOT BETWEEN 1 AND 18446744073709551615
 OR (s.claim).policy_envelope IS NULL OR octet_length((s.claim).policy_envelope) NOT BETWEEN 1 AND 1048576
 OR (s.claim).grant_digest IS NULL OR octet_length((s.claim).grant_digest)<>32
 OR x.product_leaf IS NULL OR octet_length(x.product_leaf)<>32 OR x.export_leaf IS NULL OR octet_length(x.export_leaf)<>32
 OR x.backend_leaf IS NULL OR octet_length(x.backend_leaf)<>32 OR x.evidence_leaf IS NULL OR octet_length(x.evidence_leaf)<>32
 OR gen IS NULL OR gen COLLATE "C" !~ '^[0-9a-f]{32}$' OR gen=repeat('0',32)
 OR issued IS NULL OR expires IS NULL OR NOT isfinite(issued) OR NOT isfinite(expires)
 OR issued<timestamptz '0001-01-01 00:00:00+00' OR expires>=timestamptz '10000-01-01 00:00:00+00' OR expires<=issued
 OR (s.tenant_id,s.runtime_id,s.epoch) IS DISTINCT FROM (x.tenant_id,x.runtime_id,x.session_epoch)
 THEN RAISE EXCEPTION 'receiver encoding unavailable' USING ERRCODE='23514'; END IF;
 body:=convert_to(contour.causal_json_canonical(jsonb_build_object(
  'artifact_sha256','707e7b359fb757c668d8a22c999e067556b5f2a785f9c3333c12fca7debfa660',
  'backend_leaf_sha256',encode(x.backend_leaf,'hex'), 'enrollment_generation',gen,
  'evidence_credential_id',credential::text, 'evidence_leaf_sha256',encode(x.evidence_leaf,'hex'),
  'expires_at',to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'export_leaf_sha256',encode(x.export_leaf,'hex'), 'grant_digest',encode((s.claim).grant_digest,'hex'),
  'instance_id',x.instance_id::text, 'issued_at',to_char(issued AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'lifecycle_id',x.lifecycle_id::text, 'policy_envelope_sha256',encode(sha256((s.claim).policy_envelope),'hex'),
  'policy_revision',trunc((s.claim).policy_revision)::text, 'product_credential_id',x.product_credential::text,
  'product_leaf_sha256',encode(x.product_leaf,'hex'), 'profile_id','00000000-0000-4000-8000-000000000504',
  'profile_manifest_sha256','c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0',
  'runtime_id',x.runtime_id::text, 'session_epoch',trunc(x.session_epoch)::text,
  'session_nonce',s.nonce::text, 'tenant_id',x.tenant_id::text, 'version',1)),'UTF8');
 IF octet_length(body) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'receiver encoding unavailable' USING ERRCODE='23514'; END IF;
 RETURN body;
END $$;
CREATE FUNCTION contour.receiver_enrollment_commitment(body bytea) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 IF body IS NULL OR octet_length(body) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'receiver encoding unavailable' USING ERRCODE='23514'; END IF;
 RETURN sha256(convert_to(E'apicontour/receiver-enrollment/1\n','UTF8') || int4send(octet_length(body)) || body);
END $$;
REVOKE ALL ON FUNCTION contour.receiver_enrollment_metadata(contour.receiver_enrollment_claim,contour.causal_sessions,text,uuid,timestamptz,timestamptz),contour.receiver_enrollment_commitment(bytea)
 FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer,contour_causal_evidence_provisioner;

-- Private predicate only; the caller must acquire all four credential locks and
-- the collector lock before invoking it. This is not a peer or TLS assertion.
CREATE FUNCTION contour.receiver_claim_current(x contour.receiver_enrollment_claim,
 s contour.causal_sessions, b contour.causal_runtime_bindings, at_time timestamptz)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM contour.require_origin_locks(x.tenant_id,b.collector_id,x.product_leaf);
 PERFORM contour.require_origin_locks(x.tenant_id,b.collector_id,x.export_leaf);
 PERFORM contour.require_origin_locks(x.tenant_id,b.collector_id,x.backend_leaf);
 PERFORM contour.require_origin_locks(x.tenant_id,b.collector_id,x.evidence_leaf);
 RETURN coalesce(x.tenant_id=contour.tenant_context()
  AND (s.tenant_id,s.runtime_id,s.epoch)=(x.tenant_id,x.runtime_id,x.session_epoch)
  AND (b.tenant_id,b.runtime_id)=(x.tenant_id,x.runtime_id)
  AND x.instance_id=b.instance_id AND x.lifecycle_id=b.lifecycle_id
  AND x.export_leaf=b.export_leaf_sha256 AND x.export_leaf=(s.claim).export_leaf
  AND b.profile_id='00000000-0000-4000-8000-000000000504'::uuid
  AND b.artifact_sha256=decode('c370140ed0384aa54048fb41b4a35cca162370fd25c58f55cb8b037998e308b0','hex')
  AND (s.claim).profile_name='nodered_5_0_9_receiver_v1'
  AND (s.claim).profile_hash=b.artifact_sha256
  AND at_time>=x.backend_not_before AND at_time<x.backend_not_after
  AND at_time>=x.evidence_not_before AND at_time<x.evidence_not_after
  AND contour.causal_session_locked(s.claim,s.epoch,at_time)
  AND contour.causal_marker_product_current(x.tenant_id,b,x.product_credential,x.product_leaf,at_time),false);
END $$;
REVOKE ALL ON FUNCTION contour.receiver_claim_current(contour.receiver_enrollment_claim,contour.causal_sessions,contour.causal_runtime_bindings,timestamptz)
 FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer,contour_causal_evidence_provisioner;

-- Public enrollment race qualification remains outstanding.
CREATE FUNCTION contour.enroll_causal_receiver(x contour.receiver_enrollment_claim)
RETURNS TABLE(generation text, credential_id uuid, issued_at timestamptz, expires_at timestamptz, commitment bytea)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b contour.causal_runtime_bindings; b2 contour.causal_runtime_bindings;
 s contour.causal_sessions; s2 contour.causal_sessions; old contour.causal_receiver_enrollments;
 leaf bytea; floor_at timestamptz; initial_at timestamptz; final_at timestamptz;
 used bigint; newgen text; ra text; rb text; cred uuid; until_at timestamptz; meta bytea; charge bigint;
BEGIN
 PERFORM contour.begin_origin_operation(x.tenant_id);
 IF x.runtime_id IS NULL OR x.session_epoch IS NULL OR x.session_epoch<>trunc(x.session_epoch)
 OR x.session_epoch NOT BETWEEN 1 AND 18446744073709551615 OR x.instance_id IS NULL OR x.lifecycle_id IS NULL OR x.product_credential IS NULL
 OR x.product_leaf IS NULL OR octet_length(x.product_leaf)<>32 OR x.export_leaf IS NULL OR octet_length(x.export_leaf)<>32
 OR x.backend_leaf IS NULL OR octet_length(x.backend_leaf)<>32 OR x.evidence_leaf IS NULL OR octet_length(x.evidence_leaf)<>32
 OR x.product_leaf=x.export_leaf OR x.product_leaf=x.backend_leaf OR x.product_leaf=x.evidence_leaf
 OR x.export_leaf=x.backend_leaf OR x.export_leaf=x.evidence_leaf OR x.backend_leaf=x.evidence_leaf
 OR x.provision_nonce IS NULL OR octet_length(x.provision_nonce)<>32
 OR x.ttl_microseconds IS NULL OR x.ttl_microseconds NOT BETWEEN 1 AND 900000000
 OR x.backend_not_before IS NULL OR NOT isfinite(x.backend_not_before) OR x.backend_not_after IS NULL OR NOT isfinite(x.backend_not_after)
 OR x.evidence_not_before IS NULL OR NOT isfinite(x.evidence_not_before) OR x.evidence_not_after IS NULL OR NOT isfinite(x.evidence_not_after)
 OR x.backend_not_before>=x.backend_not_after OR x.evidence_not_before>=x.evidence_not_after
 THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO b FROM contour.causal_runtime_bindings WHERE (tenant_id,runtime_id)=(x.tenant_id,x.runtime_id);
 IF NOT FOUND THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO s FROM contour.causal_sessions WHERE (tenant_id,runtime_id,epoch)=(x.tenant_id,x.runtime_id,x.session_epoch);
 IF NOT FOUND THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 FOR leaf IN SELECT DISTINCT ON (k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM
  (VALUES(x.product_leaf),(x.export_leaf),(x.backend_leaf),(x.evidence_leaf)) leaves(v)) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 PERFORM contour.lock_origin_collector(x.tenant_id,b.collector_id);
 PERFORM contour.ensure_origin_tenant_state(x.tenant_id);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=x.tenant_id FOR UPDATE;
 INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES(x.tenant_id,0) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT used_bytes INTO STRICT used FROM contour.origin_logical_usage WHERE tenant_id=x.tenant_id FOR UPDATE;
 SELECT * INTO b2 FROM contour.causal_runtime_bindings WHERE (tenant_id,runtime_id)=(x.tenant_id,x.runtime_id);
 SELECT * INTO s2 FROM contour.causal_sessions WHERE (tenant_id,runtime_id,epoch)=(x.tenant_id,x.runtime_id,x.session_epoch);
 initial_at:=clock_timestamp();
 IF b2 IS DISTINCT FROM b OR s2 IS DISTINCT FROM s OR initial_at IS NULL OR NOT isfinite(initial_at)
 OR initial_at<timestamptz '0001-01-01 00:00:00+00' OR initial_at>=timestamptz '10000-01-01 00:00:00+00'
 OR (floor_at IS NOT NULL AND initial_at<floor_at) OR NOT contour.receiver_claim_current(x,s,b,initial_at)
 THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_receiver_enrollments e WHERE (e.tenant_id,e.runtime_id,e.session_epoch)=(x.tenant_id,x.runtime_id,x.session_epoch);
 IF FOUND THEN
  IF old.claim IS DISTINCT FROM x OR initial_at>=old.expires_at OR EXISTS(SELECT 1 FROM contour.causal_receiver_terminals z WHERE (z.tenant_id,z.runtime_id,z.session_epoch)=(old.tenant_id,old.runtime_id,old.session_epoch))
  OR old.metadata IS DISTINCT FROM contour.receiver_enrollment_metadata(x,s,old.enrollment_generation,old.evidence_credential_id,old.issued_at,old.expires_at)
  OR old.commitment IS DISTINCT FROM contour.receiver_enrollment_commitment(old.metadata)
  OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations l WHERE l.leaf_sha256=x.backend_leaf AND l.leaf_class='receiver_backend')
  OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations l WHERE l.leaf_sha256=x.evidence_leaf AND l.leaf_class='receiver_evidence')
  OR NOT EXISTS(SELECT 1 FROM contour.causal_receiver_terminal_reservations r WHERE (r.tenant_id,r.runtime_id,r.session_epoch,r.charged_bytes)=(x.tenant_id,x.runtime_id,x.session_epoch,1024))
  THEN RAISE EXCEPTION 'receiver enrollment unavailable' USING ERRCODE='23505'; END IF;
 ELSE
  ra:=replace(gen_random_uuid()::text,'-',''); rb:=replace(gen_random_uuid()::text,'-','');
  newgen:=substr(ra,1,12)||substr(ra,14,3)||substr(ra,18,1)||substr(rb,1,12)||substr(rb,14,3)||substr(rb,18,1);
  cred:=gen_random_uuid(); until_at:=least(initial_at+x.ttl_microseconds*interval '1 microsecond',s.expires_at,(s.claim).grant_expires,(s.claim).policy_expires,x.backend_not_after,x.evidence_not_after);
  IF until_at<=initial_at OR newgen=repeat('0',32) THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
  IF octet_length(contour.receiver_terminal_body(x.tenant_id,x.runtime_id,x.session_epoch,newgen,initial_at,'operator_revoked')) NOT BETWEEN 1 AND 768
  THEN RAISE EXCEPTION 'receiver terminal encoding invalid' USING ERRCODE='23514'; END IF;
  meta:=contour.receiver_enrollment_metadata(x,s,newgen,cred,initial_at,until_at); charge:=octet_length(meta)+256;
  IF 1024+charge>1073741824-used THEN RAISE EXCEPTION 'origin logical quota exhausted' USING ERRCODE='54000',CONSTRAINT='origin_logical_quota_exhausted'; END IF;
  INSERT INTO contour.causal_leaf_reservations VALUES(x.backend_leaf,'receiver_backend'),(x.evidence_leaf,'receiver_evidence');
  INSERT INTO contour.causal_receiver_enrollments VALUES(x.tenant_id,x.runtime_id,x.session_epoch,newgen,cred,x,initial_at,until_at,meta,contour.receiver_enrollment_commitment(meta),charge) RETURNING * INTO old;
  INSERT INTO contour.causal_receiver_terminal_reservations VALUES(x.tenant_id,x.runtime_id,x.session_epoch,1024);
  UPDATE contour.origin_logical_usage SET used_bytes=used+charge+1024 WHERE tenant_id=x.tenant_id;
 END IF;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR (floor_at IS NOT NULL AND final_at<floor_at)
 OR final_at>=old.expires_at OR NOT contour.receiver_claim_current(x,s,b,final_at)
 THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=final_at WHERE tenant_id=x.tenant_id;
 RETURN QUERY SELECT old.enrollment_generation,old.evidence_credential_id,old.issued_at,old.expires_at,old.commitment;
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'receiver enrollment unavailable' USING ERRCODE='23505';
END $$;
REVOKE ALL ON FUNCTION contour.enroll_causal_receiver(contour.receiver_enrollment_claim) FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer,contour_causal_evidence_provisioner;

-- Exact selector only; it reports SQL authority, not peer possession or gateway authority.
CREATE FUNCTION contour.current_causal_receiver(t uuid, runtime uuid, ep numeric, gen text, evidence_leaf bytea)
RETURNS TABLE(credential_id uuid, metadata bytea, commitment bytea, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old contour.causal_receiver_enrollments; checked contour.causal_receiver_enrollments;
 b contour.causal_runtime_bindings; b2 contour.causal_runtime_bindings; s contour.causal_sessions; s2 contour.causal_sessions;
 leaf bytea; floor_at timestamptz; initial_at timestamptz; final_at timestamptz;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 IF runtime IS NULL OR ep IS NULL OR ep<>trunc(ep) OR ep NOT BETWEEN 1 AND 18446744073709551615
 OR gen IS NULL OR gen COLLATE "C" !~ '^[0-9a-f]{32}$' OR gen=repeat('0',32)
 OR evidence_leaf IS NULL OR octet_length(evidence_leaf)<>32
 THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_receiver_enrollments e WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.enrollment_generation)=(t,runtime,ep,gen);
 IF NOT FOUND THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO b FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,runtime);
 IF NOT FOUND THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO s FROM contour.causal_sessions q WHERE (q.tenant_id,q.runtime_id,q.epoch)=(t,runtime,ep);
 IF NOT FOUND THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 FOR leaf IN SELECT DISTINCT ON (k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM
  (VALUES((old.claim).product_leaf),((old.claim).export_leaf),((old.claim).backend_leaf),((old.claim).evidence_leaf)) leaves(v)) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 PERFORM contour.lock_origin_collector(t,b.collector_id);
 PERFORM contour.ensure_origin_tenant_state(t);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=t FOR UPDATE;
 PERFORM 1 FROM contour.origin_logical_usage WHERE tenant_id=t AND used_bytes>=1024 FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO checked FROM contour.causal_receiver_enrollments e WHERE (e.tenant_id,e.runtime_id,e.session_epoch)=(t,runtime,ep);
 SELECT * INTO b2 FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,runtime);
 SELECT * INTO s2 FROM contour.causal_sessions q WHERE (q.tenant_id,q.runtime_id,q.epoch)=(t,runtime,ep);
 initial_at:=clock_timestamp();
 IF checked IS DISTINCT FROM old OR b2 IS DISTINCT FROM b OR s2 IS DISTINCT FROM s
 OR initial_at IS NULL OR NOT isfinite(initial_at)
 OR initial_at<timestamptz '0001-01-01 00:00:00+00' OR initial_at>=timestamptz '10000-01-01 00:00:00+00'
 OR (floor_at IS NOT NULL AND initial_at<floor_at) OR initial_at>=old.expires_at OR (old.claim).evidence_leaf IS DISTINCT FROM evidence_leaf OR NOT contour.receiver_claim_current(old.claim,s,b,initial_at)
 OR EXISTS(SELECT 1 FROM contour.causal_receiver_terminals z WHERE (z.tenant_id,z.runtime_id,z.session_epoch)=(t,runtime,ep))
 OR old.metadata IS DISTINCT FROM contour.receiver_enrollment_metadata(old.claim,s,old.enrollment_generation,old.evidence_credential_id,old.issued_at,old.expires_at)
 OR old.commitment IS DISTINCT FROM contour.receiver_enrollment_commitment(old.metadata)
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations l WHERE l.leaf_sha256=(old.claim).backend_leaf AND l.leaf_class='receiver_backend')
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations l WHERE l.leaf_sha256=(old.claim).evidence_leaf AND l.leaf_class='receiver_evidence')
 OR NOT EXISTS(SELECT 1 FROM contour.causal_receiver_terminal_reservations r WHERE (r.tenant_id,r.runtime_id,r.session_epoch,r.charged_bytes)=(t,runtime,ep,1024))
 THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR final_at>=old.expires_at OR NOT contour.receiver_claim_current(old.claim,s,b,final_at)
 THEN RAISE EXCEPTION 'receiver authority unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=final_at WHERE tenant_id=t;
 RETURN QUERY SELECT old.evidence_credential_id,old.metadata,old.commitment,old.expires_at;
END $$;
REVOKE ALL ON FUNCTION contour.current_causal_receiver(uuid,uuid,numeric,text,bytea) FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer,contour_causal_evidence_provisioner;

CREATE FUNCTION contour.receiver_terminal_body(t uuid, runtime uuid, ep numeric, gen text, at_time timestamptz, why text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','receiver',
 'tenant_id',t,'gateway_id',NULL,'gateway_generation',NULL,'runtime_id',runtime,'session_epoch',trunc(ep)::text,
 'effective_at',to_char(at_time AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'reason',why)),'UTF8')
$$;
CREATE FUNCTION contour.close_causal_receiver(t uuid, runtime uuid, ep numeric, gen text, why text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old contour.causal_receiver_enrollments; checked contour.causal_receiver_enrollments;
 b contour.causal_runtime_bindings; b2 contour.causal_runtime_bindings; prior contour.causal_receiver_terminals;
 leaf bytea; floor_at timestamptz; initial_at timestamptz; final_at timestamptz; body bytea;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 IF runtime IS NULL OR ep IS NULL OR ep<>trunc(ep) OR ep NOT BETWEEN 1 AND 18446744073709551615
 OR gen IS NULL OR gen COLLATE "C" !~ '^[0-9a-f]{32}$' OR gen=repeat('0',32)
 OR why IS NULL OR why NOT IN ('expired','operator_revoked')
 THEN RAISE EXCEPTION 'receiver closure unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_receiver_enrollments e WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.enrollment_generation)=(t,runtime,ep,gen);
 IF NOT FOUND THEN RAISE EXCEPTION 'receiver closure unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO b FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,runtime);
 IF NOT FOUND THEN RAISE EXCEPTION 'receiver closure unavailable' USING ERRCODE='23514'; END IF;
 FOR leaf IN SELECT DISTINCT ON (k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM
  (VALUES((old.claim).product_leaf),((old.claim).export_leaf),((old.claim).backend_leaf),((old.claim).evidence_leaf)) leaves(v)) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 PERFORM contour.lock_origin_collector(t,b.collector_id);
 PERFORM contour.ensure_origin_tenant_state(t);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=t FOR UPDATE;
 PERFORM 1 FROM contour.origin_logical_usage WHERE tenant_id=t AND used_bytes>=1024 FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'receiver closure unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO checked FROM contour.causal_receiver_enrollments e WHERE (e.tenant_id,e.runtime_id,e.session_epoch)=(t,runtime,ep);
 SELECT * INTO b2 FROM contour.causal_runtime_bindings r WHERE (r.tenant_id,r.runtime_id)=(t,runtime);
 initial_at:=clock_timestamp();
 IF checked IS DISTINCT FROM old OR b2 IS DISTINCT FROM b OR initial_at IS NULL OR NOT isfinite(initial_at)
 OR initial_at<timestamptz '0001-01-01 00:00:00+00' OR initial_at>=timestamptz '10000-01-01 00:00:00+00'
 OR (floor_at IS NOT NULL AND initial_at<floor_at) OR (why='expired' AND initial_at<old.expires_at)
 OR NOT EXISTS(SELECT 1 FROM contour.causal_receiver_terminal_reservations r WHERE (r.tenant_id,r.runtime_id,r.session_epoch,r.charged_bytes)=(t,runtime,ep,1024))
 THEN RAISE EXCEPTION 'receiver closure unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO prior FROM contour.causal_receiver_terminals z WHERE (z.tenant_id,z.runtime_id,z.session_epoch)=(t,runtime,ep);
 IF FOUND THEN
  IF prior.reason<>why OR prior.canonical_body IS DISTINCT FROM contour.receiver_terminal_body(t,runtime,ep,gen,prior.effective_at,prior.reason)
  THEN RAISE EXCEPTION 'receiver closure unavailable' USING ERRCODE='23505'; END IF;
 ELSE
  body:=contour.receiver_terminal_body(t,runtime,ep,gen,initial_at,why);
  IF octet_length(body) NOT BETWEEN 1 AND 768 THEN RAISE EXCEPTION 'receiver closure unavailable' USING ERRCODE='23514'; END IF;
  INSERT INTO contour.causal_receiver_terminals VALUES(t,runtime,ep,why,initial_at,body);
 END IF;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR (floor_at IS NOT NULL AND final_at<floor_at)
 THEN RAISE EXCEPTION 'receiver closure unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=final_at WHERE tenant_id=t;
END $$;
REVOKE ALL ON FUNCTION contour.receiver_terminal_body(uuid,uuid,numeric,text,timestamptz,text),contour.close_causal_receiver(uuid,uuid,numeric,text,text)
 FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer,contour_causal_evidence_provisioner;

-- Only these fixed-purpose functions are granted; no raw table access.
GRANT USAGE ON SCHEMA contour TO contour_causal_receiver_reader;
GRANT USAGE ON TYPE contour.receiver_enrollment_claim TO contour_causal_evidence_provisioner;
GRANT EXECUTE ON FUNCTION contour.enroll_causal_receiver(contour.receiver_enrollment_claim),contour.close_causal_receiver(uuid,uuid,numeric,text,text) TO contour_causal_evidence_provisioner;
GRANT EXECUTE ON FUNCTION contour.current_causal_receiver(uuid,uuid,numeric,text,bytea) TO contour_causal_receiver_reader;

INSERT INTO contour.schema_migrations(version) VALUES(28);
COMMIT;
