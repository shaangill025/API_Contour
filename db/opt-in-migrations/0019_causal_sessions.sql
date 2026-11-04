-- Internal trusted-issuer assertions only: this migration verifies neither mTLS nor
-- signatures. A future handler must independently verify grant and policy envelopes,
-- their complete scope and capture permissions before invoking these entrypoints.
-- The future trusted binder must keep core verification at full precision, ceil
-- issued/not-before instants to PostgreSQL microseconds, floor expiry/not-after
-- instants, and refuse conversion overflow or an empty window. SQL cannot recover
-- precision already rounded by a caller or a timestamp cast.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR pg_catalog.current_setting('row_security') <> 'on'
 OR pg_catalog.current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,18))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted session migration required' USING ERRCODE='42501'; END IF;
END $$;
CREATE ROLE contour_causal_issuer NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
-- Admin already has legacy read authority; this capability returns only a boolean.
CREATE FUNCTION contour.causal_policy_exact(t uuid,c uuid,rev numeric,envelope bytea) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce(t=contour.tenant_context() AND EXISTS (
  SELECT 1 FROM contour.collector_authorization ca JOIN contour.policy_revisions pr
   ON pr.tenant_id=ca.tenant_id AND pr.collector_id=ca.collector_id AND pr.revision=ca.active_revision
  WHERE ca.tenant_id=t AND ca.collector_id=c AND ca.enabled AND ca.revoked_at IS NULL
   AND ca.active_revision=rev AND pr.signed_envelope=envelope),false)
$$;
ALTER FUNCTION contour.causal_policy_exact(uuid,uuid,numeric,bytea) OWNER TO contour_admin;
REVOKE ALL ON FUNCTION contour.causal_policy_exact(uuid,uuid,numeric,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.causal_policy_exact(uuid,uuid,numeric,bytea) TO contour_owner;
SET LOCAL ROLE contour_owner;
-- All fields are issuer assertions derived from independently verified bytes.
-- The fixed profile name maps to migration 18's canonical artifact manifest hash,
-- not the nested source hash or the grant payload digest.
CREATE TYPE contour.causal_session_claim AS (
 tenant_id uuid, runtime_id uuid, collector_id uuid, source_id uuid,
 project_id uuid, service_id uuid, environment_id uuid, deployment_id uuid,
 instance_id uuid, lifecycle_id uuid, export_leaf bytea,
 profile_name text, profile_hash bytea, nonce uuid,
 grant_revision numeric, grant_digest bytea, grant_issued timestamptz, grant_expires timestamptz,
 policy_revision numeric, policy_envelope bytea, policy_issued timestamptz, policy_expires timestamptz,
 ttl_microseconds bigint, max_batch_events bigint, max_batch_bytes bigint, queue_bytes bigint, queue_ttl_seconds bigint
);
CREATE TABLE contour.causal_sessions (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, epoch numeric NOT NULL
  CHECK (epoch=trunc(epoch) AND epoch BETWEEN 1 AND 18446744073709551615),
 nonce uuid NOT NULL, claim contour.causal_session_claim NOT NULL,
 issued_at timestamptz NOT NULL CHECK (isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at>issued_at),
 PRIMARY KEY (tenant_id,runtime_id,epoch), UNIQUE (tenant_id,runtime_id,nonce),
 FOREIGN KEY (tenant_id,runtime_id) REFERENCES contour.causal_runtime_bindings
);
ALTER TABLE contour.causal_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.causal_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY causal_session_owner ON contour.causal_sessions TO contour_owner
 USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.causal_sessions FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer;
CREATE TRIGGER causal_session_immutable BEFORE UPDATE OR DELETE ON contour.causal_sessions FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER causal_session_no_truncate BEFORE TRUNCATE ON contour.causal_sessions FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();

-- Private runtime-authority predicate for pre-issuance and the session check.
-- Both predicates require the caller to hold Q, this exact export leaf and C,
-- acquired in that order in a fresh READ COMMITTED operation. Their time input
-- is only a lower bound: each reads the DB clock. They never acquire Q again.
CREATE FUNCTION contour.causal_runtime_authority_locked(x contour.causal_session_claim, now_at timestamptz) RETURNS boolean
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
  AND b.profile_id='00000000-0000-4000-8000-000000000501'::uuid AND b.artifact_sha256=x.profile_hash
  AND x.profile_name='nodered_5_0_9_v1' AND x.profile_hash=decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')
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
-- Future admission must invoke this predicate with a real epoch in the SAME
-- locked transaction as its write. An unlocked read cannot establish a lease.
CREATE FUNCTION contour.causal_session_locked(x contour.causal_session_claim, ep numeric, now_at timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE checked_at timestamptz;
BEGIN
 IF ep IS NULL OR ep<>trunc(ep) OR ep NOT BETWEEN 1 AND 18446744073709551615 THEN RETURN false; END IF;
 PERFORM contour.require_origin_locks(x.tenant_id,x.collector_id,x.export_leaf);
 IF now_at IS NULL OR NOT isfinite(now_at) OR NOT contour.causal_runtime_authority_locked(x,now_at) THEN RETURN false; END IF;
 checked_at:=pg_catalog.clock_timestamp();
 IF checked_at IS NULL OR NOT isfinite(checked_at) OR checked_at<now_at THEN RETURN false; END IF;
 RETURN EXISTS (SELECT 1 FROM contour.causal_sessions s WHERE s.tenant_id=x.tenant_id AND s.runtime_id=x.runtime_id
    AND s.epoch=ep AND s.claim IS NOT DISTINCT FROM x AND s.issued_at<=checked_at AND checked_at<s.expires_at
    AND checked_at>=x.grant_issued AND checked_at<x.grant_expires AND checked_at>=x.policy_issued AND checked_at<x.policy_expires
    AND s.epoch=(SELECT max(y.epoch) FROM contour.causal_sessions y WHERE y.tenant_id=x.tenant_id AND y.runtime_id=x.runtime_id));
END $$;
REVOKE ALL ON FUNCTION contour.causal_runtime_authority_locked(contour.causal_session_claim,timestamptz),contour.causal_session_locked(contour.causal_session_claim,numeric,timestamptz) FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer;

CREATE FUNCTION contour.issue_causal_session(x contour.causal_session_claim)
RETURNS TABLE(epoch numeric,issued_at timestamptz,expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE now_at timestamptz; old contour.causal_sessions; highest numeric; latest contour.causal_sessions; deadline timestamptz;
BEGIN
 PERFORM contour.begin_origin_operation(x.tenant_id);
 PERFORM contour.lock_origin_credential(x.export_leaf);
 PERFORM contour.lock_origin_collector(x.tenant_id,x.collector_id);
 IF x.runtime_id IS NULL OR x.source_id IS NULL OR x.project_id IS NULL OR x.service_id IS NULL OR x.environment_id IS NULL OR x.deployment_id IS NULL OR x.instance_id IS NULL OR x.lifecycle_id IS NULL OR x.nonce IS NULL
 OR x.grant_revision IS NULL OR x.grant_revision<>trunc(x.grant_revision) OR x.grant_revision NOT BETWEEN 1 AND 18446744073709551615
 OR x.policy_revision IS NULL OR x.policy_revision<>trunc(x.policy_revision) OR x.policy_revision NOT BETWEEN 1 AND 18446744073709551615
 OR x.grant_digest IS NULL OR octet_length(x.grant_digest)<>32 OR x.policy_envelope IS NULL OR octet_length(x.policy_envelope) NOT BETWEEN 1 AND 1048576
 OR x.grant_issued IS NULL OR NOT isfinite(x.grant_issued) OR x.grant_expires IS NULL OR NOT isfinite(x.grant_expires)
 OR x.policy_issued IS NULL OR NOT isfinite(x.policy_issued) OR x.policy_expires IS NULL OR NOT isfinite(x.policy_expires)
 OR x.grant_expires<=x.grant_issued OR x.grant_expires-x.grant_issued>interval '15 minutes' OR x.policy_expires<=x.policy_issued
 OR x.ttl_microseconds IS NULL OR x.ttl_microseconds NOT BETWEEN 1 AND 900000000
 OR x.max_batch_events IS NULL OR x.max_batch_events NOT BETWEEN 1 AND 500 OR x.max_batch_bytes IS NULL OR x.max_batch_bytes NOT BETWEEN 1 AND 1048576
 OR x.queue_bytes IS NULL OR x.queue_bytes NOT BETWEEN 1 AND 268435456 OR x.queue_ttl_seconds IS NULL OR x.queue_ttl_seconds NOT BETWEEN 1 AND 86400
 THEN RAISE EXCEPTION 'invalid session assertion' USING ERRCODE='23514'; END IF;
 now_at:=pg_catalog.clock_timestamp();
 SELECT * INTO latest FROM contour.causal_sessions s WHERE s.tenant_id=x.tenant_id AND s.runtime_id=x.runtime_id ORDER BY s.epoch DESC LIMIT 1;
 IF now_at IS NULL OR NOT isfinite(now_at) OR (latest.epoch IS NOT NULL AND now_at<latest.issued_at) OR NOT contour.causal_runtime_authority_locked(x,now_at)
 THEN RAISE EXCEPTION 'session unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_sessions s WHERE s.tenant_id=x.tenant_id AND s.runtime_id=x.runtime_id AND s.nonce=x.nonce;
 IF FOUND THEN
  IF old.claim IS NOT DISTINCT FROM x AND contour.causal_session_locked(x,old.epoch,now_at) THEN
   RETURN QUERY SELECT old.epoch,old.issued_at,old.expires_at; RETURN;
  END IF;
  RAISE EXCEPTION 'nonce unavailable' USING ERRCODE='23505';
 END IF;
 IF latest.epoch IS NOT NULL AND (x.grant_revision<(latest.claim).grant_revision OR (x.grant_revision=(latest.claim).grant_revision AND x.grant_digest IS DISTINCT FROM (latest.claim).grant_digest))
 THEN RAISE EXCEPTION 'grant revision unavailable' USING ERRCODE='23514'; END IF;
 highest:=coalesce(latest.epoch,0);
 IF highest>=18446744073709551615 THEN RAISE EXCEPTION 'session epoch exhausted' USING ERRCODE='22003'; END IF;
 deadline:=least(now_at + x.ttl_microseconds * interval '1 microsecond',x.grant_expires,x.policy_expires);
 IF NOT isfinite(deadline) OR deadline<=now_at THEN RAISE EXCEPTION 'invalid session lease' USING ERRCODE='23514'; END IF;
 INSERT INTO contour.causal_sessions VALUES (x.tenant_id,x.runtime_id,highest+1,x.nonce,x,now_at,deadline);
 -- Recheck after INSERT and its triggers/constraints; if work consumed the
 -- bounded lease, raising here rolls the row, nonce and revision back together.
 IF NOT contour.causal_session_locked(x,highest+1,now_at) THEN
  RAISE EXCEPTION 'session unavailable at final lease check' USING ERRCODE='23514';
 END IF;
 -- A caller can still delay COMMIT. An atomic admission consumer must recheck
 -- the session under its locks in the transaction containing the admission.
 RETURN QUERY SELECT highest+1,now_at,deadline;
END $$;
CREATE FUNCTION contour.check_causal_session(t uuid,runtime uuid,ep numeric) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b contour.causal_runtime_bindings; s contour.causal_sessions; now_at timestamptz;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 SELECT * INTO b FROM contour.causal_runtime_bindings WHERE tenant_id=t AND runtime_id=runtime;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM contour.lock_origin_credential(b.export_leaf_sha256);
 PERFORM contour.lock_origin_collector(t,b.collector_id);
 SELECT * INTO s FROM contour.causal_sessions WHERE tenant_id=t AND runtime_id=runtime AND epoch=ep;
 IF NOT FOUND THEN RETURN false; END IF;
 now_at:=pg_catalog.clock_timestamp();
 RETURN contour.causal_session_locked(s.claim,ep,now_at);
END $$;
REVOKE ALL ON FUNCTION contour.issue_causal_session(contour.causal_session_claim),contour.check_causal_session(uuid,uuid,numeric) FROM PUBLIC,contour_runtime,contour_causal_provisioner;
GRANT USAGE ON SCHEMA contour TO contour_causal_issuer;
GRANT USAGE ON TYPE contour.causal_session_claim TO contour_causal_issuer;
GRANT EXECUTE ON FUNCTION contour.issue_causal_session(contour.causal_session_claim),contour.check_causal_session(uuid,uuid,numeric) TO contour_causal_issuer;
INSERT INTO contour.schema_migrations(version) VALUES (19);
COMMIT;
